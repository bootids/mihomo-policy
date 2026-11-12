package dashboard

import (
	"sort"
	"strings"

	"mihomo-policy/internal/analyze"
	"mihomo-policy/internal/policy"
	"mihomo-policy/internal/store"
)

func candidateStatus(c analyze.Candidate) string {
	if c.Ignored {
		return "ignored"
	}
	if c.InDirect || c.Match.Policy == "DIRECT" {
		return "direct"
	}
	if c.DirectTest != nil && c.DirectTest.Passed {
		return "passed"
	}
	return "pending"
}

func enrichCandidates(rows []analyze.Candidate, b *policy.Bundle, ig *policy.IgnoreSet, tests map[string]store.DirectTestRecord) []analyze.Candidate {
	out := make([]analyze.Candidate, len(rows))
	for i, c := range rows {
		l1, l2, err := policy.DomainLevels(c.Traffic.Host)
		if err != nil {
			l1, l2 = c.Traffic.Host, c.Traffic.Host
		}
		c.Level = "host"
		c.L1Domain = l1
		c.L2Domain = l2
		c.ChildCount = 1
		c.InDirect, c.DirectRule = b.DirectRuleMatch(c.Traffic.Host)
		c.Ignored, c.IgnoreRule = ig.Match(c.Traffic.Host)
		if dt, ok := tests[c.Traffic.Host]; ok {
			dtCopy := dt
			c.DirectTest = &dtCopy
		} else if c.Traffic.Host == l2 {
			if dt2, ok := tests[l2]; ok {
				dtCopy := dt2
				c.DirectTest = &dtCopy
			}
		}
		out[i] = c
	}
	return out
}

func countDistinctLevels(enriched []analyze.Candidate) map[string]int {
	l1Set := map[string]struct{}{}
	l2Set := map[string]struct{}{}
	for _, c := range enriched {
		if c.L1Domain != "" {
			l1Set[c.L1Domain] = struct{}{}
		}
		if c.L2Domain != "" {
			l2Set[c.L2Domain] = struct{}{}
		}
	}
	return map[string]int{
		"l1":   len(l1Set),
		"l2":   len(l2Set),
		"host": len(enriched),
	}
}

func aggregateCandidates(enriched []analyze.Candidate, level string, b *policy.Bundle, ig *policy.IgnoreSet, tests map[string]store.DirectTestRecord, fullChildren bool) []analyze.Candidate {
	if level == "" || level == "host" {
		out := make([]analyze.Candidate, len(enriched))
		copy(out, enriched)
		return out
	}

	type acc struct {
		domain       string
		l1           string
		l2           string
		traffic      store.HostStats
		routeMap     map[string]*store.RouteStats
		dimMap       map[string]*store.DimensionStats
		children     []analyze.ChildDomain
		catSet       map[string]bool
		evidence     []analyze.Evidence
		allIgnored   bool
		anyVisited   bool
		anyFailure   bool
		routeVerdict string
		verdictMixed bool
	}

	groups := map[string]*acc{}
	var order []string

	for _, c := range enriched {
		key := c.L1Domain
		if level == "l2" {
			key = c.L2Domain
		}
		if key == "" {
			key = c.Traffic.Host
		}
		g := groups[key]
		if g == nil {
			l1, l2, _ := policy.DomainLevels(key)
			if l1 == "" {
				l1, l2 = key, key
			}
			g = &acc{
				domain:     key,
				l1:         l1,
				l2:         l2,
				traffic:    store.HostStats{Host: key, FailureKinds: map[string]int64{}},
				routeMap:   map[string]*store.RouteStats{},
				dimMap:     map[string]*store.DimensionStats{},
				catSet:     map[string]bool{},
				allIgnored: true,
			}
			groups[key] = g
			order = append(order, key)
		}

		h := c.Traffic
		g.traffic.Up += h.Up
		g.traffic.Down += h.Down
		g.traffic.SampleRows += h.SampleRows
		g.traffic.Failures += h.Failures
		if h.SampleRows > 0 {
			g.anyVisited = true
		}
		if h.Failures > 0 {
			g.anyFailure = true
		}
		if h.FirstSeen != nil && (g.traffic.FirstSeen == nil || h.FirstSeen.Before(*g.traffic.FirstSeen)) {
			t := *h.FirstSeen
			g.traffic.FirstSeen = &t
		}
		if h.LastSeen != nil && (g.traffic.LastSeen == nil || h.LastSeen.After(*g.traffic.LastSeen)) {
			t := *h.LastSeen
			g.traffic.LastSeen = &t
		}
		if h.LastFailure != nil && (g.traffic.LastFailure == nil || h.LastFailure.After(*g.traffic.LastFailure)) {
			t := *h.LastFailure
			g.traffic.LastFailure = &t
		}
		for k, v := range h.FailureKinds {
			g.traffic.FailureKinds[k] += v
		}
		for _, rt := range h.Routes {
			rk := rt.Route + "\x00" + rt.Node + "\x00" + rt.Rule
			cur := g.routeMap[rk]
			if cur == nil {
				cp := rt
				g.routeMap[rk] = &cp
			} else {
				cur.Up += rt.Up
				cur.Down += rt.Down
				cur.SampleRows += rt.SampleRows
				if rt.LastSeen.After(cur.LastSeen) {
					cur.LastSeen = rt.LastSeen
				}
			}
		}
		for _, dim := range h.Dimensions {
			dk := dim.Client + "\x00" + dim.Network + "\x00" + dim.AddressFamily + "\x00" + dim.Port
			cur := g.dimMap[dk]
			if cur == nil {
				cp := dim
				g.dimMap[dk] = &cp
			} else {
				cur.Bytes += dim.Bytes
			}
		}
		if c.Match.Category != "" {
			g.catSet[c.Match.Category] = true
		}
		if !c.Ignored {
			g.allIgnored = false
		}
		if len(c.Evidence) > 0 {
			g.evidence = append(g.evidence, c.Evidence...)
		}
		if c.RouteVerdict != "" && c.RouteVerdict != "observe" {
			if g.routeVerdict == "" {
				g.routeVerdict = c.RouteVerdict
			} else if g.routeVerdict != c.RouteVerdict {
				g.verdictMixed = true
			}
		}

		g.children = append(g.children, analyze.ChildDomain{
			Host:         h.Host,
			Up:           h.Up,
			Down:         h.Down,
			SampleRows:   h.SampleRows,
			Failures:     h.Failures,
			Match:        c.Match,
			CurrentRoute: c.CurrentRoute,
			InDirect:     c.InDirect,
			Ignored:      c.Ignored,
			DirectTest:   c.DirectTest,
		})
	}

	out := make([]analyze.Candidate, 0, len(order))
	for _, key := range order {
		g := groups[key]
		for _, rt := range g.routeMap {
			g.traffic.Routes = append(g.traffic.Routes, *rt)
		}
		sort.Slice(g.traffic.Routes, func(i, j int) bool {
			a, b := g.traffic.Routes[i], g.traffic.Routes[j]
			if a.Up+a.Down != b.Up+b.Down {
				return a.Up+a.Down > b.Up+b.Down
			}
			return a.Route < b.Route
		})
		seenRoute := map[string]bool{}
		for _, rt := range g.traffic.Routes {
			if !seenRoute[rt.Route] {
				seenRoute[rt.Route] = true
				g.traffic.ObservedRoutes = append(g.traffic.ObservedRoutes, rt.Route)
			}
		}

		for _, dim := range g.dimMap {
			g.traffic.Dimensions = append(g.traffic.Dimensions, *dim)
		}
		sort.Slice(g.traffic.Dimensions, func(i, j int) bool {
			return g.traffic.Dimensions[i].Bytes > g.traffic.Dimensions[j].Bytes
		})
		if len(g.traffic.Dimensions) > 30 {
			g.traffic.Dimensions = g.traffic.Dimensions[:30]
		}

		sort.Slice(g.children, func(i, j int) bool {
			a, b := g.children[i], g.children[j]
			if a.Up+a.Down != b.Up+b.Down {
				return a.Up+a.Down > b.Up+b.Down
			}
			return a.Host < b.Host
		})
		childCount := len(g.children)
		children := g.children
		if !fullChildren && len(children) > 5 {
			children = children[:5]
		}

		var cats []string
		for cat := range g.catSet {
			cats = append(cats, cat)
		}
		sort.Strings(cats)

		var match policy.Match
		if b != nil {
			if m, e := b.MatchDomain(g.domain); e == nil {
				match = m
			}
		}
		if match.Category == "" && len(g.children) > 0 {
			match = g.children[0].Match
		}

		origin := "probe_only"
		if g.anyVisited {
			origin = "traffic"
		} else if g.anyFailure {
			origin = "failure_only"
		}

		routeKind := aggregateObservedRoute(g.traffic.Routes)
		verdict := "observe"
		if !g.verdictMixed && g.routeVerdict != "" {
			verdict = g.routeVerdict
		}

		inDirect, directRule := b.DirectRuleMatch(g.domain)
		ignored, ignoreRule := ig.Match(g.domain)
		if !ignored && g.allIgnored && childCount > 0 {
			ignored = true
			ignoreRule = "子域名已全部忽略"
		}

		var dt *store.DirectTestRecord
		if rec, ok := tests[g.domain]; ok {
			cp := rec
			dt = &cp
		} else if childCount == 1 && g.children[0].DirectTest != nil {
			cp := *g.children[0].DirectTest
			dt = &cp
		}

		suggestion := "observe"
		if inDirect || match.Policy == "DIRECT" {
			suggestion = "keep"
		} else if dt != nil && dt.Passed {
			suggestion = "direct_candidate"
		} else if verdict == "direct_candidate" || verdict == "proxy_candidate" {
			suggestion = verdict
		}

		out = append(out, analyze.Candidate{
			Traffic:         g.traffic,
			Match:           match,
			Origin:          origin,
			CurrentRoute:    routeKind,
			RouteVerdict:    verdict,
			Evidence:        g.evidence,
			Suggestion:      suggestion,
			PriorityReview:  len(cats) > 1 || (match.Category != "" && match.Category != "fallback" && match.Policy != "DIRECT"),
			Level:           level,
			L1Domain:        g.l1,
			L2Domain:        g.l2,
			ChildCount:      childCount,
			Children:        children,
			ChildCategories: cats,
			InDirect:        inDirect,
			DirectRule:      directRule,
			Ignored:         ignored,
			IgnoreRule:      ignoreRule,
			DirectTest:      dt,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		// Default order: non-ignored traffic bytes desc, then failures desc, then host asc.
		if a.Ignored != b.Ignored {
			return !a.Ignored
		}
		ab, bb := a.Traffic.Up+a.Traffic.Down, b.Traffic.Up+b.Traffic.Down
		if ab != bb {
			return ab > bb
		}
		if a.Traffic.Failures != b.Traffic.Failures {
			return a.Traffic.Failures > b.Traffic.Failures
		}
		return a.Traffic.Host < b.Traffic.Host
	})
	return out
}

func aggregateObservedRoute(routes []store.RouteStats) string {
	route := ""
	for _, r := range routes {
		kind := "unverified"
		if r.Node == "DIRECT" {
			kind = "DIRECT"
		} else if strings.HasPrefix(r.Node, "REJECT") {
			kind = "REJECT"
		}
		if route != "" && route != kind {
			return "mixed"
		}
		route = kind
	}
	if route == "" {
		return "unknown"
	}
	return route
}

func sampleHostsForTest(enriched []analyze.Candidate, domain, level string) []string {
	type scored struct {
		host  string
		bytes int64
	}
	var matches []scored
	for _, c := range enriched {
		if c.Traffic.SampleRows <= 0 {
			continue
		}
		h := c.Traffic.Host
		matched := false
		switch level {
		case "l1":
			matched = c.L1Domain == domain
		case "l2":
			matched = c.L2Domain == domain
		default:
			matched = h == domain || strings.HasSuffix(h, "."+domain)
		}
		if matched {
			matches = append(matches, scored{host: h, bytes: c.Traffic.Up + c.Traffic.Down})
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].bytes != matches[j].bytes {
			return matches[i].bytes > matches[j].bytes
		}
		return matches[i].host < matches[j].host
	})
	out := make([]string, 0, min(3, len(matches)))
	for i := 0; i < len(matches) && i < 3; i++ {
		out = append(out, matches[i].host)
	}
	return out
}
