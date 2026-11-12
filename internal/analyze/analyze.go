package analyze

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"mihomo-policy/internal/policy"
	"mihomo-policy/internal/store"
)

type Thresholds struct {
	MinPairs          int
	MinWindows        int
	Window            time.Duration
	MinSpan           time.Duration
	SuccessRate       float64
	DirectFailureRate float64
	EvidenceLookback  time.Duration
	MaxAge            time.Duration
	RecentPairs       int
	MinDirectWinRate  float64
}

func DefaultThresholds() Thresholds {
	return Thresholds{MinPairs: 20, MinWindows: 3, Window: 4 * time.Hour, MinSpan: 24 * time.Hour, SuccessRate: .95, DirectFailureRate: .8, EvidenceLookback: 7 * 24 * time.Hour, MaxAge: 12 * time.Hour, RecentPairs: 5, MinDirectWinRate: .5}
}

func (t Thresholds) defaults() Thresholds {
	d := DefaultThresholds()
	if t.MinPairs == 0 {
		t.MinPairs = d.MinPairs
	}
	if t.MinWindows == 0 {
		t.MinWindows = d.MinWindows
	}
	if t.Window == 0 {
		t.Window = d.Window
	}
	if t.MinSpan == 0 {
		t.MinSpan = d.MinSpan
	}
	if t.SuccessRate == 0 {
		t.SuccessRate = d.SuccessRate
	}
	if t.DirectFailureRate == 0 {
		t.DirectFailureRate = d.DirectFailureRate
	}
	if t.EvidenceLookback == 0 {
		t.EvidenceLookback = d.EvidenceLookback
	}
	if t.MaxAge == 0 {
		t.MaxAge = d.MaxAge
	}
	if t.RecentPairs == 0 {
		t.RecentPairs = d.RecentPairs
	}
	if t.MinDirectWinRate == 0 {
		t.MinDirectWinRate = d.MinDirectWinRate
	}
	return t
}

type ProbeTarget struct {
	Host      string
	Name      string
	ContextID string
}

type Requirements struct {
	MinPairs          int     `json:"min_pairs"`
	MinWindows        int     `json:"min_windows"`
	WindowHours       float64 `json:"window_hours"`
	MinSpanHours      float64 `json:"min_span_hours"`
	MaxAgeHours       float64 `json:"max_age_hours"`
	RecentPairs       int     `json:"recent_pairs"`
	SuccessRate       float64 `json:"success_rate"`
	DirectFailureRate float64 `json:"direct_failure_rate"`
	MinDirectWinRate  float64 `json:"min_direct_win_rate"`
}

type RecentPair struct {
	At     time.Time   `json:"at"`
	Direct store.Probe `json:"direct"`
	Proxy  store.Probe `json:"proxy"`
}

type WindowEvidence struct {
	At              time.Time `json:"at"`
	Pairs           int       `json:"pairs"`
	DirectSuccesses int       `json:"direct_successes"`
	ProxySuccesses  int       `json:"proxy_successes"`
}

type Evidence struct {
	Target                string           `json:"target"`
	ContextID             string           `json:"context_id"`
	ExcludedSamples       int              `json:"excluded_samples"`
	Pairs                 int              `json:"pairs"`
	Windows               int              `json:"windows"`
	WindowResults         []WindowEvidence `json:"window_results"`
	SpanHours             float64          `json:"span_hours"`
	FirstAt               *time.Time       `json:"first_at"`
	LastAt                *time.Time       `json:"last_at"`
	Stale                 bool             `json:"stale"`
	DirectSuccesses       int              `json:"direct_successes"`
	ProxySuccesses        int              `json:"proxy_successes"`
	DirectSuccess         float64          `json:"direct_success_rate"`
	ProxySuccess          float64          `json:"proxy_success_rate"`
	DirectNetworkFailures int              `json:"direct_network_failures"`
	DirectErrors          map[string]int   `json:"direct_errors"`
	ProxyErrors           map[string]int   `json:"proxy_errors"`
	DirectP50MS           *int64           `json:"direct_p50_ms"`
	ProxyP50MS            *int64           `json:"proxy_p50_ms"`
	DirectP95MS           *int64           `json:"direct_p95_ms"`
	ProxyP95MS            *int64           `json:"proxy_p95_ms"`
	ComparablePairs       int              `json:"comparable_pairs"`
	DirectNoWorse         int              `json:"direct_no_worse"`
	DirectWinRate         float64          `json:"direct_win_rate"`
	PairedDeltaP50MS      *int64           `json:"paired_delta_p50_ms"`
	Recent                []RecentPair     `json:"recent"`
	RecentDirectSuccesses int              `json:"recent_direct_successes"`
	RecentProxySuccesses  int              `json:"recent_proxy_successes"`
	RecentComparablePairs int              `json:"recent_comparable_pairs"`
	RecentDirectNoWorse   int              `json:"recent_direct_no_worse"`
	Verdict               string           `json:"verdict"`
	Reason                string           `json:"reason"`
}

type Change struct {
	Type          string `json:"type"`
	Value         string `json:"value"`
	Policy        string `json:"policy"`
	ObservedBytes int64  `json:"observed_bytes"`
	Note          string `json:"note"`
}

type ChildDomain struct {
	Host         string                  `json:"host"`
	Up           int64                   `json:"up"`
	Down         int64                   `json:"down"`
	SampleRows   int64                   `json:"sample_rows"`
	Failures     int64                   `json:"failures"`
	Match        policy.Match            `json:"match"`
	CurrentRoute string                  `json:"current_route"`
	InDirect     bool                    `json:"in_direct"`
	Ignored      bool                    `json:"ignored"`
	DirectTest   *store.DirectTestRecord `json:"direct_test,omitempty"`
}

type Candidate struct {
	Traffic         store.HostStats         `json:"traffic"`
	Match           policy.Match            `json:"match"`
	Origin          string                  `json:"origin"`
	CurrentRoute    string                  `json:"current_route"`
	RouteVerdict    string                  `json:"route_verdict"`
	Evidence        []Evidence              `json:"evidence"`
	Suggestion      string                  `json:"suggestion"`
	PriorityReview  bool                    `json:"priority_review"`
	Reason          string                  `json:"reason"`
	Change          *Change                 `json:"change"`
	Level           string                  `json:"level,omitempty"`
	L1Domain        string                  `json:"l1_domain,omitempty"`
	L2Domain        string                  `json:"l2_domain,omitempty"`
	ChildCount      int                     `json:"child_count,omitempty"`
	Children        []ChildDomain           `json:"children,omitempty"`
	ChildCategories []string                `json:"child_categories,omitempty"`
	InDirect        bool                    `json:"in_direct"`
	DirectRule      string                  `json:"direct_rule,omitempty"`
	Ignored         bool                    `json:"ignored"`
	IgnoreRule      string                  `json:"ignore_rule,omitempty"`
	DirectTest      *store.DirectTestRecord `json:"direct_test,omitempty"`
}

type Report struct {
	Source        string       `json:"source"`
	GeneratedAt   time.Time    `json:"generated_at"`
	Since         time.Time    `json:"since"`
	EvidenceSince time.Time    `json:"evidence_since"`
	Requirements  Requirements `json:"requirements"`
	PolicyVersion string       `json:"policy_version"`
	Candidates    []Candidate  `json:"candidates"`
	Notes         []string     `json:"notes"`
}

// Traffic uses the selected period; evidence always uses its own bounded lookback.
// Only active target configurations with an identical fingerprint are evaluated.
func ReportFor(ctx context.Context, db *store.DB, b *policy.Bundle, source string, since, now time.Time, t Thresholds, targets ...ProbeTarget) (Report, error) {
	t = t.defaults()
	r := Report{Source: source, GeneratedAt: now.UTC(), Since: since.UTC(), EvidenceSince: now.Add(-t.EvidenceLookback).UTC(), PolicyVersion: b.Version, Candidates: []Candidate{},
		Requirements: Requirements{t.MinPairs, t.MinWindows, t.Window.Hours(), t.MinSpan.Hours(), t.MaxAge.Hours(), t.RecentPairs, t.SuccessRate, t.DirectFailureRate, t.MinDirectWinRate},
		Notes: []string{
			"Only the configured source is analyzed. Traffic and probe evidence have separate periods.",
			"sample_rows counts traffic observations, not requests; polling misses short connections and connection tails. Domain-attributable bytes exclude unknown/IP-only destinations.",
			"Probe listeners and actual egress require external verification. Increment probe_environment after node, DNS or egress changes; fingerprints do not prove route identity.",
			"Failure events lack a request denominator and route correlation; counts are diagnostic signals, not failure rates.",
			"P50/P95 use successful endpoint probes only; timeout and error counts must be reviewed separately. Sample success rates are not confidence guarantees.",
			"Endpoint evidence does not establish whole-service, suffix, UDP/QUIC or IPv6 suitability. Proposed exceptions cover one exact domain only.",
			"Local draft classification may differ from deployed rules. Changes require explicit service-category and priority review; no rules are mutated.",
		}}
	hs, err := db.Hosts(ctx, source, since, now)
	if err != nil {
		return r, err
	}
	ps, err := db.Probes(ctx, source, r.EvidenceSince, now)
	if err != nil {
		return r, err
	}
	hosts := map[string]store.HostStats{}
	for _, h := range hs {
		hosts[h.Host] = h
	}
	active := map[string]map[string]ProbeTarget{}
	grouped := map[string]map[string][]store.Probe{}
	excluded := map[string]map[string]int{}
	for _, target := range targets {
		if active[target.Host] == nil {
			active[target.Host] = map[string]ProbeTarget{}
			grouped[target.Host] = map[string][]store.Probe{}
			excluded[target.Host] = map[string]int{}
		}
		active[target.Host][target.Name] = target
		if _, ok := hosts[target.Host]; !ok {
			hosts[target.Host] = store.HostStats{Host: target.Host}
		}
	}
	for _, p := range ps {
		target, ok := active[p.Host][p.Target]
		if !ok || p.At.After(now) {
			continue
		}
		if target.ContextID == "" || p.ContextID != target.ContextID {
			excluded[p.Host][p.Target]++
			continue
		}
		grouped[p.Host][p.Target] = append(grouped[p.Host][p.Target], p)
	}
	for host, h := range hosts {
		m, err := b.MatchDomain(host)
		if err != nil {
			continue
		}
		c := Candidate{Traffic: h, Match: m, Origin: "probe_only", CurrentRoute: observedRoute(h), RouteVerdict: "observe", Evidence: []Evidence{}, Suggestion: "observe", PriorityReview: m.Category != "fallback", Reason: "尚无当前配置的配对证据，请配置适合该业务的测试目标。"}
		if h.SampleRows > 0 {
			c.Origin = "traffic"
		} else if h.Failures > 0 {
			c.Origin = "failure_only"
		}
		var names []string
		for name := range active[host] {
			names = append(names, name)
		}
		sort.Strings(names)
		verdict := ""
		conflict := false
		for _, name := range names {
			e := EvaluateAt(name, grouped[host][name], t, now)
			e.ContextID = active[host][name].ContextID
			e.ExcludedSamples = excluded[host][name]
			c.Evidence = append(c.Evidence, e)
			if verdict == "" {
				verdict = e.Verdict
			} else if verdict != e.Verdict {
				conflict = true
			}
		}
		if len(names) > 0 {
			c.Reason = "探测证据不足、已过期或目标结论不一致，保持当前规则并补充验证。"
			if !conflict {
				c.RouteVerdict = verdict
			}
		}
		decide(&c)
		r.Candidates = append(r.Candidates, c)
	}
	sort.Slice(r.Candidates, func(i, j int) bool {
		a, b := r.Candidates[i], r.Candidates[j]
		rank := map[string]int{"direct_candidate": 0, "proxy_candidate": 1, "observe": 2, "keep": 3}
		if a.Suggestion != b.Suggestion {
			return rank[a.Suggestion] < rank[b.Suggestion]
		}
		if a.Traffic.Failures != b.Traffic.Failures {
			return a.Traffic.Failures > b.Traffic.Failures
		}
		x, y := a.Traffic.Up+a.Traffic.Down, b.Traffic.Up+b.Traffic.Down
		if x != y {
			return x > y
		}
		return a.Traffic.Host < b.Traffic.Host
	})
	return r, nil
}

func observedRoute(h store.HostStats) string {
	route := ""
	for _, r := range h.Routes {
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

func decide(c *Candidate) {
	if strings.HasPrefix(c.Match.Policy, "REJECT") || c.Match.Policy == "PASS" {
		c.Reason = "当前规则包含显式拦截或特殊路由意图；可达性探测不能决定是否解除该意图。"
		return
	}
	if c.RouteVerdict == "observe" {
		return
	}
	if c.RouteVerdict == "direct_candidate" && c.Match.Policy == "DIRECT" {
		if c.CurrentRoute == "DIRECT" || c.CurrentRoute == "unknown" {
			c.Suggestion = "keep"
			c.Reason = "本地草案已为 DIRECT，探测支持维持现状，无需新增直连规则。"
		} else {
			c.Reason = "本地草案为 DIRECT，但观测出口未能确认一致；请先核实已部署配置与实际线路。"
		}
		return
	}
	if c.Origin == "probe_only" {
		c.Reason = "仅有主动探测，所选访问周期内没有用户流量或失败事件；保留线路评估，不生成规则变更。"
		return
	}
	if c.RouteVerdict == "proxy_candidate" && c.Match.Policy != "DIRECT" {
		c.Reason = "探测支持使用代理；当前草案已有策略组，请核实该组实际节点和探测出口，暂不推断需要改规则。"
		return
	}
	c.Suggestion = c.RouteVerdict
	destination := ""
	if c.Suggestion == "direct_candidate" {
		destination = "DIRECT"
	}
	c.Change = &Change{Type: "DOMAIN", Value: c.Traffic.Host, Policy: destination, ObservedBytes: c.Traffic.Up + c.Traffic.Down, Note: "仅评估此精确域名；子域名不在影响范围内。代理策略组须人工指定，分类与插入优先级须复核。"}
	c.Reason = "测试目标结论一致，可复核此精确域名的线路变更；须核实当前实际出口、业务适用性与分类优先级。"
}

// Evaluate compares a supplied sample set at its latest timestamp. Reports use
// EvaluateAt with wall-clock time to additionally reject expired evidence.
func Evaluate(target string, ps []store.Probe, t Thresholds) Evidence {
	var now time.Time
	for _, p := range ps {
		if p.At.After(now) {
			now = p.At
		}
	}
	return EvaluateAt(target, ps, t, now)
}

func EvaluateAt(target string, ps []store.Probe, t Thresholds, now time.Time) Evidence {
	t = t.defaults()
	e := Evidence{Target: target, Verdict: "observe", Recent: []RecentPair{}, WindowResults: []WindowEvidence{}, DirectErrors: map[string]int{}, ProxyErrors: map[string]int{}}
	type pair struct{ direct, proxy *store.Probe }
	pairs := map[string]*pair{}
	for i := range ps {
		p := &ps[i]
		if p.RunID == "" || p.At.After(now) || p.At.Before(now.Add(-t.EvidenceLookback)) {
			continue
		}
		if pairs[p.RunID] == nil {
			pairs[p.RunID] = &pair{}
		}
		if p.Route == "DIRECT" {
			pairs[p.RunID].direct = p
		}
		if p.Route == "PROXY" {
			pairs[p.RunID].proxy = p
		}
	}
	var valid []pair
	for _, p := range pairs {
		if p.direct == nil || p.proxy == nil || p.direct.Host != p.proxy.Host || p.direct.Target != p.proxy.Target || p.direct.ContextID != p.proxy.ContextID {
			continue
		}
		delta := p.direct.At.Sub(p.proxy.At)
		if delta < 0 {
			delta = -delta
		}
		if delta > time.Minute {
			continue
		}
		valid = append(valid, *p)
	}
	sort.Slice(valid, func(i, j int) bool {
		if valid[i].direct.At.Equal(valid[j].direct.At) {
			return valid[i].direct.RunID < valid[j].direct.RunID
		}
		return valid[i].direct.At.Before(valid[j].direct.At)
	})
	var directTimes, proxyTimes, deltas []int64
	windows := map[int64]*WindowEvidence{}
	ambiguous := false
	for _, p := range valid {
		at := p.direct.At
		w := at.Unix() / int64(t.Window/time.Second)
		if windows[w] == nil {
			windows[w] = &WindowEvidence{At: time.Unix(w*int64(t.Window/time.Second), 0).UTC()}
		}
		windows[w].Pairs++
		if p.direct.OK {
			e.DirectSuccesses++
			windows[w].DirectSuccesses++
			directTimes = append(directTimes, p.direct.DurationMS)
		} else {
			e.DirectErrors[errorKey(*p.direct)]++
			if networkFailure(*p.direct) {
				e.DirectNetworkFailures++
			} else {
				ambiguous = true
			}
		}
		if p.proxy.OK {
			e.ProxySuccesses++
			windows[w].ProxySuccesses++
			proxyTimes = append(proxyTimes, p.proxy.DurationMS)
		} else {
			e.ProxyErrors[errorKey(*p.proxy)]++
			ambiguous = true
		}
		if p.direct.OK && p.proxy.OK {
			deltas = append(deltas, p.direct.DurationMS-p.proxy.DurationMS)
			if p.direct.DurationMS <= p.proxy.DurationMS {
				e.DirectNoWorse++
			}
		}
	}
	e.Pairs = len(valid)
	e.Windows = len(windows)
	e.ComparablePairs = len(deltas)
	if e.Pairs > 0 {
		first, last := valid[0].direct.At, valid[len(valid)-1].direct.At
		e.FirstAt, e.LastAt = &first, &last
		e.SpanHours = last.Sub(first).Hours()
		e.Stale = now.Sub(last) > t.MaxAge
		e.DirectSuccess = float64(e.DirectSuccesses) / float64(e.Pairs)
		e.ProxySuccess = float64(e.ProxySuccesses) / float64(e.Pairs)
	}
	if len(deltas) > 0 {
		e.DirectWinRate = float64(e.DirectNoWorse) / float64(len(deltas))
	}
	e.DirectP50MS = quantile(directTimes, .5)
	e.ProxyP50MS = quantile(proxyTimes, .5)
	e.DirectP95MS = quantile(directTimes, .95)
	e.ProxyP95MS = quantile(proxyTimes, .95)
	e.PairedDeltaP50MS = quantile(deltas, .5)
	for _, w := range windows {
		e.WindowResults = append(e.WindowResults, *w)
	}
	sort.Slice(e.WindowResults, func(i, j int) bool { return e.WindowResults[i].At.Before(e.WindowResults[j].At) })
	recentDirectOK, recentProxyOK, recentNetworkFailures := 0, 0, 0
	for i := max(0, len(valid)-t.RecentPairs); i < len(valid); i++ {
		p := valid[i]
		e.Recent = append(e.Recent, RecentPair{p.direct.At, *p.direct, *p.proxy})
		if p.direct.OK {
			recentDirectOK++
		}
		if p.proxy.OK {
			recentProxyOK++
		}
		if p.direct.OK && p.proxy.OK {
			e.RecentComparablePairs++
			if p.direct.DurationMS <= p.proxy.DurationMS {
				e.RecentDirectNoWorse++
			}
		}
		if networkFailure(*p.direct) {
			recentNetworkFailures++
		}
	}
	e.RecentDirectSuccesses, e.RecentProxySuccesses = recentDirectOK, recentProxyOK
	if e.Pairs < t.MinPairs || e.Windows < t.MinWindows || e.SpanHours < t.MinSpan.Hours() {
		e.Reason = fmt.Sprintf("有效配对 %d/%d 组、窗口 %d/%d 个、跨度 %.1f/%.1fh，尚未满足证据门槛。", e.Pairs, t.MinPairs, e.Windows, t.MinWindows, e.SpanHours, t.MinSpan.Hours())
		return e
	}
	if e.Stale {
		e.Reason = fmt.Sprintf("最近证据超过 %.1fh，需重新探测。", t.MaxAge.Hours())
		return e
	}
	if ambiguous {
		e.Reason = "存在 HTTP 拒绝、证书、DNS、入口或其他未归因错误，需要先诊断。"
		return e
	}
	recent := len(e.Recent)
	if recentProxyOK != recent {
		e.Reason = "近期代理线路尚未全部恢复成功，暂停变更建议。"
		return e
	}
	if e.DirectSuccess >= t.SuccessRate && e.ProxySuccess >= t.SuccessRate && recentDirectOK == recent && e.PairedDeltaP50MS != nil && *e.PairedDeltaP50MS <= 0 && e.DirectWinRate >= t.MinDirectWinRate && e.RecentComparablePairs > 0 && float64(e.RecentDirectNoWorse)/float64(e.RecentComparablePairs) >= t.MinDirectWinRate && *e.DirectP95MS <= *e.ProxyP95MS {
		e.Verdict = "direct_candidate"
		e.Reason = "两路成功率达标，近期配对均成功，直连的配对耗时差、不劣比例和 P95 均满足门槛；业务适用性仍须复核。"
	} else if e.ProxySuccess >= t.SuccessRate && float64(e.DirectNetworkFailures)/float64(e.Pairs) >= t.DirectFailureRate && float64(recentNetworkFailures)/float64(recent) >= t.DirectFailureRate {
		e.Verdict = "proxy_candidate"
		e.Reason = "长期与近期配对均显示重复的直连 TLS 传输失败，代理近期配对均成功。"
	} else {
		e.Reason = "近期健康度或配对耗时比较未支持稳定收益，继续观察。"
	}
	return e
}

func networkFailure(p store.Probe) bool {
	return !p.Reachable && !p.OK && p.Phase == "tls" && (p.Error == "timeout" || p.Error == "connection_failed")
}
func errorKey(p store.Probe) string {
	key := p.Error
	if key == "" {
		key = "unknown"
	}
	return p.Phase + ":" + key
}
func quantile(ns []int64, q float64) *int64 {
	if len(ns) == 0 {
		return nil
	}
	sort.Slice(ns, func(i, j int) bool { return ns[i] < ns[j] })
	var n int64
	if q == .5 && len(ns)%2 == 0 {
		a, b := ns[len(ns)/2-1], ns[len(ns)/2]
		n = a + (b-a)/2
	} else {
		index := int(float64(len(ns)) * q)
		if float64(index) < float64(len(ns))*q {
			index++
		}
		n = ns[max(0, index-1)]
	}
	return &n
}
