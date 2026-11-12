package dashboard

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"mihomo-policy/internal/analyze"
	"mihomo-policy/internal/policy"
	"mihomo-policy/internal/store"
)

type CategoryTraffic struct {
	Name    string `json:"name"`
	Up      int64  `json:"up"`
	Down    int64  `json:"down"`
	Domains int    `json:"domains"`
}

type listOptions struct {
	Page, Limit                                                  int
	Search, Category, Suggestion, Status, Level, Sort, Direction string
}

func queryHours(r *http.Request) (int, error) {
	if r.URL.Query().Get("hours") == "" {
		return 168, nil
	}
	n, err := strconv.Atoi(r.URL.Query().Get("hours"))
	if err != nil || n != 24 && n != 168 && n != 720 {
		return 0, fmt.Errorf("hours must be 24, 168 or 720")
	}
	return n, nil
}

func queryOptions(r *http.Request) (listOptions, error) {
	q := r.URL.Query()
	o := listOptions{
		Page:       1,
		Limit:      50,
		Search:     strings.ToLower(strings.TrimSpace(q.Get("q"))),
		Category:   q.Get("category"),
		Suggestion: q.Get("suggestion"),
		Status:     q.Get("status"),
		Level:      q.Get("level"),
		Sort:       q.Get("sort"),
		Direction:  q.Get("direction"),
	}
	for _, p := range []struct {
		name  string
		value *int
		max   int
	}{{"page", &o.Page, 1000000000}, {"limit", &o.Limit, 500}} {
		if raw := q.Get(p.name); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > p.max {
				return o, fmt.Errorf("invalid %s", p.name)
			}
			*p.value = n
		}
	}
	if len(o.Search) > 253 {
		return o, fmt.Errorf("search is too long")
	}
	if !oneOf(o.Suggestion, "", "direct_candidate", "proxy_candidate", "observe", "keep") ||
		!oneOf(o.Status, "", "pending", "passed", "direct", "ignored") ||
		!oneOf(o.Level, "", "l1", "l2", "host") ||
		!oneOf(o.Sort, "", "default", "host", "category", "bytes", "failures", "suggestion", "children") ||
		!oneOf(o.Direction, "", "asc", "desc") {
		return o, fmt.Errorf("invalid filter or sort")
	}
	return o, nil
}

func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}

func summarize(st *State) {
	st.SuggestionCounts = map[string]int{"direct_candidate": 0, "proxy_candidate": 0, "observe": 0, "keep": 0}
	st.StatusCounts = map[string]int{"all": len(st.Report.Candidates), "pending": 0, "passed": 0, "direct": 0, "ignored": 0}
	st.CategoryTraffic = []CategoryTraffic{}
	categories := map[string]*CategoryTraffic{}
	for _, c := range st.Report.Candidates {
		h := c.Traffic
		st.TotalUp += h.Up
		st.TotalDown += h.Down
		st.SuggestionCounts[c.Suggestion]++
		status := candidateStatus(c)
		st.StatusCounts[status]++
		if c.Ignored {
			st.IgnoredDomains++
		}
		if c.Suggestion == "direct_candidate" || c.Suggestion == "proxy_candidate" {
			st.TotalSuggestions++
		}
		if h.SampleRows > 0 {
			st.VisitedDomains++
		} else if h.Failures > 0 {
			st.FailureOnlyDomains++
		} else {
			st.ProbeOnlyDomains++
		}
		tested := c.DirectTest != nil
		if !tested {
			for _, e := range c.Evidence {
				if e.Pairs > 0 {
					tested = true
					break
				}
			}
		}
		if tested {
			st.TestedDomains++
		}
		name := c.Match.Category
		if categories[name] == nil {
			categories[name] = &CategoryTraffic{Name: name}
		}
		categories[name].Up += h.Up
		categories[name].Down += h.Down
		categories[name].Domains++
	}
	st.TotalBytes = st.TotalUp + st.TotalDown
	for _, c := range categories {
		st.CategoryTraffic = append(st.CategoryTraffic, *c)
	}
	sort.Slice(st.CategoryTraffic, func(i, j int) bool {
		a, b := st.CategoryTraffic[i], st.CategoryTraffic[j]
		if a.Up+a.Down != b.Up+b.Down {
			return a.Up+a.Down > b.Up+b.Down
		}
		return a.Name < b.Name
	})
	st.Attention = append([]analyze.Candidate{}, st.Report.Candidates...)
	sort.SliceStable(st.Attention, func(i, j int) bool {
		if st.Attention[i].Ignored != st.Attention[j].Ignored {
			return !st.Attention[i].Ignored
		}
		a, b := st.Attention[i].Traffic, st.Attention[j].Traffic
		if a.Failures != b.Failures {
			return a.Failures > b.Failures
		}
		return a.Up+a.Down > b.Up+b.Down
	})
	if len(st.Attention) > 8 {
		st.Attention = st.Attention[:8]
	}
}

// pageState filters, optionally aggregates by domain level, and paginates a copy of State.
func pageState(st *State, o listOptions, b *policy.Bundle, ig *policy.IgnoreSet, tests map[string]store.DirectTestRecord) {
	if o.Limit == 0 {
		o.Limit = 50
	}
	if o.Page < 1 {
		o.Page = 1
	}

	level := o.Level
	if level == "" {
		level = "host"
	}
	st.Level = level

	baseRows := st.Report.Candidates
	if level == "l1" || level == "l2" {
		baseRows = aggregateCandidates(st.Report.Candidates, level, b, ig, tests, false)
		// Recompute status counts & attention for the active aggregation level while preserving overall traffic totals.
		st.StatusCounts = map[string]int{"all": len(baseRows), "pending": 0, "passed": 0, "direct": 0, "ignored": 0}
		for _, c := range baseRows {
			st.StatusCounts[candidateStatus(c)]++
		}
		st.IgnoredDomains = st.StatusCounts["ignored"]
		st.Attention = append([]analyze.Candidate{}, baseRows...)
		sort.SliceStable(st.Attention, func(i, j int) bool {
			if st.Attention[i].Ignored != st.Attention[j].Ignored {
				return !st.Attention[i].Ignored
			}
			a, b := st.Attention[i].Traffic, st.Attention[j].Traffic
			if a.Failures != b.Failures {
				return a.Failures > b.Failures
			}
			return a.Up+a.Down > b.Up+b.Down
		})
		if len(st.Attention) > 8 {
			st.Attention = st.Attention[:8]
		}
	}

	rows := []analyze.Candidate{}
	for _, c := range baseRows {
		if o.Category != "" && c.Match.Category != o.Category && !containsStr(c.ChildCategories, o.Category) {
			continue
		}
		if o.Suggestion != "" && c.Suggestion != o.Suggestion {
			continue
		}
		if o.Status != "" && candidateStatus(c) != o.Status {
			continue
		}
		if o.Search != "" {
			haystack := strings.ToLower(c.Traffic.Host + " " + c.Match.Category + " " + c.Match.Policy)
			matched := strings.Contains(haystack, o.Search)
			if !matched {
				for _, ch := range c.Children {
					if strings.Contains(strings.ToLower(ch.Host), o.Search) {
						matched = true
						break
					}
				}
			}
			if !matched {
				continue
			}
		}
		rows = append(rows, c)
	}

	if o.Sort != "" && o.Sort != "default" {
		sort.SliceStable(rows, func(i, j int) bool {
			a, b := rows[i], rows[j]
			var cmp int
			switch o.Sort {
			case "host":
				cmp = strings.Compare(a.Traffic.Host, b.Traffic.Host)
			case "category":
				cmp = strings.Compare(a.Match.Category, b.Match.Category)
			case "suggestion":
				cmp = strings.Compare(a.Suggestion, b.Suggestion)
			case "bytes":
				cmp = compare(a.Traffic.Up+a.Traffic.Down, b.Traffic.Up+b.Traffic.Down)
			case "failures":
				cmp = compare(a.Traffic.Failures, b.Traffic.Failures)
			case "children":
				cmp = compare(int64(a.ChildCount), int64(b.ChildCount))
			}
			if cmp == 0 {
				return a.Traffic.Host < b.Traffic.Host
			}
			if o.Direction == "asc" {
				return cmp < 0
			}
			return cmp > 0
		})
	}
	st.FilteredDomains = len(rows)
	st.ReportLimit = o.Limit
	st.Pages = max(1, (len(rows)+o.Limit-1)/o.Limit)
	st.Page = min(o.Page, st.Pages)
	start := (st.Page - 1) * o.Limit
	end := min(start+o.Limit, len(rows))
	st.Report.Candidates = rows[start:end]
}

func containsStr(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}

func compare(a, b int64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
