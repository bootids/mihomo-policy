package analyze

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"mihomo-policy/internal/policy"
	"mihomo-policy/internal/store"
)

func evidence(directOK bool) []store.Probe {
	var ps []store.Probe
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		at := start.Add(time.Duration(i) * 2 * time.Hour)
		run := fmt.Sprint(i)
		ps = append(ps, store.Probe{RunID: run, At: at, Route: "DIRECT", OK: directOK, Reachable: directOK, Phase: "tls", Error: "timeout", DurationMS: 100}, store.Probe{RunID: run, At: at, Route: "PROXY", OK: true, Reachable: true, DurationMS: 200})
	}
	return ps
}

func TestRecentFailuresAndStaleEvidenceStopChanges(t *testing.T) {
	var ps []store.Probe
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 100; i++ {
		at := start.Add(time.Duration(i) * time.Hour)
		ok := i < 95
		ps = append(ps, store.Probe{RunID: fmt.Sprint(i), At: at, Route: "DIRECT", OK: ok, Reachable: ok, DurationMS: 100, Phase: "tls", Error: "timeout"}, store.Probe{RunID: fmt.Sprint(i), At: at, Route: "PROXY", OK: true, Reachable: true, DurationMS: 200})
	}
	e := Evaluate("recent-regression", ps, DefaultThresholds())
	if e.DirectSuccess != .95 || e.Verdict != "observe" || len(e.Recent) != 5 {
		t.Fatalf("recent failures were diluted: %+v", e)
	}
	ps = evidence(true)
	ps[len(ps)-2].OK = false
	ps[len(ps)-2].Reachable = false
	ps[len(ps)-2].Error = "certificate"
	if e := Evaluate("certificate", ps, DefaultThresholds()); e.Verdict != "observe" {
		t.Fatalf("ignored certificate failure: %+v", e)
	}
	ps = evidence(true)
	if e := EvaluateAt("expired", ps, DefaultThresholds(), ps[len(ps)-1].At.Add(13*time.Hour)); !e.Stale || e.Verdict != "observe" {
		t.Fatalf("accepted stale evidence: %+v", e)
	}
}

func TestLatencyUsesPairedDifferencesAndTail(t *testing.T) {
	ps := evidence(true)
	for i := 0; i < 20; i++ {
		ps[2*i].DurationMS = 100
		ps[2*i+1].DurationMS = 50
		if i >= 10 {
			ps[2*i+1].DurationMS = 200
		}
		if i >= 11 {
			ps[2*i].DurationMS = 1000
		}
	}
	e := Evaluate("paired", ps, DefaultThresholds())
	if *e.DirectP50MS != 100 || *e.ProxyP50MS != 125 || e.DirectNoWorse != 1 || e.Verdict != "observe" {
		t.Fatalf("independent medians overrode pairing: %+v", e)
	}
	ps = evidence(true)
	for i := 0; i < 2; i++ {
		ps[2*i].DurationMS = 2000
	}
	if e := Evaluate("tail", ps, DefaultThresholds()); e.Verdict != "observe" || *e.DirectP95MS <= *e.ProxyP95MS {
		t.Fatalf("ignored tail latency: %+v", e)
	}
}

func TestFailedPathHasNoLatencyAndProxyTLSIsInfrastructure(t *testing.T) {
	ps := evidence(false)
	e := Evaluate("all-failed", ps, DefaultThresholds())
	if e.Verdict != "proxy_candidate" || e.DirectP50MS != nil || e.DirectP95MS != nil || e.ProxyP50MS == nil || e.PairedDeltaP50MS != nil {
		t.Fatalf("misrepresented failed latency: %+v", e)
	}
	for i := range ps {
		if ps[i].Route == "DIRECT" {
			ps[i].Phase = "proxy_tls"
		}
	}
	if e := Evaluate("proxy-tls", ps, DefaultThresholds()); e.Verdict != "observe" || e.DirectNetworkFailures != 0 {
		t.Fatalf("proxy TLS mistaken for target TLS: %+v", e)
	}
}

func reportFixture(t *testing.T) (*store.DB, []store.Probe, time.Time, ProbeTarget) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ps := evidence(true)
	for i := range ps {
		ps[i].Source = "home"
		ps[i].Host = "example.com"
		ps[i].Target = "health"
		ps[i].ContextID = "current"
	}
	for i := 0; i < len(ps); i += 2 {
		if err := db.AddProbePair(context.Background(), ps[i:i+2]); err != nil {
			t.Fatal(err)
		}
	}
	return db, ps, ps[len(ps)-1].At.Add(time.Hour), ProbeTarget{Host: "example.com", Name: "health", ContextID: "current"}
}

func TestReportSeparatesPeriodsAndNoOpChanges(t *testing.T) {
	db, _, now, target := reportFixture(t)
	ctx := context.Background()
	if err := db.AddTraffic(ctx, "traffic", "home", now.Add(-time.Hour), []store.TrafficRow{{Host: target.Host, Node: "DIRECT", Route: "DIRECT", Down: 42}}); err != nil {
		t.Fatal(err)
	}
	for _, period := range []time.Duration{24 * time.Hour, 7 * 24 * time.Hour, 30 * 24 * time.Hour} {
		r, err := ReportFor(ctx, db, &policy.Bundle{Fallback: "DIRECT"}, "home", now.Add(-period), now, DefaultThresholds(), target)
		if err != nil {
			t.Fatal(err)
		}
		c := r.Candidates[0]
		if c.RouteVerdict != "direct_candidate" || c.Suggestion != "keep" || c.Change != nil || c.Evidence[0].Pairs != 20 || !r.EvidenceSince.Equal(now.Add(-7*24*time.Hour)) {
			t.Fatalf("period changed evidence or generated no-op: %+v", r)
		}
	}
}

func TestReportRequiresEveryActiveTargetAndMatchingContext(t *testing.T) {
	db, _, now, target := reportFixture(t)
	ctx := context.Background()
	if err := db.AddTraffic(ctx, "traffic", "home", now.Add(-time.Hour), []store.TrafficRow{{Host: target.Host, Node: "node-A", Down: 42}}); err != nil {
		t.Fatal(err)
	}
	b := &policy.Bundle{Fallback: "PROXY"}
	for _, tc := range []struct {
		name                    string
		targets                 []ProbeTarget
		wantPairs, wantExcluded int
	}{
		{"changed", []ProbeTarget{{Host: target.Host, Name: target.Name, ContextID: "changed"}}, 0, 40},
		{"removed", nil, 0, 0},
		{"untested-endpoint", []ProbeTarget{target, {Host: target.Host, Name: "business", ContextID: "current"}}, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ReportFor(ctx, db, b, "home", now.Add(-24*time.Hour), now, DefaultThresholds(), tc.targets...)
			if err != nil {
				t.Fatal(err)
			}
			c := r.Candidates[0]
			if c.Suggestion != "observe" || c.RouteVerdict != "observe" {
				t.Fatalf("accepted invalid endpoint evidence: %+v", c)
			}
			if tc.name == "changed" && (c.Evidence[0].Pairs != tc.wantPairs || c.Evidence[0].ExcludedSamples != tc.wantExcluded) {
				t.Fatalf("old context mixed: %+v", c)
			}
		})
	}
}

func TestProbeOnlyAndRejectedHostsDoNotGenerateChanges(t *testing.T) {
	db, _, now, target := reportFixture(t)
	ctx := context.Background()
	for _, outbound := range []string{"PROXY", "REJECT"} {
		r, err := ReportFor(ctx, db, &policy.Bundle{Fallback: outbound}, "home", now.Add(-24*time.Hour), now, DefaultThresholds(), target)
		if err != nil {
			t.Fatal(err)
		}
		c := r.Candidates[0]
		if c.RouteVerdict != "direct_candidate" || c.Suggestion != "observe" || c.Change != nil || c.Origin != "probe_only" {
			t.Fatalf("generated unsupported change: %+v", c)
		}
	}
	if err := db.AddTraffic(ctx, "real-traffic", "home", now.Add(-time.Hour), []store.TrafficRow{{Host: target.Host, Node: "DIRECT", Down: 42}}); err != nil {
		t.Fatal(err)
	}
	for _, outbound := range []string{"REJECT", "PASS"} {
		r, err := ReportFor(ctx, db, &policy.Bundle{Fallback: outbound}, "home", now.Add(-24*time.Hour), now, DefaultThresholds(), target)
		if err != nil {
			t.Fatal(err)
		}
		c := r.Candidates[0]
		if c.Origin != "traffic" || c.Suggestion != "observe" || c.Change != nil {
			t.Fatalf("ignored explicit routing intent: %+v", c)
		}
	}
}

func TestDirectDraftWithConflictingObservedExitNeedsDiagnosis(t *testing.T) {
	db, _, now, target := reportFixture(t)
	ctx := context.Background()
	if err := db.AddTraffic(ctx, "traffic", "home", now.Add(-time.Hour), []store.TrafficRow{{Host: target.Host, Node: "node-A", Route: "AI → node-A", Down: 42}}); err != nil {
		t.Fatal(err)
	}
	r, err := ReportFor(ctx, db, &policy.Bundle{Fallback: "DIRECT"}, "home", now.Add(-24*time.Hour), now, DefaultThresholds(), target)
	if err != nil {
		t.Fatal(err)
	}
	c := r.Candidates[0]
	if c.RouteVerdict != "direct_candidate" || c.CurrentRoute != "unverified" || c.Suggestion != "observe" || c.Change != nil {
		t.Fatalf("hid runtime/draft mismatch: %+v", c)
	}
}

func TestReportDoesNotIncludeMeasurementsAfterAsOfTime(t *testing.T) {
	db, _, now, target := reportFixture(t)
	ctx := context.Background()
	if err := db.AddTraffic(ctx, "future-traffic", "home", now.Add(time.Hour), []store.TrafficRow{{Host: "future.example", Down: 100000}}); err != nil {
		t.Fatal(err)
	}
	r, err := ReportFor(ctx, db, &policy.Bundle{Fallback: "PROXY"}, "home", now.Add(-24*time.Hour), now, DefaultThresholds(), target)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Candidates) != 1 || r.Candidates[0].Traffic.Host != "example.com" {
		t.Fatalf("future traffic leaked into snapshot: %+v", r)
	}
}
func TestRequiresEvidenceAcrossTime(t *testing.T) {
	ps := evidence(true)
	if e := Evaluate("x", ps, DefaultThresholds()); e.Verdict != "direct_candidate" {
		t.Fatalf("%+v", e)
	}
	for i := range ps {
		ps[i].At = time.Date(2026, 11, 1, 0, i/2, 0, 0, time.UTC)
	}
	if e := Evaluate("x", ps, DefaultThresholds()); e.Verdict != "observe" {
		t.Fatal("accepted one short burst")
	}
}
func TestHTTP403AndEndpointFailureAreNotProxyEvidence(t *testing.T) {
	ps := evidence(false)
	if e := Evaluate("x", ps, DefaultThresholds()); e.Verdict != "proxy_candidate" {
		t.Fatalf("%+v", e)
	}
	for i := range ps {
		if ps[i].Route == "DIRECT" {
			ps[i].Reachable = true
			ps[i].Status = 403
			ps[i].Phase = "http"
			ps[i].Error = "unexpected_http_status"
		}
	}
	if e := Evaluate("x", ps, DefaultThresholds()); e.Verdict != "observe" {
		t.Fatal("treated HTTP refusal as blocked transport")
	}
	for i := range ps {
		if ps[i].Route == "DIRECT" {
			ps[i].Reachable = false
			ps[i].Phase = "connect"
			ps[i].Error = "proxy_connect"
		}
	}
	if e := Evaluate("x", ps, DefaultThresholds()); e.Verdict != "observe" {
		t.Fatal("treated probe infrastructure failure as blocked target")
	}
}
func TestUnpairedResultsDoNotCount(t *testing.T) {
	ps := evidence(true)
	var only []store.Probe
	for _, p := range ps {
		if p.Route == "DIRECT" {
			only = append(only, p)
		}
	}
	if e := Evaluate("x", only, DefaultThresholds()); e.Pairs != 0 || e.Verdict != "observe" {
		t.Fatalf("%+v", e)
	}
}
