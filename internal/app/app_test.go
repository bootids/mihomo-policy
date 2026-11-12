package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mihomo-policy/internal/analyze"
	"mihomo-policy/internal/policy"
	"mihomo-policy/internal/store"
)

func TestReportUsesOnlyHomeAndPreservesAIPriority(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := filepath.Join(dir, "policy.yaml")
	os.WriteFile(p, []byte("version: 1\nfallback: DIRECT\ncategories:\n- name: ai\n  priority: 1000\n  policy: AI\n  rules: [DOMAIN-SUFFIX,google.com]\n"), 0600)
	// Quote the rule so YAML parses it as one classical rule.
	os.WriteFile(p, []byte("version: 1\nfallback: DIRECT\ncategories:\n- name: ai\n  priority: 1000\n  policy: AI\n  rules: [\"DOMAIN-SUFFIX,google.com\"]\n"), 0600)
	b, err := policy.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-48 * time.Hour)
	db.AddTraffic(ctx, "home-record", "home", start, []store.TrafficRow{{Host: "gemini.google.com", Down: 100}})
	db.AddTraffic(ctx, "office-record", "office", start, []store.TrafficRow{{Host: "office-only.example", Down: 999}})
	for i := 0; i < 20; i++ {
		at := start.Add(time.Duration(i) * 2 * time.Hour)
		id := fmt.Sprint(i)
		err = db.AddProbePair(ctx, []store.Probe{
			{RunID: id, Source: "home", At: at, Host: "gemini.google.com", Target: "gemini", ContextID: "verified-config", Route: "DIRECT", OK: true, Reachable: true, DurationMS: 10},
			{RunID: id, Source: "home", At: at, Host: "gemini.google.com", Target: "gemini", ContextID: "verified-config", Route: "PROXY", OK: true, Reachable: true, DurationMS: 20},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	r, err := analyze.ReportFor(ctx, db, b, "home", start.Add(-time.Second), time.Now(), analyze.DefaultThresholds(), analyze.ProbeTarget{Host: "gemini.google.com", Name: "gemini", ContextID: "verified-config"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Candidates) != 1 {
		t.Fatalf("other source leaked: %+v", r.Candidates)
	}
	c := r.Candidates[0]
	if c.Match.Category != "ai" || !c.PriorityReview || c.Suggestion != "direct_candidate" {
		t.Fatalf("%+v", c)
	}
	if c.Change == nil || c.Change.Type != "DOMAIN" || c.Change.Value != "gemini.google.com" || c.Change.Policy != "DIRECT" {
		t.Fatalf("proposal generalized beyond tested domain: %+v", c.Change)
	}
	current, _ := policy.Load(p)
	if current.Version != b.Version {
		t.Fatal("analysis mutated rules")
	}
}
