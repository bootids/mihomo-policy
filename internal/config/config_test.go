package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeValidation(t *testing.T) {
	for _, tc := range []struct {
		body  string
		valid bool
	}{
		{"source: home\n", true},
		{"source: home\nanalysis:\n  window: 100ms\n", false},
		{"source: home\nanalysis:\n  evidence_lookback: 1h\n", false},
		{"source: home\nanalysis:\n  max_age: 200h\n", false},
		{"source: home\nanalysis:\n  recent_pairs: 1\n", false},
		{"source: home\nanalysis:\n  min_direct_win_rate: 0.2\n", false},
		{"source: home\nanalysis:\n  success_rate: .nan\n", false},
		{"source: home\nanalysis:\n  min_direct_win_rate: .nan\n", false},
		{"source: home\ncontroller: https://user:password@example.com\n", false},
		{"source: home\nunknown: value\n", false},
		{"source: home\ndirect_proxy: http://localhost:17890\nproxy_proxy: http://localhost:17890\n", false},
	} {
		p := filepath.Join(t.TempDir(), "runtime.yaml")
		os.WriteFile(p, []byte(tc.body), 0600)
		c, err := Load(p)
		if (err == nil) != tc.valid {
			t.Fatalf("%q: %v", tc.body, err)
		}
		if tc.valid && (!filepath.IsAbs(c.Database) || c.Analysis.MinPairs != 20) {
			t.Fatalf("defaults: %+v", c)
		}
	}
}

func TestProbeContextTracksMeasurementChanges(t *testing.T) {
	c := Config{DirectProxy: "http://localhost:1", ProxyProxy: "http://localhost:2", ProbeTimeout: "1s", ProbeEnvironment: "home-v1"}
	target := Target{Name: "health", URL: "https://example.com/check", ExpectedStatus: []int{204, 200}}
	want := c.ProbeContext(target)
	reordered := target
	reordered.ExpectedStatus = []int{200, 204}
	if c.ProbeContext(reordered) != want {
		t.Fatal("status order changed semantic identity")
	}
	for _, change := range []string{"url", "content", "status", "direct", "proxy", "timeout", "environment", "controller"} {
		cc, tt := c, target
		switch change {
		case "url":
			tt.URL = "https://example.com/other"
		case "content":
			tt.Contains = "healthy"
		case "status":
			tt.ExpectedStatus = []int{200}
		case "direct":
			cc.DirectProxy = "http://localhost:3"
		case "proxy":
			cc.ProxyProxy = "http://localhost:4"
		case "timeout":
			cc.ProbeTimeout = "2s"
		case "environment":
			cc.ProbeEnvironment = "home-v2"
		case "controller":
			cc.Controller = "http://localhost:9090"
		}
		if cc.ProbeContext(tt) == want {
			t.Fatalf("%s did not invalidate old evidence", change)
		}
	}
}
