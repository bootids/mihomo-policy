package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDomainLevelsICANN(t *testing.T) {
	cases := []struct {
		host   string
		wantL1 string
		wantL2 string
	}{
		{"google.com", "google.com", "google.com"},
		{"gemini.google.com", "google.com", "gemini.google.com"},
		{"alkalimakersuite-pa.clients6.google.com", "google.com", "clients6.google.com"},
		{"www.sina.com.cn", "sina.com.cn", "www.sina.com.cn"},
		{"sina.com.cn", "sina.com.cn", "sina.com.cn"},
		{"ppl-ai-file-upload.s3.amazonaws.com", "amazonaws.com", "s3.amazonaws.com"},
		{"copilot-proxy.githubusercontent.com", "githubusercontent.com", "copilot-proxy.githubusercontent.com"},
	}
	for _, tc := range cases {
		l1, l2, err := DomainLevels(tc.host)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.host, err)
		}
		if l1 != tc.wantL1 || l2 != tc.wantL2 {
			t.Fatalf("%s: got (%q, %q), want (%q, %q)", tc.host, l1, l2, tc.wantL1, tc.wantL2)
		}
	}
}

func TestMutateDirectAndIgnoreLists(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatal(err)
	}
	directList := filepath.Join(rulesDir, "direct.list")
	if err := os.WriteFile(directList, []byte("# Direct rules\nDOMAIN-SUFFIX,kimi.com\nIP-CIDR,10.0.0.0/8,no-resolve\n"), 0644); err != nil {
		t.Fatal(err)
	}
	policyFile := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte("version: 1\nfallback: 其他\ncategories:\n  - name: direct\n    priority: 1100\n    policy: DIRECT\n    files: [rules/direct.list]\n"), 0644); err != nil {
		t.Fatal(err)
	}

	changed, err := MutateDirectRule(policyFile, "DOMAIN-SUFFIX", "bilibili.com", true)
	if err != nil || !changed {
		t.Fatalf("add direct failed: changed=%v err=%v", changed, err)
	}
	// Duplicate add should be a no-op.
	changed, err = MutateDirectRule(policyFile, "DOMAIN-SUFFIX", "api.bilibili.com", true)
	if err != nil || changed {
		t.Fatalf("subdomain already covered by suffix should not duplicate: changed=%v err=%v", changed, err)
	}

	b, err := Load(policyFile)
	if err != nil {
		t.Fatal(err)
	}
	if ok, rule := b.DirectRuleMatch("i0.bilibili.com"); !ok || rule != "DOMAIN-SUFFIX,bilibili.com" {
		t.Fatalf("expected bilibili.com direct match, got ok=%v rule=%q", ok, rule)
	}

	changed, err = MutateDirectRule(policyFile, "DOMAIN-SUFFIX", "bilibili.com", false)
	if err != nil || !changed {
		t.Fatalf("remove direct failed: changed=%v err=%v", changed, err)
	}

	ignoreFile := filepath.Join(dir, "ignore.list")
	if _, err := UpdateDomainList(ignoreFile, "DOMAIN-SUFFIX", "google.com", true); err != nil {
		t.Fatal(err)
	}
	ig, err := LoadIgnore(ignoreFile)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := ig.Match("www.google.com"); !ok {
		t.Fatal("expected www.google.com to match ignored suffix google.com")
	}
}
