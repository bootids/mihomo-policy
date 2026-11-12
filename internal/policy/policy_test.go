package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func loadText(t *testing.T, s string) *Bundle {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const overlapPolicy = `version: 1
fallback: DEFAULT
categories:
  - name: google
    priority: 800
    policy: GOOGLE
    rules: ["DOMAIN-SUFFIX,google.com"]
  - name: ai
    priority: 1000
    policy: AI
    rules: ["DOMAIN,Gemini.Google.Com."]
`

func TestPriorityOverridesDeclarationOrder(t *testing.T) {
	b := loadText(t, overlapPolicy)
	for _, tc := range []struct{ host, want string }{{"gemini.google.com", "AI"}, {"GEMINI.GOOGLE.COM.", "AI"}, {"www.google.com", "GOOGLE"}, {"not-google.com", "DEFAULT"}, {"google.com.evil.example", "DEFAULT"}} {
		m, err := b.MatchDomain(tc.host)
		if err != nil || m.Policy != tc.want {
			t.Fatalf("%s: %+v %v", tc.host, m, err)
		}
	}
	if len(b.Overlaps) != 1 || b.Overlaps[0].Kind != "partial_overlap" {
		t.Fatalf("overlaps: %+v", b.Overlaps)
	}
}
func TestValidationRejectsAmbiguousAndMalformedPolicy(t *testing.T) {
	for _, s := range []string{
		strings.Replace(overlapPolicy, "priority: 800", "priority: 1000", 1),
		strings.Replace(overlapPolicy, "priority: 800", "prioritty: 800", 1),
		strings.Replace(overlapPolicy, "name: google", "name: ../escape", 1),
		strings.Replace(overlapPolicy, "DOMAIN-SUFFIX,google.com", "DOMAIN-SUFFIX,google.com,DIRECT", 1),
		strings.Replace(overlapPolicy, "DOMAIN-SUFFIX,google.com", "DOMAIN-SUFFIX,*.google.com", 1),
		overlapPolicy + "\n---\nversion: 1\n",
	} {
		p := filepath.Join(t.TempDir(), "policy.yaml")
		os.WriteFile(p, []byte(s), 0600)
		if _, err := Load(p); err == nil {
			t.Fatalf("accepted invalid policy:\n%s", s)
		}
	}
}
func TestRuleFilesCannotEscape(t *testing.T) {
	d := t.TempDir()
	os.Mkdir(filepath.Join(d, "policy"), 0700)
	os.WriteFile(filepath.Join(d, "outside.list"), []byte("DOMAIN,secret.example\n"), 0600)
	os.Symlink(filepath.Join(d, "outside.list"), filepath.Join(d, "policy", "link.list"))
	p := filepath.Join(d, "policy", "policy.yaml")
	os.WriteFile(p, []byte("version: 1\nfallback: DIRECT\ncategories:\n- name: test\n  priority: 1\n  policy: DIRECT\n  files: [link.list]\n"), 0600)
	if _, err := Load(p); err == nil {
		t.Fatal("accepted escaping symlink")
	}
}
func TestBundleIsDeterministicAndImmutable(t *testing.T) {
	b := loadText(t, overlapPolicy)
	same := loadText(t, "# comment\n"+overlapPolicy)
	if b.Version != same.Version {
		t.Fatal("comments changed semantic version")
	}
	d := t.TempDir()
	a, c := filepath.Join(d, "a"), filepath.Join(d, "b")
	if err := b.Write(a); err != nil {
		t.Fatal(err)
	}
	if err := same.Write(c); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest.json", "fragment.yaml", "rules/ai.list"} {
		x, _ := os.ReadFile(filepath.Join(a, name))
		y, _ := os.ReadFile(filepath.Join(c, name))
		if string(x) != string(y) {
			t.Fatalf("nondeterministic %s", name)
		}
	}
	if err := b.Write(a); err == nil {
		t.Fatal("overwrote existing bundle")
	}
	data, _ := os.ReadFile(filepath.Join(a, "manifest.json"))
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
}
func TestRenderPreservesDeviceConfigAndChecksOutbounds(t *testing.T) {
	b := loadText(t, overlapPolicy)
	base := []byte("secret: private-value\ndns:\n  enable: true\nproxy-groups:\n- name: AI\n- name: GOOGLE\n- name: DEFAULT\nrule-providers:\n  stale: {}\nrules: [MATCH,REJECT]\n")
	out, err := b.Render(base, "./policy/releases/abc")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	yaml.Unmarshal(out, &doc)
	if doc["secret"] != "private-value" {
		t.Fatal("lost secret")
	}
	if strings.Contains(string(out), "stale") {
		t.Fatal("old providers retained")
	}
	rules := doc["rules"].([]any)
	if rules[0] != "RULE-SET,ai,AI" {
		t.Fatalf("bad ordering: %v", rules)
	}
	if _, err = b.Render([]byte("secret: x\n"), "."); err == nil {
		t.Fatal("accepted missing groups")
	}
}
