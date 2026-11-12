// Package policy compiles service categories into deterministic Mihomo rule bundles.
package policy

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Category struct {
	Name     string   `yaml:"name" json:"name"`
	Priority int      `yaml:"priority" json:"priority"`
	Policy   string   `yaml:"policy" json:"policy"`
	Files    []string `yaml:"files" json:"files,omitempty"`
	Rules    []string `yaml:"rules,omitempty" json:"rules,omitempty"`
	Enabled  *bool    `yaml:"enabled,omitempty" json:"-"`
}

type Config struct {
	Version    int        `yaml:"version"`
	Fallback   string     `yaml:"fallback"`
	Categories []Category `yaml:"categories"`
}

type Rule struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	NoResolve bool   `json:"no_resolve,omitempty"`
}

func (r Rule) String() string {
	s := r.Type + "," + r.Value
	if r.NoResolve {
		s += ",no-resolve"
	}
	return s
}

type Entry struct {
	Category Category `json:"category"`
	Rules    []Rule   `json:"rules"`
}

type Overlap struct {
	Higher     string `json:"higher"`
	Lower      string `json:"lower"`
	HigherRule string `json:"higher_rule"`
	LowerRule  string `json:"lower_rule"`
	Kind       string `json:"kind"` // full_shadow or partial_overlap
}

type Bundle struct {
	Version  string    `json:"version"`
	Fallback string    `json:"fallback"`
	Entries  []Entry   `json:"entries"`
	Overlaps []Overlap `json:"overlaps"`
}

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// Decode rejects misspelled keys and extra YAML documents.
func Decode(data []byte, out any) error {
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("expected one YAML document")
	}
	return nil
}

func Domain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if len(s) == 0 || len(s) > 253 {
		return "", fmt.Errorf("invalid domain %q", s)
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", fmt.Errorf("expected a domain, got an IP")
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid domain %q", s)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("domain must be ASCII/punycode: %q", s)
			}
		}
	}
	return s, nil
}

func ParseRule(line string) (Rule, error) {
	parts := strings.Split(strings.TrimSpace(line), ",")
	if len(parts) < 2 || len(parts) > 3 {
		return Rule{}, fmt.Errorf("expected TYPE,value[,no-resolve], without outbound policy: %q", line)
	}
	r := Rule{Type: strings.ToUpper(strings.TrimSpace(parts[0])), Value: strings.TrimSpace(parts[1])}
	if len(parts) == 3 {
		if strings.TrimSpace(parts[2]) != "no-resolve" {
			return r, fmt.Errorf("invalid third field in %q", line)
		}
		r.NoResolve = true
	}
	switch r.Type {
	case "DOMAIN", "DOMAIN-SUFFIX":
		v, err := Domain(r.Value)
		if err != nil {
			return r, err
		}
		r.Value = v
	case "DOMAIN-KEYWORD":
		r.Value = strings.ToLower(r.Value)
		if r.Value == "" || strings.ContainsAny(r.Value, " \t\r\n") {
			return r, fmt.Errorf("invalid keyword")
		}
	case "IP-CIDR", "IP-CIDR6":
		p, err := netip.ParsePrefix(r.Value)
		if err != nil {
			return r, err
		}
		if (r.Type == "IP-CIDR") != p.Addr().Is4() {
			return r, fmt.Errorf("CIDR family mismatch: %s", line)
		}
		r.Value = p.Masked().String()
	default:
		return r, fmt.Errorf("unsupported rule type %q (supported: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, IP-CIDR6)", r.Type)
	}
	if r.NoResolve && r.Type != "IP-CIDR" && r.Type != "IP-CIDR6" {
		return r, fmt.Errorf("no-resolve requires an IP rule")
	}
	return r, nil
}

func Load(path string) (*Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err = Decode(data, &c); err != nil {
		return nil, err
	}
	if c.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version %d", c.Version)
	}
	if err = checkPolicy(c.Fallback); err != nil {
		return nil, err
	}
	b := &Bundle{Fallback: c.Fallback, Overlaps: []Overlap{}}
	names := map[string]bool{}
	priorities := map[int]string{}
	for _, cat := range c.Categories {
		if cat.Enabled != nil && !*cat.Enabled {
			continue
		}
		if !namePattern.MatchString(cat.Name) {
			return nil, fmt.Errorf("invalid category name %q", cat.Name)
		}
		if names[cat.Name] {
			return nil, fmt.Errorf("duplicate category %q", cat.Name)
		}
		names[cat.Name] = true
		if cat.Priority <= 0 {
			return nil, fmt.Errorf("category %s requires a positive priority", cat.Name)
		}
		if other, ok := priorities[cat.Priority]; ok {
			return nil, fmt.Errorf("priority %d shared by %s and %s", cat.Priority, other, cat.Name)
		}
		priorities[cat.Priority] = cat.Name
		if err = checkPolicy(cat.Policy); err != nil {
			return nil, err
		}
		lines := append([]string(nil), cat.Rules...)
		for _, file := range cat.Files {
			if !filepath.IsLocal(file) {
				return nil, fmt.Errorf("rule file must stay within policy directory: %q", file)
			}
			full := filepath.Join(filepath.Dir(path), file)
			root, e := filepath.EvalSymlinks(filepath.Dir(path))
			if e != nil {
				return nil, e
			}
			actual, e := filepath.EvalSymlinks(full)
			if e != nil {
				return nil, e
			}
			rel, e := filepath.Rel(root, actual)
			if e != nil || !filepath.IsLocal(rel) {
				return nil, fmt.Errorf("rule file escapes policy directory: %s", file)
			}
			f, e := os.Open(full)
			if e != nil {
				return nil, e
			}
			s := bufio.NewScanner(f)
			for s.Scan() {
				lines = append(lines, s.Text())
			}
			e = s.Err()
			f.Close()
			if e != nil {
				return nil, e
			}
		}
		e := Entry{Category: Category{Name: cat.Name, Priority: cat.Priority, Policy: cat.Policy}}
		seen := map[string]bool{}
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			r, err := ParseRule(line)
			if err != nil {
				return nil, fmt.Errorf("category %s line %d: %w", cat.Name, i+1, err)
			}
			if seen[r.String()] {
				return nil, fmt.Errorf("duplicate rule in %s: %s", cat.Name, r.String())
			}
			seen[r.String()] = true
			e.Rules = append(e.Rules, r)
		}
		if len(e.Rules) == 0 {
			return nil, fmt.Errorf("category %s has no rules", cat.Name)
		}
		b.Entries = append(b.Entries, e)
	}
	if len(b.Entries) == 0 {
		return nil, fmt.Errorf("no enabled categories")
	}
	sort.Slice(b.Entries, func(i, j int) bool { return b.Entries[i].Category.Priority > b.Entries[j].Category.Priority })
	for i, hi := range b.Entries {
		for _, lo := range b.Entries[i+1:] {
			for _, hr := range hi.Rules {
				for _, lr := range lo.Rules {
					if kind := overlap(hr, lr); kind != "" {
						b.Overlaps = append(b.Overlaps, Overlap{hi.Category.Name, lo.Category.Name, hr.String(), lr.String(), kind})
					}
				}
			}
		}
	}
	// Hash semantic content rather than file paths, comments, or build time.
	type semantic struct {
		Name     string
		Priority int
		Policy   string
		Rules    []Rule
	}
	var entries []semantic
	for _, e := range b.Entries {
		entries = append(entries, semantic{e.Category.Name, e.Category.Priority, e.Category.Policy, e.Rules})
	}
	canonical, _ := json.Marshal(struct {
		Fallback string
		Entries  []semantic
	}{b.Fallback, entries})
	sum := sha256.Sum256(canonical)
	b.Version = hex.EncodeToString(sum[:])
	return b, nil
}

func checkPolicy(s string) error {
	if strings.TrimSpace(s) == "" || strings.ContainsAny(s, ",\r\n") {
		return fmt.Errorf("invalid outbound policy %q", s)
	}
	return nil
}
func suffix(host, domain string) bool { return host == domain || strings.HasSuffix(host, "."+domain) }
func domainRule(r Rule) bool          { return r.Type == "DOMAIN" || r.Type == "DOMAIN-SUFFIX" }
func overlap(hi, lo Rule) string {
	if hi.String() == lo.String() {
		return "full_shadow"
	}
	if domainRule(hi) && domainRule(lo) {
		if hi.Type == "DOMAIN-SUFFIX" && suffix(lo.Value, hi.Value) {
			return "full_shadow"
		}
		if lo.Type == "DOMAIN-SUFFIX" && suffix(hi.Value, lo.Value) {
			return "partial_overlap"
		}
	}
	if (hi.Type == "IP-CIDR" || hi.Type == "IP-CIDR6") && hi.Type == lo.Type {
		h, _ := netip.ParsePrefix(hi.Value)
		l, _ := netip.ParsePrefix(lo.Value)
		if h.Overlaps(l) {
			if h.Bits() <= l.Bits() {
				return "full_shadow"
			}
			return "partial_overlap"
		}
	}
	return ""
}

type Match struct {
	Category string `json:"category"`
	Policy   string `json:"policy"`
	Rule     string `json:"rule"`
	Priority int    `json:"priority"`
}

// MatchDomain only evaluates domain rules. IP rules require resolved-IP context.
func (b *Bundle) MatchDomain(host string) (Match, error) {
	h, err := Domain(host)
	if err != nil {
		return Match{}, err
	}
	for _, e := range b.Entries {
		for _, r := range e.Rules {
			if r.Type == "DOMAIN" && h == r.Value || r.Type == "DOMAIN-SUFFIX" && suffix(h, r.Value) || r.Type == "DOMAIN-KEYWORD" && strings.Contains(h, r.Value) {
				return Match{e.Category.Name, e.Category.Policy, r.String(), e.Category.Priority}, nil
			}
		}
	}
	return Match{Category: "fallback", Policy: b.Fallback, Rule: "MATCH"}, nil
}

func (b *Bundle) Fragment(prefix string) map[string]any {
	providers := map[string]any{}
	rules := []string{}
	for _, e := range b.Entries {
		providers[e.Category.Name] = map[string]any{"type": "file", "behavior": "classical", "format": "text", "path": filepath.ToSlash(filepath.Join(prefix, "rules", e.Category.Name+".list"))}
		rules = append(rules, "RULE-SET,"+e.Category.Name+","+e.Category.Policy)
	}
	rules = append(rules, "MATCH,"+b.Fallback)
	return map[string]any{"rule-providers": providers, "rules": rules}
}

// Write creates an immutable bundle. Existing output paths are never overwritten.
func (b *Bundle) Write(out string) error {
	parent := filepath.Dir(out)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		return fmt.Errorf("output already exists or cannot be inspected: %s", out)
	}
	tmp, err := os.MkdirTemp(parent, ".policy-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err = os.Mkdir(filepath.Join(tmp, "rules"), 0755); err != nil {
		return err
	}
	checksums := map[string]string{}
	write := func(name string, data []byte) error {
		sum := sha256.Sum256(data)
		checksums[name] = hex.EncodeToString(sum[:])
		return os.WriteFile(filepath.Join(tmp, name), data, 0644)
	}
	for _, e := range b.Entries {
		var lines []string
		for _, r := range e.Rules {
			lines = append(lines, r.String())
		}
		if err = write("rules/"+e.Category.Name+".list", []byte(strings.Join(lines, "\n")+"\n")); err != nil {
			return err
		}
	}
	y, err := yaml.Marshal(b.Fragment("."))
	if err != nil {
		return err
	}
	if err = write("fragment.yaml", y); err != nil {
		return err
	}
	j, _ := json.MarshalIndent(b, "", "  ")
	if err = write("policy.json", append(j, '\n')); err != nil {
		return err
	}
	manifest, _ := json.MarshalIndent(struct {
		Version string            `json:"version"`
		SHA256  map[string]string `json:"sha256"`
	}{b.Version, checksums}, "", "  ")
	if err = os.WriteFile(filepath.Join(tmp, "manifest.json"), append(manifest, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, out)
}

// Render replaces the complete rules section while preserving device-local settings.
func (b *Bundle) Render(base []byte, prefix string) ([]byte, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(base, &doc); err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, fmt.Errorf("base must be a YAML mapping")
	}
	available := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true}
	for _, key := range []string{"proxy-groups", "proxies"} {
		if rows, ok := doc[key].([]any); ok {
			for _, row := range rows {
				if m, ok := row.(map[string]any); ok {
					if n, ok := m["name"].(string); ok {
						available[n] = true
					}
				}
			}
		}
	}
	for _, e := range b.Entries {
		if !available[e.Category.Policy] {
			return nil, fmt.Errorf("base configuration lacks outbound %q", e.Category.Policy)
		}
	}
	if !available[b.Fallback] {
		return nil, fmt.Errorf("base configuration lacks fallback %q", b.Fallback)
	}
	f := b.Fragment(prefix)
	doc["rules"] = f["rules"]
	doc["rule-providers"] = f["rule-providers"]
	return yaml.Marshal(doc)
}
