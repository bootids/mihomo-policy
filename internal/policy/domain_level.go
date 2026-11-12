package policy

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// DomainLevels extracts the ICANN-based 1st-level registrable domain (e.g. "google.com",
// "sina.com.cn", "amazonaws.com") and 2nd-level domain (e.g. "gemini.google.com",
// "clients6.google.com", "www.sina.com.cn"). If host is already an apex domain, l2 == l1.
func DomainLevels(host string) (l1, l2 string, err error) {
	h, err := Domain(host)
	if err != nil {
		return "", "", err
	}
	icannSuffix := findICANNSuffix(h)
	if icannSuffix == "" || icannSuffix == h {
		return h, h, nil
	}
	prefix := strings.TrimSuffix(h, "."+icannSuffix)
	if prefix == h || prefix == "" {
		return h, h, nil
	}
	labels := strings.Split(prefix, ".")
	l1 = labels[len(labels)-1] + "." + icannSuffix
	if len(labels) >= 2 {
		l2 = labels[len(labels)-2] + "." + l1
	} else {
		l2 = l1
	}
	return l1, l2, nil
}

func findICANNSuffix(host string) string {
	cur := host
	for {
		suf, icann := publicsuffix.PublicSuffix(cur)
		if icann {
			return suf
		}
		idx := strings.IndexByte(cur, '.')
		if idx < 0 {
			return suf
		}
		cur = cur[idx+1:]
	}
}

// IgnoreSet holds domains marked as ignored for direct connectivity testing.
// Ignored domains remain included in traffic statistics.
type IgnoreSet struct {
	rules []Rule
}

func LoadIgnore(path string) (*IgnoreSet, error) {
	s := &IgnoreSet{}
	if strings.TrimSpace(path) == "" {
		return s, nil
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{}
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var r Rule
		if strings.Contains(line, ",") {
			r, err = ParseRule(line)
			if err != nil {
				return nil, fmt.Errorf("ignore file line %d: %w", lineNo, err)
			}
			if !domainRule(r) {
				return nil, fmt.Errorf("ignore file line %d: only DOMAIN or DOMAIN-SUFFIX allowed", lineNo)
			}
		} else {
			d, e := Domain(line)
			if e != nil {
				return nil, fmt.Errorf("ignore file line %d: %w", lineNo, e)
			}
			r = Rule{Type: "DOMAIN-SUFFIX", Value: d}
		}
		key := r.String()
		if !seen[key] {
			seen[key] = true
			s.rules = append(s.rules, r)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *IgnoreSet) Match(host string) (bool, string) {
	if s == nil {
		return false, ""
	}
	h, err := Domain(host)
	if err != nil {
		return false, ""
	}
	for _, r := range s.rules {
		if r.Type == "DOMAIN" && h == r.Value {
			return true, r.String()
		}
		if r.Type == "DOMAIN-SUFFIX" && suffix(h, r.Value) {
			return true, r.String()
		}
	}
	return false, ""
}

func (s *IgnoreSet) Count() int {
	if s == nil {
		return 0
	}
	return len(s.rules)
}

func (s *IgnoreSet) Rules() []string {
	if s == nil {
		return []string{}
	}
	out := make([]string, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, r.String())
	}
	return out
}

// DirectRuleMatch reports whether host matches a domain rule in any DIRECT category of the bundle.
func (b *Bundle) DirectRuleMatch(host string) (bool, string) {
	if b == nil {
		return false, ""
	}
	h, err := Domain(host)
	if err != nil {
		return false, ""
	}
	for _, e := range b.Entries {
		if e.Category.Policy != "DIRECT" {
			continue
		}
		for _, r := range e.Rules {
			if r.Type == "DOMAIN" && h == r.Value {
				return true, r.String()
			}
			if r.Type == "DOMAIN-SUFFIX" && suffix(h, r.Value) {
				return true, r.String()
			}
		}
	}
	return false, ""
}
