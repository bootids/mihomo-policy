package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveDirectListFile locates the primary .list file backing the DIRECT category in policy.yaml.
func ResolveDirectListFile(policyPath string) (string, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return "", err
	}
	var c Config
	if err := Decode(data, &c); err != nil {
		return "", err
	}
	for _, cat := range c.Categories {
		if cat.Enabled != nil && !*cat.Enabled {
			continue
		}
		if cat.Policy == "DIRECT" && len(cat.Files) > 0 {
			rel := cat.Files[0]
			if !filepath.IsLocal(rel) {
				return "", fmt.Errorf("invalid direct rule file path: %q", rel)
			}
			return filepath.Join(filepath.Dir(policyPath), rel), nil
		}
	}
	return "", fmt.Errorf("no enabled DIRECT category with rule file found in %s", policyPath)
}

// UpdateDomainList adds or removes a domain rule (DOMAIN-SUFFIX or DOMAIN) in a .list file,
// preserving existing comments, IP-CIDR rules, and formatting.
func UpdateDomainList(listPath, ruleType, domain string, add bool) (bool, error) {
	d, err := Domain(domain)
	if err != nil {
		return false, err
	}
	ruleType = strings.ToUpper(strings.TrimSpace(ruleType))
	if ruleType == "" {
		ruleType = "DOMAIN-SUFFIX"
	}
	if ruleType != "DOMAIN-SUFFIX" && ruleType != "DOMAIN" {
		return false, fmt.Errorf("unsupported domain rule type %q", ruleType)
	}
	target := Rule{Type: ruleType, Value: d}

	var raw []byte
	raw, err = os.ReadFile(listPath)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}

	var existingLines []string
	if len(raw) > 0 {
		trimmed := strings.TrimRight(string(raw), "\r\n")
		if trimmed != "" {
			existingLines = strings.Split(trimmed, "\n")
		}
	}

	if add {
		for _, rawLine := range existingLines {
			line := strings.TrimSpace(rawLine)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			var r Rule
			if strings.Contains(line, ",") {
				r, err = ParseRule(line)
				if err != nil {
					continue
				}
			} else if pd, e := Domain(line); e == nil {
				r = Rule{Type: "DOMAIN-SUFFIX", Value: pd}
			}
			if r.String() == target.String() {
				return false, nil
			}
			if r.Type == "DOMAIN-SUFFIX" && suffix(d, r.Value) {
				return false, nil
			}
		}
		// Place domain rules before trailing IP-CIDR block if present, otherwise append.
		insertIdx := len(existingLines)
		for i, rawLine := range existingLines {
			line := strings.TrimSpace(rawLine)
			if strings.HasPrefix(line, "IP-CIDR,") || strings.HasPrefix(line, "IP-CIDR6,") {
				insertIdx = i
				break
			}
		}
		updated := make([]string, 0, len(existingLines)+1)
		updated = append(updated, existingLines[:insertIdx]...)
		updated = append(updated, target.String())
		updated = append(updated, existingLines[insertIdx:]...)
		return true, atomicWriteFile(listPath, []byte(strings.Join(updated, "\n")+"\n"))
	}

	// Remove matching domain rule(s) for d (exact match on value for DOMAIN / DOMAIN-SUFFIX).
	changed := false
	kept := make([]string, 0, len(existingLines))
	for _, rawLine := range existingLines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			kept = append(kept, strings.TrimRight(rawLine, "\r"))
			continue
		}
		var r Rule
		if strings.Contains(line, ",") {
			if parsed, e := ParseRule(line); e == nil {
				r = parsed
			}
		} else if pd, e := Domain(line); e == nil {
			r = Rule{Type: "DOMAIN-SUFFIX", Value: pd}
		}
		if (r.Type == "DOMAIN" || r.Type == "DOMAIN-SUFFIX") && r.Value == d {
			changed = true
			continue
		}
		kept = append(kept, strings.TrimRight(rawLine, "\r"))
	}
	if !changed {
		return false, nil
	}
	content := ""
	if len(kept) > 0 {
		content = strings.Join(kept, "\n") + "\n"
	}
	return true, atomicWriteFile(listPath, []byte(content))
}

// MutateDirectRule updates the DIRECT .list file and verifies the resulting policy bundle still loads cleanly.
func MutateDirectRule(policyPath, ruleType, domain string, add bool) (bool, error) {
	listPath, err := ResolveDirectListFile(policyPath)
	if err != nil {
		return false, err
	}
	prev, prevErr := os.ReadFile(listPath)
	changed, err := UpdateDomainList(listPath, ruleType, domain, add)
	if err != nil || !changed {
		return changed, err
	}
	if _, err := Load(policyPath); err != nil {
		if prevErr == nil {
			_ = atomicWriteFile(listPath, prev)
		}
		return false, fmt.Errorf("policy validation failed after update: %w", err)
	}
	return true, nil
}

func atomicWriteFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	mode := os.FileMode(0644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".list-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
