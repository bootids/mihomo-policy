package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"mihomo-policy/internal/policy"
)

type Target struct {
	Name           string `yaml:"name"`
	URL            string `yaml:"url"`
	ExpectedStatus []int  `yaml:"expected_status"`
	Contains       string `yaml:"contains,omitempty"`
}
type Analysis struct {
	MinPairs          int     `yaml:"min_pairs"`
	MinWindows        int     `yaml:"min_windows"`
	Window            string  `yaml:"window"`
	MinSpan           string  `yaml:"min_span"`
	SuccessRate       float64 `yaml:"success_rate"`
	DirectFailureRate float64 `yaml:"direct_failure_rate"`
	EvidenceLookback  string  `yaml:"evidence_lookback"`
	MaxAge            string  `yaml:"max_age"`
	RecentPairs       int     `yaml:"recent_pairs"`
	MinDirectWinRate  float64 `yaml:"min_direct_win_rate"`
}
type GitConfig struct {
	Remote      string `yaml:"remote"`
	Branch      string `yaml:"branch"`
	AuthorName  string `yaml:"author_name"`
	AuthorEmail string `yaml:"author_email"`
}

type RouterTarget struct {
	Name                string `yaml:"name"`
	SSHAddr             string `yaml:"ssh_addr"`
	SSHUser             string `yaml:"ssh_user"`
	RemotePath          string `yaml:"remote_path"`
	Controller          string `yaml:"controller"`
	SecretEnv           string `yaml:"secret_env"`
	ContainerConfigPath string `yaml:"container_config_path"`
}

type Config struct {
	Source           string         `yaml:"source"`
	Controller       string         `yaml:"controller"`
	SecretEnv        string         `yaml:"secret_env"`
	Database         string         `yaml:"database"`
	PolicyFile       string         `yaml:"policy_file"`
	IgnoreFile       string         `yaml:"ignore_file"`
	RepoDir          string         `yaml:"repo_dir"`
	MihomoConfig     string         `yaml:"mihomo_config"`
	SSHKeyFile       string         `yaml:"ssh_key_file"`
	Git              GitConfig      `yaml:"git"`
	Routers          []RouterTarget `yaml:"routers"`
	ReportFile       string         `yaml:"report_file"`
	PollInterval     string         `yaml:"poll_interval"`
	ProbeInterval    string         `yaml:"probe_interval"`
	ReportInterval   string         `yaml:"report_interval"`
	Retention        string         `yaml:"retention"`
	ProbeTimeout     string         `yaml:"probe_timeout"`
	DirectProxy      string         `yaml:"direct_proxy"`
	ProxyProxy       string         `yaml:"proxy_proxy"`
	Concurrency      int            `yaml:"concurrency"`
	Targets          []Target       `yaml:"targets"`
	Analysis         Analysis       `yaml:"analysis"`
	Web              Web            `yaml:"web"`
	CoverageNote     string         `yaml:"coverage_note"`
	ProbeEnvironment string         `yaml:"probe_environment"`
}

// ProbeContext changes when a measurement's target, validation or route setup changes.
// The optional environment revision lets operators invalidate evidence after a node,
// DNS or egress change. A fingerprint does not prove the actual outbound route.
func (c Config) ProbeContext(t Target) string {
	statuses := append([]int(nil), t.ExpectedStatus...)
	sort.Ints(statuses)
	b, _ := json.Marshal(struct {
		Target                                          Target
		Direct, Proxy, Timeout, Environment, Controller string
	}{Target{t.Name, t.URL, statuses, t.Contains}, c.DirectProxy, c.ProxyProxy, c.ProbeTimeout, c.ProbeEnvironment, c.Controller})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type Web struct {
	Listen      string `yaml:"listen"`
	Username    string `yaml:"username"`
	PasswordEnv string `yaml:"password_env"`
}

func (w Web) Password() (string, error) {
	if w.PasswordEnv == "" {
		return "", nil
	}
	p := os.Getenv(w.PasswordEnv)
	if p == "" {
		return "", fmt.Errorf("dashboard password environment variable %s is not set", w.PasswordEnv)
	}
	return p, nil
}

func Load(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err = policy.Decode(data, &c); err != nil {
		return c, err
	}
	if c.Source == "" {
		return c, fmt.Errorf("source is required")
	}
	if c.Web.Listen != "" {
		host, _, e := net.SplitHostPort(c.Web.Listen)
		if e != nil {
			return c, fmt.Errorf("web.listen requires host:port")
		}
		ip := net.ParseIP(host)
		loopback := host == "localhost" || ip != nil && ip.IsLoopback()
		if !loopback && (c.Web.Username == "" || c.Web.PasswordEnv == "") {
			return c, fmt.Errorf("non-loopback dashboard requires web.username and web.password_env")
		}
		if (c.Web.Username == "") != (c.Web.PasswordEnv == "") {
			return c, fmt.Errorf("dashboard username and password_env must be configured together")
		}
	}
	if c.Controller != "" {
		if err = HTTPURL(c.Controller); err != nil {
			return c, fmt.Errorf("controller: %w", err)
		}
	}
	defaults := []struct {
		p *string
		v string
	}{{&c.Database, "data/policy.db"}, {&c.PolicyFile, "policy.yaml"}, {&c.ReportFile, "data/report.json"}, {&c.PollInterval, "1s"}, {&c.ProbeInterval, "6h"}, {&c.ReportInterval, "24h"}, {&c.Retention, "2160h"}, {&c.ProbeTimeout, "15s"}}
	for _, d := range defaults {
		if *d.p == "" {
			*d.p = d.v
		}
	}
	for _, s := range []string{c.PollInterval, c.ProbeInterval, c.ReportInterval, c.Retention, c.ProbeTimeout} {
		d, e := time.ParseDuration(s)
		if e != nil || d <= 0 {
			return c, fmt.Errorf("invalid positive duration %q", s)
		}
	}
	if c.Concurrency == 0 {
		c.Concurrency = 4
	}
	if c.Concurrency < 1 || c.Concurrency > 32 {
		return c, fmt.Errorf("concurrency must be between 1 and 32")
	}
	if c.Analysis.MinPairs == 0 {
		c.Analysis.MinPairs = 20
	}
	if c.Analysis.MinWindows == 0 {
		c.Analysis.MinWindows = 3
	}
	if c.Analysis.Window == "" {
		c.Analysis.Window = "4h"
	}
	if c.Analysis.MinSpan == "" {
		c.Analysis.MinSpan = "24h"
	}
	if c.Analysis.SuccessRate == 0 {
		c.Analysis.SuccessRate = .95
	}
	if c.Analysis.DirectFailureRate == 0 {
		c.Analysis.DirectFailureRate = .80
	}
	if c.Analysis.EvidenceLookback == "" {
		c.Analysis.EvidenceLookback = "168h"
	}
	if c.Analysis.MaxAge == "" {
		c.Analysis.MaxAge = (2 * Duration(c.ProbeInterval)).String()
	}
	if c.Analysis.RecentPairs == 0 {
		c.Analysis.RecentPairs = min(5, c.Analysis.MinPairs)
	}
	if c.Analysis.MinDirectWinRate == 0 {
		c.Analysis.MinDirectWinRate = .5
	}
	w, we := time.ParseDuration(c.Analysis.Window)
	s, se := time.ParseDuration(c.Analysis.MinSpan)
	if c.Analysis.MinPairs < 2 || c.Analysis.MinWindows < 1 || we != nil || se != nil || w < time.Second || s <= 0 || !(c.Analysis.SuccessRate > 0 && c.Analysis.SuccessRate <= 1) || !(c.Analysis.DirectFailureRate > 0 && c.Analysis.DirectFailureRate <= 1) {
		return c, fmt.Errorf("invalid analysis thresholds")
	}
	lookback, le := time.ParseDuration(c.Analysis.EvidenceLookback)
	maxAge, ae := time.ParseDuration(c.Analysis.MaxAge)
	if le != nil || ae != nil || lookback < s || lookback < w || maxAge <= 0 || maxAge > lookback || c.Analysis.RecentPairs < 2 || c.Analysis.RecentPairs > c.Analysis.MinPairs || !(c.Analysis.MinDirectWinRate >= .5 && c.Analysis.MinDirectWinRate <= 1) {
		return c, fmt.Errorf("invalid evidence lookback, max age, recent pairs or direct win rate")
	}
	if c.DirectProxy != "" {
		if err = HTTPURL(c.DirectProxy); err != nil {
			return c, fmt.Errorf("direct_proxy: %w", err)
		}
	}
	if c.ProxyProxy != "" {
		if err = HTTPURL(c.ProxyProxy); err != nil {
			return c, fmt.Errorf("proxy_proxy: %w", err)
		}
	}
	if c.DirectProxy != "" && c.DirectProxy == c.ProxyProxy {
		return c, fmt.Errorf("DIRECT and PROXY endpoints must differ")
	}
	names := map[string]bool{}
	for i := range c.Targets {
		t := &c.Targets[i]
		if t.Name == "" || names[t.Name] {
			return c, fmt.Errorf("target names must be unique and nonempty")
		}
		names[t.Name] = true
		if err = HTTPURL(t.URL); err != nil {
			return c, fmt.Errorf("target %s: %w", t.Name, err)
		}
		u, _ := url.Parse(t.URL)
		if _, err = policy.Domain(u.Hostname()); err != nil {
			return c, fmt.Errorf("target %s requires a domain hostname: %w", t.Name, err)
		}
		if len(t.ExpectedStatus) == 0 {
			t.ExpectedStatus = []int{200, 204}
		}
		for _, status := range t.ExpectedStatus {
			if status < 100 || status > 599 {
				return c, fmt.Errorf("invalid expected HTTP status")
			}
		}
	}
	for _, p := range []*string{&c.Database, &c.PolicyFile, &c.ReportFile} {
		if !filepath.IsAbs(*p) {
			*p = filepath.Join(filepath.Dir(path), *p)
		}
	}
	if c.IgnoreFile == "" {
		c.IgnoreFile = filepath.Join(filepath.Dir(c.PolicyFile), "ignore.list")
	} else if !filepath.IsAbs(c.IgnoreFile) {
		c.IgnoreFile = filepath.Join(filepath.Dir(path), c.IgnoreFile)
	}
	if c.RepoDir == "" {
		c.RepoDir = filepath.Dir(filepath.Dir(c.PolicyFile))
	} else if !filepath.IsAbs(c.RepoDir) {
		c.RepoDir = filepath.Join(filepath.Dir(path), c.RepoDir)
	}
	if c.MihomoConfig == "" {
		localCfg := filepath.Join(c.RepoDir, "local", "config.yaml")
		if _, statErr := os.Stat(localCfg); statErr == nil {
			c.MihomoConfig = localCfg
		} else {
			c.MihomoConfig = filepath.Join(c.RepoDir, "config.template.yaml")
		}
	} else if !filepath.IsAbs(c.MihomoConfig) {
		c.MihomoConfig = filepath.Join(filepath.Dir(path), c.MihomoConfig)
	}
	if c.SSHKeyFile != "" && !filepath.IsAbs(c.SSHKeyFile) {
		c.SSHKeyFile = filepath.Join(filepath.Dir(path), c.SSHKeyFile)
	}
	if c.Git.Remote == "" {
		c.Git.Remote = "origin"
	}
	if c.Git.Branch == "" {
		c.Git.Branch = "main"
	}
	if c.Git.AuthorName == "" {
		c.Git.AuthorName = "mihomo-policy"
	}
	if c.Git.AuthorEmail == "" {
		c.Git.AuthorEmail = "policy@localhost"
	}
	if len(c.Routers) == 0 {
		c.Routers = DefaultRouters(c.SecretEnv)
	}
	return c, nil
}

func DefaultRouters(primarySecretEnv string) []RouterTarget {
	if primarySecretEnv == "" {
		primarySecretEnv = "MIHOMO_SECRET"
	}
	return []RouterTarget{
		{
			Name:                "10.10.10.1",
			SSHAddr:             "10.10.10.1:22",
			SSHUser:             "admin",
			RemotePath:          "/containers/mihomo/config.yaml",
			Controller:          "http://10.10.10.1:9090",
			SecretEnv:           primarySecretEnv,
			ContainerConfigPath: "/root/.config/mihomo/config.yaml",
		},
		{
			Name:                "10.10.8.1",
			SSHAddr:             "10.10.8.1:22",
			SSHUser:             "admin",
			RemotePath:          "/usb1/mihomo/config.yaml",
			Controller:          "http://10.10.8.1:9090",
			SecretEnv:           "",
			ContainerConfigPath: "/root/.config/mihomo/config.yaml",
		},
	}
}
func HTTPURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("invalid URL")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return fmt.Errorf("require http(s) URL without credentials, query or fragment")
	}
	if strings.ContainsAny(u.Host, "\r\n") {
		return fmt.Errorf("invalid URL host")
	}
	return nil
}
func (c Config) Secret() (string, error) {
	if c.SecretEnv == "" {
		return "", nil
	}
	s := os.Getenv(c.SecretEnv)
	if s == "" {
		return "", fmt.Errorf("environment variable %s is not set", c.SecretEnv)
	}
	return s, nil
}
func Duration(s string) time.Duration { d, _ := time.ParseDuration(s); return d }
