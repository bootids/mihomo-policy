// Package dashboard serves the Mihomo Policy web console, including domain-level
// aggregation, direct connectivity testing, local rule file management, Git push,
// and router configuration deployment. It never exposes controller or SSH secrets.
package dashboard

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"mihomo-policy/internal/analyze"
	"mihomo-policy/internal/collect"
	"mihomo-policy/internal/config"
	"mihomo-policy/internal/ops"
	"mihomo-policy/internal/policy"
	"mihomo-policy/internal/probe"
	"mihomo-policy/internal/store"
)

//go:embed web/*
var assets embed.FS

type Task struct {
	Name        string     `json:"name"`
	LastSuccess *time.Time `json:"last_success"`
	Interval    string     `json:"interval"`
	Enabled     bool       `json:"enabled"`
}
type Category struct {
	Name      string   `json:"name"`
	Priority  int      `json:"priority"`
	Policy    string   `json:"policy"`
	RuleCount int      `json:"rule_count"`
	Rules     []string `json:"rules"`
}
type RouterSummary struct {
	Name       string `json:"name"`
	Target     string `json:"target"`
	RemotePath string `json:"remote_path"`
}
type State struct {
	Source             string                 `json:"source"`
	Controller         string                 `json:"controller"`
	CoverageNote       string                 `json:"coverage_note,omitempty"`
	Collection         collect.HealthSnapshot `json:"collection"`
	ProbesEnabled      bool                   `json:"probes_enabled"`
	Tasks              []Task                 `json:"tasks"`
	Categories         []Category             `json:"categories"`
	Overlaps           []policy.Overlap       `json:"overlaps"`
	OverlapCount       int                    `json:"overlap_count"`
	Report             analyze.Report         `json:"report"`
	Level              string                 `json:"level"`
	LevelCounts        map[string]int         `json:"level_counts"`
	StatusCounts       map[string]int         `json:"status_counts"`
	IgnoredDomains     int                    `json:"ignored_domains"`
	IgnoredRules       []string               `json:"ignored_rules"`
	Git                ops.GitStatus          `json:"git"`
	Routers            []RouterSummary        `json:"routers"`
	TotalDomains       int                    `json:"total_domains"`
	ReportLimit        int                    `json:"report_limit"`
	TotalBytes         int64                  `json:"total_bytes"`
	TotalSuggestions   int                    `json:"total_suggestions"`
	TotalUp            int64                  `json:"total_up"`
	TotalDown          int64                  `json:"total_down"`
	VisitedDomains     int                    `json:"visited_domains"`
	FailureOnlyDomains int                    `json:"failure_only_domains"`
	ProbeOnlyDomains   int                    `json:"probe_only_domains"`
	TestedDomains      int                    `json:"tested_domains"`
	SuggestionCounts   map[string]int         `json:"suggestion_counts"`
	CategoryTraffic    []CategoryTraffic      `json:"category_traffic"`
	Attention          []analyze.Candidate    `json:"attention"`
	FilteredDomains    int                    `json:"filtered_domains"`
	Page               int                    `json:"page"`
	Pages              int                    `json:"pages"`
}

type Server struct {
	Config       config.Config
	DB           *store.DB
	Health       *collect.Health
	Report       func(context.Context, time.Duration) (analyze.Report, error)
	DirectTester func(ctx context.Context, domain string, sampleHosts []string) (store.DirectTestRecord, error)
	Deployer     func(ctx context.Context, targets []config.RouterTarget) ([]ops.RouterDeployResult, error)
	GitPusher    func(ctx context.Context, message string) (ops.PushResult, error)
	Logger       *slog.Logger

	mu     sync.Mutex
	opsMu  sync.Mutex
	cached map[int]cachedEntry
}

type cachedEntry struct {
	at     time.Time
	state  State
	bundle *policy.Bundle
	ignore *policy.IgnoreSet
	tests  map[string]store.DirectTestRecord
}

func (s *Server) invalidateCache() {
	s.mu.Lock()
	s.cached = nil
	s.mu.Unlock()
}

func (s *Server) knownHostsFile() string {
	if s.Config.Database != "" {
		return filepath.Join(filepath.Dir(s.Config.Database), "known_hosts")
	}
	return ""
}

func (s *Server) ignoreFilePath() string {
	if s.Config.IgnoreFile != "" {
		return s.Config.IgnoreFile
	}
	if s.Config.PolicyFile != "" {
		return filepath.Join(filepath.Dir(s.Config.PolicyFile), "ignore.list")
	}
	return "policy/ignore.list"
}

func (s *Server) repoDirPath() string {
	if s.Config.RepoDir != "" {
		return s.Config.RepoDir
	}
	if s.Config.PolicyFile != "" {
		return filepath.Dir(filepath.Dir(s.Config.PolicyFile))
	}
	return "."
}

func (s *Server) routerTargets() []config.RouterTarget {
	if len(s.Config.Routers) > 0 {
		return s.Config.Routers
	}
	return config.DefaultRouters(s.Config.SecretEnv)
}

func (s *Server) routerSummaries() []RouterSummary {
	targets := s.routerTargets()
	out := make([]RouterSummary, 0, len(targets))
	for _, r := range targets {
		host := r.SSHAddr
		if h, p, e := net.SplitHostPort(r.SSHAddr); e == nil && p == "22" {
			host = h
		}
		user := r.SSHUser
		if user == "" {
			user = "admin"
		}
		out = append(out, RouterSummary{
			Name:       r.Name,
			Target:     user + "@" + host,
			RemotePath: r.RemotePath,
		})
	}
	return out
}

func (s *Server) loadEntry(ctx context.Context, hours int) (cachedEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.cached[hours]; ok && time.Since(c.at) < 5*time.Second {
		cp := c
		cp.state.Report.Candidates = append([]analyze.Candidate{}, c.state.Report.Candidates...)
		return cp, nil
	}
	b, err := policy.Load(s.Config.PolicyFile)
	if err != nil {
		return cachedEntry{}, err
	}
	ig, err := policy.LoadIgnore(s.ignoreFilePath())
	if err != nil {
		return cachedEntry{}, err
	}
	var tests map[string]store.DirectTestRecord
	if s.DB != nil {
		tests, err = s.DB.DirectTests(ctx, s.Config.Source)
		if err != nil {
			return cachedEntry{}, err
		}
	} else {
		tests = map[string]store.DirectTestRecord{}
	}
	r, err := s.Report(ctx, time.Duration(hours)*time.Hour)
	if err != nil {
		return cachedEntry{}, err
	}
	r.Candidates = enrichCandidates(r.Candidates, b, ig, tests)

	st := State{
		Source:        s.Config.Source,
		Controller:    s.Config.Controller,
		CoverageNote:  s.Config.CoverageNote,
		Collection:    s.Health.Snapshot(),
		ProbesEnabled: len(s.Config.Targets) > 0 && s.Config.DirectProxy != "" && s.Config.ProxyProxy != "",
		Tasks:         []Task{},
		Categories:    []Category{},
		Overlaps:      b.Overlaps,
		OverlapCount:  len(b.Overlaps),
		Report:        r,
		Level:         "host",
		LevelCounts:   countDistinctLevels(r.Candidates),
		IgnoredRules:  ig.Rules(),
		Git:           ops.RepoStatus(s.repoDirPath(), s.Config.Git),
		Routers:       s.routerSummaries(),
		TotalDomains:  len(r.Candidates),
	}
	summarize(&st)
	if len(st.Overlaps) > 1000 {
		st.Overlaps = st.Overlaps[:1000]
	}
	for _, e := range b.Entries {
		c := Category{Name: e.Category.Name, Priority: e.Category.Priority, Policy: e.Category.Policy, RuleCount: len(e.Rules), Rules: []string{}}
		for i, rule := range e.Rules {
			if i == 150 {
				break
			}
			c.Rules = append(c.Rules, rule.String())
		}
		st.Categories = append(st.Categories, c)
	}
	for _, task := range []Task{
		{Name: "probe", Interval: s.Config.ProbeInterval, Enabled: st.ProbesEnabled},
		{Name: "report", Interval: s.Config.ReportInterval, Enabled: true},
		{Name: "retention", Interval: "24h", Enabled: true},
	} {
		if !task.Enabled || s.DB == nil {
			st.Tasks = append(st.Tasks, task)
			continue
		}
		last, e := s.DB.LastTask(ctx, task.Name+":"+s.Config.Source)
		if e != nil {
			return cachedEntry{}, e
		}
		if !last.IsZero() {
			task.LastSuccess = &last
		}
		st.Tasks = append(st.Tasks, task)
	}
	if s.cached == nil {
		s.cached = map[int]cachedEntry{}
	}
	entry := cachedEntry{at: time.Now(), state: st, bundle: b, ignore: ig, tests: tests}
	s.cached[hours] = entry

	cp := entry
	cp.state.Report.Candidates = append([]analyze.Candidate{}, st.Report.Candidates...)
	return cp, nil
}

func (s *Server) loadState(ctx context.Context, hours int) (State, error) {
	e, err := s.loadEntry(ctx, hours)
	return e.state, err
}

func (s *Server) state(ctx context.Context, hours int) ([]byte, error) {
	return s.stateFor(ctx, hours, listOptions{Page: 1, Limit: 50})
}

func (s *Server) stateFor(ctx context.Context, hours int, options listOptions) ([]byte, error) {
	entry, err := s.loadEntry(ctx, hours)
	if err != nil {
		return nil, err
	}
	st := entry.state
	pageState(&st, options, entry.bundle, entry.ignore, entry.tests)
	return json.Marshal(st)
}

func requireWriteHeaders(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Requested-With") != "mihomo-policy" {
		http.Error(w, "缺少安全请求头", http.StatusForbidden)
		return false
	}
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
		http.Error(w, "拒绝跨站请求", http.StatusForbidden)
		return false
	}
	return true
}

func decodeJSONBody(r *http.Request, out any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 65536))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func (s *Server) Handler() (http.Handler, error) {
	password, err := s.Config.Web.Password()
	if err != nil {
		return nil, err
	}
	files, _ := fs.Sub(assets, "web")
	static := http.FileServer(http.FS(files))
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) {
		hours, err := queryHours(r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		options, err := queryOptions(r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		data, e := s.stateFor(ctx, hours, options)
		if e != nil {
			s.Logger.Error("dashboard state failed", "error", e)
			http.Error(w, "暂时无法读取分析数据，请检查服务日志。", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write(data)
	})

	mux.HandleFunc("GET /api/candidate", func(w http.ResponseWriter, r *http.Request) {
		hours, err := queryHours(r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		host, err := policy.Domain(r.URL.Query().Get("host"))
		if err != nil {
			http.Error(w, "请输入有效域名", 400)
			return
		}
		level := r.URL.Query().Get("level")
		if !oneOf(level, "", "l1", "l2", "host") {
			http.Error(w, "invalid level", 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		entry, err := s.loadEntry(ctx, hours)
		if err != nil {
			http.Error(w, "无法读取域名详情", 503)
			return
		}
		rows := entry.state.Report.Candidates
		if level == "l1" || level == "l2" {
			rows = aggregateCandidates(rows, level, entry.bundle, entry.ignore, entry.tests, true)
		}
		for _, c := range rows {
			if c.Traffic.Host == host {
				writeJSON(w, c)
				return
			}
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("GET /api/match", func(w http.ResponseWriter, r *http.Request) {
		b, e := policy.Load(s.Config.PolicyFile)
		if e != nil {
			http.Error(w, "无法读取本地规则", 503)
			return
		}
		m, e := b.MatchDomain(r.URL.Query().Get("host"))
		if e != nil {
			http.Error(w, "请输入有效的 ASCII / punycode 域名", 400)
			return
		}
		writeJSON(w, m)
	})

	mux.HandleFunc("GET /api/report", func(w http.ResponseWriter, r *http.Request) {
		hours, err := queryHours(r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		report, e := s.Report(ctx, time.Duration(hours)*time.Hour)
		if e != nil {
			http.Error(w, "无法生成报告", 503)
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="mihomo-policy-report.json"`)
		writeJSON(w, report)
	})

	// Immediate Direct Connectivity Test on L1 / L2 / Exact Domain
	mux.HandleFunc("POST /api/direct-test", func(w http.ResponseWriter, r *http.Request) {
		if !requireWriteHeaders(w, r) {
			return
		}
		var req struct {
			Domain string `json:"domain"`
			Level  string `json:"level"`
			Hours  int    `json:"hours"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			http.Error(w, "请求格式无效", 400)
			return
		}
		domain, err := policy.Domain(req.Domain)
		if err != nil {
			http.Error(w, "无效域名", 400)
			return
		}
		if !oneOf(req.Level, "", "l1", "l2", "host") {
			http.Error(w, "无效域名层级", 400)
			return
		}
		hours := req.Hours
		if hours != 24 && hours != 168 && hours != 720 {
			hours = 168
		}

		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		var sampleHosts []string
		if entry, e := s.loadEntry(ctx, hours); e == nil {
			sampleHosts = sampleHostsForTest(entry.state.Report.Candidates, domain, req.Level)
		}

		tester := s.DirectTester
		if tester == nil {
			timeout := config.Duration(s.Config.ProbeTimeout)
			if timeout <= 0 || timeout > 12*time.Second {
				timeout = 8 * time.Second
			}
			tester = func(testCtx context.Context, d string, hosts []string) (store.DirectTestRecord, error) {
				return probe.TestDirectDomain(testCtx, s.Config.DirectProxy, d, hosts, timeout)
			}
		}

		rec, err := tester(ctx, domain, sampleHosts)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		rec.Domain = domain
		if s.DB != nil {
			if err := s.DB.SaveDirectTest(ctx, s.Config.Source, rec); err != nil {
				s.Logger.Error("save direct test failed", "domain", domain, "error", err)
			}
		}
		s.invalidateCache()
		writeJSON(w, rec)
	})

	// Add or Remove Domain from Local Repo direct.list
	mux.HandleFunc("POST /api/rules/direct", func(w http.ResponseWriter, r *http.Request) {
		if !requireWriteHeaders(w, r) {
			return
		}
		var req struct {
			Domain   string `json:"domain"`
			Action   string `json:"action"`
			RuleType string `json:"rule_type"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			http.Error(w, "请求格式无效", 400)
			return
		}
		domain, err := policy.Domain(req.Domain)
		if err != nil {
			http.Error(w, "无效域名", 400)
			return
		}
		if req.Action != "add" && req.Action != "remove" {
			http.Error(w, "action 必须为 add 或 remove", 400)
			return
		}
		ruleType := strings.ToUpper(strings.TrimSpace(req.RuleType))
		if ruleType == "" {
			ruleType = "DOMAIN-SUFFIX"
		}
		if ruleType != "DOMAIN-SUFFIX" && ruleType != "DOMAIN" {
			http.Error(w, "rule_type 必须为 DOMAIN-SUFFIX 或 DOMAIN", 400)
			return
		}

		s.opsMu.Lock()
		changed, err := policy.MutateDirectRule(s.Config.PolicyFile, ruleType, domain, req.Action == "add")
		gitSt := ops.RepoStatus(s.repoDirPath(), s.Config.Git)
		s.opsMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		s.invalidateCache()
		writeJSON(w, map[string]any{
			"ok":      true,
			"changed": changed,
			"domain":  domain,
			"rule":    ruleType + "," + domain,
			"action":  req.Action,
			"git":     gitSt,
		})
	})

	// Ignore or Unignore Domain in Local Repo ignore.list
	mux.HandleFunc("POST /api/rules/ignore", func(w http.ResponseWriter, r *http.Request) {
		if !requireWriteHeaders(w, r) {
			return
		}
		var req struct {
			Domain   string `json:"domain"`
			Action   string `json:"action"`
			RuleType string `json:"rule_type"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			http.Error(w, "请求格式无效", 400)
			return
		}
		domain, err := policy.Domain(req.Domain)
		if err != nil {
			http.Error(w, "无效域名", 400)
			return
		}
		if req.Action != "add" && req.Action != "remove" {
			http.Error(w, "action 必须为 add 或 remove", 400)
			return
		}
		ruleType := strings.ToUpper(strings.TrimSpace(req.RuleType))
		if ruleType == "" {
			ruleType = "DOMAIN-SUFFIX"
		}
		if ruleType != "DOMAIN-SUFFIX" && ruleType != "DOMAIN" {
			http.Error(w, "rule_type 必须为 DOMAIN-SUFFIX 或 DOMAIN", 400)
			return
		}

		s.opsMu.Lock()
		changed, err := policy.UpdateDomainList(s.ignoreFilePath(), ruleType, domain, req.Action == "add")
		gitSt := ops.RepoStatus(s.repoDirPath(), s.Config.Git)
		s.opsMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		s.invalidateCache()
		writeJSON(w, map[string]any{
			"ok":      true,
			"changed": changed,
			"domain":  domain,
			"rule":    ruleType + "," + domain,
			"action":  req.Action,
			"git":     gitSt,
		})
	})

	// Commit and Push Local Repo Rule Changes
	mux.HandleFunc("POST /api/git/push", func(w http.ResponseWriter, r *http.Request) {
		if !requireWriteHeaders(w, r) {
			return
		}
		var req struct {
			Message        string `json:"message"`
			RefreshRouters bool   `json:"refresh_routers"`
		}
		if r.ContentLength != 0 {
			if err := decodeJSONBody(r, &req); err != nil && !errors.Is(err, io.EOF) {
				http.Error(w, "请求格式无效", 400)
				return
			}
		}

		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()

		s.opsMu.Lock()
		pusher := s.GitPusher
		if pusher == nil {
			pusher = func(pushCtx context.Context, msg string) (ops.PushResult, error) {
				return ops.CommitAndPush(pushCtx, s.repoDirPath(), s.Config.SSHKeyFile, s.knownHostsFile(), s.Config.Git, msg)
			}
		}
		res, err := pusher(ctx, req.Message)
		gitSt := ops.RepoStatus(s.repoDirPath(), s.Config.Git)
		var refreshed map[string][]string
		if err == nil && req.RefreshRouters {
			refreshed = ops.RefreshRoutersProviders(ctx, s.routerTargets())
		}
		s.opsMu.Unlock()

		s.invalidateCache()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, map[string]any{
			"ok":                  true,
			"result":              res,
			"git":                 gitSt,
			"providers_refreshed": refreshed,
		})
	})

	// Deploy config.yaml to admin@10.10.10.1 and admin@10.10.8.1
	mux.HandleFunc("POST /api/routers/deploy", func(w http.ResponseWriter, r *http.Request) {
		if !requireWriteHeaders(w, r) {
			return
		}
		var req struct {
			Targets []string `json:"targets"`
		}
		if r.ContentLength != 0 {
			if err := decodeJSONBody(r, &req); err != nil && !errors.Is(err, io.EOF) {
				http.Error(w, "请求格式无效", 400)
				return
			}
		}

		allTargets := s.routerTargets()
		selected := allTargets
		if len(req.Targets) > 0 {
			want := map[string]bool{}
			for _, n := range req.Targets {
				want[n] = true
			}
			selected = nil
			for _, t := range allTargets {
				if want[t.Name] {
					selected = append(selected, t)
				}
			}
			if len(selected) == 0 {
				http.Error(w, "未找到匹配的路由器目标", 400)
				return
			}
		}

		ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
		defer cancel()

		s.opsMu.Lock()
		deployer := s.Deployer
		if deployer == nil {
			cfgPath := s.Config.MihomoConfig
			if cfgPath == "" {
				cfgPath = filepath.Join(s.repoDirPath(), "config.template.yaml")
			}
			deployer = func(depCtx context.Context, targets []config.RouterTarget) ([]ops.RouterDeployResult, error) {
				return ops.DeployRouters(depCtx, cfgPath, s.Config.SSHKeyFile, s.knownHostsFile(), targets)
			}
		}
		results, err := deployer(ctx, selected)
		s.opsMu.Unlock()

		writeJSON(w, map[string]any{
			"ok":      err == nil,
			"results": results,
			"error": func() string {
				if err != nil {
					return err.Error()
				}
				return ""
			}(),
		})
	})

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/app.js" && r.URL.Path != "/style.css" {
			http.NotFound(w, r)
			return
		}
		static.ServeHTTP(w, r)
	})
	userHash, passHash := sha256.Sum256([]byte(s.Config.Web.Username)), sha256.Sum256([]byte(password))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		if password != "" {
			u, p, ok := r.BasicAuth()
			uh, ph := sha256.Sum256([]byte(u)), sha256.Sum256([]byte(p))
			if !ok || subtle.ConstantTimeCompare(uh[:], userHash[:])&subtle.ConstantTimeCompare(ph[:], passHash[:]) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="mihomo-policy", charset="UTF-8"`)
				http.Error(w, "需要看板登录凭据", 401)
				return
			}
		}
		mux.ServeHTTP(w, r)
	}), nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) Run(ctx context.Context) error {
	if s.Config.Web.Listen == "" {
		return fmt.Errorf("web.listen is required")
	}
	h, err := s.Handler()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.Config.Web.Listen)
	if err != nil {
		return err
	}
	// Allow longer WriteTimeout (90s) so interactive git push / dual-router deploy requests don't get cut off mid-flight.
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 60 * time.Second}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdown)
		case <-done:
		}
	}()
	s.Logger.Info("dashboard listening", "address", ln.Addr().String())
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
