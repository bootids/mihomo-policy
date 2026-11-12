package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mihomo-policy/internal/analyze"
	"mihomo-policy/internal/collect"
	"mihomo-policy/internal/config"
	"mihomo-policy/internal/policy"
	"mihomo-policy/internal/store"
)

func testServer(t *testing.T, auth bool) (*httptest.Server, *Server) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	path := filepath.Join(dir, "policy.yaml")
	if err = os.WriteFile(path, []byte("version: 1\nfallback: DIRECT\ncategories:\n- name: ai\n  priority: 1000\n  policy: AI\n  rules: [\"DOMAIN,gemini.google.com\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Config{Source: "home", Controller: "http://10.10.10.1:9090", SecretEnv: "SHOULD_NOT_APPEAR", PolicyFile: path, ReportInterval: "24h", ProbeInterval: "6h"}
	if auth {
		t.Setenv("TEST_DASH_PASSWORD", "test-dashboard-password")
		c.Web = config.Web{Username: "admin", PasswordEnv: "TEST_DASH_PASSWORD"}
	}
	s := &Server{Config: c, DB: db, Health: collect.NewHealth(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Report: func(context.Context, time.Duration) (analyze.Report, error) {
		return analyze.Report{Source: "home", Candidates: []analyze.Candidate{}}, nil
	}}
	h, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts, s
}

func TestFullSummaryPaginationSearchAndDetail(t *testing.T) {
	_, s := testServer(t, false)
	s.Report = func(_ context.Context, d time.Duration) (analyze.Report, error) {
		r := analyze.Report{Candidates: []analyze.Candidate{}}
		for i := 0; i < 601; i++ {
			cat := "normal"
			if i == 600 {
				cat = "tail"
			}
			r.Candidates = append(r.Candidates, analyze.Candidate{Traffic: store.HostStats{Host: fmt.Sprintf("host%03d.example", i), SampleRows: 1, Up: 1, Down: int64(i + 1), Failures: int64(i)}, Match: policy.Match{Category: cat}, Origin: "traffic", Suggestion: "direct_candidate", Evidence: []analyze.Evidence{{Pairs: 20}}})
		}
		return r, nil
	}
	h, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string) State {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var st State
		if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	st := get("/api/state?limit=500")
	if st.TotalDomains != 601 || st.VisitedDomains != 601 || st.TotalSuggestions != 601 || st.TestedDomains != 601 || st.TotalUp != 601 || st.TotalDown != 601*602/2 || len(st.Report.Candidates) != 500 || st.Attention[0].Traffic.Host != "host600.example" || st.SuggestionCounts["direct_candidate"] != 601 {
		t.Fatalf("summary truncated: %+v", st)
	}
	tail := get("/api/state?q=host600")
	if tail.FilteredDomains != 1 || len(tail.Report.Candidates) != 1 || tail.Report.Candidates[0].Traffic.Host != "host600.example" || tail.TotalDomains != 601 {
		t.Fatalf("search did not cover all rows: %+v", tail)
	}
	category := get("/api/state?category=tail")
	if category.FilteredDomains != 1 {
		t.Fatalf("category only searched loaded rows: %+v", category)
	}
	sorted := get("/api/state?sort=bytes&direction=desc&limit=1")
	if sorted.Report.Candidates[0].Traffic.Host != "host600.example" {
		t.Fatalf("sort only covered one page: %+v", sorted)
	}
	last := get("/api/state?page=999999999&limit=500")
	if last.Page != 2 || len(last.Report.Candidates) != 101 || last.Report.Candidates[0].Traffic.Host != "host500.example" {
		t.Fatalf("pagination mutated cached ordering: %+v", last)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/candidate?host=host600.example", nil))
	var c analyze.Candidate
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &c) != nil || c.Traffic.Host != "host600.example" {
		t.Fatal("unloaded detail unavailable", w.Code, w.Body.String())
	}
}

func TestExportUsesSelectedPeriodAndValidatesQueries(t *testing.T) {
	_, s := testServer(t, false)
	var periods []time.Duration
	s.Report = func(_ context.Context, d time.Duration) (analyze.Report, error) {
		periods = append(periods, d)
		return analyze.Report{Candidates: []analyze.Candidate{}}, nil
	}
	h, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/state?hours=720", "/api/report?hours=720", "/api/report?hours=24"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if len(periods) != 3 || periods[0] != 720*time.Hour || periods[1] != 720*time.Hour || periods[2] != 24*time.Hour {
		t.Fatalf("export changed selected period: %+v", periods)
	}
	for _, path := range []string{"/api/report?hours=1", "/api/state?page=-1", "/api/state?limit=501", "/api/state?sort=invalid", "/api/state?suggestion=invalid", "/api/candidate?host=bad%2Fhost"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 400 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
}

func TestSummarySeparatesVisitsProbeOnlyAndKeep(t *testing.T) {
	st := State{Report: analyze.Report{Candidates: []analyze.Candidate{
		{Traffic: store.HostStats{Host: "visited.example", SampleRows: 1}, Suggestion: "keep"},
		{Traffic: store.HostStats{Host: "failed.example", Failures: 2}, Suggestion: "observe"},
		{Traffic: store.HostStats{Host: "probe.example"}, Suggestion: "observe", Evidence: []analyze.Evidence{{Pairs: 20}}},
	}}}
	summarize(&st)
	if st.VisitedDomains != 1 || st.FailureOnlyDomains != 1 || st.ProbeOnlyDomains != 1 || st.TotalSuggestions != 0 || st.SuggestionCounts["keep"] != 1 || st.TestedDomains != 1 {
		t.Fatalf("mixed summary definitions: %+v", st)
	}
}

func TestDashboardJavaScript(t *testing.T) {
	// Record script reads in Go's test cache, even though Node executes the tests.
	for _, path := range []string{"app_test.cjs", "web/app.js"} {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node is optional; needed only for frontend regression tests")
	}
	if out, err := exec.Command(node, "--test", "app_test.cjs").CombinedOutput(); err != nil {
		t.Fatalf("frontend tests: %v\n%s", err, out)
	}
}
func TestDashboardRequiresCredentialsAndNeverLeaksConfig(t *testing.T) {
	ts, _ := testServer(t, true)
	for _, path := range []string{"/", "/api/state", "/healthz"} {
		r, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 401 {
			t.Fatalf("%s unprotected: %d", path, r.StatusCode)
		}
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/state", nil)
	req.SetBasicAuth("admin", "test-dashboard-password")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	data, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, data)
	}
	for _, secret := range []string{"test-dashboard-password", "SHOULD_NOT_APPEAR", "TEST_DASH_PASSWORD"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("sensitive config leaked")
		}
	}
	var s State
	if err = json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	if s.Source != "home" || s.Categories[0].Priority != 1000 || s.ProbesEnabled {
		t.Fatalf("%+v", s)
	}
}
func TestMatchValidationStaticAssetsAndReadOnlyMethods(t *testing.T) {
	ts, _ := testServer(t, false)
	for _, tc := range []struct {
		path   string
		status int
	}{{"/", 200}, {"/app.js", 200}, {"/style.css", 200}, {"/api/match?host=gemini.google.com", 200}, {"/api/match?host=bad%2Fhost", 400}, {"/api/state?hours=9999999999", 400}, {"/config.yaml", 404}} {
		r, err := http.Get(ts.URL + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != tc.status {
			t.Fatalf("%s: %d", tc.path, r.StatusCode)
		}
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/state", nil)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 405 {
		t.Fatal("write method accepted")
	}
}

func TestDomainLevelAggregationIgnoreStatsAndDirectRuleMutations(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	directList := filepath.Join(rulesDir, "direct.list")
	if err := os.WriteFile(directList, []byte("# direct\nDOMAIN-SUFFIX,baidu.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ignorePath := filepath.Join(dir, "ignore.list")
	if err := os.WriteFile(ignorePath, []byte("# ignore\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.yaml")
	policyYAML := "version: 1\nfallback: 其他\ncategories:\n" +
		"- name: direct\n  priority: 1100\n  policy: DIRECT\n  files: [\"rules/direct.list\"]\n" +
		"- name: google\n  priority: 800\n  policy: Google\n  rules: [\"DOMAIN-SUFFIX,google.com\"]\n"
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if err := db.AddTraffic(ctx, "rec-1", "home", now, []store.TrafficRow{
		{Host: "a.sub.example.com", Route: "其他", Node: "ProxyA", Up: 100, Down: 1000},
		{Host: "b.sub.example.com", Route: "其他", Node: "ProxyA", Up: 200, Down: 2000},
		{Host: "news.sina.com.cn", Route: "其他", Node: "ProxyA", Up: 50, Down: 500},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveDirectTest(ctx, "home", store.DirectTestRecord{
		Domain: "example.com", At: now, Passed: true, Status: 200, DurationMS: 42,
	}); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{
		Source:         "home",
		Controller:     "http://10.10.10.1:9090",
		PolicyFile:     policyPath,
		IgnoreFile:     ignorePath,
		RepoDir:        dir,
		ReportInterval: "24h",
		ProbeInterval:  "6h",
	}
	s := &Server{
		Config: cfg,
		DB:     db,
		Health: collect.NewHealth(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Report: func(rctx context.Context, window time.Duration) (analyze.Report, error) {
			b, err := policy.Load(policyPath)
			if err != nil {
				return analyze.Report{}, err
			}
			tNow := time.Now()
			return analyze.ReportFor(rctx, db, b, "home", tNow.Add(-window), tNow, analyze.DefaultThresholds())
		},
	}
	h, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}

	getState := func(query string) State {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/api/state?"+query, nil))
		if w.Code != 200 {
			t.Fatalf("GET /api/state?%s -> %d: %s", query, w.Code, w.Body.String())
		}
		var st State
		if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
		return st
	}

	// 1. L1 aggregation merges a.sub.example.com + b.sub.example.com -> example.com, and news.sina.com.cn -> sina.com.cn
	stL1 := getState("level=l1")
	if stL1.LevelCounts["l1"] != 2 || stL1.StatusCounts["all"] != 2 || stL1.TotalDown != 3500 || stL1.StatusCounts["passed"] != 1 {
		t.Fatalf("unexpected L1 aggregation: levels=%+v down=%d counts=%+v", stL1.LevelCounts, stL1.TotalDown, stL1.StatusCounts)
	}

	// 2. L2 aggregation merges a.sub.example.com + b.sub.example.com -> sub.example.com, and news.sina.com.cn -> news.sina.com.cn
	stL2 := getState("level=l2")
	if stL2.LevelCounts["l2"] != 2 || stL2.StatusCounts["all"] != 2 || stL2.Report.Candidates[0].Traffic.Host != "sub.example.com" || stL2.Report.Candidates[0].ChildCount != 2 {
		t.Fatalf("unexpected L2 aggregation: %+v", stL2.Report.Candidates)
	}

	// 3. CSRF header required on POST mutations
	wNoCSRF := httptest.NewRecorder()
	reqNoCSRF := httptest.NewRequest("POST", "/api/rules/ignore", strings.NewReader(`{"domain":"sina.com.cn","action":"add"}`))
	h.ServeHTTP(wNoCSRF, reqNoCSRF)
	if wNoCSRF.Code != 403 {
		t.Fatalf("expected 403 without CSRF header, got %d", wNoCSRF.Code)
	}

	postJSON := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "mihomo-policy")
		h.ServeHTTP(w, req)
		return w
	}

	// 4. Ignore sina.com.cn -> remains in traffic stats, marked ignored, excluded from pending direct test filter
	if w := postJSON("/api/rules/ignore", `{"domain":"sina.com.cn","action":"add"}`); w.Code != 200 {
		t.Fatalf("ignore add failed: %d %s", w.Code, w.Body.String())
	}
	stAfterIgnore := getState("level=l1")
	if stAfterIgnore.TotalDomains != 3 || stAfterIgnore.StatusCounts["all"] != 2 || stAfterIgnore.TotalDown != 3500 || stAfterIgnore.IgnoredDomains != 1 {
		t.Fatalf("ignored domain dropped from stats: total=%d counts=%+v down=%d ignored=%d", stAfterIgnore.TotalDomains, stAfterIgnore.StatusCounts, stAfterIgnore.TotalDown, stAfterIgnore.IgnoredDomains)
	}
	stPending := getState("level=l1&status=pending")
	for _, c := range stPending.Report.Candidates {
		if c.Traffic.Host == "sina.com.cn" {
			t.Fatal("ignored domain still appeared in pending direct-test list")
		}
	}

	// 5. Add example.com to direct.list -> StatusCounts["direct"] becomes 1
	if w := postJSON("/api/rules/direct", `{"domain":"example.com","action":"add"}`); w.Code != 200 {
		t.Fatalf("direct add failed: %d %s", w.Code, w.Body.String())
	}
	stAfterDirect := getState("level=l1")
	if stAfterDirect.StatusCounts["direct"] != 1 {
		t.Fatalf("expected StatusCounts[direct]=1 after adding example.com, got %+v", stAfterDirect.StatusCounts)
	}
	rawDirect, _ := os.ReadFile(directList)
	if !strings.Contains(string(rawDirect), "DOMAIN-SUFFIX,example.com") {
		t.Fatalf("direct.list not updated: %s", rawDirect)
	}
}
