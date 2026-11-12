package ops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	gitcfg "github.com/go-git/go-git/v5/config"
	"gopkg.in/yaml.v3"

	"mihomo-policy/internal/config"
)

func TestRenderRouterConfigPerDeviceSecret(t *testing.T) {
	templatePath := filepath.Join("..", "..", "config.template.yaml")
	t.Setenv("MIHOMO_SUB_URL", "https://sub.example.invalid/clash")
	t.Setenv("TEST_ROUTER_SECRET", "router-10-secret")

	routers := config.DefaultRouters("TEST_ROUTER_SECRET")
	out10, err := RenderRouterConfig(templatePath, routers[0])
	if err != nil {
		t.Fatalf("render 10.10.10.1 failed: %v", err)
	}
	out8, err := RenderRouterConfig(templatePath, routers[1])
	if err != nil {
		t.Fatalf("render 10.10.8.1 failed: %v", err)
	}

	var doc10, doc8 map[string]any
	if err := yaml.Unmarshal(out10, &doc10); err != nil {
		t.Fatalf("unmarshal 10.10.10.1: %v", err)
	}
	if err := yaml.Unmarshal(out8, &doc8); err != nil {
		t.Fatalf("unmarshal 10.10.8.1: %v", err)
	}
	if doc10["secret"] != "router-10-secret" {
		t.Fatalf("10.10.10.1 secret mismatch: %v", doc10["secret"])
	}
	if doc8["secret"] != "" {
		t.Fatalf("10.10.8.1 secret should remain empty, got %v", doc8["secret"])
	}
	if strings.Contains(string(out10), "${MIHOMO_SUB_URL}") {
		t.Fatal("subscription placeholder was not expanded")
	}
	if !strings.Contains(string(out10), "raw.githubusercontent.com/bootids/mihomo-policy/refs/heads/main/policy/rules/direct.list") {
		t.Fatal("expected GitHub repo direct.list URL in rule-providers")
	}
}

func TestCommitAndPushLocalBareRemote(t *testing.T) {
	tmp := t.TempDir()
	bareDir := filepath.Join(tmp, "remote.git")
	if _, err := git.PlainInit(bareDir, true); err != nil {
		t.Fatal(err)
	}

	workDir := filepath.Join(tmp, "work")
	repo, err := git.PlainInit(workDir, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateRemote(&gitcfg.RemoteConfig{Name: "origin", URLs: []string{bareDir}}); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(workDir, "policy", "rules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "policy", "rules", "direct.list"), []byte("DOMAIN-SUFFIX,kimi.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Secret file in local/ must never be staged.
	if err := os.MkdirAll(filepath.Join(workDir, "local"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "local", "config.yaml"), []byte("secret: do-not-commit\n"), 0600); err != nil {
		t.Fatal(err)
	}

	gcfg := config.GitConfig{Remote: "origin", Branch: "main", AuthorName: "Test", AuthorEmail: "test@example.com"}
	st := RepoStatus(workDir, gcfg)
	if !st.Available || st.DirtyCount != 1 || st.ChangedFiles[0] != "policy/rules/direct.list" {
		t.Fatalf("unexpected repo status: %+v", st)
	}

	res, err := CommitAndPush(context.Background(), workDir, "", "", gcfg, "test: add kimi.com")
	if err != nil {
		t.Fatalf("CommitAndPush failed: %v", err)
	}
	if !res.Committed || !res.Pushed || res.CommitHash == "" {
		t.Fatalf("unexpected push result: %+v", res)
	}

	stAfter := RepoStatus(workDir, gcfg)
	if stAfter.DirtyCount != 0 {
		t.Fatalf("expected clean repo after push, got %+v", stAfter)
	}
}
