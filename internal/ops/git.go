package ops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	gitcfg "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"golang.org/x/crypto/ssh"

	"mihomo-policy/internal/config"
)

type GitStatus struct {
	Available    bool     `json:"available"`
	Branch       string   `json:"branch"`
	Head         string   `json:"head"`
	Remote       string   `json:"remote"`
	RemoteURL    string   `json:"remote_url,omitempty"`
	HasRemote    bool     `json:"has_remote"`
	ChangedFiles []string `json:"changed_files"`
	DirtyCount   int      `json:"dirty_count"`
	AheadCount   int      `json:"ahead_count"`
}

type PushResult struct {
	Committed    bool     `json:"committed"`
	CommitHash   string   `json:"commit_hash,omitempty"`
	Pushed       bool     `json:"pushed"`
	Branch       string   `json:"branch"`
	Remote       string   `json:"remote"`
	ChangedFiles []string `json:"changed_files"`
	Message      string   `json:"message"`
}

func isAllowedRepoPath(rel string) bool {
	rel = filepath.ToSlash(strings.TrimSpace(rel))
	if rel == "" || strings.HasPrefix(rel, ".") && rel != ".gitignore" && !strings.HasPrefix(rel, ".github/") {
		return false
	}
	for _, blocked := range []string{"local/", "data/", "bin/", "dist/"} {
		if strings.HasPrefix(rel, blocked) || rel == strings.TrimSuffix(blocked, "/") {
			return false
		}
	}
	if strings.HasSuffix(rel, ".db") || strings.HasSuffix(rel, ".db-wal") || strings.HasSuffix(rel, ".db-shm") || rel == ".env" || strings.HasSuffix(rel, ".DS_Store") {
		return false
	}
	return strings.HasPrefix(rel, "policy/") || rel == "config.template.yaml"
}

// RepoStatus inspects git status for policy/ and config.template.yaml.
func RepoStatus(repoDir string, gitCfg config.GitConfig) GitStatus {
	st := GitStatus{
		Branch:       gitCfg.Branch,
		Remote:       gitCfg.Remote,
		ChangedFiles: []string{},
	}
	if st.Branch == "" {
		st.Branch = "main"
	}
	if st.Remote == "" {
		st.Remote = "origin"
	}
	if repoDir == "" {
		return st
	}
	if _, err := os.Stat(filepath.Join(repoDir, ".git")); err != nil {
		return st
	}
	st.Available = true

	if gitBin, err := exec.LookPath("git"); err == nil {
		if b := runGitQuiet(gitBin, repoDir, " symbolic-ref --short HEAD"); b != "" {
			st.Branch = b
		}
		if h := runGitQuiet(gitBin, repoDir, "rev-parse", "--short", "HEAD"); h != "" {
			st.Head = h
		}
		if u := runGitQuiet(gitBin, repoDir, "remote", "get-url", st.Remote); u != "" {
			st.RemoteURL = sanitizeRemoteURL(u)
			st.HasRemote = true
		}
		if st.HasRemote && st.Head != "" {
			if cnt := runGitQuiet(gitBin, repoDir, "rev-list", "--count", st.Remote+"/"+st.Branch+"..HEAD"); cnt != "" {
				fmt.Sscanf(cnt, "%d", &st.AheadCount)
			}
		}
		out, err := exec.Command(gitBin, "-C", repoDir, "status", "--porcelain", "-uall", "--", "policy", "config.template.yaml").Output()
		if err == nil {
			seen := map[string]bool{}
			for _, line := range strings.Split(strings.TrimRight(string(out), "\r\n"), "\n") {
				if len(line) < 4 {
					continue
				}
				file := strings.TrimSpace(line[3:])
				if idx := strings.Index(file, " -> "); idx >= 0 {
					file = file[idx+4:]
				}
				file = strings.Trim(file, `"`)
				if isAllowedRepoPath(file) && !seen[file] {
					seen[file] = true
					st.ChangedFiles = append(st.ChangedFiles, file)
				}
			}
			sort.Strings(st.ChangedFiles)
			st.DirtyCount = len(st.ChangedFiles)
			return st
		}
	}

	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		return st
	}
	if head, e := repo.Head(); e == nil {
		st.Head = head.Hash().String()[:min(8, len(head.Hash().String()))]
		if head.Name().IsBranch() {
			st.Branch = head.Name().Short()
		}
	}
	if rem, e := repo.Remote(st.Remote); e == nil && len(rem.Config().URLs) > 0 {
		st.RemoteURL = sanitizeRemoteURL(rem.Config().URLs[0])
		st.HasRemote = true
	}
	if st.HasRemote {
		if head, e := repo.Head(); e == nil {
			remRefName := plumbing.NewRemoteReferenceName(st.Remote, st.Branch)
			if remRef, re := repo.Reference(remRefName, true); re == nil && remRef.Hash() != head.Hash() {
				ahead := 0
				if iter, ie := repo.Log(&git.LogOptions{From: head.Hash()}); ie == nil {
					_ = iter.ForEach(func(c *object.Commit) error {
						if c.Hash == remRef.Hash() || ahead >= 100 {
							return errors.New("stop")
						}
						ahead++
						return nil
					})
				}
				if ahead == 0 {
					ahead = 1
				}
				st.AheadCount = ahead
			}
		}
	}
	if wt, e := repo.Worktree(); e == nil {
		if ws, e := wt.Status(); e == nil {
			for file, fs := range ws {
				if (fs.Worktree != git.Unmodified || fs.Staging != git.Unmodified) && isAllowedRepoPath(file) {
					st.ChangedFiles = append(st.ChangedFiles, file)
				}
			}
			sort.Strings(st.ChangedFiles)
			st.DirtyCount = len(st.ChangedFiles)
		}
	}
	return st
}

func runGitQuiet(gitBin, repoDir string, args ...string) string {
	var cmdArgs []string
	if len(args) == 1 && strings.Contains(args[0], " ") {
		cmdArgs = append([]string{"-C", repoDir}, strings.Fields(args[0])...)
	} else {
		cmdArgs = append([]string{"-C", repoDir}, args...)
	}
	out, err := exec.Command(gitBin, cmdArgs...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func sanitizeRemoteURL(raw string) string {
	if idx := strings.Index(raw, "@"); idx > 0 && strings.HasPrefix(raw, "http") {
		schemeIdx := strings.Index(raw, "://")
		if schemeIdx > 0 && idx > schemeIdx+3 {
			return raw[:schemeIdx+3] + raw[idx+1:]
		}
	}
	return raw
}

// CommitAndPush stages policy/ & config.template.yaml changes, commits them, and pushes to remote.
func CommitAndPush(ctx context.Context, repoDir, sshKeyFile, knownHostsFile string, gitCfg config.GitConfig, message string) (PushResult, error) {
	if repoDir == "" {
		return PushResult{}, fmt.Errorf("未配置本地仓库目录 (repo_dir)")
	}
	if _, err := os.Stat(filepath.Join(repoDir, ".git")); err != nil {
		return PushResult{}, fmt.Errorf("目录 %s 不是 Git 仓库", repoDir)
	}
	if gitCfg.Remote == "" {
		gitCfg.Remote = "origin"
	}
	if gitCfg.Branch == "" {
		gitCfg.Branch = "main"
	}
	if gitCfg.AuthorName == "" {
		gitCfg.AuthorName = "mihomo-policy"
	}
	if gitCfg.AuthorEmail == "" {
		gitCfg.AuthorEmail = "policy@localhost"
	}

	st := RepoStatus(repoDir, gitCfg)
	message = strings.TrimSpace(message)
	if message == "" {
		if len(st.ChangedFiles) > 0 {
			message = fmt.Sprintf("chore(policy): update %s", strings.Join(st.ChangedFiles, ", "))
			if len(message) > 96 {
				message = fmt.Sprintf("chore(policy): update %d policy files", len(st.ChangedFiles))
			}
		} else {
			message = "chore(policy): sync rules"
		}
	}

	// Verify no subscription URL secret leaked into tracked files before staging.
	if subURL := strings.TrimSpace(os.Getenv("MIHOMO_SUB_URL")); subURL != "" {
		for _, rel := range st.ChangedFiles {
			if data, err := os.ReadFile(filepath.Join(repoDir, rel)); err == nil && bytes.Contains(data, []byte(subURL)) {
				return PushResult{}, fmt.Errorf("检测到敏感订阅地址出现在待提交文件 %s 中，已拒绝提交", rel)
			}
		}
	}

	if gitBin, err := exec.LookPath("git"); err == nil {
		return commitAndPushCLI(ctx, gitBin, repoDir, sshKeyFile, knownHostsFile, gitCfg, st, message)
	}
	return commitAndPushGoGit(ctx, repoDir, sshKeyFile, knownHostsFile, gitCfg, st, message)
}

func commitAndPushCLI(ctx context.Context, gitBin, repoDir, sshKeyFile, knownHostsFile string, gitCfg config.GitConfig, st GitStatus, message string) (PushResult, error) {
	res := PushResult{
		Branch:       gitCfg.Branch,
		Remote:       gitCfg.Remote,
		ChangedFiles: st.ChangedFiles,
		Message:      message,
	}

	env := os.Environ()
	if sshKeyFile != "" {
		sshCmd := fmt.Sprintf("ssh -i %q -o IdentitiesOnly=yes -o BatchMode=yes", sshKeyFile)
		if knownHostsFile != "" {
			sshCmd += fmt.Sprintf(" -o UserKnownHostsFile=%q -o StrictHostKeyChecking=accept-new", knownHostsFile)
		} else {
			sshCmd += " -o StrictHostKeyChecking=accept-new"
		}
		env = append(env, "GIT_SSH_COMMAND="+sshCmd)
	}

	run := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, gitBin, append([]string{"-C", repoDir}, args...)...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("git %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return strings.TrimSpace(string(out)), nil
	}

	pathsToStage := []string{"policy"}
	if _, err := os.Stat(filepath.Join(repoDir, "config.template.yaml")); err == nil {
		pathsToStage = append(pathsToStage, "config.template.yaml")
	}
	if _, err := run(append([]string{"add", "--"}, pathsToStage...)...); err != nil {
		return res, err
	}

	diffCmd := exec.CommandContext(ctx, gitBin, "-C", repoDir, "diff", "--cached", "--quiet")
	diffCmd.Env = env
	hasStaged := diffCmd.Run() != nil

	if hasStaged {
		commitArgs := []string{
			"-c", "user.name=" + gitCfg.AuthorName,
			"-c", "user.email=" + gitCfg.AuthorEmail,
			"commit", "-m", message,
		}
		if _, err := run(commitArgs...); err != nil {
			return res, err
		}
		res.Committed = true
	}

	if hash, err := run("rev-parse", "--short", "HEAD"); err == nil {
		res.CommitHash = hash
	}

	if !st.HasRemote {
		return res, fmt.Errorf("已提交本地仓库 (%s)，但尚未配置远端仓库 (%s)", res.CommitHash, gitCfg.Remote)
	}

	if _, err := run("push", "-u", gitCfg.Remote, "HEAD:"+gitCfg.Branch); err != nil {
		return res, err
	}
	res.Pushed = true
	return res, nil
}

func commitAndPushGoGit(ctx context.Context, repoDir, sshKeyFile, knownHostsFile string, gitCfg config.GitConfig, st GitStatus, message string) (PushResult, error) {
	res := PushResult{
		Branch:       gitCfg.Branch,
		Remote:       gitCfg.Remote,
		ChangedFiles: st.ChangedFiles,
		Message:      message,
	}
	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		return res, err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return res, err
	}

	ws, err := wt.Status()
	if err != nil {
		return res, err
	}
	stagedAny := false
	for file, fs := range ws {
		if (fs.Worktree != git.Unmodified || fs.Staging != git.Unmodified) && isAllowedRepoPath(file) {
			if _, e := wt.Add(file); e != nil {
				return res, e
			}
			stagedAny = true
		}
	}

	if stagedAny {
		hash, err := wt.Commit(message, &git.CommitOptions{
			Author: &object.Signature{
				Name:  gitCfg.AuthorName,
				Email: gitCfg.AuthorEmail,
				When:  time.Now(),
			},
		})
		if err != nil {
			return res, err
		}
		res.Committed = true
		res.CommitHash = hash.String()[:8]
	} else if head, e := repo.Head(); e == nil {
		res.CommitHash = head.Hash().String()[:8]
	}

	rem, err := repo.Remote(gitCfg.Remote)
	if err != nil || len(rem.Config().URLs) == 0 {
		return res, fmt.Errorf("已提交本地仓库 (%s)，但尚未配置远端仓库 (%s)", res.CommitHash, gitCfg.Remote)
	}

	remoteURL := rem.Config().URLs[0]
	pushOpts := &git.PushOptions{
		RemoteName: gitCfg.Remote,
		RefSpecs:   []gitcfg.RefSpec{gitcfg.RefSpec(fmt.Sprintf("HEAD:refs/heads/%s", gitCfg.Branch))},
	}

	if strings.HasPrefix(remoteURL, "http://") || strings.HasPrefix(remoteURL, "https://") {
		if tok := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); tok != "" {
			pushOpts.Auth = &githttp.BasicAuth{Username: "x-access-token", Password: tok}
		}
	} else {
		signer, err := loadSSHSigner(sshKeyFile)
		if err != nil {
			return res, fmt.Errorf("无法加载 Git SSH 密钥: %w", err)
		}
		hkCb, err := tofuHostKeyCallback(knownHostsFile)
		if err != nil {
			return res, err
		}
		auth := &gitssh.PublicKeys{User: "git", Signer: signer}
		auth.HostKeyCallback = hkCb
		pushOpts.Auth = auth
	}

	err = repo.PushContext(ctx, pushOpts)
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return res, fmt.Errorf("git push 失败: %w", err)
	}
	if head, e := repo.Head(); e == nil {
		remRef := plumbing.NewHashReference(plumbing.NewRemoteReferenceName(gitCfg.Remote, gitCfg.Branch), head.Hash())
		_ = repo.Storer.SetReference(remRef)
	}
	res.Pushed = true
	return res, nil
}

func loadSSHSigner(sshKeyFile string) (ssh.Signer, error) {
	candidates := []string{}
	if sshKeyFile != "" {
		candidates = append(candidates, sshKeyFile)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".ssh", "id_ed25519"),
			filepath.Join(home, ".ssh", "id_ecdsa"),
			filepath.Join(home, ".ssh", "id_rsa"),
		)
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err == nil {
			return signer, nil
		}
	}
	return nil, fmt.Errorf("未找到可用的 SSH 私钥，请配置 ssh_key_file")
}
