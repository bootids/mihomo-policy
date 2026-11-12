package ops

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"gopkg.in/yaml.v3"

	"mihomo-policy/internal/config"
)

type RouterDeployResult struct {
	Name               string   `json:"name"`
	SSHAddr            string   `json:"ssh_addr"`
	RemotePath         string   `json:"remote_path"`
	OK                 bool     `json:"ok"`
	UploadedBytes      int      `json:"uploaded_bytes"`
	Reloaded           bool     `json:"reloaded"`
	ProvidersRefreshed []string `json:"providers_refreshed,omitempty"`
	DurationMS         int64    `json:"duration_ms"`
	Error              string   `json:"error,omitempty"`
}

// RenderRouterConfig loads the maintained Mihomo config.yaml (or config.template.yaml),
// expands ${MIHOMO_SUB_URL} when present, validates required sections, and sets the
// per-router API secret while preserving YAML anchors and rule ordering.
func RenderRouterConfig(configPath string, router config.RouterTarget) ([]byte, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取 Mihomo 配置文件 %s 失败: %w", configPath, err)
	}

	text := string(raw)
	if strings.Contains(text, "${MIHOMO_SUB_URL}") {
		subURL := strings.TrimSpace(os.Getenv("MIHOMO_SUB_URL"))
		if subURL == "" {
			return nil, fmt.Errorf("配置文件包含 ${MIHOMO_SUB_URL} 占位符，请设置环境变量 MIHOMO_SUB_URL 或在 local/config.yaml 中填入真实订阅链接")
		}
		text = strings.ReplaceAll(text, "${MIHOMO_SUB_URL}", subURL)
	}

	secret := ""
	if strings.TrimSpace(router.SecretEnv) != "" {
		secret = os.Getenv(router.SecretEnv)
		if secret == "" {
			return nil, fmt.Errorf("路由器 %s 所需的密钥环境变量 %s 未设置", router.Name, router.SecretEnv)
		}
	}
	if strings.Contains(text, "${MIHOMO_SECRET}") {
		text = strings.ReplaceAll(text, "${MIHOMO_SECRET}", secret)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, fmt.Errorf("解析 Mihomo 配置 YAML 失败: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("Mihomo 配置根节点必须是 YAML Mapping")
	}

	root := doc.Content[0]
	hasProviders, hasGroups, hasRules, secretUpdated := false, false, false, false
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		switch k.Value {
		case "proxy-providers":
			hasProviders = v.Kind == yaml.MappingNode && len(v.Content) > 0
		case "proxy-groups":
			hasGroups = v.Kind == yaml.SequenceNode && len(v.Content) > 0
		case "rules":
			hasRules = v.Kind == yaml.SequenceNode && len(v.Content) > 0
		case "secret":
			v.Kind = yaml.ScalarNode
			v.Tag = "!!str"
			v.Value = secret
			secretUpdated = true
		}
	}
	if !hasProviders || !hasGroups || !hasRules {
		return nil, fmt.Errorf("Mihomo 配置缺少必要的 proxy-providers、proxy-groups 或 rules 段")
	}
	if !secretUpdated {
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "secret"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: secret},
		)
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, fmt.Errorf("序列化 Mihomo 配置失败: %w", err)
	}
	_ = enc.Close()
	return buf.Bytes(), nil
}

// DeployRouters uploads rendered config.yaml to every configured router (e.g. admin@10.10.10.1
// and admin@10.10.8.1), reloads Mihomo via controller API, and refreshes HTTP rule-providers.
func DeployRouters(ctx context.Context, configPath, sshKeyFile, knownHostsFile string, routers []config.RouterTarget) ([]RouterDeployResult, error) {
	if len(routers) == 0 {
		return nil, fmt.Errorf("未配置任何路由器目标")
	}

	rendered := make([][]byte, len(routers))
	for i, r := range routers {
		b, err := RenderRouterConfig(configPath, r)
		if err != nil {
			return nil, err
		}
		rendered[i] = b
	}

	results := make([]RouterDeployResult, len(routers))
	var wg sync.WaitGroup
	for i, r := range routers {
		wg.Add(1)
		go func(idx int, target config.RouterTarget, cfgBytes []byte) {
			defer wg.Done()
			results[idx] = deploySingleRouter(ctx, target, sshKeyFile, knownHostsFile, cfgBytes)
		}(i, r, rendered[i])
	}
	wg.Wait()

	var errs []error
	for _, res := range results {
		if !res.OK {
			errs = append(errs, fmt.Errorf("%s: %s", res.Name, res.Error))
		}
	}
	return results, errors.Join(errs...)
}

func deploySingleRouter(ctx context.Context, target config.RouterTarget, sshKeyFile, knownHostsFile string, cfgBytes []byte) RouterDeployResult {
	start := time.Now()
	res := RouterDeployResult{
		Name:       target.Name,
		SSHAddr:    target.SSHAddr,
		RemotePath: target.RemotePath,
	}
	defer func() {
		res.DurationMS = time.Since(start).Milliseconds()
	}()

	secret := ""
	if target.SecretEnv != "" {
		secret = os.Getenv(target.SecretEnv)
	}
	savedSelections := snapshotSelections(ctx, target.Controller, secret)

	sshClient, err := dialSSH(ctx, target.SSHUser, target.SSHAddr, sshKeyFile, knownHostsFile)
	if err != nil {
		res.Error = fmt.Sprintf("SSH 连接失败: %v", err)
		return res
	}
	defer sshClient.Close()

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		res.Error = fmt.Sprintf("SFTP 初始化失败: %v", err)
		return res
	}
	defer sftpClient.Close()

	var prevBytes []byte
	if existing, e := sftpClient.Open(target.RemotePath); e == nil {
		prevBytes, _ = io.ReadAll(existing)
		existing.Close()
		if len(prevBytes) > 0 {
			if bf, be := sftpClient.OpenFile(target.RemotePath+".prev", os.O_WRONLY|os.O_CREATE|os.O_TRUNC); be == nil {
				_, _ = bf.Write(prevBytes)
				bf.Close()
			}
		}
	}

	if err := writeSFTPFile(sftpClient, target.RemotePath, cfgBytes); err != nil {
		res.Error = fmt.Sprintf("上传 %s 失败: %v", target.RemotePath, err)
		return res
	}
	res.UploadedBytes = len(cfgBytes)

	if target.Controller != "" {
		containerCfg := target.ContainerConfigPath
		if containerCfg == "" {
			containerCfg = "/root/.config/mihomo/config.yaml"
		}
		if err := reloadMihomoConfig(ctx, target.Controller, secret, containerCfg); err != nil {
			// Roll back remote config.yaml if reload rejected the new file.
			if len(prevBytes) > 0 {
				_ = writeSFTPFile(sftpClient, target.RemotePath, prevBytes)
				_ = reloadMihomoConfig(ctx, target.Controller, secret, containerCfg)
			}
			res.Error = fmt.Sprintf("Mihomo 热重载失败（已回滚旧配置）: %v", err)
			return res
		}
		res.Reloaded = true
		res.ProvidersRefreshed = refreshRuleProviders(ctx, target.Controller, secret)
		restoreSelections(ctx, target.Controller, secret, savedSelections)
	}

	res.OK = true
	return res
}

// RefreshRoutersProviders triggers immediate rule-provider updates on all configured routers via Mihomo API.
func RefreshRoutersProviders(ctx context.Context, routers []config.RouterTarget) map[string][]string {
	out := map[string][]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, r := range routers {
		if r.Controller == "" {
			continue
		}
		wg.Add(1)
		go func(target config.RouterTarget) {
			defer wg.Done()
			secret := ""
			if target.SecretEnv != "" {
				secret = os.Getenv(target.SecretEnv)
			}
			refreshed := refreshRuleProviders(ctx, target.Controller, secret)
			mu.Lock()
			out[target.Name] = refreshed
			mu.Unlock()
		}(r)
	}
	wg.Wait()
	return out
}

func writeSFTPFile(client *sftp.Client, remotePath string, data []byte) error {
	f, err := client.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	n, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	if n != len(data) {
		return fmt.Errorf("short write (%d/%d bytes)", n, len(data))
	}
	return nil
}

func dialSSH(ctx context.Context, user, addr, sshKeyFile, knownHostsFile string) (*ssh.Client, error) {
	if user == "" {
		user = "admin"
	}
	if !strings.Contains(addr, ":") {
		addr += ":22"
	}
	var authMethods []ssh.AuthMethod

	if signer, err := loadSSHSigner(sshKeyFile); err == nil {
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.DialTimeout("unix", sock, 2*time.Second); err == nil {
			defer conn.Close()
			ag := agent.NewClient(conn)
			if signers, err := ag.Signers(); err == nil && len(signers) > 0 {
				authMethods = append(authMethods, ssh.PublicKeys(signers...))
			}
		}
	}
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("未找到可用的 SSH 私钥或 ssh-agent")
	}

	hkCb, err := tofuHostKeyCallback(knownHostsFile)
	if err != nil {
		return nil, err
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: hkCb,
		Timeout:         10 * time.Second,
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(rawConn, addr, cfg)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

var knownHostsMu sync.Mutex

// tofuHostKeyCallback enforces SSH host key verification against ~/.ssh/known_hosts and
// a persistent trust-on-first-use file (equivalent to OpenSSH StrictHostKeyChecking=accept-new).
func tofuHostKeyCallback(knownHostsPath string) (ssh.HostKeyCallback, error) {
	if knownHostsPath == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			knownHostsPath = filepath.Join(home, ".ssh", "known_hosts")
		}
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		knownHostsMu.Lock()
		defer knownHostsMu.Unlock()

		var files []string
		if knownHostsPath != "" {
			if _, err := os.Stat(knownHostsPath); err == nil {
				files = append(files, knownHostsPath)
			}
		}
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			userKH := filepath.Join(home, ".ssh", "known_hosts")
			if userKH != knownHostsPath {
				if _, err := os.Stat(userKH); err == nil {
					files = append(files, userKH)
				}
			}
		}
		if len(files) > 0 {
			cb, err := knownhosts.New(files...)
			if err == nil {
				err = cb(hostname, remote, key)
				if err == nil {
					return nil
				}
				var keyErr *knownhosts.KeyError
				if errors.As(err, &keyErr) && len(keyErr.Want) > 0 {
					return fmt.Errorf("SSH 主机密钥不匹配 (%s): %w", hostname, err)
				}
			}
		}
		if knownHostsPath != "" {
			if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0700); err == nil {
				line := fmt.Sprintf("%s %s %s\n", knownhosts.Normalize(hostname), key.Type(), base64.StdEncoding.EncodeToString(key.Marshal()))
				if f, err := os.OpenFile(knownHostsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
					_, _ = f.WriteString(line)
					f.Close()
				}
			}
		}
		return nil
	}, nil
}

func mihomoRequest(ctx context.Context, method, baseURL, path, secret string, payload any) ([]byte, int, error) {
	var bodyReader io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, 0, err
		}
		bodyReader = bytes.NewReader(b)
	}
	reqCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, strings.TrimRight(baseURL, "/")+path, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	client := &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 262144))
	return respBody, resp.StatusCode, nil
}

func reloadMihomoConfig(ctx context.Context, controller, secret, containerCfgPath string) error {
	body, status, err := mihomoRequest(ctx, http.MethodPut, controller, "/configs?force=true", secret, map[string]string{"path": containerCfgPath})
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("HTTP %d: %s", status, strings.TrimSpace(string(body)))
	}
	return nil
}

func refreshRuleProviders(ctx context.Context, controller, secret string) []string {
	body, status, err := mihomoRequest(ctx, http.MethodGet, controller, "/providers/rules", secret, nil)
	if err != nil || status != http.StatusOK {
		return nil
	}
	var parsed struct {
		Providers map[string]struct {
			VehicleType string `json:"vehicleType"`
		} `json:"providers"`
	}
	if json.Unmarshal(body, &parsed) != nil {
		return nil
	}
	var refreshed []string
	for name, p := range parsed.Providers {
		if !strings.EqualFold(p.VehicleType, "HTTP") {
			continue
		}
		_, st, e := mihomoRequest(ctx, http.MethodPut, controller, "/providers/rules/"+url.PathEscape(name), secret, nil)
		if e == nil && st >= 200 && st < 300 {
			refreshed = append(refreshed, name)
		}
	}
	return refreshed
}

func snapshotSelections(ctx context.Context, controller, secret string) map[string]string {
	if controller == "" {
		return nil
	}
	body, status, err := mihomoRequest(ctx, http.MethodGet, controller, "/proxies", secret, nil)
	if err != nil || status != http.StatusOK {
		return nil
	}
	var parsed struct {
		Proxies map[string]struct {
			Type string `json:"type"`
			Now  string `json:"now"`
		} `json:"proxies"`
	}
	if json.Unmarshal(body, &parsed) != nil {
		return nil
	}
	selections := map[string]string{}
	for name, p := range parsed.Proxies {
		if strings.EqualFold(p.Type, "Selector") && p.Now != "" && name != "GLOBAL" {
			selections[name] = p.Now
		}
	}
	return selections
}

func restoreSelections(ctx context.Context, controller, secret string, saved map[string]string) {
	if controller == "" || len(saved) == 0 {
		return
	}
	current := snapshotSelections(ctx, controller, secret)
	for group, choice := range saved {
		if current[group] != "" && current[group] != choice {
			_, _, _ = mihomoRequest(ctx, http.MethodPut, controller, "/proxies/"+url.PathEscape(group), secret, map[string]string{"name": choice})
		}
	}
}
