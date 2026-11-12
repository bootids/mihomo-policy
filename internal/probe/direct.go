package probe

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"mihomo-policy/internal/policy"
	"mihomo-policy/internal/store"
)

var (
	fakeIPPrefix = netip.MustParsePrefix("198.18.0.0/15")
	cgnatPrefix  = netip.MustParsePrefix("100.64.0.0/10")
)

// IsPublicRoutableIP rejects loopback, private, link-local, CGNAT, and Fake-IP ranges.
func IsPublicRoutableIP(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
		return false
	}
	if fakeIPPrefix.Contains(addr) || cgnatPrefix.Contains(addr) {
		return false
	}
	return true
}

func resolvePublicIPDoH(ctx context.Context, host string, timeout time.Duration) (netip.Addr, error) {
	endpoints := []string{
		"https://223.5.5.5/resolve?name=" + url.QueryEscape(host) + "&type=1",
		"https://1.12.12.12/resolve?name=" + url.QueryEscape(host) + "&type=1",
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   min(timeout, 4*time.Second),
		ResponseHeaderTimeout: min(timeout, 4*time.Second),
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: min(timeout, 5*time.Second)}

	var lastErr error
	for _, ep := range endpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 32768))
		resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("doh status %d", resp.StatusCode)
			continue
		}
		var parsed struct {
			Status int `json:"Status"`
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			lastErr = err
			continue
		}
		for _, ans := range parsed.Answer {
			if ans.Type != 1 && ans.Type != 28 {
				continue
			}
			ip, e := netip.ParseAddr(strings.TrimSpace(ans.Data))
			if e == nil && IsPublicRoutableIP(ip) {
				return ip.Unmap(), nil
			}
		}
		if parsed.Status != 0 {
			lastErr = fmt.Errorf("dns rcode %d", parsed.Status)
		} else {
			lastErr = fmt.Errorf("no public A record")
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dns resolution failed")
	}
	return netip.Addr{}, lastErr
}

// TestDirectHost tests immediate HTTPS direct reachability for a single hostname.
func TestDirectHost(ctx context.Context, directProxy, host string, timeout time.Duration) store.DirectHostResult {
	h, err := policy.Domain(host)
	if err != nil {
		return store.DirectHostResult{Host: host, Phase: "validate", Error: "invalid_domain"}
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res := store.DirectHostResult{Host: h, Phase: "dns"}
	start := time.Now()

	tr := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig:       &tls.Config{ServerName: h, MinVersion: tls.VersionTLS12},
	}
	defer tr.CloseIdleConnections()

	if strings.TrimSpace(directProxy) != "" {
		p, e := url.Parse(directProxy)
		if e != nil || p.Host == "" {
			res.Phase = "connect"
			res.Error = "invalid_direct_proxy"
			return res
		}
		tr.Proxy = http.ProxyURL(p)
		res.Phase = "connect"
	} else {
		ip, e := resolvePublicIPDoH(ctx, h, timeout)
		if e != nil {
			res.DurationMS = time.Since(start).Milliseconds()
			res.Phase = "dns"
			res.Error = "dns"
			return res
		}
		res.ResolvedIP = ip.String()
		res.Phase = "connect"
		dialer := &net.Dialer{Timeout: timeout}
		targetAddr := net.JoinHostPort(ip.String(), "443")
		tr.DialContext = func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(dialCtx, "tcp", targetAddr)
		}
	}

	var mu sync.Mutex
	phase := res.Phase
	setPhase := func(p string) { mu.Lock(); phase = p; mu.Unlock() }
	trace := &httptrace.ClientTrace{
		ConnectStart:      func(_, _ string) { setPhase("connect") },
		TLSHandshakeStart: func() { setPhase("tls") },
		TLSHandshakeDone: func(_ tls.ConnectionState, e error) {
			if e == nil {
				setPhase("http")
			}
		},
		WroteRequest: func(httptrace.WroteRequestInfo) { setPhase("http") },
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, "https://"+h+"/", nil)
	if err != nil {
		res.Error = "invalid_url"
		return res
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	res.DurationMS = time.Since(start).Milliseconds()
	mu.Lock()
	res.Phase = phase
	mu.Unlock()
	if err != nil {
		res.Error = classify(err)
		return res
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	res.DurationMS = time.Since(start).Milliseconds()
	res.Status = resp.StatusCode
	res.Phase = "http"

	if resp.StatusCode >= 100 && resp.StatusCode < 500 {
		res.Passed = true
	} else {
		res.Error = fmt.Sprintf("http_%d", resp.StatusCode)
	}
	return res
}

// TestDirectDomain tests a 1st-level, 2nd-level, or exact domain using observed sample hosts when available.
func TestDirectDomain(ctx context.Context, directProxy, domain string, sampleHosts []string, timeout time.Duration) (store.DirectTestRecord, error) {
	d, err := policy.Domain(domain)
	if err != nil {
		return store.DirectTestRecord{}, err
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}

	var targets []string
	seen := map[string]bool{}
	for _, sh := range sampleHosts {
		if h, e := policy.Domain(sh); e == nil && !seen[h] {
			seen[h] = true
			targets = append(targets, h)
			if len(targets) == 3 {
				break
			}
		}
	}
	if len(targets) == 0 {
		targets = append(targets, d)
	}

	results := make([]store.DirectHostResult, len(targets))
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func(idx int, host string) {
			defer wg.Done()
			results[idx] = TestDirectHost(ctx, directProxy, host, timeout)
		}(i, target)
	}
	wg.Wait()

	// Fallback: if bare apex had no A record and no sampleHosts were supplied, try www.<domain>.
	if len(sampleHosts) == 0 && len(results) == 1 && !results[0].Passed && results[0].Error == "dns" && !strings.HasPrefix(d, "www.") {
		if l1, _, e := policy.DomainLevels(d); e == nil && l1 == d {
			wwwRes := TestDirectHost(ctx, directProxy, "www."+d, timeout)
			if wwwRes.Passed {
				results = append(results, wwwRes)
			}
		}
	}

	rec := store.DirectTestRecord{
		Domain: d,
		At:     time.Now().UTC(),
		Hosts:  results,
	}

	passCount := 0
	var maxDuration int64
	for _, r := range results {
		if r.Passed {
			passCount++
			if r.DurationMS > maxDuration {
				maxDuration = r.DurationMS
			}
			if rec.Status == 0 {
				rec.Status = r.Status
			}
			if rec.ResolvedIP == "" {
				rec.ResolvedIP = r.ResolvedIP
			}
		} else if rec.Error == "" {
			if r.Phase != "" && r.Phase != r.Error {
				rec.Error = r.Phase + ":" + r.Error
			} else {
				rec.Error = r.Error
			}
		}
	}

	if len(sampleHosts) > 0 {
		// All tested traffic-carrying hosts should pass for safe suffix direct rule.
		rec.Passed = passCount == len(results) && passCount > 0
	} else {
		rec.Passed = passCount > 0
	}
	if rec.Passed {
		rec.DurationMS = maxDuration
		rec.Error = ""
	} else if len(results) > 0 {
		rec.DurationMS = results[0].DurationMS
	}
	return rec, nil
}
