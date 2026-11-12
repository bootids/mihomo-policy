package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"

	"mihomo-policy/internal/collect"
	"mihomo-policy/internal/config"
	"mihomo-policy/internal/policy"
	"mihomo-policy/internal/store"
)

// Once never falls back to a local or environment-provided proxy path.
func Once(ctx context.Context, source, runID, route, endpoint string, target config.Target, timeout time.Duration) store.Probe {
	u, _ := url.Parse(target.URL)
	host, _ := policy.Domain(u.Hostname())
	r := store.Probe{RunID: runID, Source: source, At: time.Now().UTC(), Host: host, Target: target.Name, Route: route, Phase: "connect"}
	p, err := url.Parse(endpoint)
	if err != nil || p.Host == "" || (p.Scheme != "http" && p.Scheme != "https") {
		r.Error = "invalid explicit proxy endpoint"
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tr := &http.Transport{Proxy: http.ProxyURL(p), DisableKeepAlives: true, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// Trace callbacks may run concurrently with Do. Protect classification state.
	var mu sync.Mutex
	phase := "connect"
	proxyTLS := p.Scheme == "https"
	tlsCount := 0
	set := func(s string) { mu.Lock(); phase = s; mu.Unlock() }
	trace := &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) { set("connect") },
		TLSHandshakeStart: func() {
			mu.Lock()
			tlsCount++
			phase = "tls"
			if proxyTLS && tlsCount == 1 {
				phase = "proxy_tls"
			}
			mu.Unlock()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, e error) {
			if e == nil {
				set("http")
			}
		},
		WroteRequest: func(httptrace.WroteRequestInfo) { set("http") },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, target.URL, nil)
	if err != nil {
		r.Error = "invalid target URL"
		return r
	}
	req.Header.Set("User-Agent", "mihomo-policy/0.1")
	start := time.Now()
	resp, err := client.Do(req)
	r.DurationMS = time.Since(start).Milliseconds()
	mu.Lock()
	r.Phase = phase
	mu.Unlock()
	if err != nil {
		r.Error = classify(err)
		return r
	}
	defer resp.Body.Close()
	r.Reachable = true
	r.Status = resp.StatusCode
	r.Phase = "http"
	// Bounded content checks; response bodies and request paths are not persisted.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	r.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		r.Phase = "body"
		r.Error = classify(err)
		return r
	}
	for _, status := range target.ExpectedStatus {
		if resp.StatusCode == status {
			r.OK = true
			break
		}
	}
	if !r.OK {
		r.Error = "unexpected_http_status"
		return r
	}
	if target.Contains != "" && !strings.Contains(string(body), target.Contains) {
		r.OK = false
		r.Error = "content_mismatch"
		r.Phase = "content"
	}
	return r
}

func classify(err error) string {
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "dns"
	}
	// Do not retain err.Error(): it may embed a target URL or proxy credentials.
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "certificate") {
		return "certificate"
	}
	if strings.Contains(s, "refused") {
		return "refused"
	}
	if strings.Contains(s, "unreachable") {
		return "unreachable"
	}
	if strings.Contains(s, "proxyconnect") || strings.Contains(s, "proxy connection") {
		return "proxy_connect"
	}
	return "connection_failed"
}

func Run(ctx context.Context, c config.Config, db *store.DB) ([]store.Probe, error) {
	if c.DirectProxy == "" || c.ProxyProxy == "" {
		return nil, fmt.Errorf("both direct_proxy and proxy_proxy must be configured as forced-route listeners")
	}
	if len(c.Targets) == 0 {
		return nil, fmt.Errorf("no explicit probe targets configured")
	}
	runID := collect.ID()
	sem := make(chan struct{}, c.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var all []store.Probe
	var errs []error
	for _, target := range c.Targets {
		select {
		case <-ctx.Done():
			wg.Wait()
			return all, ctx.Err()
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(t config.Target) {
			defer wg.Done()
			defer func() { <-sem }()
			// Run the two paths at the same time to reduce time-of-day confounding.
			pair := make([]store.Probe, 2)
			var p sync.WaitGroup
			p.Add(2)
			go func() {
				defer p.Done()
				pair[0] = Once(ctx, c.Source, runID, "DIRECT", c.DirectProxy, t, config.Duration(c.ProbeTimeout))
			}()
			go func() {
				defer p.Done()
				pair[1] = Once(ctx, c.Source, runID, "PROXY", c.ProxyProxy, t, config.Duration(c.ProbeTimeout))
			}()
			p.Wait()
			for i := range pair {
				pair[i].ContextID = c.ProbeContext(t)
			}
			if ctx.Err() != nil {
				return
			}
			err := db.AddProbePair(ctx, pair)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			} else {
				all = append(all, pair...)
			}
		}(target)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return all, ctx.Err()
	}
	return all, errors.Join(errs...)
}
