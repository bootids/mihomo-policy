package probe

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"mihomo-policy/internal/config"
	"mihomo-policy/internal/store"
)

func TestExplicitProxyAndHTTPRefusal(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(403) }))
	defer s.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	r := Once(context.Background(), "home", "run", "DIRECT", s.URL, config.Target{Name: "t", URL: "http://example.invalid/check", ExpectedStatus: []int{200}}, time.Second)
	if calls.Load() != 1 || r.OK || !r.Reachable || r.Status != 403 || r.Error != "unexpected_http_status" {
		t.Fatalf("%+v calls=%d", r, calls.Load())
	}
}
func TestContentAndPairedPersistence(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("healthy")) }))
	defer s.Close()
	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("healthy")) }))
	defer s2.Close()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c := config.Config{Source: "home", DirectProxy: s.URL, ProxyProxy: s2.URL, Concurrency: 2, ProbeTimeout: "1s", Targets: []config.Target{{Name: "health", URL: "http://example.invalid/", ExpectedStatus: []int{200}, Contains: "healthy"}}}
	rs, err := Run(context.Background(), c, db)
	if err != nil || len(rs) != 2 || !rs[0].OK || !rs[1].OK {
		t.Fatalf("%+v %v", rs, err)
	}
	stored, err := db.Probes(context.Background(), "home", time.Time{})
	if err != nil || len(stored) != 2 || stored[0].RunID != stored[1].RunID || stored[0].ContextID != c.ProbeContext(c.Targets[0]) || stored[0].ContextID != stored[1].ContextID {
		t.Fatalf("%+v %v", stored, err)
	}
}

func TestTLSFailureToHTTPSProxyIsNotDestinationFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.Copy(io.Discard, c)
	}()
	r := Once(context.Background(), "home", "run", "DIRECT", "https://"+listener.Addr().String(), config.Target{URL: "https://example.invalid/"}, 100*time.Millisecond)
	if r.OK || r.Phase != "proxy_tls" || r.Error != "timeout" {
		t.Fatalf("proxy handshake mislabeled: %+v", r)
	}
	<-done
}
func TestMissingEndpointNeverFallsBackToLocalDirect(t *testing.T) {
	r := Once(context.Background(), "home", "r", "DIRECT", "", config.Target{URL: "http://example.invalid/"}, time.Second)
	if r.OK || r.Reachable || r.Error != "invalid explicit proxy endpoint" {
		t.Fatalf("%+v", r)
	}
}
