package app

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"mihomo-policy/internal/collect"
	"mihomo-policy/internal/store"
)

func TestCollectorShutdownAndSingleWriter(t *testing.T) {
	ready := make(chan string, 4)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ready <- r.URL.Path
		if r.URL.Path == "/connections" {
			io.WriteString(w, `{"connections":[]}`)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer s.Close()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &collect.Collector{BaseURL: s.URL, Source: "home", DB: db, Interval: time.Hour, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	done := make(chan error, 1)
	go func() { done <- CollectOnly(ctx, c) }()
	for i := 0; i < 2; i++ {
		select {
		case <-ready:
		case <-time.After(5 * time.Second):
			t.Fatal("collector did not start")
		}
	}
	if err := CollectOnly(ctx, c); err == nil {
		t.Fatal("second collector accepted")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("collector failed to stop")
	}
	ok, err := db.Lease(context.Background(), "collector:home", "replacement", time.Now(), 30*time.Second)
	if err != nil || !ok {
		t.Fatalf("lease not released: %t %v", ok, err)
	}
}
