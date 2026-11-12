package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"mihomo-policy/internal/analyze"
	"mihomo-policy/internal/collect"
	"mihomo-policy/internal/config"
	"mihomo-policy/internal/dashboard"
	"mihomo-policy/internal/policy"
	"mihomo-policy/internal/probe"
	"mihomo-policy/internal/store"
)

func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".policy-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

func Report(ctx context.Context, c config.Config, db *store.DB, lookback time.Duration) (analyze.Report, error) {
	b, err := policy.Load(c.PolicyFile)
	if err != nil {
		return analyze.Report{}, err
	}
	now := time.Now().UTC()
	t := analyze.Thresholds{MinPairs: c.Analysis.MinPairs, MinWindows: c.Analysis.MinWindows, Window: config.Duration(c.Analysis.Window), MinSpan: config.Duration(c.Analysis.MinSpan), SuccessRate: c.Analysis.SuccessRate, DirectFailureRate: c.Analysis.DirectFailureRate}
	t.EvidenceLookback = config.Duration(c.Analysis.EvidenceLookback)
	t.MaxAge = config.Duration(c.Analysis.MaxAge)
	t.RecentPairs = c.Analysis.RecentPairs
	t.MinDirectWinRate = c.Analysis.MinDirectWinRate
	var targets []analyze.ProbeTarget
	for _, target := range c.Targets {
		u, err := url.Parse(target.URL)
		if err != nil {
			return analyze.Report{}, err
		}
		host, err := policy.Domain(u.Hostname())
		if err != nil {
			return analyze.Report{}, err
		}
		targets = append(targets, analyze.ProbeTarget{Host: host, Name: target.Name, ContextID: c.ProbeContext(target)})
	}
	return analyze.ReportFor(ctx, db, b, c.Source, now.Add(-lookback), now, t, targets...)
}

func Serve(ctx context.Context, c config.Config, db *store.DB, logger *slog.Logger) error {
	if c.Controller == "" {
		return fmt.Errorf("controller is required for serve")
	}
	secret, err := c.Secret()
	if err != nil {
		return err
	}
	if _, err = policy.Load(c.PolicyFile); err != nil {
		return err
	}
	health := collect.NewHealth()
	collector := collect.Collector{BaseURL: c.Controller, Secret: secret, Source: c.Source, DB: db, Interval: config.Duration(c.PollInterval), Logger: logger, Health: health}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	collectionErr := make(chan error, 1)
	go func() { defer wg.Done(); collectionErr <- CollectOnly(ctx, &collector); cancel() }()
	webErr := make(chan error, 1)
	if c.Web.Listen != "" {
		wg.Add(1)
		go func() { defer wg.Done(); webErr <- DashboardServer(c, db, health, logger).Run(ctx); cancel() }()
	}
	defer func() { cancel(); wg.Wait() }()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	run := func() {
		jobs := []struct {
			name     string
			interval time.Duration
			fn       func() error
		}{
			{"probe", config.Duration(c.ProbeInterval), func() error {
				if len(c.Targets) == 0 {
					return nil
				}
				_, e := probe.Run(ctx, c, db)
				return e
			}},
			{"report", config.Duration(c.ReportInterval), func() error {
				r, e := Report(ctx, c, db, 7*24*time.Hour)
				if e != nil {
					return e
				}
				data, e := json.MarshalIndent(r, "", "  ")
				if e != nil {
					return e
				}
				return AtomicWrite(c.ReportFile, append(data, '\n'), 0600)
			}},
			{"retention", 24 * time.Hour, func() error { return db.Prune(ctx, time.Now().Add(-config.Duration(c.Retention))) }},
		}
		for _, job := range jobs {
			if ctx.Err() != nil {
				return
			}
			if job.name == "probe" && (len(c.Targets) == 0 || c.DirectProxy == "" || c.ProxyProxy == "") {
				continue
			}
			last, e := db.LastTask(ctx, job.name+":"+c.Source)
			if e != nil {
				logger.Error("read task state", "error", e)
				continue
			}
			if time.Since(last) < job.interval {
				continue
			}
			if e = job.fn(); e != nil {
				logger.Warn("scheduled task failed", "task", job.name, "error", e)
				continue
			}
			if e = db.MarkTask(ctx, job.name+":"+c.Source, time.Now()); e != nil {
				logger.Error("persist task state", "error", e)
			}
		}
	}
	logger.Info("service started", "source", c.Source)
	for {
		run()
		select {
		case <-ctx.Done():
			cancel()
			select {
			case err := <-webErr:
				if err != nil {
					return err
				}
			default:
			}
			select {
			case err := <-collectionErr:
				return err
			default:
				return nil
			}
		case <-ticker.C:
		}
	}
}

func DashboardServer(c config.Config, db *store.DB, health *collect.Health, logger *slog.Logger) *dashboard.Server {
	return &dashboard.Server{Config: c, DB: db, Health: health, Logger: logger, Report: func(ctx context.Context, lookback time.Duration) (analyze.Report, error) {
		return Report(ctx, c, db, lookback)
	}}
}

// CheckCases verifies domain-only routing expectations against the compiler.
func CheckCases(b *policy.Bundle, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var c struct {
		Cases []struct {
			Host     string `yaml:"host"`
			Category string `yaml:"category"`
			Policy   string `yaml:"policy"`
		} `yaml:"cases"`
	}
	if err = policy.Decode(data, &c); err != nil {
		return err
	}
	if len(c.Cases) == 0 {
		return fmt.Errorf("no routing cases")
	}
	var errs []error
	for _, test := range c.Cases {
		m, e := b.MatchDomain(test.Host)
		if e != nil {
			errs = append(errs, e)
			continue
		}
		if m.Category != test.Category || m.Policy != test.Policy {
			errs = append(errs, fmt.Errorf("%s: got %s/%s, want %s/%s", test.Host, m.Category, m.Policy, test.Category, test.Policy))
		}
	}
	return errors.Join(errs...)
}
