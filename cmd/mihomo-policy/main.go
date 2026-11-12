package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"mihomo-policy/internal/app"
	"mihomo-policy/internal/collect"
	"mihomo-policy/internal/config"
	"mihomo-policy/internal/policy"
	"mihomo-policy/internal/probe"
	"mihomo-policy/internal/store"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
func usage(w io.Writer) {
	fmt.Fprintln(w, `mihomo-policy — service-aware Mihomo rules and evidence-based route analysis

Commands:
  validate  --policy policy/policy.yaml [--cases tests/routing-cases.yaml]
  build     --policy policy/policy.yaml --out dist/<version>
  render    --policy policy/policy.yaml --base local/base.yaml --bundle-path ./policy/<version> --out local/config.yaml
  match     --policy policy/policy.yaml --host gemini.google.com
  import    --config local/runtime.yaml <file.jsonl>...
  probe     --config local/runtime.yaml
  analyze   --config local/runtime.yaml [--since 168h] [--format json|markdown] [--out data/report.json]
  report    (alias of analyze)
  collect   --config local/runtime.yaml
  serve     --config local/runtime.yaml
  dashboard --config local/runtime.yaml  (read-only UI without collection)
  version

Only the configured source (10.10.10.1 by default in the example) is analyzed.
No command changes router configuration or automatically modifies policy files.`)
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		usage(out)
		return nil
	}
	cmd := args[0]
	if cmd == "version" {
		fmt.Fprintln(out, version)
		return nil
	}
	f := flag.NewFlagSet(cmd, flag.ContinueOnError)
	f.SetOutput(out)
	policyPath := f.String("policy", "policy/policy.yaml", "policy configuration")
	runtimePath := f.String("config", "local/runtime.yaml", "local runtime configuration")
	outPath := f.String("out", "", "output path")
	cases := f.String("cases", "", "routing cases YAML")
	host := f.String("host", "", "domain to classify")
	base := f.String("base", "", "device-local base configuration")
	bundlePath := f.String("bundle-path", "", "rule bundle directory as seen inside Mihomo")
	since := f.Duration("since", 7*24*time.Hour, "analysis lookback")
	format := f.String("format", "json", "json or markdown")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	emit := func(v any) error { e := json.NewEncoder(out); e.SetIndent("", "  "); return e.Encode(v) }
	switch cmd {
	case "validate", "build", "render", "match":
		if len(f.Args()) > 0 {
			return fmt.Errorf("unexpected arguments: %v", f.Args())
		}
		b, err := policy.Load(*policyPath)
		if err != nil {
			return err
		}
		switch cmd {
		case "validate":
			if *cases != "" {
				if err = app.CheckCases(b, *cases); err != nil {
					return err
				}
			}
			return emit(struct {
				Version    string           `json:"version"`
				Categories int              `json:"categories"`
				Overlaps   []policy.Overlap `json:"overlaps"`
			}{b.Version, len(b.Entries), b.Overlaps})
		case "build":
			if *outPath == "" {
				*outPath = "dist/" + b.Version
			}
			if err = b.Write(*outPath); err != nil {
				return err
			}
			fmt.Fprintln(out, *outPath)
			return nil
		case "render":
			if *base == "" || *outPath == "" || *bundlePath == "" {
				return fmt.Errorf("render requires --base, --bundle-path and --out")
			}
			data, err := os.ReadFile(*base)
			if err != nil {
				return err
			}
			data, err = b.Render(data, *bundlePath)
			if err != nil {
				return err
			}
			if err = app.AtomicWrite(*outPath, data, 0600); err != nil {
				return err
			}
			fmt.Fprintln(out, *outPath)
			return nil
		case "match":
			m, err := b.MatchDomain(*host)
			if err != nil {
				return err
			}
			return emit(m)
		}
	case "import", "probe", "analyze", "report", "serve", "collect", "dashboard":
		c, err := config.Load(*runtimePath)
		if err != nil {
			return err
		}
		db, err := store.Open(c.Database)
		if err != nil {
			return err
		}
		defer db.Close()
		switch cmd {
		case "import":
			if len(f.Args()) == 0 {
				return fmt.Errorf("import requires JSONL file paths")
			}
			for _, path := range f.Args() {
				file, err := os.Open(path)
				if err != nil {
					return err
				}
				n, err := db.ImportLegacy(ctx, c.Source, file)
				file.Close()
				if err != nil {
					return fmt.Errorf("%s: %w", path, err)
				}
				fmt.Fprintf(out, "%s: imported %d traffic rows\n", path, n)
			}
			return nil
		case "probe":
			r, err := probe.Run(ctx, c, db)
			if err != nil {
				return err
			}
			return emit(r)
		case "analyze", "report":
			if *since <= 0 {
				return fmt.Errorf("since must be positive")
			}
			if *format != "json" && *format != "markdown" {
				return fmt.Errorf("format must be json or markdown")
			}
			r, err := app.Report(ctx, c, db, *since)
			if err != nil {
				return err
			}
			var data []byte
			if *format == "markdown" {
				data = []byte(app.Markdown(r))
			} else {
				data, err = json.MarshalIndent(r, "", "  ")
				if err != nil {
					return err
				}
				data = append(data, '\n')
			}
			if *outPath != "" {
				return app.AtomicWrite(*outPath, data, 0600)
			}
			_, err = out.Write(data)
			return err
		case "serve":
			return app.Serve(ctx, c, db, slog.Default())
		case "dashboard":
			return app.DashboardServer(c, db, nil, slog.Default()).Run(ctx)
		case "collect":
			if c.Controller == "" {
				return fmt.Errorf("controller is required")
			}
			secret, err := c.Secret()
			if err != nil {
				return err
			}
			cc := collect.Collector{BaseURL: c.Controller, Secret: secret, Source: c.Source, DB: db, Interval: config.Duration(c.PollInterval), Logger: slog.Default()}
			return app.CollectOnly(ctx, &cc)
		}
	default:
		return fmt.Errorf("unknown command %q; run mihomo-policy help", strings.TrimSpace(cmd))
	}
	return nil
}
