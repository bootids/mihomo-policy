package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const record = `{"source":"old","start":"2026-11-10T00:00:00Z","end":"2026-11-10T00:01:00Z","samples":60,"rows":[{"Host":"Gemini.Google.Com","Route":"AI","Node":"test","Rule":"DOMAIN","up":10,"down":100}]}`

func openTest(t *testing.T) *DB {
	t.Helper()
	d, err := Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestUpgradeVersionOnePreservesDataAndCanReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.sqlite")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = old.Exec(`CREATE TABLE traffic(record_id TEXT,row_id INTEGER,source TEXT,at INTEGER,host TEXT,route TEXT,node TEXT,rule TEXT,up INTEGER,down INTEGER,PRIMARY KEY(record_id,row_id));
CREATE TABLE probes(run_id TEXT,source TEXT,at INTEGER,host TEXT,target TEXT,route TEXT,ok INTEGER,reachable INTEGER,status INTEGER,duration_ms INTEGER,phase TEXT,error TEXT,PRIMARY KEY(run_id,target,route));
INSERT INTO traffic VALUES('old',0,'home',1,'example.com','DIRECT','DIRECT','MATCH',1,41);
INSERT INTO probes VALUES('old','home',1,'example.com','health','DIRECT',1,1,200,12,'http','');
PRAGMA user_version=1;`)
	if err != nil {
		t.Fatal(err)
	}
	old.Close()
	for i := 0; i < 2; i++ {
		db, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		var version int
		if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 3 {
			t.Fatalf("migration: version=%d err=%v", version, err)
		}
		if i == 0 {
			if err := db.SaveDirectTest(context.Background(), "home", DirectTestRecord{
				Domain: "example.com", At: time.Unix(100, 0), Passed: true, Status: 200, DurationMS: 35,
			}); err != nil {
				t.Fatal(err)
			}
		} else {
			dts, err := db.DirectTests(context.Background(), "home")
			if err != nil || !dts["example.com"].Passed || dts["example.com"].DurationMS != 35 {
				t.Fatalf("lost direct_tests across reopen: %+v %v", dts, err)
			}
		}
		hs, err := db.Hosts(context.Background(), "home", time.Time{})
		if err != nil || len(hs) != 1+i {
			t.Fatalf("lost legacy traffic: %+v %v", hs, err)
		}
		found := false
		for _, h := range hs {
			if h.Host == "example.com" {
				found = true
				if h.Down != 41 || h.Dimensions[0].Client != "" {
					t.Fatalf("changed legacy traffic: %+v", h)
				}
			}
		}
		if !found {
			t.Fatal("legacy host missing")
		}
		ps, err := db.Probes(context.Background(), "home", time.Time{})
		if err != nil || len(ps) != 1 || ps[0].ContextID != "" {
			t.Fatalf("invented legacy probe identity: %+v %v", ps, err)
		}
		if i == 0 {
			if _, err := db.ImportLegacy(context.Background(), "home", strings.NewReader(record)); err != nil {
				t.Fatal(err)
			}
		}
		db.Close()
	}
}

func TestHostBreakdownsPreserveRouteAndFailureDimensions(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Second)
	rows := []TrafficRow{
		{Host: "example.com", Route: "DIRECT", Node: "DIRECT", Rule: "DOMAIN,example.com", Up: 10, Down: 90, Client: "10.0.0.2", Network: "tcp", DestinationIP: "1.1.1.1", DestinationPort: "443"},
		{Host: "example.com", Route: "AI → node-A", Node: "node-A", Rule: "RULE-SET,ai", Up: 20, Down: 180, Client: "10.0.0.3", Network: "udp", DestinationIP: "2606:4700::1", DestinationPort: "443"},
	}
	if err := db.AddTraffic(ctx, "mixed", "home", at, rows); err != nil {
		t.Fatal(err)
	}
	if err := db.AddTraffic(ctx, "other-source", "office", at, rows); err != nil {
		t.Fatal(err)
	}
	for i, kind := range []string{"dns", "timeout", "dns"} {
		if err := db.AddFailure(ctx, fmt.Sprint(i), "home", "example.com", kind, "warning", at.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	hs, err := db.Hosts(ctx, "home", at.Add(-time.Second))
	if err != nil || len(hs) != 1 {
		t.Fatalf("%+v %v", hs, err)
	}
	h := hs[0]
	if h.Up+h.Down != 300 || h.Failures != 3 || h.FailureKinds["dns"] != 2 || len(h.Routes) != 2 || h.Routes[0].Node != "node-A" || len(h.Dimensions) != 2 || h.Dimensions[0].AddressFamily != "IPv6" || h.FirstSeen == nil || !h.LastFailure.Equal(at.Add(2*time.Second)) {
		t.Fatalf("lost dimensions: %+v", h)
	}
}

func TestProbePairRejectsMismatchedContextOrSource(t *testing.T) {
	db := openTest(t)
	for _, field := range []string{"source", "context", "route"} {
		pair := []Probe{{RunID: "run", Source: "home", Host: "example.com", Target: "health", Route: "DIRECT", ContextID: "one"}, {RunID: "run", Source: "home", Host: "example.com", Target: "health", Route: "PROXY", ContextID: "one"}}
		switch field {
		case "source":
			pair[1].Source = "office"
		case "context":
			pair[1].ContextID = "two"
		case "route":
			pair[1].Route = "OTHER"
		}
		if err := db.AddProbePair(context.Background(), pair); err == nil {
			t.Fatalf("accepted mismatched %s", field)
		}
	}
}
func TestImportIdempotentAndSourceScoped(t *testing.T) {
	d := openTest(t)
	ctx := context.Background()
	for i, want := range []int64{1, 0} {
		n, err := d.ImportLegacy(ctx, "home", strings.NewReader(record))
		if err != nil || n != want {
			t.Fatalf("iteration %d: %d %v", i, n, err)
		}
	}
	d.ImportLegacy(ctx, "office", strings.NewReader(record))
	stats, err := d.Hosts(ctx, "home", time.Time{})
	if err != nil || len(stats) != 1 || stats[0].Down != 100 || stats[0].SampleRows != 1 {
		t.Fatalf("%+v %v", stats, err)
	}
}
func TestImportRollsBackOnMalformedLaterLine(t *testing.T) {
	d := openTest(t)
	ctx := context.Background()
	if _, err := d.ImportLegacy(ctx, "home", strings.NewReader(record+"\n{broken")); err == nil {
		t.Fatal("accepted broken file")
	}
	hs, _ := d.Hosts(ctx, "home", time.Time{})
	if len(hs) != 0 {
		t.Fatal("partial import committed")
	}
}
func TestPruningDoesNotLoseNewData(t *testing.T) {
	d := openTest(t)
	ctx := context.Background()
	d.ImportLegacy(ctx, "home", strings.NewReader(record))
	d.AddTraffic(ctx, "new", "home", time.Now(), []TrafficRow{{Host: "new.example", Down: 42}})
	if err := d.Prune(ctx, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	hs, _ := d.Hosts(ctx, "home", time.Time{})
	if len(hs) != 1 || hs[0].Host != "new.example" {
		t.Fatalf("%+v", hs)
	}
}

func TestCollectorLeaseExclusionAndExpiry(t *testing.T) {
	d := openTest(t)
	ctx := context.Background()
	now := time.Now()
	ok, err := d.Lease(ctx, "collector:home", "a", now, 30*time.Second)
	if err != nil || !ok {
		t.Fatalf("first lease: %t %v", ok, err)
	}
	ok, err = d.Lease(ctx, "collector:home", "b", now, 30*time.Second)
	if err != nil || ok {
		t.Fatalf("duplicate collector admitted: %t %v", ok, err)
	}
	ok, err = d.Lease(ctx, "collector:home", "b", now.Add(31*time.Second), 30*time.Second)
	if err != nil || !ok {
		t.Fatalf("expired lease not recovered: %t %v", ok, err)
	}
}
