package store

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mihomo-policy/internal/policy"
	_ "modernc.org/sqlite"
)

type DB struct{ *sql.DB }

func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	// Pre-create with private permissions; SQLite sidecars inherit this mode.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	d := &DB{db}
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS traffic (
 record_id TEXT NOT NULL, row_id INTEGER NOT NULL, source TEXT NOT NULL,
 at INTEGER NOT NULL, host TEXT NOT NULL, route TEXT NOT NULL, node TEXT NOT NULL,
 rule TEXT NOT NULL, up INTEGER NOT NULL, down INTEGER NOT NULL,
 PRIMARY KEY(record_id,row_id));
CREATE INDEX IF NOT EXISTS traffic_source_at ON traffic(source,at);
CREATE TABLE IF NOT EXISTS probes (
 run_id TEXT NOT NULL, source TEXT NOT NULL, at INTEGER NOT NULL,
 host TEXT NOT NULL, target TEXT NOT NULL, route TEXT NOT NULL,
 ok INTEGER NOT NULL, reachable INTEGER NOT NULL, status INTEGER NOT NULL,
 duration_ms INTEGER NOT NULL, phase TEXT NOT NULL, error TEXT NOT NULL,
 PRIMARY KEY(run_id,target,route));
CREATE INDEX IF NOT EXISTS probes_source_host_at ON probes(source,host,at);
CREATE TABLE IF NOT EXISTS failures (
 id TEXT PRIMARY KEY, source TEXT NOT NULL, at INTEGER NOT NULL,
 host TEXT NOT NULL, kind TEXT NOT NULL, level TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS failures_source_at ON failures(source,at);
CREATE TABLE IF NOT EXISTS tasks(name TEXT PRIMARY KEY, last_success INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS leases(name TEXT PRIMARY KEY, owner TEXT NOT NULL, expires INTEGER NOT NULL);
`)
	if err != nil {
		db.Close()
		return nil, err
	}
	if err = d.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return d, nil
}

func (d *DB) migrate() error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version < 2 {
		for _, statement := range []string{
			`ALTER TABLE probes ADD COLUMN context_id TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE traffic ADD COLUMN client TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE traffic ADD COLUMN network TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE traffic ADD COLUMN destination_ip TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE traffic ADD COLUMN destination_port TEXT NOT NULL DEFAULT ''`,
			`PRAGMA user_version=2`,
		} {
			if _, err = tx.Exec(statement); err != nil {
				return err
			}
		}
	}
	if version < 3 {
		for _, statement := range []string{
			`CREATE TABLE IF NOT EXISTS direct_tests (
				source TEXT NOT NULL,
				domain TEXT NOT NULL,
				at INTEGER NOT NULL,
				passed INTEGER NOT NULL,
				status INTEGER NOT NULL,
				duration_ms INTEGER NOT NULL,
				resolved_ip TEXT NOT NULL DEFAULT '',
				error TEXT NOT NULL DEFAULT '',
				detail_json TEXT NOT NULL DEFAULT '',
				PRIMARY KEY(source, domain)
			)`,
			`PRAGMA user_version=3`,
		} {
			if _, err = tx.Exec(statement); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

type TrafficRow struct {
	Host            string
	Route           string
	Node            string
	Rule            string
	Client          string
	Network         string
	DestinationIP   string
	DestinationPort string
	Up              int64 `json:"up"`
	Down            int64 `json:"down"`
}
type LegacyRecord struct {
	Start string       `json:"start"`
	End   string       `json:"end"`
	Rows  []TrafficRow `json:"rows"`
}

func timestamp(s string) (time.Time, error) { return time.Parse(time.RFC3339Nano, s) }

// ImportLegacy is transactional and idempotent, including repeat imports under new filenames.
func (d *DB) ImportLegacy(ctx context.Context, source string, r io.Reader) (int64, error) {
	if strings.TrimSpace(source) == "" {
		return 0, fmt.Errorf("source is required")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 65536), 16*1024*1024)
	var count int64
	line := 0
	for s.Scan() {
		line++
		raw := s.Bytes()
		if len(strings.TrimSpace(string(raw))) == 0 {
			continue
		}
		var rec LegacyRecord
		if err = json.Unmarshal(raw, &rec); err != nil {
			return 0, fmt.Errorf("line %d: %w", line, err)
		}
		at, err := timestamp(rec.End)
		if err != nil {
			return 0, fmt.Errorf("line %d end time: %w", line, err)
		}
		start, err := timestamp(rec.Start)
		if err != nil || start.After(at) {
			return 0, fmt.Errorf("line %d invalid start time", line)
		}
		// Canonical JSON ensures whitespace changes do not cause duplicate imports.
		var canonical any
		if err = json.Unmarshal(raw, &canonical); err != nil {
			return 0, err
		}
		c, _ := json.Marshal(canonical)
		hash := sha256.Sum256(append([]byte(source+"\x00"), c...))
		id := hex.EncodeToString(hash[:])
		for i, row := range rec.Rows {
			if row.Up < 0 || row.Down < 0 {
				return 0, fmt.Errorf("line %d has negative byte counters", line)
			}
			host, e := policy.Domain(row.Host)
			if e != nil {
				continue
			}
			res, e := tx.ExecContext(ctx, `INSERT OR IGNORE INTO traffic(record_id,row_id,source,at,host,route,node,rule,up,down) VALUES(?,?,?,?,?,?,?,?,?,?)`, id, i, source, at.Unix(), host, row.Route, row.Node, row.Rule, row.Up, row.Down)
			if e != nil {
				return 0, e
			}
			n, _ := res.RowsAffected()
			count += n
		}
	}
	if err = s.Err(); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

func (d *DB) AddTraffic(ctx context.Context, id, source string, at time.Time, rows []TrafficRow) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for i, row := range rows {
		host, e := policy.Domain(row.Host)
		if e != nil {
			continue
		}
		if row.Up < 0 || row.Down < 0 {
			return fmt.Errorf("negative byte counters")
		}
		if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO traffic(record_id,row_id,source,at,host,route,node,rule,up,down,client,network,destination_ip,destination_port) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, i, source, at.Unix(), host, row.Route, row.Node, row.Rule, row.Up, row.Down, row.Client, row.Network, row.DestinationIP, row.DestinationPort); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type Probe struct {
	RunID      string    `json:"run_id"`
	Source     string    `json:"source"`
	At         time.Time `json:"at"`
	Host       string    `json:"host"`
	Target     string    `json:"target"`
	Route      string    `json:"route"`
	OK         bool      `json:"ok"`
	Reachable  bool      `json:"reachable"`
	Status     int       `json:"status"`
	DurationMS int64     `json:"duration_ms"`
	Phase      string    `json:"phase"`
	Error      string    `json:"error,omitempty"`
	ContextID  string    `json:"context_id"`
}

func (d *DB) AddProbePair(ctx context.Context, rows []Probe) error {
	if len(rows) != 2 || rows[0].RunID == "" || rows[0].RunID != rows[1].RunID || rows[0].Target != rows[1].Target || rows[0].Source != rows[1].Source || rows[0].Host != rows[1].Host || rows[0].ContextID != rows[1].ContextID || !((rows[0].Route == "DIRECT" && rows[1].Route == "PROXY") || (rows[0].Route == "PROXY" && rows[1].Route == "DIRECT")) {
		return fmt.Errorf("expected a paired DIRECT/PROXY probe")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, r := range rows {
		if _, err = tx.ExecContext(ctx, `INSERT INTO probes(run_id,source,at,host,target,route,ok,reachable,status,duration_ms,phase,error,context_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, r.RunID, r.Source, r.At.Unix(), r.Host, r.Target, r.Route, r.OK, r.Reachable, r.Status, r.DurationMS, r.Phase, r.Error, r.ContextID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) AddFailure(ctx context.Context, id, source, host, kind, level string, at time.Time) error {
	_, err := d.ExecContext(ctx, `INSERT OR IGNORE INTO failures VALUES(?,?,?,?,?,?)`, id, source, at.Unix(), host, kind, level)
	return err
}

type HostStats struct {
	Host           string           `json:"host"`
	Up             int64            `json:"up"`
	Down           int64            `json:"down"`
	SampleRows     int64            `json:"sample_rows"`
	Failures       int64            `json:"failures"`
	ObservedRoutes []string         `json:"observed_routes"`
	FirstSeen      *time.Time       `json:"first_seen"`
	LastSeen       *time.Time       `json:"last_seen"`
	LastFailure    *time.Time       `json:"last_failure"`
	Routes         []RouteStats     `json:"routes"`
	FailureKinds   map[string]int64 `json:"failure_kinds"`
	Dimensions     []DimensionStats `json:"dimensions"`
}

type RouteStats struct {
	Route      string    `json:"route"`
	Node       string    `json:"node"`
	Rule       string    `json:"rule"`
	Up         int64     `json:"up"`
	Down       int64     `json:"down"`
	SampleRows int64     `json:"sample_rows"`
	LastSeen   time.Time `json:"last_seen"`
}

type DimensionStats struct {
	Client        string `json:"client"`
	Network       string `json:"network"`
	AddressFamily string `json:"address_family"`
	Port          string `json:"port"`
	Bytes         int64  `json:"bytes"`
}

func (d *DB) Hosts(ctx context.Context, source string, since time.Time, until ...time.Time) ([]HostStats, error) {
	// Keep totals and breakdowns on the same SQLite snapshot while collection runs.
	tx, err := d.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	end := endTime(until)
	rows, err := tx.QueryContext(ctx, `SELECT host,SUM(up),SUM(down),COUNT(*),MIN(at),MAX(at) FROM traffic WHERE source=? AND at>=? AND at<=? GROUP BY host`, source, since.Unix(), end)
	if err != nil {
		return nil, err
	}
	m := map[string]*HostStats{}
	for rows.Next() {
		var s HostStats
		var first, last int64
		if err = rows.Scan(&s.Host, &s.Up, &s.Down, &s.SampleRows, &first, &last); err != nil {
			rows.Close()
			return nil, err
		}
		f, l := time.Unix(first, 0).UTC(), time.Unix(last, 0).UTC()
		s.FirstSeen, s.LastSeen = &f, &l
		m[s.Host] = &s
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT host,kind,COUNT(*),MAX(at) FROM failures WHERE source=? AND at>=? AND at<=? AND host<>'' GROUP BY host,kind`, source, since.Unix(), end)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var host, kind string
		var n, last int64
		if err = rows.Scan(&host, &kind, &n, &last); err != nil {
			rows.Close()
			return nil, err
		}
		if m[host] == nil {
			m[host] = &HostStats{Host: host}
		}
		h := m[host]
		h.Failures += n
		if h.FailureKinds == nil {
			h.FailureKinds = map[string]int64{}
		}
		h.FailureKinds[kind] += n
		at := time.Unix(last, 0).UTC()
		if h.LastFailure == nil || at.After(*h.LastFailure) {
			h.LastFailure = &at
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT host,route,node,rule,SUM(up),SUM(down),COUNT(*),MAX(at) FROM traffic WHERE source=? AND at>=? AND at<=? GROUP BY host,route,node,rule ORDER BY SUM(up)+SUM(down) DESC,route,node,rule`, source, since.Unix(), end)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var host string
		var route RouteStats
		var last int64
		if err = rows.Scan(&host, &route.Route, &route.Node, &route.Rule, &route.Up, &route.Down, &route.SampleRows, &last); err != nil {
			rows.Close()
			return nil, err
		}
		if m[host] != nil {
			route.LastSeen = time.Unix(last, 0).UTC()
			m[host].Routes = append(m[host].Routes, route)
			if !contains(m[host].ObservedRoutes, route.Route) {
				m[host].ObservedRoutes = append(m[host].ObservedRoutes, route.Route)
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT host,client,network,CASE WHEN destination_ip='' THEN 'unknown' WHEN instr(destination_ip,':')>0 THEN 'IPv6' ELSE 'IPv4' END,destination_port,SUM(up)+SUM(down) FROM traffic WHERE source=? AND at>=? AND at<=? GROUP BY host,client,network,4,destination_port ORDER BY SUM(up)+SUM(down) DESC,host,client,network,4,destination_port`, source, since.Unix(), end)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var host string
		var dim DimensionStats
		if err = rows.Scan(&host, &dim.Client, &dim.Network, &dim.AddressFamily, &dim.Port, &dim.Bytes); err != nil {
			rows.Close()
			return nil, err
		}
		if m[host] != nil {
			m[host].Dimensions = append(m[host].Dimensions, dim)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	var result []HostStats
	for _, s := range m {
		result = append(result, *s)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func endTime(until []time.Time) int64 {
	if len(until) > 0 {
		return until[0].Unix()
	}
	return 1<<63 - 1
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func (d *DB) Probes(ctx context.Context, source string, since time.Time, until ...time.Time) ([]Probe, error) {
	rows, err := d.QueryContext(ctx, `SELECT run_id,source,at,host,target,route,ok,reachable,status,duration_ms,phase,error,context_id FROM probes WHERE source=? AND at>=? AND at<=? ORDER BY at,run_id,target,route`, source, since.Unix(), endTime(until))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Probe
	for rows.Next() {
		var p Probe
		var at int64
		if err = rows.Scan(&p.RunID, &p.Source, &at, &p.Host, &p.Target, &p.Route, &p.OK, &p.Reachable, &p.Status, &p.DurationMS, &p.Phase, &p.Error, &p.ContextID); err != nil {
			return nil, err
		}
		p.At = time.Unix(at, 0).UTC()
		out = append(out, p)
	}
	return out, rows.Err()
}

func (d *DB) LastTask(ctx context.Context, name string) (time.Time, error) {
	var at int64
	err := d.QueryRowContext(ctx, `SELECT last_success FROM tasks WHERE name=?`, name).Scan(&at)
	if err == sql.ErrNoRows {
		return time.Time{}, nil
	}
	return time.Unix(at, 0), err
}
func (d *DB) MarkTask(ctx context.Context, name string, at time.Time) error {
	_, err := d.ExecContext(ctx, `INSERT INTO tasks VALUES(?,?) ON CONFLICT(name) DO UPDATE SET last_success=excluded.last_success`, name, at.Unix())
	return err
}
func (d *DB) Prune(ctx context.Context, before time.Time) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"traffic", "failures", "probes"} {
		if _, err = tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE at<?`, before.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Lease prevents two collectors from double-counting the same source.
func (d *DB) Lease(ctx context.Context, name, owner string, now time.Time, ttl time.Duration) (bool, error) {
	r, err := d.ExecContext(ctx, `INSERT INTO leases VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET owner=excluded.owner,expires=excluded.expires WHERE leases.expires<? OR leases.owner=excluded.owner`, name, owner, now.Add(ttl).Unix(), now.Unix())
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}
func (d *DB) ReleaseLease(ctx context.Context, name, owner string) error {
	_, err := d.ExecContext(ctx, `DELETE FROM leases WHERE name=? AND owner=?`, name, owner)
	return err
}

type DirectHostResult struct {
	Host       string `json:"host"`
	ResolvedIP string `json:"resolved_ip,omitempty"`
	Passed     bool   `json:"passed"`
	Status     int    `json:"status,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Phase      string `json:"phase,omitempty"`
	Error      string `json:"error,omitempty"`
}

type DirectTestRecord struct {
	Domain     string             `json:"domain"`
	At         time.Time          `json:"at"`
	Passed     bool               `json:"passed"`
	Status     int                `json:"status,omitempty"`
	DurationMS int64              `json:"duration_ms"`
	ResolvedIP string             `json:"resolved_ip,omitempty"`
	Error      string             `json:"error,omitempty"`
	Hosts      []DirectHostResult `json:"hosts,omitempty"`
}

func (d *DB) SaveDirectTest(ctx context.Context, source string, rec DirectTestRecord) error {
	domain, err := policy.Domain(rec.Domain)
	if err != nil {
		return err
	}
	detail, err := json.Marshal(rec.Hosts)
	if err != nil {
		return err
	}
	if rec.At.IsZero() {
		rec.At = time.Now().UTC()
	}
	_, err = d.ExecContext(ctx, `INSERT INTO direct_tests(source,domain,at,passed,status,duration_ms,resolved_ip,error,detail_json)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(source,domain) DO UPDATE SET
			at=excluded.at,
			passed=excluded.passed,
			status=excluded.status,
			duration_ms=excluded.duration_ms,
			resolved_ip=excluded.resolved_ip,
			error=excluded.error,
			detail_json=excluded.detail_json`,
		source, domain, rec.At.Unix(), rec.Passed, rec.Status, rec.DurationMS, rec.ResolvedIP, rec.Error, string(detail))
	return err
}

func (d *DB) DirectTests(ctx context.Context, source string) (map[string]DirectTestRecord, error) {
	rows, err := d.QueryContext(ctx, `SELECT domain,at,passed,status,duration_ms,resolved_ip,error,detail_json FROM direct_tests WHERE source=?`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]DirectTestRecord{}
	for rows.Next() {
		var r DirectTestRecord
		var at int64
		var detail string
		if err := rows.Scan(&r.Domain, &at, &r.Passed, &r.Status, &r.DurationMS, &r.ResolvedIP, &r.Error, &detail); err != nil {
			return nil, err
		}
		r.At = time.Unix(at, 0).UTC()
		if detail != "" {
			_ = json.Unmarshal([]byte(detail), &r.Hosts)
		}
		out[r.Domain] = r
	}
	return out, rows.Err()
}
