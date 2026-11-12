package collect

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"mihomo-policy/internal/policy"
	"mihomo-policy/internal/store"
)

func ID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

type Connection struct {
	ID          string   `json:"id"`
	Upload      int64    `json:"upload"`
	Download    int64    `json:"download"`
	Chains      []string `json:"chains"`
	Rule        string   `json:"rule"`
	RulePayload string   `json:"rulePayload"`
	Metadata    struct {
		Host            string `json:"host"`
		InboundName     string `json:"inboundName"`
		SourceIP        string `json:"sourceIP"`
		Network         string `json:"network"`
		DestinationIP   string `json:"destinationIP"`
		DestinationPort string `json:"destinationPort"`
	} `json:"metadata"`
}
type Snapshot struct {
	Connections []Connection `json:"connections"`
}

// Mihomo serializes an idle connection set as null on some core versions.
// A missing field is still a malformed API response, rather than an idle sample.
func (s *Snapshot) UnmarshalJSON(data []byte) error {
	var raw struct {
		Connections json.RawMessage `json:"connections"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if len(raw.Connections) == 0 {
		return fmt.Errorf("missing connections field")
	}
	if string(raw.Connections) == "null" {
		s.Connections = []Connection{}
		return nil
	}
	return json.Unmarshal(raw.Connections, &s.Connections)
}

type Tracker struct{ previous map[string]Connection }

func (t *Tracker) Reset() { t.previous = nil }
func (t *Tracker) Delta(s Snapshot) []store.TrafficRow {
	next := make(map[string]Connection, len(s.Connections))
	var rows []store.TrafficRow
	for _, c := range s.Connections {
		if c.ID == "" || c.Upload < 0 || c.Download < 0 {
			continue
		}
		next[c.ID] = c
		if t.previous == nil {
			continue
		}
		if strings.HasPrefix(c.Metadata.InboundName, "probe-") {
			continue
		}
		up, down := c.Upload, c.Download
		if prev, ok := t.previous[c.ID]; ok {
			if up < prev.Upload || down < prev.Download {
				continue
			}
			up -= prev.Upload
			down -= prev.Download
		}
		if up == 0 && down == 0 {
			continue
		}
		route, node := "", ""
		if len(c.Chains) > 0 {
			node = c.Chains[0]
			chain := slices.Clone(c.Chains)
			slices.Reverse(chain)
			route = strings.Join(chain, " → ")
		}
		rows = append(rows, store.TrafficRow{Host: c.Metadata.Host, Route: route, Node: node, Rule: c.Rule + "," + c.RulePayload, Up: up, Down: down, Client: c.Metadata.SourceIP, Network: c.Metadata.Network, DestinationIP: c.Metadata.DestinationIP, DestinationPort: c.Metadata.DestinationPort})
	}
	t.previous = next
	return rows
}

type Collector struct {
	BaseURL, Secret, Source string
	DB                      *store.DB
	Interval                time.Duration
	Logger                  *slog.Logger
	Health                  *Health
}

func (c *Collector) request(ctx context.Context, path string) (*http.Request, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+path, nil)
	if err == nil && c.Secret != "" {
		r.Header.Set("Authorization", "Bearer "+c.Secret)
	}
	return r, err
}
func (c *Collector) Poll(ctx context.Context) error {
	// No environment proxy: controller traffic must remain on the configured local path.
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	var tracker Tracker
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	for {
		active := 0
		err := func() error {
			req, err := c.request(ctx, "/connections")
			if err != nil {
				return err
			}
			r, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("controller request failed")
			}
			defer r.Body.Close()
			if r.StatusCode != 200 {
				return fmt.Errorf("controller returned HTTP %d", r.StatusCode)
			}
			var s Snapshot
			if err = json.NewDecoder(http.MaxBytesReader(nil, r.Body, 32<<20)).Decode(&s); err != nil {
				return fmt.Errorf("invalid connections response: %w", err)
			}
			if s.Connections == nil {
				return fmt.Errorf("connections response lacks a non-null connections array")
			}
			active = len(s.Connections)
			return c.DB.AddTraffic(ctx, ID(), c.Source, time.Now().UTC(), tracker.Delta(s))
		}()
		c.Health.sample(err, active)
		if err != nil {
			tracker.Reset()
			if ctx.Err() == nil {
				c.Logger.Warn("connection sample failed; next sample is baseline", "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

var targetPattern = regexp.MustCompile(`-->\s+([A-Za-z0-9.-]+):[0-9]+`)

func Failure(message string) (host, kind string) {
	if m := targetPattern.FindStringSubmatch(message); len(m) == 2 {
		host, _ = policy.Domain(m[1])
	}
	s := strings.ToLower(message)
	switch {
	case strings.Contains(s, "no such host") || strings.Contains(s, "dns resolve") || strings.Contains(s, "dns lookup"):
		kind = "dns"
	case strings.Contains(s, "certificate") || strings.Contains(s, "tls"):
		kind = "tls"
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline exceeded"):
		kind = "timeout"
	case strings.Contains(s, "refused"):
		kind = "refused"
	case strings.Contains(s, "unreachable"):
		kind = "unreachable"
	default:
		kind = "unknown"
	}
	return
}

func (c *Collector) Logs(ctx context.Context) error {
	// Some core versions do not flush response headers until the first log event.
	// Keep idle streams open, while bounding connection and TLS establishment.
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for {
		err := func() error {
			req, err := c.request(ctx, "/logs?level=warning")
			if err != nil {
				return err
			}
			r, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("log stream request failed")
			}
			defer r.Body.Close()
			if r.StatusCode != 200 {
				return fmt.Errorf("logs returned HTTP %d", r.StatusCode)
			}
			c.Health.logs(true, false)
			s := bufio.NewScanner(r.Body)
			s.Buffer(make([]byte, 4096), 1<<20)
			for s.Scan() {
				var event struct {
					Type    string `json:"type"`
					Payload string `json:"payload"`
					Level   string `json:"level"`
					Message string `json:"message"`
				}
				if err = json.Unmarshal(s.Bytes(), &event); err != nil {
					return fmt.Errorf("invalid log stream JSON")
				}
				if event.Type == "" {
					event.Type = event.Level
				}
				if event.Payload == "" {
					event.Payload = event.Message
				}
				if event.Type != "warning" && event.Type != "error" {
					continue
				}
				c.Health.logs(true, true)
				host, kind := Failure(event.Payload)
				// Retain classifications only. Raw payloads may contain credentials or URLs.
				if err = c.DB.AddFailure(ctx, ID(), c.Source, host, kind, event.Type, time.Now().UTC()); err != nil {
					return err
				}
			}
			return s.Err()
		}()
		c.Health.logs(false, false)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.Logger.Warn("log stream disconnected; reconnecting", "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}
