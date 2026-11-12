package collect

import (
	"encoding/json"
	"testing"
)

func TestMihomoIdleNullIsValidButMissingFieldIsNot(t *testing.T) {
	for _, body := range []string{`{"connections":null}`, `{"connections":[]}`} {
		var s Snapshot
		if err := json.Unmarshal([]byte(body), &s); err != nil || s.Connections == nil || len(s.Connections) != 0 {
			t.Fatalf("idle sample %s: %+v %v", body, s, err)
		}
	}
	var s Snapshot
	if err := json.Unmarshal([]byte(`{"error":"unauthorized"}`), &s); err == nil {
		t.Fatal("accepted non-connection response")
	}
}

func conn(id string, up, down int64) Connection {
	c := Connection{ID: id, Upload: up, Download: down, Chains: []string{"node", "AI"}}
	c.Metadata.Host = "gemini.google.com"
	return c
}
func TestCounterDeltasAndReconnectBaseline(t *testing.T) {
	var tr Tracker
	if got := tr.Delta(Snapshot{[]Connection{conn("a", 100, 1000)}}); len(got) != 0 {
		t.Fatal("counted historical baseline")
	}
	got := tr.Delta(Snapshot{[]Connection{conn("a", 110, 1020), conn("b", 5, 8)}})
	if len(got) != 2 || got[0].Up != 10 || got[0].Down != 20 || got[1].Down != 8 {
		t.Fatalf("%+v", got)
	}
	if got := tr.Delta(Snapshot{[]Connection{conn("a", 1, 2)}}); len(got) != 0 {
		t.Fatal("counted reset")
	}
	tr.Reset()
	if got := tr.Delta(Snapshot{[]Connection{conn("a", 500, 500)}}); len(got) != 0 {
		t.Fatal("counted reconnection baseline")
	}
}
func TestFailureAttributionIsConservative(t *testing.T) {
	h, k := Failure("[TCP] dial failed client --> api.example.com:443 error: i/o timeout")
	if h != "api.example.com" || k != "timeout" {
		t.Fatalf("%s %s", h, k)
	}
	h, _ = Failure("subscription download failed: https://secret.example/token")
	if h != "" {
		t.Fatal("attributed arbitrary URL as destination")
	}
}
