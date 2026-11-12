package collect

import (
	"sync"
	"time"
)

type HealthSnapshot struct {
	StartedAt         time.Time  `json:"started_at"`
	LastSample        *time.Time `json:"last_sample"`
	LastSampleError   string     `json:"last_sample_error,omitempty"`
	Samples           uint64     `json:"samples"`
	SampleErrors      uint64     `json:"sample_errors"`
	ActiveConnections int        `json:"active_connections"`
	LogsConnected     bool       `json:"logs_connected"`
	LastLogEvent      *time.Time `json:"last_log_event"`
}
type Health struct {
	mu    sync.RWMutex
	state HealthSnapshot
}

func NewHealth() *Health { return &Health{state: HealthSnapshot{StartedAt: time.Now().UTC()}} }
func (h *Health) Snapshot() HealthSnapshot {
	if h == nil {
		return HealthSnapshot{}
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.state
}
func (h *Health) sample(err error, active int) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err != nil {
		h.state.SampleErrors++
		h.state.LastSampleError = err.Error()
		return
	}
	now := time.Now().UTC()
	h.state.LastSample = &now
	h.state.Samples++
	h.state.LastSampleError = ""
	h.state.ActiveConnections = active
}
func (h *Health) logs(connected bool, event bool) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state.LogsConnected = connected
	if event {
		now := time.Now().UTC()
		h.state.LastLogEvent = &now
	}
}
