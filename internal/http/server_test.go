package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

// mockConsumer implements ConsumerStatus for testing.
type mockConsumer struct {
	joined bool
}

func (m *mockConsumer) IsJoined() bool { return m.joined }

// mockDBChecker implements DBChecker for testing.
type mockDBChecker struct {
	err error
}

func (m *mockDBChecker) Ping(_ context.Context) error { return m.err }

func newTestServer(stateJoined, historyJoined bool) *Server {
	logger := zap.NewNop()
	sc := &mockConsumer{joined: stateJoined}
	hc := &mockConsumer{joined: historyJoined}
	// nil pool — readyz will report postgres as "error".
	return NewServer(":0", nil, sc, hc, logger)
}

func newTestServerWithDB(db DBChecker, stateJoined, historyJoined bool) *Server {
	s := newTestServer(stateJoined, historyJoined)
	s.dbChecker = db
	return s
}

func TestHealthz_AlwaysOK(t *testing.T) {
	s := newTestServer(false, false)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	s.handleHealthz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected status 'ok', got '%s'", body["status"])
	}
}

func TestHealthz_ContentType(t *testing.T) {
	s := newTestServer(false, false)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	s.handleHealthz(w, req)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got '%s'", ct)
	}
}

func TestReadyz_NotReady_ConsumersNotJoined(t *testing.T) {
	s := newTestServer(false, false)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()

	s.handleReadyz(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["status"] != "not_ready" {
		t.Errorf("expected status 'not_ready', got '%v'", body["status"])
	}

	checks := body["checks"].(map[string]any)
	if checks["kafka_state"] != "not_joined" {
		t.Errorf("expected kafka_state 'not_joined', got '%v'", checks["kafka_state"])
	}
	if checks["kafka_history"] != "not_joined" {
		t.Errorf("expected kafka_history 'not_joined', got '%v'", checks["kafka_history"])
	}
	if checks["postgres"] != "error" {
		t.Errorf("expected postgres 'error' (nil pool), got '%v'", checks["postgres"])
	}
}

func TestReadyz_ConsumersJoinedButDBDown(t *testing.T) {
	s := newTestServer(true, true)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()

	s.handleReadyz(w, req)

	// Consumers joined but pool is nil → postgres check fails → 503.
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (DB down), got %d", w.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	checks := body["checks"].(map[string]any)
	if checks["kafka_state"] != "ok" {
		t.Errorf("expected kafka_state 'ok', got '%v'", checks["kafka_state"])
	}
	if checks["kafka_history"] != "ok" {
		t.Errorf("expected kafka_history 'ok', got '%v'", checks["kafka_history"])
	}
	if checks["postgres"] != "error" {
		t.Errorf("expected postgres 'error', got '%v'", checks["postgres"])
	}
}

func TestReadyz_ContentType(t *testing.T) {
	s := newTestServer(false, false)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()

	s.handleReadyz(w, req)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got '%s'", ct)
	}
}

func TestReadyz_AllHealthy(t *testing.T) {
	db := &mockDBChecker{err: nil}
	s := newTestServerWithDB(db, true, true)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()

	s.handleReadyz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["status"] != "ready" {
		t.Errorf("expected status 'ready', got '%v'", body["status"])
	}

	checks := body["checks"].(map[string]any)
	if checks["postgres"] != "ok" {
		t.Errorf("expected postgres 'ok', got '%v'", checks["postgres"])
	}
	if checks["kafka_state"] != "ok" {
		t.Errorf("expected kafka_state 'ok', got '%v'", checks["kafka_state"])
	}
	if checks["kafka_history"] != "ok" {
		t.Errorf("expected kafka_history 'ok', got '%v'", checks["kafka_history"])
	}
}
