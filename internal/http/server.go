package http

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// ConsumerStatus is an interface for checking Kafka consumer join state.
type ConsumerStatus interface {
	IsJoined() bool
}

// DBChecker abstracts the database health check for testability.
type DBChecker interface {
	Ping(ctx context.Context) error
}

type Server struct {
	srv             *http.Server
	pool            *pgxpool.Pool
	dbChecker       DBChecker
	stateConsumer   ConsumerStatus
	historyConsumer ConsumerStatus
	logger          *zap.Logger
}

func NewServer(addr string, pool *pgxpool.Pool, stateConsumer, historyConsumer ConsumerStatus, logger *zap.Logger) *Server {
	s := &Server{
		pool:            pool,
		stateConsumer:   stateConsumer,
		historyConsumer: historyConsumer,
		logger:          logger,
	}
	if pool != nil {
		s.dbChecker = pool
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.Handle("/metrics", promhttp.Handler())

	s.srv = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return s
}

func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return err
	}
	s.logger.Info("HTTP server listening", zap.String("addr", s.srv.Addr))
	go func() {
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTP server error", zap.Error(err))
		}
	}()
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	allOK := true

	// Check PostgreSQL.
	if s.dbChecker != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if err := s.dbChecker.Ping(ctx); err != nil {
			checks["postgres"] = "error"
			allOK = false
		} else {
			checks["postgres"] = "ok"
		}
	} else {
		checks["postgres"] = "error"
		allOK = false
	}

	// Check Kafka state consumer.
	if s.stateConsumer != nil && s.stateConsumer.IsJoined() {
		checks["kafka_state"] = "ok"
	} else {
		checks["kafka_state"] = "not_joined"
		allOK = false
	}

	// Check Kafka history consumer.
	if s.historyConsumer != nil && s.historyConsumer.IsJoined() {
		checks["kafka_history"] = "ok"
	} else {
		checks["kafka_history"] = "not_joined"
		allOK = false
	}

	w.Header().Set("Content-Type", "application/json")
	status := "ready"
	httpStatus := http.StatusOK
	if !allOK {
		status = "not_ready"
		httpStatus = http.StatusServiceUnavailable
	}

	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(map[string]any{
		"status": status,
		"checks": checks,
	})
}
