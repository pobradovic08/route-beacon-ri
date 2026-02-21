package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"time"

	"github.com/route-beacon/rib-ingester/internal/config"
	"github.com/route-beacon/rib-ingester/internal/db"
	"github.com/route-beacon/rib-ingester/internal/history"
	ribhttp "github.com/route-beacon/rib-ingester/internal/http"
	"github.com/route-beacon/rib-ingester/internal/kafka"
	"github.com/route-beacon/rib-ingester/internal/maintenance"
	"github.com/route-beacon/rib-ingester/internal/metrics"
	"github.com/route-beacon/rib-ingester/internal/state"
	"github.com/twmb/franz-go/pkg/kgo"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		runServe()
	case "migrate":
		runMigrate()
	case "maintenance":
		runMaintenance()
	case "--help", "-h", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: rib-ingester <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  serve         Start the ingestion service")
	fmt.Println("  migrate       Run database migrations")
	fmt.Println("  maintenance   Run partition maintenance (create new, drop old)")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --config <path>   Path to configuration YAML file")
	fmt.Println("  --log-level <lvl> Override log level (debug, info, warn, error)")
}

func parseFlags(args []string) (configPath string, logLevel string) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config":
			if i+1 < len(args) {
				configPath = args[i+1]
				i++
			}
		case "--log-level":
			if i+1 < len(args) {
				logLevel = args[i+1]
				i++
			}
		}
	}
	return
}

func loadConfig(args []string) (*config.Config, *zap.Logger) {
	configPath, logLevelOverride := parseFlags(args)

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	if logLevelOverride != "" {
		cfg.Service.LogLevel = logLevelOverride
	}

	logger := initLogger(cfg.Service.LogLevel)
	return cfg, logger
}

func initLogger(level string) *zap.Logger {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zap.DebugLevel
	case "warn":
		zapLevel = zap.WarnLevel
	case "error":
		zapLevel = zap.ErrorLevel
	default:
		zapLevel = zap.InfoLevel
	}

	zapCfg := zap.NewProductionConfig()
	zapCfg.Level = zap.NewAtomicLevelAt(zapLevel)
	zapCfg.EncoderConfig.TimeKey = "ts"
	zapCfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger, err := zapCfg.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing logger: %v\n", err)
		os.Exit(1)
	}
	return logger
}

// migrationsDir returns the path to the migrations directory relative to the binary.
func migrationsDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "migrations"
	}
	return filepath.Join(filepath.Dir(exe), "migrations")
}

func runServe() {
	cfg, logger := loadConfig(os.Args[2:])
	defer logger.Sync()

	metrics.Register()

	logger.Info("starting rib-ingester",
		zap.String("instance_id", cfg.Service.InstanceID),
		zap.String("http_listen", cfg.Service.HTTPListen),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to database.
	pool, err := db.NewPool(ctx, cfg.Postgres.DSN, cfg.Postgres.MaxConns, cfg.Postgres.MinConns)
	if err != nil {
		logger.Fatal("failed to connect to database", zap.Error(err))
	}
	defer pool.Close()

	// Ensure partitions exist on startup.
	pm := maintenance.NewPartitionManager(pool, cfg.Retention.Days, cfg.Retention.Timezone, logger)
	if err := pm.CreatePartitions(ctx); err != nil {
		logger.Fatal("failed to create partitions on startup", zap.Error(err))
	}

	// Build TLS and SASL from config.
	tlsCfg, err := cfg.Kafka.BuildTLSConfig()
	if err != nil {
		logger.Fatal("failed to build TLS config", zap.Error(err))
	}
	saslMech := cfg.Kafka.BuildSASLMechanism()

	// --- State pipeline ---
	stateWriter := state.NewWriter(pool, logger.Named("state.writer"))
	statePipeline := state.NewPipeline(stateWriter, cfg.Ingest.BatchSize, cfg.Ingest.FlushIntervalMs, cfg.Kafka.State.RawMode, cfg.Ingest.MaxPayloadBytes, logger.Named("state.pipeline"))

	stateRecords := make(chan []*kgo.Record, cfg.Ingest.ChannelBufferSize)
	stateFlushed := make(chan []*kgo.Record, cfg.Ingest.ChannelBufferSize)

	stateConsumer, err := kafka.NewStateConsumer(
		cfg.Kafka.Brokers, cfg.Kafka.State.GroupID, cfg.Kafka.State.Topics,
		cfg.Kafka.ClientID+"-state", cfg.Kafka.FetchMaxBytes, tlsCfg, saslMech, logger.Named("kafka.state"),
	)
	if err != nil {
		logger.Fatal("failed to create state consumer", zap.Error(err))
	}
	defer stateConsumer.Close()

	var wg sync.WaitGroup
	var commitWg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); stateConsumer.Run(ctx, stateRecords, stateFlushed, &commitWg) }()
	go func() {
		defer wg.Done()
		statePipeline.Run(ctx, stateRecords, stateFlushed)
		close(stateFlushed)
	}()

	logger.Info("state pipeline started",
		zap.Strings("topics", cfg.Kafka.State.Topics),
		zap.String("group_id", cfg.Kafka.State.GroupID),
	)

	// --- History pipeline ---
	historyWriter := history.NewWriter(pool, logger.Named("history.writer"),
		cfg.Ingest.StoreRawBytes, cfg.Ingest.StoreRawBytesCompress)
	historyPipeline := history.NewPipeline(historyWriter,
		cfg.Ingest.BatchSize, cfg.Ingest.FlushIntervalMs, cfg.Ingest.MaxPayloadBytes,
		logger.Named("history.pipeline"))

	historyRecords := make(chan []*kgo.Record, cfg.Ingest.ChannelBufferSize)
	historyFlushed := make(chan []*kgo.Record, cfg.Ingest.ChannelBufferSize)

	historyConsumer, err := kafka.NewHistoryConsumer(
		cfg.Kafka.Brokers, cfg.Kafka.History.GroupID, cfg.Kafka.History.Topics,
		cfg.Kafka.ClientID+"-history", cfg.Kafka.FetchMaxBytes, tlsCfg, saslMech, logger.Named("kafka.history"),
	)
	if err != nil {
		logger.Fatal("failed to create history consumer", zap.Error(err))
	}
	defer historyConsumer.Close()

	wg.Add(2)
	go func() { defer wg.Done(); historyConsumer.Run(ctx, historyRecords, historyFlushed, &commitWg) }()
	go func() {
		defer wg.Done()
		historyPipeline.Run(ctx, historyRecords, historyFlushed)
		close(historyFlushed)
	}()

	logger.Info("history pipeline started",
		zap.Strings("topics", cfg.Kafka.History.Topics),
		zap.String("group_id", cfg.Kafka.History.GroupID),
	)

	// --- HTTP server ---
	httpServer := ribhttp.NewServer(cfg.Service.HTTPListen, pool, stateConsumer, historyConsumer, logger.Named("http"))
	if err := httpServer.Start(); err != nil {
		logger.Fatal("failed to start HTTP server", zap.Error(err))
	}

	logger.Info("all pipelines and HTTP server started")

	// Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	logger.Info("received shutdown signal", zap.String("signal", sig.String()))

	// Graceful shutdown.
	shutdownTimeout := time.Duration(cfg.Service.ShutdownTimeoutSeconds) * time.Second
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	// Stop accepting HTTP traffic first.
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown error", zap.Error(err))
	}

	// Cancel context to stop pipelines.
	cancel()

	// Wait for consumer and pipeline goroutines to finish their final flush/commit.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		commitWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("all pipelines stopped gracefully")
	case <-shutdownCtx.Done():
		logger.Warn("shutdown timeout reached, some goroutines may not have finished")
	}

	logger.Info("rib-ingester stopped")
}

func runMigrate() {
	cfg, logger := loadConfig(os.Args[2:])
	defer logger.Sync()

	logger.Info("running migrations",
		zap.String("dsn", redactDSN(cfg.Postgres.DSN)),
	)

	ctx := context.Background()
	pool, err := db.NewPool(ctx, cfg.Postgres.DSN, cfg.Postgres.MaxConns, cfg.Postgres.MinConns)
	if err != nil {
		logger.Fatal("failed to connect to database", zap.Error(err))
	}
	defer pool.Close()

	if err := db.RunMigrations(ctx, pool, migrationsDir(), logger); err != nil {
		logger.Fatal("migration failed", zap.Error(err))
	}

	logger.Info("migrations complete")
}

func runMaintenance() {
	cfg, logger := loadConfig(os.Args[2:])
	defer logger.Sync()

	logger.Info("running partition maintenance",
		zap.Int("retention_days", cfg.Retention.Days),
		zap.String("timezone", cfg.Retention.Timezone),
	)

	ctx := context.Background()
	pool, err := db.NewPool(ctx, cfg.Postgres.DSN, cfg.Postgres.MaxConns, cfg.Postgres.MinConns)
	if err != nil {
		logger.Fatal("failed to connect to database", zap.Error(err))
	}
	defer pool.Close()

	pm := maintenance.NewPartitionManager(pool, cfg.Retention.Days, cfg.Retention.Timezone, logger)
	if err := pm.Run(ctx); err != nil {
		logger.Fatal("maintenance failed", zap.Error(err))
	}

	logger.Info("partition maintenance complete")
}

func redactDSN(dsn string) string {
	if !strings.Contains(dsn, "://") {
		// keyword=value format — redact password=... portion
		re := regexp.MustCompile(`password\s*=\s*\S+`)
		return re.ReplaceAllString(dsn, "password=***")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return "***"
	}
	if u.User != nil {
		u.User = url.UserPassword(u.User.Username(), "***")
	}
	return u.String()
}
