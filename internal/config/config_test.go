package config

import (
	"os"
	"path/filepath"
	"testing"
)

func validConfig() *Config {
	return &Config{
		Service: ServiceConfig{
			InstanceID:             "test",
			HTTPListen:             ":8080",
			LogLevel:               "info",
			ShutdownTimeoutSeconds: 30,
		},
		Kafka: KafkaConfig{
			Brokers:       []string{"localhost:9092"},
			FetchMaxBytes: 52428800,
			State:         ConsumerConfig{GroupID: "g1", Topics: []string{"t1"}},
			History:       ConsumerConfig{GroupID: "g2", Topics: []string{"t2"}},
		},
		Postgres: PostgresConfig{
			DSN:      "postgres://localhost/test",
			MaxConns: 10,
			MinConns: 2,
		},
		Ingest: IngestConfig{
			BatchSize:         1000,
			FlushIntervalMs:   200,
			ChannelBufferSize: 16,
			MaxPayloadBytes:   1024,
		},
		Retention: RetentionConfig{
			Days:     30,
			Timezone: "UTC",
		},
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
}

func TestValidate_NoBrokers(t *testing.T) {
	cfg := validConfig()
	cfg.Kafka.Brokers = nil
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty brokers")
	}
}

func TestValidate_NoDSN(t *testing.T) {
	cfg := validConfig()
	cfg.Postgres.DSN = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty DSN")
	}
}

func TestValidate_NoStateGroupID(t *testing.T) {
	cfg := validConfig()
	cfg.Kafka.State.GroupID = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty state group_id")
	}
}

func TestValidate_NoHistoryGroupID(t *testing.T) {
	cfg := validConfig()
	cfg.Kafka.History.GroupID = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty history group_id")
	}
}

func TestValidate_NoStateTopics(t *testing.T) {
	cfg := validConfig()
	cfg.Kafka.State.Topics = nil
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty state topics")
	}
}

func TestValidate_NoHistoryTopics(t *testing.T) {
	cfg := validConfig()
	cfg.Kafka.History.Topics = nil
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty history topics")
	}
}

func TestValidate_FlushIntervalZero(t *testing.T) {
	cfg := validConfig()
	cfg.Ingest.FlushIntervalMs = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for flush_interval_ms = 0")
	}
}

func TestValidate_FlushIntervalNegative(t *testing.T) {
	cfg := validConfig()
	cfg.Ingest.FlushIntervalMs = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for negative flush_interval_ms")
	}
}

func TestValidate_BatchSizeZero(t *testing.T) {
	cfg := validConfig()
	cfg.Ingest.BatchSize = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for batch_size = 0")
	}
}

func TestValidate_ChannelBufferSizeZero(t *testing.T) {
	cfg := validConfig()
	cfg.Ingest.ChannelBufferSize = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for channel_buffer_size = 0")
	}
}

func TestValidate_RetentionDaysZero(t *testing.T) {
	cfg := validConfig()
	cfg.Retention.Days = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for retention.days = 0")
	}
}

func TestValidate_ShutdownTimeoutZero(t *testing.T) {
	cfg := validConfig()
	cfg.Service.ShutdownTimeoutSeconds = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for shutdown_timeout_seconds = 0")
	}
}

func TestValidate_InvalidTimezone(t *testing.T) {
	cfg := validConfig()
	cfg.Retention.Timezone = "Not/A/Real/Zone"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid timezone")
	}
}

func TestValidate_ValidTimezone(t *testing.T) {
	cfg := validConfig()
	cfg.Retention.Timezone = "America/New_York"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
}

func writeMinimalYAML(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	data := `
kafka:
  brokers:
    - "localhost:9092"
  state:
    topics:
      - "t1"
  history:
    topics:
      - "t2"
postgres:
  dsn: "postgres://localhost/test"
`
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_EnvOverrideDSN(t *testing.T) {
	p := writeMinimalYAML(t)
	t.Setenv("RIB_INGESTER_POSTGRES__DSN", "postgres://envhost/envdb")

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Postgres.DSN != "postgres://envhost/envdb" {
		t.Errorf("expected DSN from env, got %q", cfg.Postgres.DSN)
	}
}

func TestLoad_EnvOverrideLogLevel(t *testing.T) {
	p := writeMinimalYAML(t)
	t.Setenv("RIB_INGESTER_SERVICE__LOG_LEVEL", "debug")

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Service.LogLevel != "debug" {
		t.Errorf("expected log_level 'debug' from env, got %q", cfg.Service.LogLevel)
	}
}

func TestLoad_EnvEmptyGroupIDFailsValidation(t *testing.T) {
	p := writeMinimalYAML(t)
	t.Setenv("RIB_INGESTER_KAFKA__STATE__GROUP_ID", "")

	_, err := Load(p)
	if err == nil {
		t.Fatal("expected validation error for empty state group_id via env")
	}
}
