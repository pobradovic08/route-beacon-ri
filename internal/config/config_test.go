package config

import (
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
			Brokers: []string{"localhost:9092"},
			State:   ConsumerConfig{GroupID: "g1", Topics: []string{"t1"}},
			History: ConsumerConfig{GroupID: "g2", Topics: []string{"t2"}},
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
