package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

type Config struct {
	Service   ServiceConfig   `koanf:"service"`
	Kafka     KafkaConfig     `koanf:"kafka"`
	Postgres  PostgresConfig  `koanf:"postgres"`
	Ingest    IngestConfig    `koanf:"ingest"`
	Retention RetentionConfig `koanf:"retention"`
}

type ServiceConfig struct {
	InstanceID             string `koanf:"instance_id"`
	HTTPListen             string `koanf:"http_listen"`
	LogLevel               string `koanf:"log_level"`
	ShutdownTimeoutSeconds int    `koanf:"shutdown_timeout_seconds"`
}

type KafkaConfig struct {
	Brokers       []string       `koanf:"brokers"`
	ClientID      string         `koanf:"client_id"`
	TLS           TLSConfig      `koanf:"tls"`
	SASL          SASLConfig     `koanf:"sasl"`
	State         ConsumerConfig `koanf:"state"`
	History       ConsumerConfig `koanf:"history"`
	FetchMaxBytes int32          `koanf:"fetch_max_bytes"`
}

type TLSConfig struct {
	Enabled  bool   `koanf:"enabled"`
	CAFile   string `koanf:"ca_file"`
	CertFile string `koanf:"cert_file"`
	KeyFile  string `koanf:"key_file"`
}

type SASLConfig struct {
	Enabled   bool   `koanf:"enabled"`
	Mechanism string `koanf:"mechanism"`
	Username  string `koanf:"username"`
	Password  string `koanf:"password"`
}

type ConsumerConfig struct {
	GroupID string   `koanf:"group_id"`
	Topics  []string `koanf:"topics"`
}

type PostgresConfig struct {
	DSN      string `koanf:"dsn"`
	MaxConns int32  `koanf:"max_conns"`
	MinConns int32  `koanf:"min_conns"`
}

type IngestConfig struct {
	BatchSize            int  `koanf:"batch_size"`
	FlushIntervalMs      int  `koanf:"flush_interval_ms"`
	ChannelBufferSize    int  `koanf:"channel_buffer_size"`
	MaxPayloadBytes      int  `koanf:"max_payload_bytes"`
	StoreRawBytes        bool `koanf:"store_raw_bytes"`
	StoreRawBytesCompress bool `koanf:"store_raw_bytes_compress"`
}

type RetentionConfig struct {
	Days     int    `koanf:"days"`
	Timezone string `koanf:"timezone"`
}

func Load(path string) (*Config, error) {
	k := koanf.New(".")

	// Load YAML file first.
	if path != "" {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("loading config file %s: %w", path, err)
		}
	}

	// Overlay environment variables: RIB_INGESTER_KAFKA__BROKERS → kafka.brokers
	if err := k.Load(env.Provider("RIB_INGESTER_", ".", func(s string) string {
		s = strings.TrimPrefix(s, "RIB_INGESTER_")
		s = strings.ToLower(s)
		s = strings.ReplaceAll(s, "__", ".")
		return s
	}), nil); err != nil {
		return nil, fmt.Errorf("loading env config: %w", err)
	}

	cfg := &Config{
		Service: ServiceConfig{
			InstanceID:             "rib-ingester-1",
			HTTPListen:             ":8080",
			LogLevel:               "info",
			ShutdownTimeoutSeconds: 30,
		},
		Kafka: KafkaConfig{
			ClientID:      "rib-ingester",
			FetchMaxBytes: 52428800,
			State: ConsumerConfig{
				GroupID: "rib-ingester-state",
			},
			History: ConsumerConfig{
				GroupID: "rib-ingester-history",
			},
		},
		Postgres: PostgresConfig{
			MaxConns: 20,
			MinConns: 2,
		},
		Ingest: IngestConfig{
			BatchSize:             1000,
			FlushIntervalMs:       200,
			ChannelBufferSize:     16,
			MaxPayloadBytes:       16777216,
			StoreRawBytesCompress: true,
		},
		Retention: RetentionConfig{
			Days:     30,
			Timezone: "UTC",
		},
	}

	if err := k.Unmarshal("", cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if len(c.Kafka.Brokers) == 0 {
		return fmt.Errorf("config: kafka.brokers is required")
	}
	if c.Postgres.DSN == "" {
		return fmt.Errorf("config: postgres.dsn is required")
	}
	if c.Kafka.State.GroupID == "" {
		return fmt.Errorf("config: kafka.state.group_id is required")
	}
	if len(c.Kafka.State.Topics) == 0 {
		return fmt.Errorf("config: kafka.state.topics is required")
	}
	if c.Kafka.History.GroupID == "" {
		return fmt.Errorf("config: kafka.history.group_id is required")
	}
	if len(c.Kafka.History.Topics) == 0 {
		return fmt.Errorf("config: kafka.history.topics is required")
	}
	if c.Ingest.FlushIntervalMs <= 0 {
		return fmt.Errorf("config: ingest.flush_interval_ms must be > 0 (got %d)", c.Ingest.FlushIntervalMs)
	}
	if c.Ingest.BatchSize <= 0 {
		return fmt.Errorf("config: ingest.batch_size must be > 0 (got %d)", c.Ingest.BatchSize)
	}
	if c.Ingest.ChannelBufferSize <= 0 {
		return fmt.Errorf("config: ingest.channel_buffer_size must be > 0 (got %d)", c.Ingest.ChannelBufferSize)
	}
	if c.Retention.Days <= 0 {
		return fmt.Errorf("config: retention.days must be > 0 (got %d)", c.Retention.Days)
	}
	if c.Service.ShutdownTimeoutSeconds <= 0 {
		return fmt.Errorf("config: service.shutdown_timeout_seconds must be > 0 (got %d)", c.Service.ShutdownTimeoutSeconds)
	}
	if _, err := time.LoadLocation(c.Retention.Timezone); err != nil {
		return fmt.Errorf("config: retention.timezone is invalid: %w", err)
	}
	return nil
}
