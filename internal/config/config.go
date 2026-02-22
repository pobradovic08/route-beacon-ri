package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/twmb/franz-go/pkg/sasl"
	"github.com/twmb/franz-go/pkg/sasl/plain"
)

type Config struct {
	Service   ServiceConfig          `koanf:"service"`
	Kafka     KafkaConfig            `koanf:"kafka"`
	Postgres  PostgresConfig         `koanf:"postgres"`
	Ingest    IngestConfig           `koanf:"ingest"`
	Retention RetentionConfig        `koanf:"retention"`
	Routers   map[string]RouterMeta  `koanf:"routers"`
}

type RouterMeta struct {
	Name     string `koanf:"name"`
	Location string `koanf:"location"`
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
	// RawMode is only applicable to the state pipeline consumer.
	// The history pipeline always processes raw BMP data directly.
	RawMode bool `koanf:"raw_mode"`
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

	// Split comma-separated env strings for slice fields.
	if len(cfg.Kafka.Brokers) == 1 && strings.Contains(cfg.Kafka.Brokers[0], ",") {
		cfg.Kafka.Brokers = strings.Split(cfg.Kafka.Brokers[0], ",")
	}
	if len(cfg.Kafka.State.Topics) == 1 && strings.Contains(cfg.Kafka.State.Topics[0], ",") {
		cfg.Kafka.State.Topics = strings.Split(cfg.Kafka.State.Topics[0], ",")
	}
	if len(cfg.Kafka.History.Topics) == 1 && strings.Contains(cfg.Kafka.History.Topics[0], ",") {
		cfg.Kafka.History.Topics = strings.Split(cfg.Kafka.History.Topics[0], ",")
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
	if c.Ingest.MaxPayloadBytes <= 0 {
		return fmt.Errorf("config: ingest.max_payload_bytes must be > 0 (got %d)", c.Ingest.MaxPayloadBytes)
	}
	if c.Kafka.FetchMaxBytes <= 0 {
		return fmt.Errorf("config: kafka.fetch_max_bytes must be > 0 (got %d)", c.Kafka.FetchMaxBytes)
	}
	if c.Postgres.MaxConns <= 0 {
		return fmt.Errorf("config: postgres.max_conns must be > 0 (got %d)", c.Postgres.MaxConns)
	}
	if c.Postgres.MinConns < 0 {
		return fmt.Errorf("config: postgres.min_conns must be >= 0 (got %d)", c.Postgres.MinConns)
	}
	if c.Service.ShutdownTimeoutSeconds <= 0 {
		return fmt.Errorf("config: service.shutdown_timeout_seconds must be > 0 (got %d)", c.Service.ShutdownTimeoutSeconds)
	}
	if _, err := time.LoadLocation(c.Retention.Timezone); err != nil {
		return fmt.Errorf("config: retention.timezone is invalid: %w", err)
	}
	if int32(c.Ingest.MaxPayloadBytes) > c.Kafka.FetchMaxBytes {
		return fmt.Errorf("config: ingest.max_payload_bytes (%d) exceeds kafka.fetch_max_bytes (%d); messages larger than fetch_max_bytes will be dropped by the broker",
			c.Ingest.MaxPayloadBytes, c.Kafka.FetchMaxBytes)
	}
	return nil
}

// BuildTLSConfig creates a *tls.Config from the Kafka TLS settings. Returns nil if TLS is disabled.
func (k *KafkaConfig) BuildTLSConfig() (*tls.Config, error) {
	if !k.TLS.Enabled {
		return nil, nil
	}
	tlsCfg := &tls.Config{}
	if k.TLS.CAFile != "" {
		caPEM, err := os.ReadFile(k.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsCfg.RootCAs = pool
	}
	if k.TLS.CertFile != "" && k.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(k.TLS.CertFile, k.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

// BuildSASLMechanism creates a SASL mechanism from the Kafka SASL settings. Returns nil if SASL is disabled.
func (k *KafkaConfig) BuildSASLMechanism() sasl.Mechanism {
	if !k.SASL.Enabled {
		return nil
	}
	switch strings.ToUpper(k.SASL.Mechanism) {
	case "PLAIN":
		return plain.Auth{User: k.SASL.Username, Pass: k.SASL.Password}.AsMechanism()
	default:
		return nil
	}
}
