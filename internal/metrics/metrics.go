package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	KafkaMessagesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ribingester_kafka_messages_total",
			Help: "Total messages consumed from Kafka.",
		},
		[]string{"pipeline", "topic", "afi", "action"},
	)

	DBWriteDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ribingester_db_write_duration_seconds",
			Help:    "DB write latency.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
		[]string{"pipeline", "op"},
	)

	DBRowsAffectedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ribingester_db_rows_affected_total",
			Help: "DB rows written or deleted.",
		},
		[]string{"pipeline", "table", "op"},
	)

	HistoryDedupConflictsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ribingester_history_dedup_conflicts_total",
			Help: "History dedup hits (ON CONFLICT DO NOTHING skips).",
		},
		[]string{"topic"},
	)

	ParseErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ribingester_parse_errors_total",
			Help: "Parse failures by stage.",
		},
		[]string{"stage", "reason"},
	)

	EORSeen = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ribingester_eor_seen",
			Help: "EOR received (0/1).",
		},
		[]string{"router_id", "table_name", "afi"},
	)

	LastMsgTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ribingester_last_msg_timestamp_seconds",
			Help: "Unix timestamp of last processed message.",
		},
		[]string{"pipeline", "router_id", "table_name", "afi"},
	)

	BatchSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ribingester_batch_size",
			Help:    "Batch sizes flushed to DB.",
			Buckets: []float64{1, 10, 50, 100, 250, 500, 1000, 2000, 5000},
		},
		[]string{"pipeline"},
	)

	RoutesPurgedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ribingester_routes_purged_total",
			Help: "Routes purged (eor_stale, session_down).",
		},
		[]string{"reason"},
	)
)

func Register() {
	prometheus.MustRegister(
		KafkaMessagesTotal,
		DBWriteDuration,
		DBRowsAffectedTotal,
		HistoryDedupConflictsTotal,
		ParseErrorsTotal,
		EORSeen,
		LastMsgTimestamp,
		BatchSize,
		RoutesPurgedTotal,
	)
}
