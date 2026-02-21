package kafka

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"go.uber.org/zap"
)

type HistoryConsumer struct {
	client *kgo.Client
	logger *zap.Logger
	joined atomic.Bool
}

func NewHistoryConsumer(brokers []string, groupID string, topics []string, clientID string, fetchMaxBytes int32, logger *zap.Logger) (*HistoryConsumer, error) {
	hc := &HistoryConsumer{logger: logger}

	opts := []kgo.Opt{
		kgo.SeedBrokers(brokers...),
		kgo.ConsumerGroup(groupID),
		kgo.ConsumeTopics(topics...),
		kgo.ClientID(clientID),
		kgo.FetchMaxBytes(fetchMaxBytes),
		kgo.DisableAutoCommit(),
		kgo.OnPartitionsAssigned(func(_ context.Context, _ *kgo.Client, _ map[string][]int32) {
			hc.joined.Store(true)
			logger.Info("history consumer: partitions assigned")
		}),
		kgo.OnPartitionsRevoked(func(ctx context.Context, cl *kgo.Client, _ map[string][]int32) {
			if err := cl.CommitMarkedOffsets(ctx); err != nil {
				logger.Error("history consumer: commit on revoke failed", zap.Error(err))
			}
			hc.joined.Store(false)
			logger.Info("history consumer: partitions revoked")
		}),
		kgo.OnPartitionsLost(func(_ context.Context, _ *kgo.Client, _ map[string][]int32) {
			hc.joined.Store(false)
			logger.Info("history consumer: partitions lost")
		}),
	}

	client, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, err
	}

	hc.client = client
	return hc, nil
}

// Run fetches records and sends them to the records channel.
func (hc *HistoryConsumer) Run(ctx context.Context, records chan<- []*kgo.Record, flushed <-chan []*kgo.Record) {
	// Start a goroutine to handle offset commits.
	// Drains the flushed channel completely before exiting.
	go func() {
		for recs := range flushed {
			for _, r := range recs {
				hc.client.MarkCommitRecords(r)
			}
			commitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := hc.client.CommitMarkedOffsets(commitCtx); err != nil {
				hc.logger.Error("history consumer: commit offsets failed", zap.Error(err))
			}
			cancel()
		}
	}()

	for {
		fetches := hc.client.PollFetches(ctx)
		if ctx.Err() != nil {
			return
		}

		if errs := fetches.Errors(); len(errs) > 0 {
			for _, e := range errs {
				hc.logger.Error("history consumer: fetch error",
					zap.String("topic", e.Topic),
					zap.Int32("partition", e.Partition),
					zap.Error(e.Err),
				)
			}
		}

		var batch []*kgo.Record
		fetches.EachRecord(func(r *kgo.Record) {
			batch = append(batch, r)
		})

		if len(batch) > 0 {
			select {
			case records <- batch:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (hc *HistoryConsumer) IsJoined() bool {
	return hc.joined.Load()
}

func (hc *HistoryConsumer) Close() {
	hc.client.Close()
}
