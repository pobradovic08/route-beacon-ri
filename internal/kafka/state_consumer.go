package kafka

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"go.uber.org/zap"
)

type StateConsumer struct {
	client  *kgo.Client
	logger  *zap.Logger
	joined  atomic.Bool
}

func NewStateConsumer(brokers []string, groupID string, topics []string, clientID string, fetchMaxBytes int32, logger *zap.Logger) (*StateConsumer, error) {
	sc := &StateConsumer{logger: logger}

	opts := []kgo.Opt{
		kgo.SeedBrokers(brokers...),
		kgo.ConsumerGroup(groupID),
		kgo.ConsumeTopics(topics...),
		kgo.ClientID(clientID),
		kgo.FetchMaxBytes(fetchMaxBytes),
		kgo.DisableAutoCommit(),
		kgo.OnPartitionsAssigned(func(_ context.Context, _ *kgo.Client, _ map[string][]int32) {
			sc.joined.Store(true)
			logger.Info("state consumer: partitions assigned")
		}),
		kgo.OnPartitionsRevoked(func(ctx context.Context, cl *kgo.Client, _ map[string][]int32) {
			if err := cl.CommitMarkedOffsets(ctx); err != nil {
				logger.Error("state consumer: commit on revoke failed", zap.Error(err))
			}
			sc.joined.Store(false)
			logger.Info("state consumer: partitions revoked")
		}),
		kgo.OnPartitionsLost(func(_ context.Context, _ *kgo.Client, _ map[string][]int32) {
			sc.joined.Store(false)
			logger.Info("state consumer: partitions lost")
		}),
	}

	client, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, err
	}

	sc.client = client
	return sc, nil
}

// Run fetches records and sends them to the records channel.
// It reads from flushed to commit offsets after successful DB writes.
func (sc *StateConsumer) Run(ctx context.Context, records chan<- []*kgo.Record, flushed <-chan []*kgo.Record) {
	// Start a goroutine to handle offset commits.
	// Drains the flushed channel completely before exiting.
	go func() {
		for recs := range flushed {
			for _, r := range recs {
				sc.client.MarkCommitRecords(r)
			}
			commitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := sc.client.CommitMarkedOffsets(commitCtx); err != nil {
				sc.logger.Error("state consumer: commit offsets failed", zap.Error(err))
			}
			cancel()
		}
	}()

	for {
		fetches := sc.client.PollFetches(ctx)
		if ctx.Err() != nil {
			return
		}

		if errs := fetches.Errors(); len(errs) > 0 {
			for _, e := range errs {
				sc.logger.Error("state consumer: fetch error",
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

func (sc *StateConsumer) IsJoined() bool {
	return sc.joined.Load()
}

func (sc *StateConsumer) Close() {
	sc.client.Close()
}
