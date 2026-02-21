package kafka

import (
	"context"
	"sync/atomic"

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
		kgo.OnPartitionsRevoked(func(_ context.Context, _ *kgo.Client, _ map[string][]int32) {
			hc.joined.Store(false)
			logger.Info("history consumer: partitions revoked")
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
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case recs, ok := <-flushed:
				if !ok {
					return
				}
				for _, r := range recs {
					hc.client.MarkCommitRecords(r)
				}
				if err := hc.client.CommitMarkedOffsets(ctx); err != nil {
					hc.logger.Error("history consumer: commit offsets failed", zap.Error(err))
				}
			}
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
