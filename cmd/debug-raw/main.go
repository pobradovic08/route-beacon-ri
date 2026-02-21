package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/route-beacon/rib-ingester/internal/bgp"
	"github.com/route-beacon/rib-ingester/internal/bmp"
	"github.com/twmb/franz-go/pkg/kgo"
)

func main() {
	broker := "localhost:29092"
	topic := "gobmp.raw"
	if len(os.Args) > 1 {
		broker = os.Args[1]
	}
	if len(os.Args) > 2 {
		topic = os.Args[2]
	}

	cl, err := kgo.NewClient(
		kgo.SeedBrokers(broker),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		kgo.ConsumerGroup(fmt.Sprintf("debug-raw-%d", time.Now().UnixNano())),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kafka client: %v\n", err)
		os.Exit(1)
	}
	defer cl.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	msgNum := 0
	for {
		fetches := cl.PollRecords(ctx, 100)
		if fetches.IsClientClosed() || ctx.Err() != nil {
			break
		}

		fetches.EachRecord(func(rec *kgo.Record) {
			msgNum++
			fmt.Printf("=== Kafka msg %d (partition=%d offset=%d, %d bytes) ===\n",
				msgNum, rec.Partition, rec.Offset, len(rec.Value))

			analyzeMessage(rec.Value)
			fmt.Println()
		})

		if msgNum > 0 && len(fetches.Records()) == 0 {
			break
		}
	}

	fmt.Printf("Total Kafka messages: %d\n", msgNum)
}

func analyzeMessage(data []byte) {
	bmpBytes, err := bmp.DecodeOpenBMPFrame(data, 16*1024*1024)
	if err != nil {
		fmt.Printf("  DecodeOpenBMPFrame error: %v\n", err)
		return
	}
	fmt.Printf("  BMP payload: %d bytes\n", len(bmpBytes))

	routerIP := bmp.RouterIPFromOpenBMPV17(data)
	fmt.Printf("  OpenBMP router IP: %q\n", routerIP)

	msgs, err := bmp.ParseAll(bmpBytes)
	if err != nil {
		fmt.Printf("  ParseAll error: %v\n", err)
		return
	}
	fmt.Printf("  BMP messages in payload: %d\n", len(msgs))

	for i, m := range msgs {
		fmt.Printf("\n  --- BMP msg %d (offset=%d) ---\n", i, m.Offset)
		fmt.Printf("    MsgType:    %d (%s)\n", m.MsgType, bmpMsgName(m.MsgType))
		fmt.Printf("    PeerType:   %d (LocRIB=%v)\n", m.PeerType, m.IsLocRIB)
		fmt.Printf("    PeerFlags:  0x%02x (AddPath=%v)\n", m.PeerFlags, m.HasAddPath)
		fmt.Printf("    TableName:  %q\n", m.TableName)

		if m.BGPData != nil {
			fmt.Printf("    BGPData:    %d bytes\n", len(m.BGPData))
			if len(m.BGPData) >= 19 {
				fmt.Printf("    BGP header hex: %s\n", hex.EncodeToString(m.BGPData[:19]))
				fmt.Printf("    BGP msg type: %d, length: %d\n",
					m.BGPData[18],
					int(m.BGPData[16])<<8|int(m.BGPData[17]))
			}
		}

		if !m.IsLocRIB {
			continue
		}

		// Extract router ID the same way the pipeline does
		peerHdrOffset := m.Offset + bmp.CommonHeaderSize
		if peerHdrOffset < len(bmpBytes) {
			rid := bmp.RouterIDFromPeerHeader(bmpBytes[peerHdrOffset:])
			fmt.Printf("    RouterID (peer hdr): %q\n", rid)
		}

		if m.MsgType != bmp.MsgTypeRouteMonitoring || m.BGPData == nil {
			continue
		}
		if len(m.BGPData) < bgp.BGPHeaderSize || m.BGPData[18] != bgp.BGPMsgTypeUpdate {
			continue
		}

		events, err := bgp.ParseUpdate(m.BGPData, m.HasAddPath)
		if err != nil {
			fmt.Printf("    ParseUpdate error: %v\n", err)
			if len(m.BGPData) > 19 && len(m.BGPData) <= 60 {
				fmt.Printf("    Full BGPData hex: %s\n", hex.EncodeToString(m.BGPData))
			} else if len(m.BGPData) > 19 {
				fmt.Printf("    BGPData[19:50] hex: %s\n", hex.EncodeToString(m.BGPData[19:min(50, len(m.BGPData))]))
			}
			continue
		}

		if len(events) == 0 {
			afi := bgp.DetectEORAFI(m.BGPData)
			fmt.Printf("    EOR (AFI=%d)\n", afi)
			continue
		}

		fmt.Printf("    Routes: %d\n", len(events))
		for j, ev := range events {
			if j < 5 || j == len(events)-1 {
				fmt.Printf("      [%d] AFI=%d %s %s nexthop=%s as=%s pathID=%d\n",
					j, ev.AFI, ev.Action, ev.Prefix, ev.Nexthop, ev.ASPath, ev.PathID)
			} else if j == 5 {
				fmt.Printf("      ... (%d more) ...\n", len(events)-6)
			}
		}
	}
}

func bmpMsgName(t uint8) string {
	switch t {
	case 0:
		return "RouteMonitoring"
	case 1:
		return "StatisticsReport"
	case 2:
		return "PeerDown"
	case 3:
		return "PeerUp"
	case 4:
		return "Initiation"
	case 5:
		return "Termination"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}
