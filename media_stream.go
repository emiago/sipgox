package sipgox

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/rs/zerolog"
)

// type RTPReader interface {
// 	ReadRTP() (rtp.Packet, error)
// }

// type RTPWriter interface {
// 	WriteRTP(p rtp.Packet) error
// }

// type RTPReaderWritter interface {
// 	RTPReader
// 	RTPWriter
// }

type MediaStreamer interface {
	MediaStream(s *MediaSession) error
}

type MediaStreamFunc func(s *MediaSession) error

func (f MediaStreamFunc) MediaStream(s *MediaSession) error {
	return f(s)
}

// TODO file stream
// Writes RTP only

// Audio devices
// Reads Mic and then WriteRTP
// ReadRTP and then go to speaker

func MediaStreamLogger(log zerolog.Logger) MediaStreamer {
	return MediaStreamFunc(func(s *MediaSession) error {

		// Just reader
		defer s.Close()

		go func() {
			log := log.With().Str("caller", "RTCP recv").Logger()
			for {
				pkts, err := s.ReadRTCP()
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						log.Info().Msg("rctp stopped")
						return
					}
					log.Debug().Err(err).Msg("RTCP read error")
					return
				}

				for _, p := range pkts {
					log.Debug().Interface("data", p).
						Msg("RTCP packet received")
				}
			}
		}()

		lastSummaryTime := time.Now()
		packetsCount := 0
		payloadSizeTotal := 0
		payloadTypeCount := map[uint8]int{}

		var logRTPSummary = func() {

			l := log.Info().Int("packets", packetsCount)
			for k, v := range payloadTypeCount {
				l.Int(fmt.Sprintf("packets_type-%d", k), v)
			}
			l.Int("payload_total_size", payloadSizeTotal)
			l.Msg("RTP received")
		}

		var lastRTPTime time.Time

		log = log.With().Str("caller", "RTP recv").Logger()
		for {
			p, err := s.ReadRTP()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					log.Info().Msg("rtp stopped")
					return nil
				}
				// log.Debug().Err(err).Msg("RTP read error")
				return err
			}

			now := time.Now()
			if now.Sub(lastRTPTime) > 1*time.Second {
				log.Info().Msg("Talking started")
			}

			log.Debug().Msg(p.String())

			// Do some summary for info logging
			if now.Add(-3 * time.Second).After(lastSummaryTime) {
				logRTPSummary()
				lastSummaryTime = now
			}
			// p.String()
			packetsCount++
			payloadSizeTotal += len(p.Payload)
			payloadTypeCount[p.PayloadType]++

			lastRTPTime = now
		}
	})
}
