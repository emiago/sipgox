package sipgox

import (
	"context"
	"time"

	"github.com/emiago/sipgo"
	"github.com/pion/rtp"
	"github.com/rs/zerolog/log"
)

type DialogClientSession struct {
	*MediaSession

	*sipgo.DialogClientSession

	done chan struct{}
}

// func (d *DialogClientSession) Close() error {
// 	select {
// 	case <-d.done:
// 		d.MediaSession.Close()
// 	default:
// 		// In case running session than do try sending hangup
// 		ctx, _ := context.WithTimeout(context.Background(), 2*time.Second)
// 		return d.Bye(ctx)
// 	}
// 	return nil
// }

func (d *DialogClientSession) Done() <-chan struct{} {
	return d.done
}

// Hangup is alias for Bye
func (d *DialogClientSession) Hangup(ctx context.Context) error {
	return d.Bye(ctx)
}
func (d *DialogClientSession) Bye(ctx context.Context) error {
	defer close(d.done)
	defer d.MediaSession.Close()
	return d.DialogClientSession.Bye(ctx)
}

func (d *DialogClientSession) Echo() {
	if d.InviteResponse.StatusCode != 200 {
		return
	}

	sequencer := rtp.NewFixedSequencer(1)
	for i := 0; ; i++ {
		select {
		case <-d.Done():
			return
		case <-time.After(200 * time.Millisecond):
			// Do every 200 milisecond RTP and check echo
		}
		log.Debug().Msg("Sending RTP")
		pkt := &rtp.Packet{
			Header: rtp.Header{
				Version:        2,
				Padding:        false,
				Extension:      false,
				Marker:         false,
				PayloadType:    0,
				SequenceNumber: sequencer.NextSequenceNumber(),
				Timestamp:      20, // Figure out how to do timestamps
				SSRC:           111222,
			},
			Payload: []byte("1234567890"),
		}

		if err := d.WriteRTP(pkt); err != nil {
			log.Error().Err(err).Msg("Fail to send RTP")
			return
		}

		p, err := d.ReadRTP()
		if err != nil {
			log.Error().Err(err).Msg("Fail to read RTP")
			return
		}

		log.Info().Str("payload", string(p.Payload)).Msg("Received echo")

		if p.PayloadType != pkt.PayloadType {
			log.Info().Msg("Received unknown typ")
		}

	}
}

// Deprecated. Use MediaStream
func (d *DialogClientSession) DumpMedia() {
	mlog := MediaStreamLogger(log.Logger)
	d.MediaStream(mlog)
}

func (d *DialogClientSession) MediaStream(s MediaStreamer) error {
	return s.MediaStream(d.MediaSession)
}
