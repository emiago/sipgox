package sipgox

import (
	"context"

	"github.com/emiago/sipgo"
	"github.com/rs/zerolog/log"
)

type DialogServerSession struct {
	*MediaSession

	*sipgo.DialogServerSession

	done chan struct{}
}

func (d *DialogServerSession) Done() <-chan struct{} {
	return d.done
}

// Hangup is alias for Bye
func (d *DialogServerSession) Hangup(ctx context.Context) error {
	return d.Bye(ctx)
}
func (d *DialogServerSession) Bye(ctx context.Context) error {
	defer d.MediaSession.Close()
	return d.DialogServerSession.Bye(ctx)
}

func (d *DialogServerSession) Echo() {
	if d.InviteResponse.StatusCode != 200 {
		return
	}

	for {
		p, err := d.ReadRTP()
		if err != nil {
			log.Error().Err(err).Msg("Fail to read RTP")
			return
		}

		log.Info().Str("payload", string(p.Payload)).Msg("Received echo")

		if err := d.WriteRTP(&p); err != nil {
			log.Error().Err(err).Msg("Fail to send RTP")
			return
		}
	}
}

// Deprecated. Use MediaStream
func (d *DialogServerSession) DumpMedia() {
	mlog := MediaStreamLogger(log.Logger)
	d.MediaStream(mlog)
}

func (d *DialogServerSession) MediaStream(s MediaStreamer) error {
	return s.MediaStream(d.MediaSession)
}
