package sipgox

import (
	"context"
	"fmt"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/pion/rtp"
	"github.com/rs/zerolog/log"
)

type DialDialog struct {
	*MediaSession

	// read only. Should not be modified
	// Useful to use in testing
	InviteRequest  *sip.Request
	InviteResponse *sip.Response

	c *sipgo.Client
	// Depending are we UAC or UAS we need to change destination
	// In case of answering this must be changed to contact of received INVITE
	contact     *sip.Uri
	destination string

	done chan struct{}
}

func (d *DialDialog) Done() <-chan struct{} {
	return d.done
}

func (d *DialDialog) Hangup(ctx context.Context) error {
	req, res := d.InviteRequest, d.InviteResponse

	reqBye := sip.NewByeRequest(req, res, nil)
	if d.contact != nil {
		// Reverse from and to
		fmt.Println("REVERSING HEADERS")
		from, _ := res.From()
		to, _ := res.To()

		newFrom := &sip.FromHeader{
			DisplayName: to.DisplayName,
			Address:     to.Address,
			Params:      to.Params,
		}

		newTo := &sip.ToHeader{
			DisplayName: from.DisplayName,
			Address:     from.Address,
			Params:      from.Params,
		}
		reqBye.Recipient = &from.Address
		reqBye.ReplaceHeader(newFrom)
		reqBye.ReplaceHeader(newTo)

		f, _ := reqBye.From()
		if f.Address.String() != newFrom.Address.String() {
			return fmt.Errorf("Hangup can not be done")
		}

		if d.destination == "" {
			reqBye.SetDestination(d.contact.HostPort())
		} else {
			reqBye.SetDestination(d.destination)
		}
	}
	defer d.MediaSession.Close()

	tx, err := d.sendRequest(ctx, reqBye)
	if err != nil {
		return err
	}

	defer tx.Terminate()

	// Wait 200
	select {
	case res := <-tx.Responses():
		if res.StatusCode != 200 {
			return fmt.Errorf("Received non 200 response. %s", res.StartLine())
		}
	case <-tx.Done():
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func (d *DialDialog) sendRequest(ctx context.Context, req *sip.Request) (sip.ClientTransaction, error) {
	// Create new via header depending on our client settings
	// OTHERWISE this can fail and it will try to reuse connection from VIA header
	req.RemoveHeader("Via")
	tx, err := d.c.TransactionRequest(ctx, req, sipgo.ClientRequestAddVia)
	return tx, err
}

func (d *DialDialog) Playback(file string) error {
	//TODO
	if d.InviteResponse.StatusCode != 200 {
		return fmt.Errorf("call not answered")
	}
	return nil
}

func (d *DialDialog) Echo() {
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
func (d *DialDialog) DumpMedia() {
	mlog := MediaStreamLogger(log.Logger)
	d.MediaStream(mlog)
}

func (d *DialDialog) MediaStream(s MediaStreamer) error {
	return s.MediaStream(d.MediaSession)
}
