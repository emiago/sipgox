package sipgox

import (
	"context"
	"fmt"
	"strings"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/rs/zerolog/log"
)

type DialogServerSession struct {
	*MediaSession

	*sipgo.DialogServerSession

	waitNotify chan error

	// onClose used to cleanup internal logic
	onClose func()
}

func (d *DialogServerSession) Close() error {
	err := d.DialogServerSession.Close()

	if d.MediaSession != nil {
		d.MediaSession.Close()
	}

	if d.onClose != nil {
		d.onClose()
	}
	return err
}

// Hangup is alias for Bye
func (d *DialogServerSession) Hangup(ctx context.Context) error {
	return d.Bye(ctx)
}
func (d *DialogServerSession) Bye(ctx context.Context) error {
	// defer close(d.done)
	// defer d.MediaSession.Close()
	return d.DialogServerSession.Bye(ctx)
}

// Refer tries todo refer (blind transfer) on call
func (d *DialogServerSession) Refer(ctx context.Context, referTo sip.Uri) error {
	// TODO check state of call

	req := sip.NewRequest(sip.REFER, d.InviteRequest.Contact().Address)
	UASRequestBuild(req, d.InviteResponse)

	// Invite request tags must be preserved but switched
	req.AppendHeader(sip.NewHeader("Refer-to", referTo.String()))

	d.waitNotify = make(chan error)

	tx, err := d.TransactionRequest(ctx, req)
	if err != nil {
		return err
	}

	select {
	case <-tx.Done():
		return tx.Err()
	case res := <-tx.Responses():
		if res.StatusCode != sip.StatusAccepted {
			return sipgo.ErrDialogResponse{
				Res: res,
			}
		}

	case <-ctx.Done():
		return tx.Cancel()
	}

	return d.Hangup(ctx)

	// There is now implicit subscription
	select {
	case e := <-d.waitNotify:
		return e
	case <-d.Context().Done():
		return d.Context().Err()
	}
}

func (d *DialogServerSession) Notify(req *sip.Request) error {
	if req.CallID().Value() != d.InviteResponse.CallID().Value() {
		return sipgo.ErrDialogDoesNotExists
	}

	if req.Body() == nil {
		return fmt.Errorf("no body in notify")
	}

	if strings.HasPrefix("SIP/2.0 1", string(req.Body())) {
		return nil
	}

	var e error = nil
	if !strings.HasPrefix("SIP/2.0 200", string(req.Body())) {
		e = fmt.Errorf("not 200 response")
	}

	select {
	case d.waitNotify <- e:
	case <-d.Context().Done():
		return d.Context().Err()
	}
	return nil
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

func (d *DialogServerSession) MediaStream(s MediaStreamer) error {
	return s.MediaStream(d.MediaSession)
}

func UACRequestBuild(req *sip.Request, lastReq *sip.Request, lastResp *sip.Response) {
	from := lastReq.From()
	to := lastReq.To()
	callid := lastReq.CallID()
	if lastResp != nil {
		// To normally gets updated with tag
		to = lastResp.To()
	}

	req.AppendHeader(from)
	req.AppendHeader(to)
	req.AppendHeader(callid)

	if cont := lastReq.GetHeader("Contact"); cont != nil {
		req.AppendHeader(cont)
	}

	// This is not clear
	// hdrs := res.GetHeaders("Record-Route")
	// for i := len(hdrs) - 1; i >= 0; i-- {
	// 	recordRoute := hdrs[i]
	// 	req.AppendHeader(sip.NewHeader("Route", recordRoute.Value()))
	// }
}

func UASRequestBuild(req *sip.Request, lastResp *sip.Response) {
	// UAS building request from previous sent response has some work
	// From and To must be swapped
	// Callid and contact hdr is preserved
	// Record-Route hdrs become Route hdrs
	//
	// rest must be filled by client

	from := lastResp.From()
	to := lastResp.To()
	callid := lastResp.CallID()

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

	req.AppendHeader(newFrom)
	req.AppendHeader(newTo)
	req.AppendHeader(callid)

	if cont := lastResp.GetHeader("Contact"); cont != nil {
		req.AppendHeader(cont)
	}
}
