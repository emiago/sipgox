package sipgox

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/rs/zerolog"
)

type RegisterTransaction struct {
	opts   RegisterOptions
	origin *sip.Request

	client *sipgo.Client
	log    zerolog.Logger
}

func (t *RegisterTransaction) Terminate() error {
	return t.client.Close()
}

func newRegisterTransaction(log zerolog.Logger, client *sipgo.Client, recipient sip.Uri, contact sip.ContactHeader, opts RegisterOptions) *RegisterTransaction {
	expiry, allowHDRS := opts.Expiry, opts.AllowHeaders
	// log := p.getLoggerCtx(ctx, "Register")
	req := sip.NewRequest(sip.REGISTER, &recipient)
	req.AppendHeader(&contact)
	expires := sip.ExpiresHeader(expiry)
	req.AppendHeader(&expires)
	if allowHDRS != nil {
		req.AppendHeader(sip.NewHeader("Allow", strings.Join(allowHDRS, ", ")))
	}

	t := &RegisterTransaction{
		origin: req, // origin maybe updated after first register
		opts:   opts,
		client: client,
		log:    log,
	}

	return t
}

func (p *RegisterTransaction) register(ctx context.Context, recipient sip.Uri, contact sip.ContactHeader) error {
	username, password, expiry := p.opts.Username, p.opts.Password, p.opts.Expiry
	client := p.client
	log := p.log
	req := p.origin

	// Send request and parse response
	// req.SetDestination(*dst)
	log.Info().Str("uri", req.Recipient.String()).Int("expiry", int(expiry)).Msg("sending request")
	tx, err := client.TransactionRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("fail to create transaction req=%q: %w", req.StartLine(), err)
	}
	defer tx.Terminate()

	res, err := getResponse(ctx, tx)
	if err != nil {
		return fmt.Errorf("fail to get response req=%q : %w", req.StartLine(), err)
	}

	via := res.Via()
	if via == nil {
		return fmt.Errorf("No Via header in response")
	}

	// https://datatracker.ietf.org/doc/html/rfc3581#section-9
	if rport, _ := via.Params.Get("rport"); rport != "" {
		if p, err := strconv.Atoi(rport); err == nil {
			contact.Address.Port = p
		}

		if received, _ := via.Params.Get("received"); received != "" {
			// TODO: consider parsing IP
			contact.Address.Host = received
		}

		// Update contact address of NAT
		req.ReplaceHeader(&contact)
	}

	log.Info().Int("status", int(res.StatusCode)).Msg("Received status")
	if res.StatusCode == sip.StatusUnauthorized {
		tx.Terminate() //Terminate previous
		log.Info().Msg("Unathorized. Doing digest auth")
		tx, err = digestTransactionRequest(client, username, password, req, res)
		if err != nil {
			return err
		}
		defer tx.Terminate()

		res, err = getResponse(ctx, tx)
		if err != nil {
			return fmt.Errorf("fail to get response req=%q : %w", req.StartLine(), err)
		}
		log.Info().Int("status", int(res.StatusCode)).Msg("Received status")
	}

	if res.StatusCode != 200 {
		return &RegisterResponseError{
			RegisterReq: req,
			RegisterRes: res,
			Msg:         res.StartLine(),
		}
	}

	return nil
}

func (t *RegisterTransaction) qualifyLoop(ctx context.Context) error {

	// TODO: based on server response Expires header this must be adjusted
	expiry := t.opts.Expiry
	if expiry == 0 {
		expiry = 30
	}

	ticker := time.NewTicker(time.Duration(expiry) * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C: // TODO make configurable
		}
		err := t.qualify(ctx)
		if err != nil {
			return err
		}
	}
}

func (t *RegisterTransaction) unregister(ctx context.Context) error {
	log := t.log
	req := t.origin

	req.RemoveHeader("Expires")
	req.RemoveHeader("Contact")
	req.AppendHeader(sip.NewHeader("Contact", "*"))
	expires := sip.ExpiresHeader(0)
	req.AppendHeader(&expires)

	log.Info().Str("uri", req.Recipient.String()).Msg("UNREGISTER")
	return t.reregister(ctx, req)
}

func (t *RegisterTransaction) qualify(ctx context.Context) error {
	return t.reregister(ctx, t.origin)
}

func (t *RegisterTransaction) reregister(ctx context.Context, req *sip.Request) error {
	// log := p.getLoggerCtx(ctx, "Register")
	log := t.log
	client := t.client
	username, password := t.opts.Username, t.opts.Password
	// Send request and parse response
	// req.SetDestination(*dst)
	req.RemoveHeader("Via")
	tx, err := client.TransactionRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("fail to create transaction req=%q: %w", req.StartLine(), err)
	}
	defer tx.Terminate()

	res, err := getResponse(ctx, tx)
	if err != nil {
		return fmt.Errorf("fail to get response req=%q : %w", req.StartLine(), err)
	}

	log.Info().Int("status", int(res.StatusCode)).Msg("Received status")
	if res.StatusCode == sip.StatusUnauthorized {
		tx.Terminate() //Terminate previous
		log.Info().Msg("Unathorized. Doing digest auth")
		tx, err = digestTransactionRequest(client, username, password, req, res)
		if err != nil {
			return err
		}
		defer tx.Terminate()

		res, err = getResponse(ctx, tx)
		if err != nil {
			return fmt.Errorf("fail to get response req=%q : %w", req.StartLine(), err)
		}
		log.Info().Int("status", int(res.StatusCode)).Msg("Received status")
	}

	if res.StatusCode != 200 {
		return &RegisterResponseError{
			RegisterReq: req,
			RegisterRes: res,
			Msg:         res.StartLine(),
		}
	}

	return nil
}
