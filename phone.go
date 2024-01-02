package sipgox

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Phone is easy wrapper for creating phone like functionaliy
// but actions are creating clients and servers on a fly so
// it is not designed for long running apps

var (
	ContextLoggerKey = "logger"
)

type Phone struct {
	ua *sipgo.UserAgent
	// listenAddrs is map of transport:addr which will phone use to listen incoming requests
	listenAddrs []ListenAddr

	log zerolog.Logger
}

type ListenAddr struct {
	Network string
	Addr    string
	TLSConf *tls.Config
}

type Listener struct {
	ListenAddr
	io.Closer
	Listen func() error
}

type PhoneOption func(p *Phone)

// WithPhoneListenAddrs
// NOT TLS supported
func WithPhoneListenAddr(addr ListenAddr) PhoneOption {
	return func(p *Phone) {
		p.listenAddrs = append(p.listenAddrs, addr)
	}
}

func WithPhoneLogger(l zerolog.Logger) PhoneOption {
	return func(p *Phone) {
		p.log = l
	}
}

func NewPhone(ua *sipgo.UserAgent, options ...PhoneOption) *Phone {
	p := &Phone{
		ua: ua,
		// c:           client,
		listenAddrs: []ListenAddr{},
		log:         log.Logger,
	}

	for _, o := range options {
		o(p)
	}

	if len(p.listenAddrs) == 0 {
		// WithPhoneListenAddr(ListenAddr{"udp", "127.0.0.1:5060"})(p)
		// WithPhoneListenAddr(ListenAddr{"tcp", "0.0.0.0:5060"})(p)
	}

	// In case ws we want to run http
	return p
}

func (p *Phone) Close() {
}

func (p *Phone) getLoggerCtx(ctx context.Context, caller string) zerolog.Logger {
	l := ctx.Value(ContextLoggerKey)
	if l != nil {
		log, ok := l.(zerolog.Logger)
		if ok {
			return log
		}
	}
	return p.log.With().Str("caller", caller).Logger()
}

func (p *Phone) getInterfaceAddr(network string, targetAddr string) (addr string, err error) {
	host, port, err := p.getInterfaceHostPort(network, targetAddr)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func (p *Phone) getInterfaceHostPort(network string, targetAddr string) (ipstr string, port int, err error) {
	for _, a := range p.listenAddrs {
		if a.Network == network {
			return sip.ParseAddr(a.Addr)
		}
	}

	// Go with random
	port = rand.Intn(9999) + 6000

	if network == "udp" {
		tip, _, _ := sip.ParseAddr(targetAddr)
		if ip := net.ParseIP(tip); ip != nil {
			if ip.IsLoopback() {
				// TO avoid UDP COnnected connection problem hitting different subnet
				return "127.0.0.99", port, nil
			}
		}
	}

	ip, err := sip.ResolveSelfIP()
	return ip.String(), port, err
}

func (p *Phone) createServerListener(s *sipgo.Server, a ListenAddr) (*Listener, error) {

	network, addr := a.Network, a.Addr
	switch network {
	case "udp":
		// resolve local UDP endpoint
		laddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("fail to resolve address. err=%w", err)
		}
		udpConn, err := net.ListenUDP("udp", laddr)
		if err != nil {
			return nil, fmt.Errorf("listen udp error. err=%w", err)
		}

		return &Listener{
			a,
			udpConn,
			func() error { return s.ServeUDP(udpConn) },
		}, nil

	case "ws", "tcp":
		laddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("fail to resolve address. err=%w", err)
		}

		conn, err := net.ListenTCP("tcp", laddr)
		if err != nil {
			return nil, fmt.Errorf("listen tcp error. err=%w", err)
		}

		// and uses listener to buffer
		if network == "ws" {
			return &Listener{
				a,
				conn,
				func() error { return s.ServeWS(conn) },
			}, nil
		}

		return &Listener{
			a,
			conn,
			func() error { return s.ServeTCP(conn) },
		}, nil
	}
	return nil, fmt.Errorf("Unsuported protocol")
}

func (p *Phone) createServerListeners(s *sipgo.Server) (listeners []*Listener, e error) {
	newListener := func(a ListenAddr) error {
		l, err := p.createServerListener(s, a)
		if err != nil {
			return err
		}

		listeners = append(listeners, l)
		return nil
	}

	if len(p.listenAddrs) == 0 {
		addr, _ := p.getInterfaceAddr("udp", "")
		err := newListener(ListenAddr{Network: "udp", Addr: addr})
		return listeners, err
	}

	for _, a := range p.listenAddrs {
		err := newListener(a)
		if err != nil {
			return nil, err
		}
	}
	return listeners, nil
}

var (
	ErrRegisterFail        = fmt.Errorf("register failed")
	ErrRegisterUnathorized = fmt.Errorf("register unathorized")
)

type RegisterOptions struct {
	Username string
	Password string
}

// Register the phone by sip uri. Pass username and password via opts
// NOTE: this will block and keep periodic registration. Use context to cancel
func (p *Phone) Register(ctx context.Context, recipient sip.Uri, opts RegisterOptions) error {
	// Make our client reuse address
	network := recipient.Headers["transport"]
	lhost, lport, _ := p.getInterfaceHostPort(network, recipient.HostPort())
	addr := net.JoinHostPort(lhost, strconv.Itoa(lport))

	client, err := sipgo.NewClient(p.ua,
		sipgo.WithClientAddr(addr),
		sipgo.WithClientNAT(), // add rport support
	)
	defer client.Close()

	contactHdr := sip.ContactHeader{
		Address: sip.Uri{
			User:      p.ua.Name(),
			Host:      lhost,
			Port:      lport,
			Headers:   sip.HeaderParams{"transport": network},
			UriParams: sip.NewParams(),
		},
		Params: sip.NewParams(),
	}

	ticker := time.NewTicker(30 * time.Second)
	regReq, err := p.register(ctx, client, recipient, contactHdr, registerOpts{
		Username: opts.Username,
		Password: opts.Password,
		Expiry:   30,
	})
	if err != nil {
		return err
	}

	// Unregister
	defer func() {
		err := p.unregister(context.TODO(), client, regReq, opts.Username, opts.Password)
		if err != nil {
			log.Error().Err(err).Msg("Fail to unregister")
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C: // TODO make configurable
		}
		err := p.registerQualify(ctx, client, regReq, opts.Username, opts.Password)
		if err != nil {
			return err
		}
	}
}

type registerOpts struct {
	Username     string
	Password     string
	Expiry       int
	AllowHeaders []string
}

func (p *Phone) register(ctx context.Context, client *sipgo.Client, recipient sip.Uri, contact sip.ContactHeader, opts registerOpts) (*sip.Request, error) {
	username, password, expiry, allowHDRS := opts.Username, opts.Password, opts.Expiry, opts.AllowHeaders
	log := p.getLoggerCtx(ctx, "Register")

	req := sip.NewRequest(sip.REGISTER, &recipient)
	req.AppendHeader(&contact)
	expires := sip.ExpiresHeader(expiry)
	req.AppendHeader(&expires)
	if allowHDRS != nil {
		req.AppendHeader(sip.NewHeader("Allow", strings.Join(allowHDRS, ", ")))
	}

	// Send request and parse response
	// req.SetDestination(*dst)
	log.Info().Str("uri", req.Recipient.String()).Int("expiry", int(expiry)).Msg("sending request")
	tx, err := client.TransactionRequest(ctx, req)
	if err != nil {
		return req, fmt.Errorf("fail to create transaction req=%q: %w", req.StartLine(), err)
	}
	defer tx.Terminate()

	res, err := getResponse(ctx, tx)
	if err != nil {
		return req, fmt.Errorf("fail to get response req=%q : %w", req.StartLine(), err)
	}

	via := res.Via()
	if via == nil {
		return nil, fmt.Errorf("No Via header in response")
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
			return req, err
		}
		defer tx.Terminate()

		res, err = getResponse(ctx, tx)
		if err != nil {
			return req, fmt.Errorf("fail to get response req=%q : %w", req.StartLine(), err)
		}
		log.Info().Int("status", int(res.StatusCode)).Msg("Received status")
	}

	if res.StatusCode != 200 {
		return req, fmt.Errorf("%s: %w", res.StartLine(), ErrRegisterFail)
	}

	return req, nil
}

func (p *Phone) unregister(ctx context.Context, client *sipgo.Client, req *sip.Request, username string, password string) error {
	log := p.getLoggerCtx(ctx, "Unregister")
	req.RemoveHeader("Expires")
	req.RemoveHeader("Contact")
	req.AppendHeader(sip.NewHeader("Contact", "*"))
	expires := sip.ExpiresHeader(0)
	req.AppendHeader(&expires)

	log.Info().Str("uri", req.Recipient.String()).Msg("sending request")
	return p.registerQualify(ctx, client, req, username, password)
}

func (p *Phone) registerQualify(ctx context.Context, client *sipgo.Client, req *sip.Request, username string, password string) error {
	log := p.getLoggerCtx(ctx, "Register")

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
		return fmt.Errorf("%s: %w", res.StartLine(), ErrRegisterFail)
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("%s: %w", res.StartLine(), ErrRegisterFail)
	}

	return nil
}

type DialResponseError struct {
	InviteReq  *sip.Request
	InviteResp *sip.Response

	Msg string
}

func (e *DialResponseError) StatusCode() sip.StatusCode {
	return e.InviteResp.StatusCode
}

func (e DialResponseError) Error() string {
	return e.Msg
}

type DialOptions struct {
	// Authentication via digest challenge
	Username string
	Password string

	// Custom headers passed on INVITE
	SipHeaders []sip.Header

	Formats Formats
}

// Dial creates dialog with recipient
//
// return DialResponseError in case non 200 responses
func (p *Phone) Dial(dialCtx context.Context, recipient sip.Uri, o DialOptions) (*DialogClientSession, error) {
	log := p.getLoggerCtx(dialCtx, "Dial")
	ctx, _ := context.WithCancel(dialCtx)
	// defer cancel()

	network := "udp"
	if recipient.UriParams != nil {
		if t := recipient.UriParams["transport"]; t != "" {
			network = t
		}
	}
	// Remove password from uri.
	recipient.Password = ""

	// Get our address.
	// TODO have a interface for defining instead listen
	host, listenPort, err := p.getInterfaceHostPort(network, recipient.HostPort())
	if err != nil {
		return nil, fmt.Errorf("Parsing interface host port failed. Check ListenAddr for defining : %w", err)
	}
	contactUri := sip.Uri{User: p.ua.Name(), Host: host, Port: listenPort}
	contactHDR := sip.ContactHeader{
		Address: contactUri,
		Params:  sip.HeaderParams{"transport": network},
	}

	client, err := sipgo.NewClient(p.ua,
		// We must have this address for Contact header
		sipgo.WithClientHostname(host),
		sipgo.WithClientPort(listenPort),
	)
	if err != nil {
		return nil, err
	}

	server, err := sipgo.NewServer(p.ua)
	if err != nil {
		return nil, err
	}

	dc := sipgo.NewDialogClient(client, contactHDR)
	dialogCh := make(chan struct{})
	// Setup srv for bye
	server.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		close(dialogCh)
		if err := dc.ReadBye(req, tx); err != nil {
			log.Error().Err(err).Msg("Fail to setup client handle")
			return
		}
		log.Debug().Msg("Received BYE")
	})

	// TODO setup session before
	rtpIp := p.ua.GetIP()
	msess, err := NewMediaSession(&net.UDPAddr{IP: rtpIp, Port: 0}, nil)
	if err != nil {
		return nil, err
	}

	// Create Generic SDP
	sdpSend := msess.localSDP(o.Formats)

	// Creating INVITE
	req := sip.NewRequest(sip.INVITE, &recipient)
	req.SetTransport(network)
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	req.SetBody(sdpSend)

	// Add custom headers
	for _, h := range o.SipHeaders {
		log.Info().Str(h.Name(), h.Value()).Msg("Adding SIP header")
		req.AppendHeader(h)
	}

	waitStart := time.Now()
	dialog, err := dc.WriteInvite(ctx, req)
	if err != nil {
		return nil, err
	}

	log.Info().
		Str("Call-ID", req.CallID().Value()).
		// Str("FromAddr", req.From().Address.Addr()).
		// Str("ToAddr", req.To().Address.Addr()).
		Msgf("Request: %s", req.StartLine())

	// Wait 200
	err = dialog.WaitAnswer(ctx, sipgo.AnswerOptions{
		OnResponse: func(res *sip.Response) {
			log.Info().Msgf("Response: %s", res.StartLine())
		},
		Username: o.Username,
		Password: o.Password,
	})

	var rerr *sipgo.ErrDialogResponse
	if errors.As(err, &rerr) {
		return nil, &DialResponseError{
			InviteReq:  req,
			InviteResp: rerr.Res,
			Msg:        fmt.Sprintf("Call not answered: %s", rerr.Res.StartLine()),
		}
	}

	if err != nil {
		return nil, err
	}

	r := dialog.InviteResponse
	log.Info().
		Int("code", int(r.StatusCode)).
		// Str("reason", r.Reason).
		Str("duration", time.Since(waitStart).String()).
		Msg("Call answered")

	// Setup media
	err = msess.remoteSDP(r.Body())
	// TODO handle bad SDP
	if err != nil {
		return nil, err
	}

	log.Info().
		Str("formats", FormatsList(msess.Formats).String()).
		Str("localAddr", msess.Laddr.String()).
		Str("remoteAddr", msess.Raddr.String()).
		Msg("Media/RTP session created")

	// Send ACK
	if err := dialog.Ack(ctx); err != nil {
		return nil, fmt.Errorf("fail to send ACK: %w", err)
	}

	return &DialogClientSession{
		MediaSession:        msess,
		DialogClientSession: dialog,
	}, nil
}

var (
	// You can use this key with AnswerReadyCtxValue to get signal when
	// Answer is ready to receive traffic
	AnswerReadyCtxKey = "AnswerReadyCtxKey"
)

type AnswerReadyCtxValue chan struct{}
type AnswerOptions struct {
	Ringtime   time.Duration
	SipHeaders []sip.Header

	// For authorizing INVITE unless RegisterAddr is defined
	Username string
	Password string
	Realm    string //default sipgo

	RegisterAddr string //If defined it will keep registration in background

	// For SDP codec manipulating
	Formats Formats

	// Default is 200 (answer a call)
	answerCode   sip.StatusCode
	answerReason string
}

// Answer will answer call
// Closing ansCtx will close listeners or it will be closed on BYE
// TODO: reusing listener
func (p *Phone) Answer(ansCtx context.Context, opts AnswerOptions) (*DialogServerSession, error) {
	log := p.getLoggerCtx(ansCtx, "Answer")
	ringtime := opts.Ringtime

	waitDialog := make(chan *DialogServerSession)
	var d *DialogServerSession

	// TODO reuse server and listener
	server, err := sipgo.NewServer(p.ua)
	if err != nil {
		return nil, err
	}

	// We need to listen as long our answer context is running
	// Listener needs to be alive even after we have created dialog
	listeners, err := p.createServerListeners(server)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ansCtx)
	var exitErr error
	stopAnswer := sync.OnceFunc(func() {
		cancel() // Cancel context
		for _, l := range listeners {
			l.Close()
		}
	})

	exitError := func(err error) {
		exitErr = err
	}

	lhost, lport, _ := sip.ParseAddr(listeners[0].Addr)
	contactHdr := sip.ContactHeader{
		Address: sip.Uri{
			User:      p.ua.Name(),
			Host:      lhost,
			Port:      lport,
			Headers:   sip.HeaderParams{"transport": listeners[0].Network},
			UriParams: sip.NewParams(),
		},
		Params: sip.NewParams(),
	}

	// Create client handle for responding
	client, _ := sipgo.NewClient(p.ua)

	if opts.RegisterAddr != "" {
		// We will use registration to resolve NAT
		client, _ = sipgo.NewClient(p.ua,
			sipgo.WithClientNAT(),
		)

		// Keep registration
		rhost, rport, _ := sip.ParseAddr(opts.RegisterAddr)
		registerURI := sip.Uri{
			Host: rhost,
			Port: rport,
			User: p.ua.Name(),
		}

		regReq, err := p.register(ctx, client, registerURI, contactHdr, registerOpts{
			Username: opts.Username,
			Password: opts.Password,
			Expiry:   30,
			// AllowHeaders: server.RegisteredMethods(),
		})
		if err != nil {
			return nil, err
		}

		// In case our register changed contact due to NAT detection via rport, lets update
		contact := regReq.Contact()
		contactHdr = *contact.Clone()

		origStopAnswer := stopAnswer
		go func(ctx context.Context) {
			ticker := time.NewTicker(30 * time.Second)

			// Override stopAnswer with unregister
			stopAnswer = sync.OnceFunc(func() {
				err := p.unregister(context.TODO(), client, regReq, opts.Username, opts.Password)
				if err != nil {
					log.Error().Err(err).Msg("Fail to unregister")
				}
				regReq = nil
				origStopAnswer()
			})
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C: // TODO make configurable
				}

				err := p.registerQualify(ctx, client, regReq, opts.Username, opts.Password)
				if err != nil {
					exitError(err)
					stopAnswer()
					return
				}
			}
		}(ctx)
	}

	ds := sipgo.NewDialogServer(client, contactHdr)
	var chal *digest.Challenge
	server.OnInvite(func(req *sip.Request, tx sip.ServerTransaction) {
		if d != nil {
			didAnswered, _ := sip.MakeDialogIDFromResponse(d.InviteResponse)
			did, _ := sip.MakeDialogIDFromRequest(req)
			if did == didAnswered {
				// We received INVITE for update
				if err := d.MediaSession.UpdateDestinationSDP(req.Body()); err != nil {
					res := sip.NewResponseFromRequest(req, 400, err.Error(), nil)
					if err := tx.Respond(res); err != nil {
						log.Error().Err(err).Msg("Fail to send 400")
						return
					}
					return
				}

				res := sip.NewResponseFromRequest(req, 200, "OK", nil)
				if err := tx.Respond(res); err != nil {
					log.Error().Err(err).Msg("Fail to send 200")
					return
				}
				return
			}
			log.Error().Msg("Received second INVITE is not yet supported")
			return
		}

		// We authorize request if password provided and no register addr defined
		// Use cases:
		// 1. INVITE auth like registrar before processing INVITE
		// 2. Auto answering client which keeps registration and accepts calls
		if opts.Password != "" && opts.RegisterAddr == "" {
			// https://www.rfc-editor.org/rfc/rfc2617#page-6
			h := req.GetHeader("Authorization")

			if h == nil {
				if chal != nil {
					// If challenge is created next is forbidden
					res := sip.NewResponseFromRequest(req, 403, "Forbidden", nil)
					tx.Respond(res)
					return
				}

				if opts.Realm == "" {
					opts.Realm = "sipgo"
				}

				chal = &digest.Challenge{
					Realm: opts.Realm,
					Nonce: fmt.Sprintf("%d", time.Now().UnixMicro()),
					// Opaque:    "sipgo",
					Algorithm: "MD5",
				}

				res := sip.NewResponseFromRequest(req, 401, "Unathorized", nil)
				res.AppendHeader(sip.NewHeader("WWW-Authenticate", chal.String()))
				tx.Respond(res)
				return
			}

			cred, err := digest.ParseCredentials(h.Value())
			if err != nil {
				log.Error().Err(err).Msg("parsing creds failed")
				tx.Respond(sip.NewResponseFromRequest(req, 401, "Bad credentials", nil))
				return
			}

			// Make digest and compare response
			digCred, err := digest.Digest(chal, digest.Options{
				Method:   "INVITE",
				URI:      cred.URI,
				Username: opts.Username,
				Password: opts.Password,
			})

			if err != nil {
				log.Error().Err(err).Msg("Calc digest failed")
				tx.Respond(sip.NewResponseFromRequest(req, 401, "Bad credentials", nil))
				return
			}

			if cred.Response != digCred.Response {
				tx.Respond(sip.NewResponseFromRequest(req, 401, "Unathorized", nil))
				return
			}
			log.Info().Str("username", cred.Username).Str("source", req.Source()).Msg("INVITE authorized")
		}

		from := req.From()
		log.Info().Str("from", from.Address.Addr()).Str("name", from.DisplayName).Msg("Received call")

		err := func() error {
			dialog, err := ds.ReadInvite(req, tx)
			if err != nil {
				res := sip.NewResponseFromRequest(req, 400, err.Error(), nil)
				if err := tx.Respond(res); err != nil {
					log.Error().Err(err).Msg("Failed to send 400 response")
				}
				return err
			}

			if opts.answerCode > 0 && opts.answerCode != sip.StatusOK {
				if err := dialog.Respond(opts.answerCode, opts.answerReason, nil); err != nil {
					d = nil
					return fmt.Errorf("Failed to respond custom status code %d: %w", int(opts.answerCode), err)
				}

				d = &DialogServerSession{
					DialogServerSession: dialog,
					// done:                make(chan struct{}),
				}
				select {
				case <-tx.Done():
				case <-tx.Acks():
					// Wait for ack
					waitDialog <- d
				case <-ctx.Done():
				}
				return nil
			}

			if err != nil {
				return fmt.Errorf("fail to setup client handle: %w", err)
			}

			// Now place a ring tone or do autoanswer
			if ringtime > 0 {
				res := sip.NewResponseFromRequest(req, 180, "Ringing", nil)
				if err := dialog.WriteResponse(res); err != nil {
					return fmt.Errorf("failed to send 180 response: %w", err)
				}
				log.Info().Msgf("Response: %s", res.StartLine())

				select {
				case <-tx.Cancels():
					return fmt.Errorf("Received CANCEL")
				case <-tx.Done():
					return fmt.Errorf("Invite transaction finished while ringing")
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(ringtime):
					// Ring time finished
				}
			} else {
				// Send progress
				res := sip.NewResponseFromRequest(req, 100, "Trying", nil)
				if err := dialog.WriteResponse(res); err != nil {
					return fmt.Errorf("Fail to send 100 response: %w", err)
				}

				log.Info().Msgf("Response: %s", res.StartLine())
			}

			// Setup media
			msess, answerSD, err := func() (*MediaSession, []byte, error) {
				// for {
				// Now generate answer with our rtp ports
				ip := p.ua.GetIP()
				// rtpPort := rand.Intn(1000*2)/2 + 6000
				msess, err := NewMediaSession(&net.UDPAddr{IP: ip, Port: 0}, nil)
				if err != nil {
					return nil, nil, err
				}

				err = msess.remoteSDP(req.Body())
				if err != nil {
					return nil, nil, err
				}

				answerSD := msess.localSDP(opts.Formats)
				return msess, answerSD, err
			}()

			if err != nil {
				return fmt.Errorf("Fail to setup media session: %w", err)
			}

			log.Info().
				Ints("formats", msess.Formats).
				Str("localAddr", msess.Laddr.String()).
				Str("remoteAddr", msess.Raddr.String()).
				Msg("Media/RTP session created")

			res := sip.NewSDPResponseFromRequest(req, answerSD)
			// via, _ := res.Via()
			// via.Params["received"] = rhost
			// via.Params["rport"] = strconv.Itoa(rport)

			// Add custom headers
			for _, h := range opts.SipHeaders {
				log.Info().Str(h.Name(), h.Value()).Msg("Adding SIP header")
				res.AppendHeader(h)
			}

			d = &DialogServerSession{
				DialogServerSession: dialog,
				MediaSession:        msess,
				// done:                make(chan struct{}),
			}

			if err := dialog.WriteResponse(res); err != nil {
				d = nil
				return fmt.Errorf("Fail to send 200 response: %w", err)
			}
			log.Info().Msgf("Response: %s", res.StartLine())

			// FOR ASTERISK YOU NEED TO REPLY WITH SAME RECIPIENT
			// IN CASE PROXY AND IN DIALOG handling this must be contact address -.-
			// if req.GetHeader("Record-Route") == nil {
			// 	f, _ := req.From()
			// 	d.contact = &f.Address
			// 	d.destination = req.Source()
			// }

			// applyCodecs(msess, sd)

			// defer close(d.done)

			select {
			case <-tx.Done():
				// This can be as well TIMER L, which means we received ACK and no more retransmission of 200 will be done
			case <-ctx.Done():
				// We have received BYE OR Cancel, so we will ignore transaction waiting.
			}

			if err := tx.Err(); err != nil {
				return fmt.Errorf("Invite transaction ended with error: %w", err)
			}
			return nil
		}()

		if err != nil {
			exitError(err)
			stopAnswer()
		}

	})

	server.OnAck(func(req *sip.Request, tx sip.ServerTransaction) {
		// This on 2xx
		if d == nil {
			if chal != nil {
				// Ack is for authorization
				return
			}

			exitError(fmt.Errorf("Received ack but no dialog"))
			stopAnswer()
		}

		if err := ds.ReadAck(req, tx); err != nil {
			exitError(fmt.Errorf("Dialog ACK err: %w", err))
			stopAnswer()
			return
		}

		select {
		case waitDialog <- d:
			// Reset dialog for next receive
			d = nil
		case <-ctx.Done():
		}

		// Needs check for SDP is right?
	})

	server.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		if err := ds.ReadBye(req, tx); err != nil {
			exitError(fmt.Errorf("Dialog BYE err: %w", err))
			return
		}

		stopAnswer() // This will close listener

		// // Close dialog as well
		// if d != nil {
		// 	close(d.done)
		// 	d = nil
		// }
	})

	server.OnOptions(func(req *sip.Request, tx sip.ServerTransaction) {
		res := sip.NewResponseFromRequest(req, 200, "OK", nil)
		tx.Respond(res)
	})

	for _, l := range listeners {
		log.Info().Str("network", l.Network).Str("addr", l.Addr).Msg("Listening on")
		go l.Listen()
	}

	if v := ctx.Value(AnswerReadyCtxKey); v != nil {
		close(v.(AnswerReadyCtxValue))
	}

	log.Info().Msg("Waiting for INVITE...")
	select {
	case d = <-waitDialog:
		// Make sure we have cleanup after dialog stop
		go func() {
			select {
			case <-d.Done():
				stopAnswer()
			}
		}()

		return d, nil
	case <-ctx.Done():
		// Check is this caller stopped answer
		if ansCtx.Err() != nil {
			stopAnswer()
			return nil, ansCtx.Err()
		}

		// This is when our processing of answer stopped
		return nil, exitErr
	}
}

// AnswerWithCode will answer with custom code
// Dialog object is created but it is immediately closed
func (p *Phone) AnswerWithCode(ansCtx context.Context, code sip.StatusCode, reason string, opts AnswerOptions) (*DialogServerSession, error) {
	// TODO, do all options make sense?
	opts.answerCode = code
	opts.answerReason = reason
	dialog, err := p.Answer(ansCtx, opts)
	if err != nil {
		return nil, err
	}

	if !dialog.InviteResponse.IsSuccess() {
		return dialog, dialog.Close()
	}
	// Return closed/terminated dialog
	return dialog, nil
}

func (p *Phone) generateSDP(ip net.IP, rtpPort int, f Formats) []byte {
	if !f.Alaw && !f.Ulaw {
		f = Formats{
			Ulaw: true, // Enable only ulaw
		}
	}

	return SDPGeneric(ip, ip, rtpPort, SDPModeSendrecv, f)
}

func getResponse(ctx context.Context, tx sip.ClientTransaction) (*sip.Response, error) {
	select {
	case <-tx.Done():
		return nil, fmt.Errorf("transaction died")
	case res := <-tx.Responses():
		return res, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// digestTransactionRequest checks response if 401 and sends digest auth
// TODO maybe this should be part of client
func digestTransactionRequest(client *sipgo.Client, username string, password string, req *sip.Request, res *sip.Response) (sip.ClientTransaction, error) {
	// Get WwW-Authenticate
	wwwAuth := res.GetHeader("WWW-Authenticate")
	chal, err := digest.ParseChallenge(wwwAuth.Value())
	if err != nil {
		return nil, fmt.Errorf("fail to parse chalenge wwwauth=%q: %w", wwwAuth.Value(), err)
	}

	// Reply with digest
	cred, err := digest.Digest(chal, digest.Options{
		Method:   req.Method.String(),
		URI:      req.Recipient.Addr(),
		Username: username,
		Password: password,
	})
	if err != nil {
		return nil, fmt.Errorf("fail to build digest: %w", err)
	}

	cseq := req.CSeq()
	cseq.SeqNo++
	// newReq := req.Clone()

	req.AppendHeader(sip.NewHeader("Authorization", cred.String()))
	defer req.RemoveHeader("Authorization")

	req.RemoveHeader("Via")
	tx, err := client.TransactionRequest(context.TODO(), req, sipgo.ClientRequestAddVia)
	return tx, err
}
