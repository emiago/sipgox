package sipgox

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/emiago/sipgox/sdp"
	"github.com/icholy/digest"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Phone is easy wrapper for creating phone like functionaliy
// but actions are creating clients and servers on a fly so
// it is not designed for long running apps

var (
	// Value must be zerolog.Logger
	ContextLoggerKey = "logger"
)

type Phone struct {
	UA *sipgo.UserAgent
	// listenAddrs is map of transport:addr which will phone use to listen incoming requests
	listenAddrs []ListenAddr

	log zerolog.Logger

	// Custom client or server
	// By default they are created
	client *sipgo.Client
	server *sipgo.Server
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

// func WithPhoneClient(c *sipgo.Client) PhoneOption {
// 	return func(p *Phone) {
// 		p.client = c
// 	}
// }

// func WithPhoneServer(s *sipgo.Server) PhoneOption {
// 	return func(p *Phone) {
// 		p.server = s
// 	}
// }

func NewPhone(ua *sipgo.UserAgent, options ...PhoneOption) *Phone {
	p := &Phone{
		UA: ua,
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

// func (p *Phone) getOrCreateClient(opts ...sipgo.ClientOption) (*sipgo.Client, error) {
// 	if p.client != nil {
// 		return p.client, nil
// 	}

// 	return sipgo.NewClient(p.ua, opts...)
// }

// func (p *Phone) getOrCreateServer(opts ...sipgo.ServerOption) (*sipgo.Server, error) {
// 	if p.server != nil {
// 		return p.server, nil
// 	}

// 	return sipgo.NewServer(p.ua, opts...)
// }

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

		// Port can be dynamic
		a.Addr = udpConn.LocalAddr().String()

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

		a.Addr = conn.Addr().String()
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
	return nil, fmt.Errorf("unsuported protocol")
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
		addr, err := p.getInterfaceAddr("udp", "")
		if err != nil {
			return listeners, err
		}
		err = newListener(ListenAddr{Network: "udp", Addr: addr})
		// ip, err := resolveHostIPWithTarget("udp", "")
		// if err != nil {
		// 	return listeners, err
		// }
		// err = newListener(ListenAddr{Network: "udp", Addr: ip.String() + ":0"})
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

func (p *Phone) getInterfaceHostPort(network string, targetAddr string) (host string, port int, err error) {
	for _, a := range p.listenAddrs {
		if a.Network == network {
			host, port, err = sip.ParseAddr(a.Addr)
			if err != nil {
				return
			}

			// What is with port
			// If user provides this 127.0.0.1:0 -> then this tell us to use random port
			// If user provides this non IP then port will stay empty
			if port != 0 {
				return
			}

			ip := net.ParseIP(host)
			if ip != nil {
				port, err = findFreePort(network, ip)
				return
			}

			// port = sip.DefaultPort(network)
			return
		}
	}

	ip, port, err := FindFreeInterfaceHostPort(network, targetAddr)
	if err != nil {
		return "", 0, err
	}
	return ip.String(), port, nil
}

var (
	ErrRegisterFail        = fmt.Errorf("register failed")
	ErrRegisterUnathorized = fmt.Errorf("register unathorized")
)

type RegisterResponseError struct {
	RegisterReq *sip.Request
	RegisterRes *sip.Response

	Msg string
}

func (e *RegisterResponseError) StatusCode() sip.StatusCode {
	return e.RegisterRes.StatusCode
}

func (e RegisterResponseError) Error() string {
	return e.Msg
}

// Register the phone by sip uri. Pass username and password via opts
// NOTE: this will block and keep periodic registration. Use context to cancel
type RegisterOptions struct {
	Username string
	Password string

	Expiry        int
	AllowHeaders  []string
	UnregisterAll bool
}

func (p *Phone) Register(ctx context.Context, recipient sip.Uri, opts RegisterOptions) error {
	log := p.getLoggerCtx(ctx, "Register")
	// Make our client reuse address
	network := recipient.Headers["transport"]
	if network == "" {
		network = "udp"
	}
	lhost, lport, _ := p.getInterfaceHostPort(network, recipient.HostPort())
	// addr := net.JoinHostPort(lhost, strconv.Itoa(lport))

	// Run server on UA just to handle OPTIONS
	// We do not need to create listener as client will create underneath connections and point contact header
	server, err := sipgo.NewServer(p.UA)
	if err != nil {
		return err
	}
	defer server.Close()

	server.OnOptions(func(req *sip.Request, tx sip.ServerTransaction) {
		res := sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil)
		if err := tx.Respond(res); err != nil {
			log.Error().Err(err).Msg("OPTIONS 200 failed to respond")
		}
	})

	client, err := sipgo.NewClient(p.UA,
		sipgo.WithClientHostname(lhost),
		sipgo.WithClientPort(lport),
		sipgo.WithClientNAT(), // add rport support
	)
	defer client.Close()

	contactHdr := sip.ContactHeader{
		Address: sip.Uri{
			User:      p.UA.Name(),
			Host:      lhost,
			Port:      lport,
			Headers:   sip.HeaderParams{"transport": network},
			UriParams: sip.NewParams(),
		},
		Params: sip.NewParams(),
	}

	t, err := p.register(ctx, client, recipient, contactHdr, opts)
	if err != nil {
		return err
	}

	// Unregister
	defer func() {
		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
		err := t.Unregister(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Fail to unregister")
		}
	}()

	return t.QualifyLoop(ctx)
}

func (p *Phone) register(ctx context.Context, client *sipgo.Client, recipient sip.Uri, contact sip.ContactHeader, opts RegisterOptions) (*RegisterTransaction, error) {
	t := NewRegisterTransaction(p.getLoggerCtx(ctx, "Register"), client, recipient, contact, opts)

	if opts.UnregisterAll {
		if err := t.Unregister(ctx); err != nil {
			return nil, ErrRegisterFail
		}
	}

	err := t.Register(ctx, recipient)
	if err != nil {
		return nil, err
	}

	return t, nil
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

	// SDP Formats to customize. NOTE: Only ulaw and alaw are fully supported
	Formats sdp.Formats

	// OnResponse is just callback called after INVITE is sent and all responses before final one
	// Useful for tracking call state
	OnResponse func(inviteResp *sip.Response)

	// OnRefer is called 2 times.
	// 1st with state NONE and dialog=nil. This is to have caller prepared
	// 2nd with state Established or Ended with dialog
	OnRefer func(state DialogReferState)
}

type DialogReferState struct {
	// Updates current transfer progress with state
	State sip.DialogState
	// Dialog present when state is answered (Confirmed dialog state)
	Dialog *DialogClientSession
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

	server, err := sipgo.NewServer(p.UA)
	if err != nil {
		return nil, err
	}

	// We need to listen as long our answer context is running
	// Listener needs to be alive even after we have created dialog
	// listeners, err := p.createServerListeners(server)
	// if err != nil {
	// 	return nil, err
	// }
	// host, listenPort, _ := sip.ParseAddr(listeners[0].Addr)

	// NOTE: this can return empty port, in this case we probably have hostname
	host, port, err := p.getInterfaceHostPort(network, recipient.HostPort())
	if err != nil {
		return nil, err
	}

	contactHDR := sip.ContactHeader{
		Address: sip.Uri{User: p.UA.Name(), Host: host, Port: port},
		Params:  sip.HeaderParams{"transport": network},
	}

	// We will force client to use same interface and port as defined for contact header
	// The problem could be if this is required to be different, but for now keeping phone simple
	client, err := sipgo.NewClient(p.UA,
		sipgo.WithClientHostname(host),
		sipgo.WithClientPort(port),
	)
	if err != nil {
		return nil, err
	}

	// Setup dialog client
	dc := sipgo.NewDialogClient(client, contactHDR)

	server.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		if err := dc.ReadBye(req, tx); err != nil {
			if errors.Is(err, sipgo.ErrDialogDoesNotExists) {
				log.Info().Msg("Received BYE but dialog was already closed")
				return
			}

			log.Error().Err(err).Msg("Dialog reading BYE failed")
			return
		}
		log.Debug().Msg("Received BYE")
	})

	server.OnRefer(func(req *sip.Request, tx sip.ServerTransaction) {
		if o.OnRefer == nil {
			log.Warn().Str("req", req.StartLine()).Msg("Refer is not handled. Missing OnRefer")
			tx.Respond(sip.NewResponseFromRequest(req, sip.StatusMethodNotAllowed, "Method not allowed", nil))
			return
		}

		var dialog *sipgo.DialogClientSession
		var newDialog *DialogClientSession
		var err error
		// TODO refactor this
		refer := func() error {
			referUri := sip.Uri{}
			dialog, err = dc.ReadRefer(req, tx, &referUri)
			if err != nil {
				return err
			}

			// Setup session
			rtpIp := p.UA.GetIP()
			if lip := net.ParseIP(host); lip != nil && !lip.IsUnspecified() {
				rtpIp = lip
			}
			msess, err := NewMediaSession(&net.UDPAddr{IP: rtpIp, Port: 0})
			if err != nil {
				return err
			}

			notifyAccepted := true
			{
				// Do Notify
				log.Info().Msg("Sending NOTIFY")
				notify := sip.NewRequest(sip.NOTIFY, req.Contact().Address)
				notify.AppendHeader(sip.NewHeader("Content-Type", "message/sipfrag;version=2.0"))
				notify.SetBody([]byte("SIP/2.0 100 Trying"))
				cliTx, err := dialog.TransactionRequest(dialog.Context(), notify)
				if err != nil {
					return err
				}
				defer cliTx.Terminate()

				select {
				case <-cliTx.Done():
				case res := <-cliTx.Responses():
					notifyAccepted = res.StatusCode == sip.StatusOK
				}
			}

			invite := sip.NewRequest(sip.INVITE, referUri)
			invite.SetTransport(network)
			invite.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
			invite.SetBody(msess.LocalSDP())

			newDialog, err = p.dial(context.TODO(), dc, invite, msess, o)
			if err != nil {
				return err
			}

			if notifyAccepted {
				notify := sip.NewRequest(sip.NOTIFY, req.Contact().Address)
				notify.AppendHeader(sip.NewHeader("Content-Type", "message/sipfrag;version=2.0"))
				notify.SetBody([]byte("SIP/2.0 200 OK"))
				cliTx, err := dialog.TransactionRequest(dialog.Context(), notify)
				if err != nil {
					return err
				}
				defer cliTx.Terminate()
			}
			return nil
		}

		// Refer can happen and due to new dialog creation current one could be terminated.
		// Caller would not be able to get control of new dialog until it is answered
		// This way we say to caller to wait transfer completition, and current dialog can be terminated
		o.OnRefer(DialogReferState{State: 0})
		if err := refer(); err != nil {
			log.Error().Err(err).Msg("Fail to dial REFER")
			// Handle better this errors
			tx.Respond(sip.NewResponseFromRequest(req, sip.StatusInternalServerError, err.Error(), nil))
			o.OnRefer(DialogReferState{State: sip.DialogStateEnded})
			return
		}

		// Let caller decide will it close current dialog or continue with transfer
		// defer dialog.Close()
		// defer dialog.Bye(context.TODO())

		o.OnRefer(DialogReferState{State: sip.DialogStateConfirmed, Dialog: newDialog})
	})

	// Start server
	// for _, l := range listeners {
	// 	log.Info().Str("network", l.Network).Str("addr", l.Addr).Msg("Listening on")
	// 	go l.Listen()
	// }

	// Setup session
	rtpIp := p.UA.GetIP()
	if lip := net.ParseIP(host); lip != nil && !lip.IsUnspecified() {
		rtpIp = lip
	}
	msess, err := NewMediaSession(&net.UDPAddr{IP: rtpIp, Port: 0})
	if err != nil {
		return nil, err
	}

	// Create Generic SDP
	if len(o.Formats) > 0 {
		msess.Formats = o.Formats
	}
	sdpSend := msess.LocalSDP()

	// Creating INVITE
	req := sip.NewRequest(sip.INVITE, recipient)
	req.SetTransport(network)
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	req.SetBody(sdpSend)

	// Add custom headers
	for _, h := range o.SipHeaders {
		log.Info().Str(h.Name(), h.Value()).Msg("Adding SIP header")
		req.AppendHeader(h)
	}

	dialog, err := p.dial(ctx, dc, req, msess, o)
	if err != nil {
		return nil, err
	}

	return dialog, nil
}

func (p *Phone) dial(ctx context.Context, dc *sipgo.DialogClient, invite *sip.Request, msess *MediaSession, o DialOptions) (*DialogClientSession, error) {
	log := p.getLoggerCtx(ctx, "Dial")
	dialog, err := dc.WriteInvite(ctx, invite)
	if err != nil {
		return nil, err
	}
	p.logSipRequest(&log, invite)
	return p.dialWaitAnswer(ctx, dialog, msess, o)
}

func (p *Phone) dialWaitAnswer(ctx context.Context, dialog *sipgo.DialogClientSession, msess *MediaSession, o DialOptions) (*DialogClientSession, error) {
	log := p.getLoggerCtx(ctx, "Dial")
	invite := dialog.InviteRequest
	// Wait 200
	waitStart := time.Now()
	err := dialog.WaitAnswer(ctx, sipgo.AnswerOptions{
		OnResponse: func(res *sip.Response) {
			p.logSipResponse(&log, res)
			if o.OnResponse != nil {
				o.OnResponse(res)
			}
		},
		Username: o.Username,
		Password: o.Password,
	})

	var rerr *sipgo.ErrDialogResponse
	if errors.As(err, &rerr) {
		return nil, &DialResponseError{
			InviteReq:  invite,
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
	err = msess.RemoteSDP(r.Body())
	// TODO handle bad SDP
	if err != nil {
		return nil, err
	}

	log.Info().
		Str("formats", logFormats(msess.Formats)).
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
	Formats sdp.Formats

	// OnCall is just INVITE request handler that you can use to notify about incoming call
	// After this dialog should be created and you can watch your changes with dialog.State
	// -1 == Cancel
	// 0 == continue
	// >0 different response
	OnCall func(inviteRequest *sip.Request) int

	// Default is 200 (answer a call)
	AnswerCode   sip.StatusCode
	AnswerReason string
}

// Answer will answer call
// Closing ansCtx will close listeners or it will be closed on BYE
// TODO: reusing listener
func (p *Phone) Answer(ansCtx context.Context, opts AnswerOptions) (*DialogServerSession, error) {

	dialog, err := p.answer(ansCtx, opts)
	if err != nil {
		return nil, err
	}
	log.Debug().Msg("Dialog answer created")
	if !dialog.InviteResponse.IsSuccess() {
		// Return closed/terminated dialog
		return dialog, dialog.Close()
	}

	return dialog, nil
}

func (p *Phone) answer(ansCtx context.Context, opts AnswerOptions) (*DialogServerSession, error) {
	log := p.getLoggerCtx(ansCtx, "Answer")
	ringtime := opts.Ringtime

	waitDialog := make(chan *DialogServerSession)
	var d *DialogServerSession

	// TODO reuse server and listener
	server, err := sipgo.NewServer(p.UA)
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
			log.Debug().Str("addr", l.Addr).Msg("Closing listener")
			l.Close()
		}
	})

	exitError := func(err error) {
		exitErr = err
	}

	lhost, lport, _ := sip.ParseAddr(listeners[0].Addr)
	contactHdr := sip.ContactHeader{
		Address: sip.Uri{
			User:      p.UA.Name(),
			Host:      lhost,
			Port:      lport,
			Headers:   sip.HeaderParams{"transport": listeners[0].Network},
			UriParams: sip.NewParams(),
		},
		Params: sip.NewParams(),
	}

	// Create client handle for responding
	client, err := sipgo.NewClient(p.UA,
		sipgo.WithClientNAT(), // needed for registration
		sipgo.WithClientHostname(lhost),
		// Do not use with ClientPort as we want always this to be a seperate connection
	)
	if err != nil {
		return nil, err
	}

	if opts.RegisterAddr != "" {
		// We will use registration to resolve NAT
		// so WithClientNAT must be present

		// Keep registration
		rhost, rport, _ := sip.ParseAddr(opts.RegisterAddr)
		registerURI := sip.Uri{
			Host: rhost,
			Port: rport,
			User: p.UA.Name(),
		}

		regTr, err := p.register(ctx, client, registerURI, contactHdr, RegisterOptions{
			Username: opts.Username,
			Password: opts.Password,
			Expiry:   30,
			// UnregisterAll: true,
			// AllowHeaders: server.RegisteredMethods(),
		})
		if err != nil {
			return nil, err
		}

		// In case our register changed contact due to NAT detection via rport, lets update
		contact := regTr.Origin.Contact()
		contactHdr = *contact.Clone()

		origStopAnswer := stopAnswer
		// Override stopAnswer with unregister
		stopAnswer = sync.OnceFunc(func() {
			ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
			err := regTr.Unregister(ctx)
			if err != nil {
				log.Error().Err(err).Msg("Fail to unregister")
			}
			regTr = nil
			origStopAnswer()
		})
		go func(ctx context.Context) {
			err := regTr.QualifyLoop(ctx)
			exitError(err)
			stopAnswer()
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
		p.logSipRequest(&log, req)

		dialog, err := ds.ReadInvite(req, tx)
		if err != nil {
			res := sip.NewResponseFromRequest(req, 400, err.Error(), nil)
			if err := tx.Respond(res); err != nil {
				log.Error().Err(err).Msg("Failed to send 400 response")
			}

			exitError(err)
			stopAnswer()
			return
		}

		err = func() error {
			if opts.OnCall != nil {
				// Handle OnCall handler
				res := opts.OnCall(req)
				switch {
				case res < 0:
					if err := dialog.Respond(sip.StatusBusyHere, "Busy", nil); err != nil {
						d = nil
						return fmt.Errorf("failed to respond oncall status code %d: %w", res, err)
					}
				case res > 0:
					if err := dialog.Respond(sip.StatusCode(res), "", nil); err != nil {
						d = nil
						return fmt.Errorf("failed to respond oncall status code %d: %w", res, err)
					}
				}
			}

			if opts.AnswerCode > 0 && opts.AnswerCode != sip.StatusOK {
				log.Info().Int("code", int(opts.AnswerCode)).Msg("Answering call")
				if opts.AnswerReason == "" {
					// apply some default one
					switch opts.AnswerCode {
					case sip.StatusBusyHere:
						opts.AnswerReason = "Busy"
					case sip.StatusForbidden:
						opts.AnswerReason = "Forbidden"
					case sip.StatusUnauthorized:
						opts.AnswerReason = "Unathorized"
					}
				}

				if err := dialog.Respond(opts.AnswerCode, opts.AnswerReason, nil); err != nil {
					d = nil
					return fmt.Errorf("failed to respond custom status code %d: %w", int(opts.AnswerCode), err)
				}
				p.logSipResponse(&log, dialog.InviteResponse)

				d = &DialogServerSession{
					DialogServerSession: dialog,
					// done:                make(chan struct{}),
				}
				select {
				case <-tx.Done():
					return tx.Err()
				case <-tx.Acks():
					log.Debug().Msg("ACK received. Returning dialog")
					// Wait for ack
				case <-ctx.Done():
					return ctx.Err()
				}

				select {
				case waitDialog <- d:
				case <-ctx.Done():
					return ctx.Err()
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
				p.logSipResponse(&log, res)

				select {
				case <-tx.Cancels():
					return fmt.Errorf("received CANCEL")
				case <-tx.Done():
					return fmt.Errorf("invite transaction finished while ringing")
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(ringtime):
					// Ring time finished
				}
			} else {
				// Send progress
				res := sip.NewResponseFromRequest(req, 100, "Trying", nil)
				if err := dialog.WriteResponse(res); err != nil {
					return fmt.Errorf("failed to send 100 response: %w", err)
				}

				p.logSipResponse(&log, res)
			}

			contentType := req.ContentType()
			if contentType == nil || contentType.Value() != "application/sdp" {
				return fmt.Errorf("no SDP in INVITE provided")
			}

			ip := p.UA.GetIP()
			// rtpPort := rand.Intn(1000*2)/2 + 6000
			if lip := net.ParseIP(lhost); lip != nil && !lip.IsUnspecified() {
				ip = lip
			}

			msess, err := NewMediaSession(&net.UDPAddr{IP: ip, Port: 0})
			if err != nil {
				return err
			}
			// Set our custom formats in this negotiation
			if len(opts.Formats) > 0 {
				msess.Formats = opts.Formats
			}

			err = msess.RemoteSDP(req.Body())
			if err != nil {
				return err
			}

			log.Info().
				Str("formats", logFormats(msess.Formats)).
				Str("localAddr", msess.Laddr.String()).
				Str("remoteAddr", msess.Raddr.String()).
				Msg("Media/RTP session created")

			res := sip.NewSDPResponseFromRequest(req, msess.LocalSDP())

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

			log.Info().Msg("Answering call")
			if err := dialog.WriteResponse(res); err != nil {
				d = nil
				return fmt.Errorf("fail to send 200 response: %w", err)
			}
			p.logSipResponse(&log, res)

			select {
			case <-tx.Done():
				// This can be as well TIMER L, which means we received ACK and no more retransmission of 200 will be done
			case <-ctx.Done():
				// We have received BYE OR Cancel, so we will ignore transaction waiting.
			}

			if err := tx.Err(); err != nil {
				return fmt.Errorf("invite transaction ended with error: %w", err)
			}
			return nil
		}()

		if err != nil {
			dialog.Close()
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

			exitError(fmt.Errorf("received ack but no dialog"))
			stopAnswer()
		}

		if err := ds.ReadAck(req, tx); err != nil {
			exitError(fmt.Errorf("dialog ACK err: %w", err))
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
			exitError(fmt.Errorf("dialog BYE err: %w", err))
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
		d.onClose = stopAnswer
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
// Deprecated: Use Answer with options
func (p *Phone) AnswerWithCode(ansCtx context.Context, code sip.StatusCode, reason string, opts AnswerOptions) (*DialogServerSession, error) {
	// TODO, do all options make sense?
	opts.AnswerCode = code
	opts.AnswerReason = reason
	dialog, err := p.answer(ansCtx, opts)
	if err != nil {
		return nil, err
	}

	if !dialog.InviteResponse.IsSuccess() {
		return dialog, dialog.Close()
	}

	// Return closed/terminated dialog
	return dialog, nil
}

// TODO allow this to be reformated outside
func (p *Phone) logSipRequest(log *zerolog.Logger, req *sip.Request) {
	log.Info().
		Str("request", req.StartLine()).
		Str("call_id", req.CallID().Value()).
		Str("from", req.From().Value()).
		Str("event", "SIP").
		Msg("Request")
}

func (p *Phone) logSipResponse(log *zerolog.Logger, res *sip.Response) {
	log.Info().
		Str("response", res.StartLine()).
		Str("call_id", res.CallID().Value()).
		Str("event", "SIP").
		Msg("Response")
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

func logFormats(f sdp.Formats) string {
	out := make([]string, len(f))
	for i, v := range f {
		switch v {
		case "0":
			out[i] = "0(ulaw)"
		case "8":
			out[i] = "8(alaw)"
		default:
			// Unknown then just use as number
			out[i] = v
		}
	}
	return strings.Join(out, ",")
}
