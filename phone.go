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
	"syscall"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Phone struct {
	ua *sipgo.UserAgent
	// c  *sipgo.Client
	s *sipgo.Server

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

	var err error
	p.s, err = sipgo.NewServer(ua)
	if err != nil {
		p.log.Fatal().Err(err).Msg("Fail to setup server handle")
	}

	if len(p.listenAddrs) == 0 {
		// WithPhoneListenAddr(ListenAddr{"udp", "127.0.0.1:5060"})(p)
		// WithPhoneListenAddr(ListenAddr{"tcp", "0.0.0.0:5060"})(p)
	}

	// In case ws we want to run http
	return p
}

func (p *Phone) Close() {
	p.s.Close()
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
	port = rand.Intn(9999) + 50000

	ip, err := sip.ResolveSelfIP()
	return ip.String(), port, err
}

func (p *Phone) createServerListener(a ListenAddr) (*Listener, error) {
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
			func() error { return p.s.ServeUDP(udpConn) },
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
				func() error { return p.s.ServeWS(conn) },
			}, nil
		}

		return &Listener{
			a,
			conn,
			func() error { return p.s.ServeTCP(conn) },
		}, nil
	}
	return nil, fmt.Errorf("Unsuported protocol")
}

func (p *Phone) createServerListeners() (listeners []*Listener, e error) {
	newListener := func(a ListenAddr) error {
		l, err := p.createServerListener(a)
		if err != nil {
			return err
		}

		// p.log.Info().Str("addr", a.Addr).Str("network", a.Network).Msg("Listening on")
		// go l.Listen()

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

// Register the phone by sip uri.
// Sip should have sip:username:password@destination at least defined
func (p *Phone) Register(ctx context.Context, recipient sip.Uri) error {
	// Make our client reuse address
	network := recipient.Headers["transport"]
	host, port, _ := p.getInterfaceHostPort(network, recipient.HostPort())
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	client, err := sipgo.NewClient(p.s.UserAgent,
		sipgo.WithClientAddr(addr),
	)
	defer client.Close()
	if err != nil {
		p.log.Fatal().Err(err).Msg("Fail to setup client handle")
	}

	// Create basic REGISTER request structure
	username := recipient.User
	password := recipient.Password

	// As we will use digest request, remove password
	recipient.Password = ""

	req := sip.NewRequest(sip.REGISTER, &recipient)
	req.AppendHeader(
		sip.NewHeader("Contact", fmt.Sprintf("<sip:%s@%s>", username, host)),
	)

	// Send request and parse response
	// req.SetDestination(*dst)
	tx, err := client.TransactionRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("fail to create transaction req=%q: %w", req.StartLine(), err)
	}
	defer tx.Terminate()

	res, err := getResponse(ctx, tx)
	if err != nil {
		return fmt.Errorf("fail to get response req=%q : %w", req.StartLine(), err)
	}

	p.log.Info().Int("status", int(res.StatusCode)).Msg("Received status")
	if res.StatusCode == sip.StatusUnauthorized {
		tx.Terminate() //Terminate previous
		tx, err = digestTransactionRequest(client, username, password, req, res)
		if err != nil {
			return err
		}

		res, err = getResponse(ctx, tx)
		if err != nil {
			return fmt.Errorf("fail to get response req=%q : %w", req.StartLine(), err)
		}
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("%s: %w", res.StartLine(), ErrRegisterFail)
	}

	return nil
}

type DialOptions struct {
	// Authentication via digest challenge
	Username string
	Password string

	// Custom headers passed on INVITE
	SipHeaders []sip.Header
}

func (p *Phone) Dial(dialCtx context.Context, recipient sip.Uri, o DialOptions) (*DialDialog, error) {
	// ip := p.ua.GetIP()
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

	dialogCh := make(chan struct{})
	closeDialog := func() {
		close(dialogCh)
	}

	// Setup srv for bye
	p.s.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		defer closeDialog()
		res := sip.NewResponseFromRequest(req, 200, "OK", nil)
		if err := tx.Respond(res); err != nil {
			p.log.Error().Err(err).Msg("Fail to send BYE 200 response")
			return
		}
		p.log.Debug().Msg("Received BYE")
	})

	// We only need client handle
	// Server handle will register our handler on UA level
	// Here we make sure we are using server UA
	client, err := sipgo.NewClient(p.s.UserAgent,
		// We must have this address for Contact header
		sipgo.WithClientHostname(host),
		sipgo.WithClientPort(listenPort),
	)

	if err != nil {
		p.log.Fatal().Err(err).Msg("Fail to setup client handle")
	}

	// TODO setup session before
	rtpPort := rand.Intn(1000*2)/2 + 6000

	// Create Generic SDP
	sdpSend := p.generateSDP(rtpPort)

	// Creating INVITE
	req := sip.NewRequest(sip.INVITE, &recipient)
	req.SetTransport(network)
	req.AppendHeader(&sip.ContactHeader{
		Address: contactUri,
		Params:  sip.HeaderParams{"transport": network},
	})
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	req.SetBody(sdpSend)

	// Add custom headers
	for _, h := range o.SipHeaders {
		log.Info().Str(h.Name(), h.Value()).Msg("Adding SIP header")
		req.AppendHeader(h)
	}

	tx, err := client.TransactionRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("fail to send invite: %w", err)
	}
	defer tx.Terminate()
	p.log.Info().Msgf("Request: %s", req.StartLine())

	// Wait 200
	waitStart := time.Now()
	var r *sip.Response
	not200err := func() error {
		for {
			r, err = getResponse(ctx, tx)
			if err == context.Canceled || err == context.DeadlineExceeded {
				if err := client.WriteRequest(sip.NewCancelRequest(req)); err != nil {
					p.log.Error().Err(err).Msg("Failed to send CANCEL")
				}
				return ctx.Err()
			}

			if err != nil {
				return err
			}

			p.log.Info().Msgf("Response: %s", r.StartLine())

			if r.StatusCode == sip.StatusUnauthorized && o.Password != "" {
				tx.Terminate() // Terminate previous
				tx, err = digestTransactionRequest(client, o.Username, o.Password, req, r)
				if err != nil {
					return err
				}

				continue
			}

			if r.StatusCode == 200 {
				return nil
			}

			if r.StatusCode/100 == 1 {
				continue
			}

			// p.log.Info().Msgf("Got unvanted response\n%s", r.String())
			return fmt.Errorf("Call not answered: %s", r.StartLine())
		}
	}()

	if not200err != nil {
		return nil, not200err
	}

	p.log.Info().
		Int("code", int(r.StatusCode)).
		Str("reason", r.Reason).
		Str("duration", time.Since(waitStart).String()).
		Msg("Call answered")

	// Send ACK
	reqACK := sip.NewAckRequest(req, r, nil)
	if err := client.WriteRequest(reqACK); err != nil {
		return nil, fmt.Errorf("fail to send ACK: %w", err)
	}

	// Setup media
	msess, err := NewMediaSessionFromSDP(sdpSend, r.Body())
	// msess, err := NewMediaSession(ip, rtpPort, dstIP, dstPort.Value)
	if err != nil {
		return nil, err
	}

	if err := msess.Dial(); err != nil {
		return nil, fmt.Errorf("Fail to open media connection: %w", err)
	}

	return &DialDialog{
		MediaSession:   msess,
		InviteRequest:  req,
		InviteResponse: r,
		c:              client,
		done:           dialogCh,
	}, nil
}

type AnswerOptions struct {
	Ringtime   time.Duration
	SipHeaders []sip.Header
}

// Answer will answer call
func (p *Phone) Answer(ansCtx context.Context, opts AnswerOptions) (*DialDialog, error) {
	ringtime := opts.Ringtime

	waitDialog := make(chan *DialDialog)
	var d *DialDialog

	// We need to listen as long our answer context is running
	// Listener needs to be alive even after we have created dialog
	listeners, err := p.createServerListeners()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ansCtx)
	stopAnswer := func() {
		cancel() // Cancel context
		for _, l := range listeners {
			l.Close()
		}
	}

	p.s.OnInvite(func(req *sip.Request, tx sip.ServerTransaction) {
		if d != nil {
			didAnswered, _ := sip.MakeDialogIDFromResponse(d.InviteResponse)
			did, _ := sip.MakeDialogIDFromRequest(req)
			if did == didAnswered {
				// We received INVITE for update
				if err := d.MediaSession.UpdateDestinationSDP(req.Body()); err != nil {
					res := sip.NewResponseFromRequest(req, 400, err.Error(), nil)
					if err := tx.Respond(res); err != nil {
						p.log.Error().Err(err).Msg("Fail to send 400")
						return
					}
					return
				}

				res := sip.NewResponseFromRequest(req, 200, "OK", nil)
				if err := tx.Respond(res); err != nil {
					p.log.Error().Err(err).Msg("Fail to send 200")
					return
				}
				return
			}
			p.log.Error().Msg("Received second INVITE is not yet supported")
			return
		}

		from, _ := req.From()
		defer stopAnswer()

		p.log.Info().Str("from", from.Address.Addr()).Str("name", from.DisplayName).Msg("Received call")

		contact, exists := req.Contact()
		if !exists {
			res := sip.NewResponseFromRequest(req, 400, "No Contact header", nil)
			if err := tx.Respond(res); err != nil {
				p.log.Error().Err(err).Msg("Fail to send 400 response")
				return
			}
		}

		// Create client handle for responding
		// It is hard here to force address in case multiple listeners
		client, err := sipgo.NewClient(p.s.UserAgent) // sipgo.WithClientHostname("127.0.0.100"),

		if err != nil {
			p.log.Fatal().Err(err).Msg("Fail to setup client handle")
		}

		// Now place a ring tone or do autoanswer
		if ringtime > 0 {
			res := sip.NewResponseFromRequest(req, 180, "Ringing", nil)
			if err := tx.Respond(res); err != nil {
				p.log.Error().Err(err).Msg("Fail to send 180 response")
				return
			}
			p.log.Info().Msgf("Response: %s", res.StartLine())

			select {
			case <-tx.Cancels():
				p.log.Info().Msg("Received CANCEL")
				return
			case <-tx.Done():
				p.log.Error().Msg("Invite transaction finished while ringing")
				return
			case <-ctx.Done():
				return
			case <-time.After(ringtime):
				// Ring time finished
			}
		} else {
			// Send progress
			res := sip.NewResponseFromRequest(req, 100, "Trying", nil)
			if err := tx.Respond(res); err != nil {
				p.log.Error().Err(err).Msg("Fail to send 100 response")
				return
			}
		}

		// Setup media
		msess, answerSD, err := func() (*MediaSession, []byte, error) {
			for {
				// Now generate answer with our rtp ports
				rtpPort := rand.Intn(1000*2)/2 + 6000
				answerSD := p.generateSDP(rtpPort)

				// TODO in order to support SDP updates for formats
				msess, err := NewMediaSessionFromSDP(answerSD, req.Body())
				if err != nil {
					return nil, nil, err
				}

				err = msess.Dial()
				if errors.Is(err, syscall.EADDRINUSE) {
					continue
				}
				return msess, answerSD, err
			}
		}()

		if err != nil {
			p.log.Error().Err(err).Msg("Fail to setup media session")
			return
		}
		p.log.Info().Ints("formats", msess.Formats).Msg("Media session created")

		res := sip.NewSDPResponseFromRequest(req, answerSD)

		// Add custom headers
		for _, h := range opts.SipHeaders {
			log.Info().Str(h.Name(), h.Value()).Msg("Adding SIP header")
			res.AppendHeader(h)
		}

		if err := tx.Respond(res); err != nil {
			p.log.Error().Err(err).Msg("Fail to send BYE 200 response")
			return
		}
		p.log.Info().Msgf("Response: %s", res.StartLine())

		d = &DialDialog{
			MediaSession:   msess,
			InviteRequest:  req,
			InviteResponse: res,
			contact:        &contact.Address,
			c:              client,
			done:           make(chan struct{}),
		}

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
			p.log.Error().Err(err).Msg("Invite transaction ended with error")
		}
	})

	p.s.OnAck(func(req *sip.Request, tx sip.ServerTransaction) {
		// https://datatracker.ietf.org/doc/html/rfc3261#section-13.2.2.4
		// 	However, the callee's UA MUST NOT send a BYE on a confirmed dialog
		//    until it has received an ACK for its 2xx response or until the server
		//    transaction times out.  If no SIP extensions have defined other
		//    application layer states associated with the dialog, the BYE also
		//    terminates the diap.log.

		// This on 2xx
		if d == nil {
			p.log.Error().Msg("Received ack but no dialog")
			stopAnswer()
		}

		select {
		case waitDialog <- d:
		case <-ctx.Done():
		}

		// Needs check for SDP is right?
	})

	p.s.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		p.log.Debug().Msg("Received BYE")
		res := sip.NewResponseFromRequest(req, 200, "OK", nil)
		if err := tx.Respond(res); err != nil {
			p.log.Error().Err(err).Msg("Fail to send BYE 200 response")
			return
		}
		stopAnswer()

		// Close dialog as well
		if d != nil {
			close(d.done)
			d = nil
		}

		for _, l := range listeners {
			l.Close()
		}
	})

	for _, l := range listeners {
		p.log.Info().Str("network", l.Network).Str("addr", l.Addr).Msg("Listening on")
		go l.Listen()
	}

	select {
	case d = <-waitDialog:
		return d, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *Phone) generateSDP(rtpPort int) []byte {
	ip := p.ua.GetIP()
	return SDPGeneric(ip, ip, rtpPort, SDPModeSendrecv)
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
		Method: req.Method.String(),
		// URI:      req.Recipient.Addr(),
		Username: username,
		Password: password,
	})
	if err != nil {
		return nil, fmt.Errorf("fail to build digest: %w", err)
	}

	cseq, _ := req.CSeq()
	cseq.SeqNo++
	// newReq := req.Clone()

	req.AppendHeader(sip.NewHeader("Authorization", cred.String()))
	defer req.RemoveHeader("Authorization")

	req.RemoveHeader("Via")
	tx, err := client.TransactionRequest(context.TODO(), req, sipgo.ClientRequestAddVia)
	return tx, err
}
