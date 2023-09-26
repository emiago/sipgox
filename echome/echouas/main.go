package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgox"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	addr := flag.String("l", "", "My listen ip")
	username := flag.String("u", "alice", "SIP Username")
	echoCount := flag.Int("echo", 1, "How many echos")
	// password := flag.String("p", "alice", "Password")
	flag.Parse()

	lev, err := zerolog.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil || lev == zerolog.NoLevel {
		lev = zerolog.InfoLevel
	}

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMicro
	log.Logger = zerolog.New(zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.StampMicro,
	}).With().Timestamp().Logger().Level(lev)

	// Setup UAC
	ua, err := sipgo.NewUA(
		sipgo.WithUserAgent(*username),
		// sipgo.WithUserAgentIP(net.ParseIP(ip)),
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Fail to setup user agent")
	}

	phoneOpts := []sipgox.PhoneOption{}
	if *addr != "" {
		phoneOpts = append(phoneOpts,
			sipgox.WithPhoneListenAddr(sipgox.ListenAddr{
				// Network: *tran,
				Network: "udp",
				Addr:    *addr,
			}),
		)
	}

	phone := sipgox.NewPhone(ua, phoneOpts...)
	ctx, _ := context.WithCancel(context.Background())
	dialog, err := phone.Answer(ctx, sipgox.AnswerOptions{
		Ringtime: 1 * time.Second,
		// SipHeaders: []sip.Header{sip.NewHeader("X-ECHO-ID", "sipgo")},
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Fail to answer")
	}

	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt)
	// Start echo
	go func() {
		for {
			p, err := dialog.ReadRTP()
			if err != nil {
				if errors.Is(err, io.ErrClosedPipe) {
					return
				}
				log.Error().Err(err).Msg("Fail to read RTP")
				return
			}

			log.Info().Msg(p.String())

			p.Payload = append(p.Payload, bytes.Repeat(p.Payload, *echoCount-1)...)

			if err := dialog.WriteRTP(&p); err != nil {
				log.Error().Err(err).Msg("Fail to echo RTP")
				return
			}
		}
	}()

	select {
	case <-sig:
		ctx, _ := context.WithTimeout(context.Background(), 3*time.Second)
		dialog.Hangup(ctx)
		return

	case <-dialog.Done():
		return
	}
}
