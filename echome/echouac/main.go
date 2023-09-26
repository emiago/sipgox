package main

import (
	"bytes"
	"context"
	"flag"
	"os"
	"os/signal"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/parser"
	"github.com/emiago/sipgo/sip"
	"github.com/emiago/sipgox"
	"github.com/pion/rtp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// addr := flag.String("l", "127.0.0.100:5060", "My listen ip")
	// dst := flag.String("d", "127.0.0.10:5060", "Destination")
	username := flag.String("u", "alice", "SIP Username")
	echoCount := flag.Int("echo", 1, "How many echos to expect")

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
	// ip, _, _ := net.SplitHostPort(*addr)
	ua, err := sipgo.NewUA(
		sipgo.WithUserAgent(*username),
		// sipgo.WithUserAgentIP(net.ParseIP(ip)),
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Fail to setup user agent")
	}

	// udpAddr, err := net.ResolveUDPAddr("udp", *addr)
	// if err != nil {
	// 	log.Fatal().Err(err).Msg("Bad addr")
	// }

	phone := sipgox.NewPhone(ua) // sipgox.WithPhoneListenAddr(udpAddr),

	target := flag.Arg(0)

	recipient := sip.Uri{User: *username, Headers: sip.NewParams()}
	if err := parser.ParseUri(target, &recipient); err != nil {
		log.Fatal().Err(err).Msg("Target bad format")
	}

	ctx, _ := context.WithTimeout(context.Background(), 60*time.Second)
	dialog, err := phone.Dial(ctx, recipient, sipgox.DialOptions{})
	if err != nil {
		log.Fatal().Err(err).Msg("Fail to dial")
	}
	defer dialog.Close()

	sequencer := rtp.NewFixedSequencer(1)
	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt)

	go func() {
		for {
			select {
			case <-dialog.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}

			pkt := &rtp.Packet{
				Header: rtp.Header{
					Version:        2,
					Padding:        false,
					Extension:      false,
					Marker:         false,
					PayloadType:    0,
					SequenceNumber: sequencer.NextSequenceNumber(),
					Timestamp:      20, // We do not care as we are not playing out
					SSRC:           111222,
				},
				Payload: []byte("1234567890"),
			}

			log.Info().Msgf("Sent RTP\n%s", pkt.String())

			if err := dialog.WriteRTP(pkt); err != nil {
				log.Error().Err(err).Msg("Fail to send RTP")
				return
			}

			p, err := dialog.ReadRTP()
			if err != nil {
				log.Error().Err(err).Msg("Fail to read RTP")
				return
			}

			// use debug if you want to see what is received
			log.Debug().Msgf("Recv RTP\n%s", pkt.String())
			if p.PayloadType != pkt.PayloadType {
				log.Error().Msg("RTP type mismatch")
			}

			// TODO: move this out of loop
			expectedPayload := make([]byte, 0, len(pkt.Payload)*(*echoCount))
			for i := 0; i < *echoCount; i++ {
				expectedPayload = append(expectedPayload, pkt.Payload...)
			}

			if !bytes.Equal(p.Payload, expectedPayload) {
				log.Error().Str("recv", string(p.Payload)).Str("expected", string(expectedPayload)).Msg("RTP payload mismatch")
			}
		}
	}()

	for i := 0; ; i++ {
		select {
		case <-sig:
			ctx, _ := context.WithTimeout(context.Background(), 3*time.Second)
			dialog.Hangup(ctx)
			return

		case <-dialog.Done():
			return
		case <-time.After(200 * time.Millisecond):
			// Do every 200 milisecond RTP and check echo
		}
	}
}
