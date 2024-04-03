package sipgox

import (
	"fmt"

	"github.com/pion/rtp"
	"github.com/rs/zerolog/log"
)

// RTP Writer packetize any payload before pushing to active media session
type RTPReader struct {
	Sess *MediaSession

	OnRTP       func(pkt *rtp.Packet)
	LastPacket  rtp.Packet // After calling Read this will be stored before returning
	PayloadType uint8

	unreadPayload []byte
	unread        int

	pktBuffer chan []byte
}

// RTP reader consumes samples of audio from session
// TODO should it also decode ?
func NewRTPReader(sess *MediaSession) *RTPReader {
	fmts, _ := sess.Formats.ToNumeric()

	w := RTPReader{
		Sess:          sess,
		unreadPayload: []byte{},
		PayloadType:   uint8(fmts[0]),

		pktBuffer: make(chan []byte, 100),
	}

	return &w
}

// Read Implements io.Reader and extracts Payload from RTP packet
// has no input queue or sorting control of packets
func (r *RTPReader) Read(b []byte) (int, error) {
	if r.unread > 0 {
		n := r.readPayload(b, r.unreadPayload)
		return n, nil
	}

	pkt, err := r.Sess.ReadRTP()
	if err != nil {
		return 0, err
	}

	if r.PayloadType != pkt.PayloadType {
		return 0, fmt.Errorf("payload type does not match. expected=%d, actual=%d", r.PayloadType, pkt.PayloadType)
	}

	// First packet
	if r.LastPacket.SSRC != 0 {
		expectedSeq := r.LastPacket.SequenceNumber + 1
		if pkt.SequenceNumber != expectedSeq {
			log.Warn().Msg("Out of order pkt received")
		}
	}

	r.LastPacket = pkt
	if r.OnRTP != nil {
		r.OnRTP(&pkt)
	}

	return r.readPayload(b, pkt.Payload), nil
}

func (r *RTPReader) readPayload(b []byte, payload []byte) int {
	n := copy(b, payload)
	if n < len(payload) {
		r.unreadPayload = payload[n:]
		r.unread = len(payload) - n
	} else {
		r.unread = 0
	}
	return n
}
