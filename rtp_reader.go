package sipgox

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/emiago/sipgox/sdp"
	"github.com/pion/rtp"
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

	// We want to track our last SSRC.
	lastSSRC uint32
}

// RTP reader consumes samples of audio from session
// TODO should it also decode ?
func NewRTPReader(sess *MediaSession) *RTPReader {
	f := sess.Formats[0]
	var payloadType uint8 = sdp.FormatNumeric(f)
	switch f {
	case sdp.FORMAT_TYPE_ALAW:
	case sdp.FORMAT_TYPE_ULAW:
		// TODO more support
	default:
		sess.log.Warn().Str("format", f).Msg("Unsupported format. Using default clock rate")
	}

	w := RTPReader{
		Sess:          sess,
		unreadPayload: []byte{},
		PayloadType:   payloadType,
		OnRTP:         func(pkt *rtp.Packet) {},

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

	pkt := rtp.Packet{}
	if err := r.Sess.readRTPNoAlloc(&pkt); err != nil {
		if errors.Is(err, net.ErrClosed) {
			return 0, io.EOF
		}

		return 0, err
	}

	if r.PayloadType != pkt.PayloadType {
		return 0, fmt.Errorf("payload type does not match. expected=%d, actual=%d", r.PayloadType, pkt.PayloadType)
	}

	// If we are tracking this source, do check are we keep getting pkts in sequence
	if r.lastSSRC == pkt.SSRC {
		expectedSeq := r.LastPacket.SequenceNumber + 1
		if pkt.SequenceNumber == r.LastPacket.SequenceNumber {
			r.Sess.log.Warn().Msg("Duplicate pkts received")
			return 0, nil
		}

		if pkt.SequenceNumber != expectedSeq {
			r.Sess.log.Warn().Msg("Out of order pkt received")
		}
	}

	r.lastSSRC = pkt.SSRC
	r.LastPacket = pkt
	r.OnRTP(&pkt)

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
