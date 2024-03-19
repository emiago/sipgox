package sipgox

import (
	"github.com/pion/rtp"
)

// RTP Writer packetize any payload before pushing to active media session
type RTPWriter struct {
	Sess *MediaSession

	seq rtp.Sequencer

	PayloadType uint8
	SSRC        uint32
	SamplesRate uint32

	lastTimestamp uint32

	// After each write this is set as packet.
	LastPacket rtp.Packet
}

// RTP writer wraps payload in RTP packet before passing on session
// TODO: should it also encode?
func NewRTPWriter(sess *MediaSession) *RTPWriter {
	fmts, _ := sess.Formats.ToNumeric()
	payloadType := uint8(fmts[0])

	w := RTPWriter{
		Sess:        sess,
		seq:         rtp.NewRandomSequencer(),
		PayloadType: payloadType,
		SamplesRate: 160, // 20ms 0.02 * 8000 = 160
	}

	return &w
}

// TODO multiple payloads?
// Implements io.Writer
func (p *RTPWriter) Write(b []byte) (int, error) {
	pkt := rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			Padding:        false,
			Extension:      false,
			Marker:         p.lastTimestamp == 0,
			PayloadType:    p.PayloadType,
			SequenceNumber: p.seq.NextSequenceNumber(),
			Timestamp:      p.lastTimestamp, // Figure out how to do timestamps
			SSRC:           p.SSRC,
			CSRC:           []uint32{},
		},
		Payload: b,
	}
	p.LastPacket = pkt
	p.lastTimestamp += p.SamplesRate

	err := p.Sess.WriteRTP(&pkt)
	return len(pkt.Payload), err
	// TODO write RTCP
}
