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

	nextTimestamp uint32

	// After each write this is set as packet.
	LastPacket rtp.Packet
	OnRTP      func(pkt *rtp.Packet)
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
		SSRC:        111222,
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
			Marker:         p.nextTimestamp == 0,
			PayloadType:    p.PayloadType,
			Timestamp:      p.nextTimestamp,
			SequenceNumber: p.seq.NextSequenceNumber(),
			SSRC:           p.SSRC,
			CSRC:           []uint32{},
		},
		Payload: b,
	}
	p.LastPacket = pkt
	p.nextTimestamp += p.SamplesRate

	if p.OnRTP != nil {
		p.OnRTP(&pkt)
	}

	err := p.Sess.WriteRTP(&pkt)
	return len(pkt.Payload), err
	// TODO write RTCP
}

func (p *RTPWriter) WriteSamples(b []byte, timestampRateIncrease uint32, marker bool, payloadType uint8) (int, error) {
	pkt := rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			Padding:        false,
			Extension:      false,
			Marker:         marker,
			PayloadType:    payloadType,
			Timestamp:      p.nextTimestamp,
			SequenceNumber: p.seq.NextSequenceNumber(),
			SSRC:           p.SSRC,
			CSRC:           []uint32{},
		},
		Payload: b,
	}

	if p.OnRTP != nil {
		p.OnRTP(&pkt)
	}

	p.LastPacket = pkt
	p.nextTimestamp += timestampRateIncrease

	err := p.Sess.WriteRTP(&pkt)
	return len(pkt.Payload), err
	// TODO write RTCP
}
