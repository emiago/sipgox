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
	ClockRate   uint32

	nextTimestamp uint32

	// After each write this is set as packet.
	LastPacket rtp.Packet
	OnRTP      func(pkt *rtp.Packet)
}

// RTP writer packetize payload in RTP packet before passing on media session
// Not having:
// - random SSRC
// - random Timestamp
// - allow different clock rate
// - CSRC contribution source
// - Silence detection and marker set
// - Padding and encryyption
func NewRTPWriter(sess *MediaSession) *RTPWriter {
	fmts, _ := sess.Formats.ToNumeric()
	payloadType := uint8(fmts[0])
	var sampleRate uint32 = 8000

	w := RTPWriter{
		Sess:        sess,
		seq:         rtp.NewRandomSequencer(),
		PayloadType: payloadType,
		ClockRate:   uint32(sampleRate * 20 / 1000), // 20ms 0.02 * 8000 = 160
		SSRC:        111222,

		// TODO: CSRC CSRC is contribution source identifiers.
		// This is set when media is passed trough mixer/translators and original SSRC wants to be preserverd
	}

	return &w
}

// Write implements io.Writer and does payload RTP packetization
// Media clock rate is determined
// For more control or dynamic payload rate check WriteSamples
// It is not thread safe and order of payload frames is required
// Has no capabilities (yet):
// - MTU UDP limit handling
// - Media clock rate of payload is consistent
// - Packet loss detection
// - RTCP generating
func (p *RTPWriter) Write(b []byte) (int, error) {
	// b is our frame
	// Spliting into multiple:
	// multiple frame packets should preserve same timestamp

	pkt := rtp.Packet{
		Header: rtp.Header{
			Version:     2,
			Padding:     false,
			Extension:   false,
			Marker:      p.nextTimestamp == 0,
			PayloadType: p.PayloadType,
			// Timestamp should increase linear and monotonic for media clock
			// Payload must be in same clock rate
			// TODO: what about wrapp arround
			Timestamp: p.nextTimestamp,

			// TODO handle seq.RollOverAccount and packet loss detection
			SequenceNumber: p.seq.NextSequenceNumber(),
			SSRC:           p.SSRC,
			CSRC:           []uint32{},
		},
		Payload: b,
	}
	p.LastPacket = pkt
	p.nextTimestamp += p.ClockRate

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
