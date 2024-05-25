package sipgox

import (
	"bytes"
	"net"
	"testing"

	"github.com/emiago/sipgo/fakes"
	"github.com/emiago/sipgox/sdp"
	"github.com/pion/rtp"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

func TestRTPReader(t *testing.T) {
	// originIP := net.IPv4(127, 0, 0, 1)
	sess := &MediaSession{
		Formats: sdp.Formats{
			sdp.FORMAT_TYPE_ALAW, sdp.FORMAT_TYPE_ULAW,
		},
		Laddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		log:   log.Logger,
	}

	conn := &fakes.UDPConn{}
	sess.rtpConn = conn

	rtpReader := NewRTPReader(sess)

	payload := []byte("12312313")
	N := 10

	buf := make([]byte, 3200)
	for i := 0; i < N; i++ {
		writePkt := rtp.Packet{
			Header: rtp.Header{
				SSRC:           1234,
				Version:        2,
				PayloadType:    8,
				SequenceNumber: uint16(i),
				Timestamp:      160 * uint32(i),
				Marker:         i == 0,
			},
			Payload: payload,
		}
		data, _ := writePkt.Marshal()
		conn.Reader = bytes.NewBuffer(data)

		n, err := rtpReader.Read(buf)
		require.NoError(t, err)

		pkt := rtpReader.PacketHeader
		require.Equal(t, writePkt.PayloadType, pkt.PayloadType)
		require.Equal(t, writePkt.SSRC, pkt.SSRC)
		require.Equal(t, i == 0, pkt.Marker)
		require.Equal(t, n, len(payload))
		require.Equal(t, rtpReader.Seq.ReadExtendedSeq(), uint64(writePkt.SequenceNumber))
	}
}

func BenchmarkRTPReader(b *testing.B) {
	sess := &MediaSession{
		Formats: sdp.Formats{
			sdp.FORMAT_TYPE_ALAW, sdp.FORMAT_TYPE_ULAW,
		},
		Laddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		log:   log.Logger,
	}

	dataBuf := bytes.NewBuffer([]byte{})
	conn := &fakes.UDPConn{
		Reader: dataBuf,
	}
	sess.rtpConn = conn

	rtpReader := NewRTPReader(sess)
	payload := []byte("12312313")
	buf := make([]byte, 3200)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writePkt := rtp.Packet{
			Header: rtp.Header{
				SSRC:           1234,
				Version:        2,
				PayloadType:    8,
				SequenceNumber: uint16(i % (1 << 16)),
				Timestamp:      160 * uint32(i),
				Marker:         i == 0,
			},
			Payload: payload,
		}
		data, _ := writePkt.Marshal()
		dataBuf.Write(data)

		_, err := rtpReader.Read(buf)
		require.NoError(b, err)
	}
}
