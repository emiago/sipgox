package sipgox

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/emiago/sipgo/fakes"
	"github.com/emiago/sipgox/sdp"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

func TestRTPWriter(t *testing.T) {
	sess := &MediaSession{
		Formats: sdp.Formats{
			sdp.FORMAT_TYPE_ALAW, sdp.FORMAT_TYPE_ULAW,
		},
		Laddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		Raddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
	}
	sess.SetLogger(log.Logger)

	conn := &fakes.UDPConn{
		Writers: map[string]io.Writer{
			"127.0.0.1:1234": bytes.NewBuffer([]byte{}),
		},
	}
	sess.rtpConn = conn

	rtpWriter := NewRTPWriter(sess)
	payload := []byte("12312313")
	N := 10

	for i := 0; i < N; i++ {
		_, err := rtpWriter.Write(payload)
		require.NoError(t, err)

		pkt := rtpWriter.LastPacket

		require.Equal(t, rtpWriter.PayloadType, pkt.PayloadType)
		require.Equal(t, rtpWriter.SSRC, pkt.SSRC)
		require.Equal(t, rtpWriter.nextTimestamp, pkt.Timestamp+160, "%d vs %d", rtpWriter.nextTimestamp, pkt.Timestamp)
		require.Equal(t, i == 0, pkt.Marker)
		require.Equal(t, len(payload), len(pkt.Payload))
	}
}

func TestBinary(t *testing.T) {
	var v uint16 = 5
	seqN := 9

	var res uint32 = uint32(v)<<16 + uint32(seqN)

	t.Logf("%032b", res)

}
