package sipgox

import (
	"io"
	"testing"

	"github.com/emiago/sipgo/fakes"
	"github.com/pion/rtcp"
)

func BenchmarkRTCPUnmarshal(b *testing.B) {

	session := &MediaSession{}
	reader, writer := io.Pipe()
	session.rtcpConn = &fakes.UDPConn{
		Reader: reader,
	}

	go func() {
		for {
			sr := rtcp.SenderReport{}
			data, err := sr.Marshal()
			if err != nil {
				return
			}

			writer.Write(data)
		}
	}()

	b.Run("pionRTCP", func(b *testing.B) {
		buf := make([]byte, 1500)
		for i := 0; i < b.N; i++ {
			n, err := reader.Read(buf)
			if err != nil {
				b.Fatal(err)
			}
			pkts, err := rtcp.Unmarshal(buf[:n])
			if err != nil {
				b.Fatal(err)
			}
			if len(pkts) == 0 {
				b.Fatal("no packet read")
			}
		}
	})

	b.Run("RTCPImproved", func(b *testing.B) {
		buf := make([]byte, 1500)
		pkts := make([]rtcp.Packet, 5)
		for i := 0; i < b.N; i++ {
			n, err := reader.Read(buf)
			if err != nil {
				b.Fatal(err)
			}
			n, err = RTCPUnmarshal(buf[:n], pkts)
			if err != nil {
				b.Fatal(err)
			}
			if n < 0 {
				b.Fatal("no read RTCP")
			}
		}
	})
}
