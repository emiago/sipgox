package sipgox

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMediaPortRange(t *testing.T) {
	RTPPortStart = 5000
	RTPPortEnd = 5010

	sessions := []*MediaSession{}
	for i := RTPPortStart; i < RTPPortEnd; i += 2 {
		require.Equal(t, i-RTPPortStart, int(rtpPortOffset.Load()))
		mess, err := NewMediaSession(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		t.Log(mess.rtpConn.LocalAddr(), mess.rtcpConn.LocalAddr())
		require.NoError(t, err)
		sessions = append(sessions, mess)
	}

	for _, s := range sessions {
		s.Close()
	}

}

func TestDTMFEncodeDecode(t *testing.T) {
	// Example payload for DTMF digit '1' with volume 10 and duration 1000
	// Event: 0x01 (DTMF digit '1')
	// E bit: 0x80 (End of Event)
	// Volume: 0x0A (Volume 10)
	// Duration: 0x03E8 (Duration 1000)
	payload := []byte{0x01, 0x8A, 0x03, 0xE8}

	event := DTMFEvent{}
	err := DTMFDecode(payload, &event)
	if err != nil {
		t.Fatalf("Error decoding payload: %v", err)
	}

	if event.Event != 0x01 {
		t.Errorf("Unexpected Event. got: %v, want: %v", event.Event, 0x01)
	}

	if event.EndOfEvent != true {
		t.Errorf("Unexpected EndOfEvent. got: %v, want: %v", event.EndOfEvent, true)
	}

	if event.Volume != 0x0A {
		t.Errorf("Unexpected Volume. got: %v, want: %v", event.Volume, 0x0A)
	}

	if event.Duration != 0x03E8 {
		t.Errorf("Unexpected Duration. got: %v, want: %v", event.Duration, 0x03E8)
	}

	encoded := DTMFEncode(event)
	require.Equal(t, payload, encoded)
}
