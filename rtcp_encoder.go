package sipgox

import (
	"fmt"

	"github.com/pion/rtcp"
)

// RTCPUnmarshal is improved version of pion/rtcp.Unmarshal where we allow caller to define and control
// buffer of rtcp packets. This also reduces one allocation
func RTCPUnmarshal(data []byte, packets []rtcp.Packet) (n int, err error) {
	for i := 0; i < len(packets) && len(data) != 0; i++ {
		var h rtcp.Header

		err = h.Unmarshal(data)
		if err != nil {
			return 0, err
		}

		pktLen := int(h.Length+1) * 4
		if pktLen > len(data) {
			return 0, fmt.Errorf("packet too short")
		}
		inPacket := data[:pktLen]

		// Check the type and unmarshal
		packet := rtcpTypedPacket(h.Type)
		err = packet.Unmarshal(inPacket)
		if err != nil {
			return 0, err
		}

		packets[i] = packet

		data = data[pktLen:]
		n++
	}

	return n, nil
}

func RTCPMarshal(packets []rtcp.Packet) ([]byte, error) {
	return rtcp.Marshal(packets)
}

// TODO this would be nice that pion exports
func rtcpTypedPacket(htype rtcp.PacketType) rtcp.Packet {
	// Currently we are not interested

	switch htype {
	case rtcp.TypeSenderReport:
		return new(rtcp.SenderReport)

	case rtcp.TypeReceiverReport:
		return new(rtcp.ReceiverReport)

	case rtcp.TypeSourceDescription:
		return new(rtcp.SourceDescription)

	case rtcp.TypeGoodbye:
		return new(rtcp.Goodbye)

	default:
		return new(rtcp.RawPacket)
	}
}
