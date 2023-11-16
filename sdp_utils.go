package sipgox

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/sdp"
	"github.com/rs/zerolog/log"
)

func GetCurrentNTPTimestamp() uint64 {
	ntpEpochOffset := 2208988800 // Offset from Unix epoch (January 1, 1970) to NTP epoch (January 1, 1900)
	currentTime := time.Now().Unix() + int64(ntpEpochOffset)

	return uint64(currentTime)
}

type SDPMode string

const (
	// https://datatracker.ietf.org/doc/html/rfc4566#section-6
	SDPModeRecvonly SDPMode = "recvonly"
	SDPModeSendrecv SDPMode = "sendrecv"
	SDPModeSendonly SDPMode = "sendonly"
)

type Formats struct {
	Ulaw bool
	Alaw bool
}

func SDPGeneric(originIP net.IP, connectionIP net.IP, rtpPort int, mode SDPMode, f Formats) []byte {
	ntpTime := GetCurrentNTPTimestamp()

	formatsStrArr := []string{}
	formatsMap := []string{}
	if f.Ulaw {
		formatsStrArr = append(formatsStrArr, "0")
		formatsMap = append(formatsMap, "a=rtpmap:0 PCMU/8000")
	}

	if f.Alaw {
		formatsStrArr = append(formatsStrArr, "8")
		formatsMap = append(formatsMap, "a=rtpmap:8 PCMA/8000")
	}

	// Support only ulaw and alaw
	s := []string{
		"v=0",
		fmt.Sprintf("o=user1 %d %d IN IP4 %s", ntpTime, ntpTime, originIP),
		"s=Sip Go Media",
		// "b=AS:84",
		fmt.Sprintf("c=IN IP4 %s", connectionIP),
		"t=0 0",
		fmt.Sprintf("m=audio %d RTP/AVP %s", rtpPort, strings.Join(formatsStrArr, " ")),
		"a=" + string(mode),
		// "a=rtpmap:0 PCMU/8000",
		// "a=rtpmap:8 PCMA/8000",
		// "a=rtpmap:101 telephone-event/8000",
		// "a=fmtp:101 0-16",
		// "",
		// "a=rtpmap:120 telephone-event/16000",
		// "a=fmtp:120 0-16",
		// "a=rtpmap:121 telephone-event/8000",
		// "a=fmtp:121 0-16",
		// "a=rtpmap:122 telephone-event/32000",
		// "a=rtcp-mux",
		// fmt.Sprintf("a=rtcp:%d IN IP4 %s", rtpPort+1, connectionIP),
	}

	s = append(s, formatsMap...)

	// s := []string{
	// 	"v=0",
	// 	fmt.Sprintf("o=- %d %d IN IP4 %s", ntpTime, ntpTime, originIP),
	// 	"s=Sip Go Media",
	// 	// "b=AS:84",
	// 	fmt.Sprintf("c=IN IP4 %s", connectionIP),
	// 	"t=0 0",
	// 	fmt.Sprintf("m=audio %d RTP/AVP 96 97 98 99 3 0 8 9 120 121 122", rtpPort),
	// 	"a=" + string(mode),
	// 	"a=rtpmap:96 speex/16000",
	// 	"a=rtpmap:97 speex/8000",
	// 	"a=rtpmap:98 speex/32000",
	// 	"a=rtpmap:99 iLBC/8000",
	// 	"a=fmtp:99 mode=30",
	// 	"a=rtpmap:120 telephone-event/16000",
	// 	"a=fmtp:120 0-16",
	// 	"a=rtpmap:121 telephone-event/8000",
	// 	"a=fmtp:121 0-16",
	// 	"a=rtpmap:122 telephone-event/32000",
	// 	"a=rtcp-mux",
	// 	fmt.Sprintf("a=rtcp:%d IN IP4 %s", rtpPort+1, connectionIP),
	// }

	res := strings.Join(s, "\r\n")
	return []byte(res)
}

func GenerateUASDP(originIP string, connectionIP string, port int) []byte {
	sd := &sdp.SessionDescription{
		Version: 0,
		Origin: sdp.Origin{
			Username:       "-",
			SessionID:      GetCurrentNTPTimestamp(),
			SessionVersion: GetCurrentNTPTimestamp(),
			NetworkType:    "IN",
			AddressType:    "IP4",
			UnicastAddress: originIP,
			// UnicastAddress: "10.47.16.5",
		},
		SessionName: "SIP GO MEDIA",
		// SessionInformation: &(&struct{ x Information }{"A Seminar on the session description protocol"}).x,
		// URI: func() *url.URL {
		// 	uri, err := url.Parse("http://www.example.com/seminars/sdp.pdf")
		// 	if err != nil {
		// 		return nil
		// 	}
		// 	return uri
		// }(),
		// EmailAddress: &(&struct{ x EmailAddress }{"j.doe@example.com (Jane Doe)"}).x,
		// PhoneNumber:  &(&struct{ x PhoneNumber }{"+1 617 555-6011"}).x,
		ConnectionInformation: &sdp.ConnectionInformation{
			NetworkType: "IN",
			AddressType: "IP4",
			Address: &sdp.Address{
				// Address: "224.2.17.12",
				IP: net.ParseIP(connectionIP),
				// TTL: &(&struct{ x int }{127}).x,
			},
		},
		Bandwidth: []sdp.Bandwidth{
			// {
			// 	Experimental: true,
			// 	Type:         "YZ",
			// 	Bandwidth:    128,
			// },
			// {
			// 	Type:      "AS",
			// 	Bandwidth: 84,
			// },
		},
		TimeDescriptions: []sdp.TimeDescription{
			{
				Timing: sdp.Timing{
					StartTime: 0,
					StopTime:  0,
				},
				RepeatTimes: nil,
			},
			// {
			// 	Timing: Timing{
			// 		StartTime: 3034423619,
			// 		StopTime:  3042462419,
			// 	},
			// 	RepeatTimes: []RepeatTime{
			// 		{
			// 			Interval: 604800,
			// 			Duration: 3600,
			// 			Offsets:  []int64{0, 90000},
			// 		},
			// 	},
			// },
		},
		// TimeZones: []sdp.TimeZone{
		// 	{
		// 		AdjustmentTime: 2882844526,
		// 		Offset:         -3600,
		// 	},
		// 	{
		// 		AdjustmentTime: 2898848070,
		// 		Offset:         0,
		// 	},
		// },
		// EncryptionKey: &(&struct{ x EncryptionKey }{"prompt"}).x,
		Attributes: []sdp.Attribute{
			// sdp.NewAttribute("candidate:0 1 UDP 2113667327 203.0.113.1 54400 typ host", ""),
			sdp.NewAttribute("rtpmap:0 PCMU/8000", ""),
			sdp.NewAttribute("rtpmap:121 telephone-event/8000", ""),
			sdp.NewAttribute("sendrecv", ""),
			// "a=rtcp-mux",
			// sdp.NewAttribute("a=group:BUNDLE audio", ""),
			// sdp.NewAttribute("recvonly", ""),
			sdp.NewAttribute("rtcp-mux", ""),
		},
		MediaDescriptions: []*sdp.MediaDescription{
			{
				MediaName: sdp.MediaName{
					Media: "audio",

					// If non-contiguous ports are used or if they don't follow the
					// parity rule of even RTP ports and odd RTCP ports, the "a=rtcp:"
					// 				// attribute MUST be used.
					// 				Applications that are requested to send
					//   media to a <port> that is odd and where the "a=rtcp:" is present
					//   MUST NOT subtract 1 from the RTP port: that is, they MUST send the
					//   RTP to the port indicated in <port> and send the RTCP to the port
					//   indicated in the "a=rtcp" attribute.
					Port: sdp.RangedPort{
						Value: port,
					},
					Protos: []string{"RTP", "AVP"},
					// Protos:  []string{"UDP"},
					Formats: []string{"0", "121"},
				},
				// MediaTitle: &(&struct{ x Information }{"Vivamus a posuere nisl"}).x,
				// ConnectionInformation: &sdp.ConnectionInformation{
				// 	NetworkType: "IN",
				// 	AddressType: "IP4",
				// 	Address: &sdp.Address{
				// 		IP: net.ParseIP("203.0.113.1"),
				// 	},
				// },
				// Bandwidth: []Bandwidth{
				// 	{
				// 		Experimental: true,
				// 		Type:         "YZ",
				// 		Bandwidth:    128,
				// 	},
				// },
				// EncryptionKey: &(&struct{ x EncryptionKey }{"prompt"}).x,
				// Attributes: []Attribute{
				// 	NewAttribute("sendrecv", ""),
				// },
			},
			// {
			// 	MediaName: MediaName{
			// 		Media: "video",
			// 		Port: RangedPort{
			// 			Value: 51372,
			// 		},
			// 		Protos:  []string{"RTP", "AVP"},
			// 		Formats: []string{"99"},
			// 	},
			// 	Attributes: []Attribute{
			// 		NewAttribute("rtpmap:99 h263-1998/90000", ""),
			// 	},
			// },
		},
	}

	str := sd.Marshal()
	return []byte(str)

}

func SendDummyRTP(rtpConn *net.UDPConn, raddr net.Addr) {
	// Create an RTP packetizer for PCMU
	// Create an RTP packetizer
	mtu := uint16(1200)                    // Maximum Transmission Unit (MTU)
	payloadType := uint8(0)                // Payload type for PCMU
	ssrc := uint32(123456789)              // Synchronization Source Identifier (SSRC)
	payloader := &codecs.G711Payloader{}   // Payloader for PCMU
	sequencer := rtp.NewRandomSequencer()  // Sequencer for generating sequence numbers
	clockRate := uint32(8000)              // Audio clock rate for PCMU
	frameDuration := 20 * time.Millisecond // Duration of each audio frame

	packetizer := rtp.NewPacketizer(mtu, payloadType, ssrc, payloader, sequencer, clockRate)

	// Generate and send RTP packets every 20 milliseconds
	for {
		// Generate a dummy audio frame (replace with your actual audio data)
		audioData := generateSilentAudioFrame()

		// Calculate the number of samples
		numSamples := uint32(frameDuration.Seconds() * float64(clockRate))

		// Packetize the audio data into RTP packets
		packets := packetizer.Packetize(audioData, numSamples)

		// Send each RTP packet
		for _, packet := range packets {
			// Marshal the RTP packet into a byte slice
			data, err := packet.Marshal()
			if err != nil {
				log.Error().Err(err).Msg("Error marshaling RTP packet")
				continue
			}

			// Send the RTP packet
			if _, err := rtpConn.WriteTo(data, raddr); err != nil {
				log.Error().Err(err).Msg("Error sending RTP packet")
				return
			}

			log.Printf("Sent RTP packet: SeqNum=%d, Timestamp=%d, Payload=%d bytes\n", packet.SequenceNumber, packet.Timestamp, len(packet.Payload))
		}

		time.Sleep(20 * time.Millisecond)
	}
}

// Function to generate a silent audio frame
func generateSilentAudioFrame() []byte {
	frame := make([]byte, 160) // 160 bytes for a 20ms frame at 8kHz

	// Fill the frame with silence (zero values)
	for i := 0; i < len(frame); i++ {
		frame[i] = 0
	}

	return frame
}

func rtpUnmarshalAndReply(buf []byte) []byte {
	receivedPacket := &rtp.Packet{}
	if err := receivedPacket.Unmarshal(buf); err != nil {
		// Handle the error
	}

	// Prepare and send RTP replies
	replyPacket := &rtp.Packet{
		Header: rtp.Header{
			// Set the sequence number and timestamp appropriately
			SequenceNumber: receivedPacket.SequenceNumber,
			Timestamp:      receivedPacket.Timestamp,
			SSRC:           receivedPacket.SSRC,
			PayloadType:    receivedPacket.PayloadType,
		},
		Payload: []byte{ /* Set the payload for the reply */ },
	}

	// Marshal the RTP packet into a byte slice
	data, err := replyPacket.Marshal()
	if err != nil {
		// Handle the error
	}
	return data
}
