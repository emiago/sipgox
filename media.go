package sipgox

import (
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/rs/zerolog/log"
)

type MediaSession struct {
	RTPport int
	Dst     *net.UDPAddr
	// rtpDstConn *net.UDPConn

	rtpConn  *net.UDPConn
	rtcpConn *net.UDPConn

	Formats []int // For now can be set depending on SDP exchange
}

func (m *MediaSession) LocalRTPAddr() *net.UDPAddr {
	return m.rtpConn.LocalAddr().(*net.UDPAddr)
}

func (m *MediaSession) LocalRTCPAddr() *net.UDPAddr {
	return m.rtcpConn.LocalAddr().(*net.UDPAddr)
}

func NewMediaSessionFromSDP(sdpSend []byte, sdpReceived []byte) (s *MediaSession, err error) {
	sd := SessionDescription{}
	if err := UnmarshalSDP(sdpSend, &sd); err != nil {
		// p.log.Debug().Err(err).Msgf("Fail to parse SDP\n%q", string(r.Body()))
		return nil, fmt.Errorf("fail to parse send SDP: %w", err)
	}

	md, err := sd.MediaDescription("audio")
	if err != nil {
		return nil, err
	}

	ci, err := sd.ConnectionInformation()
	if err != nil {
		return nil, err
	}

	rtpPort := md.Port
	sendCodecs := md.Formats
	connectionIP := ci.IP

	sd = SessionDescription{}
	if err := UnmarshalSDP(sdpReceived, &sd); err != nil {
		// p.log.Debug().Err(err).Msgf("Fail to parse SDP\n%q", string(r.Body()))
		return nil, fmt.Errorf("fail to parse received SDP: %w", err)
	}

	md, err = sd.MediaDescription("audio")
	if err != nil {
		return nil, err
	}

	ci, err = sd.ConnectionInformation()
	if err != nil {
		return nil, err
	}

	dstIP := ci.IP
	dstPort := md.Port
	recvCodecs := md.Formats

	// Check codecs but expect all send codecs are send
	formats := make([]int, 0, cap(sendCodecs))
	parseErr := []error{}
	for _, cr := range recvCodecs {
		for _, cs := range sendCodecs {
			if cr == cs {
				f, err := strconv.Atoi(cs)
				// keep going
				if err != nil {
					parseErr = append(parseErr, err)
					continue
				}
				formats = append(formats, f)
			}
		}
	}

	if len(formats) == 0 {
		emsg := "No formats found"
		for _, e := range parseErr {
			emsg += ": " + e.Error()
		}
		return nil, fmt.Errorf(emsg)
	}

	mess, err := NewMediaSession(connectionIP, rtpPort, dstIP, dstPort, formats)
	if err != nil {
		return nil, err
	}

	return mess, nil
}

func NewMediaSession(ip net.IP, rtpPort int, dstIP net.IP, dstPort int, formats []int) (s *MediaSession, err error) {
	// Generate random rtp port
	// Prepare our media ports for recv
	// RTP port must be even, but RTCP must be odd
	// Range 6000 - 7000
	// rtpPort := rand.Intn(1000*2)/2 + 6000

	// What if RTP port not availale?

	// RTP
	rtpladdr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip.String(), rtpPort))
	rtpConn, err := net.ListenUDP("udp", rtpladdr)
	if err != nil {
		return nil, err
	}

	// RTCP is always rtpPort + 1
	rtcpladdr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip.String(), rtpPort+1))
	rtcpConn, err := net.ListenUDP("udp", rtcpladdr)
	if err != nil {
		return nil, err
	}

	log.Debug().Str("rtp", rtpladdr.String()).Str("rtcp", rtcpladdr.String()).Msg("Setting up media session")
	s = &MediaSession{
		RTPport:  rtpPort,
		rtpConn:  rtpConn,
		rtcpConn: rtcpConn,
		Dst: &net.UDPAddr{
			IP:   dstIP,
			Port: dstPort,
		},
		// rtpDstConn: rtpDstConn,
		Formats: formats,
	}

	return s, nil
}

func (s *MediaSession) Close() {
	s.rtcpConn.Close()
	s.rtpConn.Close()
}

func (s *MediaSession) UpdateDestinationSDP(sdpReceived []byte) error {
	sd := SessionDescription{}
	if err := UnmarshalSDP(sdpReceived, &sd); err != nil {
		// p.log.Debug().Err(err).Msgf("Fail to parse SDP\n%q", string(r.Body()))
		return fmt.Errorf("fail to parse received SDP: %w", err)
	}

	md, err := sd.MediaDescription("audio")
	if err != nil {
		return err
	}

	ci, err := sd.ConnectionInformation()
	if err != nil {
		return err
	}

	s.Dst.IP = ci.IP
	s.Dst.Port = md.Port

	// TODO, we should maybe again check with our previous SDP?
	// we will consider that update is considering sent codecs
	s.Formats = selectFormats(md.Formats, md.Formats)
	return nil
}

func (m *MediaSession) ReadRTP() (rtp.Packet, error) {
	p := rtp.Packet{}

	buf := make([]byte, 1600)
	n, err := m.rtpConn.Read(buf)
	if err != nil {
		return p, err
	}

	return p, p.Unmarshal(buf[:n])
}

func (m *MediaSession) ReadRTCP() ([]rtcp.Packet, error) {

	buf := make([]byte, 1600)
	n, err := m.rtcpConn.Read(buf)
	if err != nil {
		return nil, err
	}

	return rtcp.Unmarshal(buf[:n])
}

func (m *MediaSession) WriteRTP(p *rtp.Packet) error {
	data, err := p.Marshal()
	if err != nil {
		return err
	}

	n, err := m.rtpConn.WriteTo(data, m.Dst)
	if err != nil {
		return err
	}

	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func selectFormats(sendCodecs []string, recvCodecs []string) []int {
	formats := make([]int, 0, cap(sendCodecs))
	parseErr := []error{}
	for _, cr := range recvCodecs {
		for _, cs := range sendCodecs {
			if cr == cs {
				f, err := strconv.Atoi(cs)
				// keep going
				if err != nil {
					parseErr = append(parseErr, err)
					continue
				}
				formats = append(formats, f)
			}
		}
	}
	return formats
}
