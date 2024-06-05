package sipgox

import (
	"net"

	"github.com/emiago/media"
	"github.com/pion/rtp"
)

// Temporarly wrapper
type MediaSession struct {
	*media.MediaSession
}

type MediaStreamer interface {
	MediaStream(s *MediaSession) error
}

func NewMediaSession(laddr *net.UDPAddr) (s *MediaSession, e error) {
	sess, err := media.NewMediaSession(laddr)
	return &MediaSession{sess}, err
}

func (sess *MediaSession) ReadRTP() (rtp.Packet, error) {
	pkt := rtp.Packet{}
	buf := make([]byte, media.RTPBufSize)
	return pkt, sess.MediaSession.ReadRTP(buf, &pkt)
}
