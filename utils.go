package sipgox

import (
	"net"
	"strings"

	"github.com/emiago/sipgo/sip"
)

// We are lazy to write full sip uris
func CheckLazySipUri(target string, destOverwrite string) string {
	if !strings.Contains(target, "@") {
		target = target + "@" + destOverwrite
	}

	if !strings.HasPrefix(target, "sip") {
		target = "sip:" + target
	}

	return target
}

func resolveHostIPWithTarget(network string, targetAddr string) (net.IP, error) {
	if network == "udp" {
		tip, _, _ := sip.ParseAddr(targetAddr)
		if ip := net.ParseIP(tip); ip != nil {
			if ip.IsLoopback() {
				// TO avoid UDP COnnected connection problem hitting different subnet
				return net.ParseIP("127.0.0.99"), nil
			}
		}
	}
	return sip.ResolveSelfIP()
}
