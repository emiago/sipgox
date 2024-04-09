package sipgox

import (
	"fmt"
	"math/rand"
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

func FindFreeInterfaceHostPort(network string, targetAddr string) (ip net.IP, port int, err error) {
	// Go with random
	// use empheral instead of this
	ip, err = resolveHostIPWithTarget(network, targetAddr)
	if err != nil {
		return ip, port, err
	}

	port, err = findFreePort(network, ip)
	if err != nil {
		return
	}

	if port == 0 {
		return ip, port, fmt.Errorf("failed to find free port")
	}

	return ip, port, err
}

func findFreePort(network string, ip net.IP) (int, error) {
	switch network {
	case "udp":
		var l *net.UDPConn
		l, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
		if err != nil {
			return 0, err
		}
		l.Close()
		// defer l.Close()
		port := l.LocalAddr().(*net.UDPAddr).Port
		return port, nil

	case "tcp", "ws", "tls", "wss":
		var l *net.TCPListener
		l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ip})
		if err != nil {
			return 0, err
		}
		defer l.Close()
		port := l.Addr().(*net.TCPAddr).Port
		return port, nil
	default:
		return rand.Intn(9999) + 6000, nil
	}
}
