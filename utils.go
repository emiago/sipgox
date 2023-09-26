package sipgox

import "strings"

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
