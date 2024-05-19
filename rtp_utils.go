package sipgox

import (
	"time"
)

func GetCurrentNTPTimestamp() uint64 {
	ntpEpochOffset := 2208988800 // Offset from Unix epoch (January 1, 1970) to NTP epoch (January 1, 1900)
	currentTime := time.Now().Unix() + int64(ntpEpochOffset)

	return uint64(currentTime)
}

func NTPTimestamp(now time.Time) uint64 {
	ntpEpochOffset := 2208988800 // Offset from Unix epoch (January 1, 1970) to NTP epoch (January 1, 1900)
	currentTime := now.Unix() + int64(ntpEpochOffset)

	return uint64(currentTime)
}
