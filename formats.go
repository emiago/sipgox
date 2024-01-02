package sipgox

import (
	"strconv"
	"strings"
)

type FormatsList []int

func (f FormatsList) String() string {
	out := make([]string, len(f))
	for i, v := range f {
		switch v {
		case 0:
			out[i] = "0(ulaw)"
		case 8:
			out[i] = "8(alaw)"
		default:
			// Unknown then just use as number
			out[i] = strconv.Itoa(v)
		}
	}

	return strings.Join(out, ",")
}
