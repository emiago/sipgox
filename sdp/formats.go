package sdp

import "strconv"

const (
	FORMAT_TYPE_ULAW = "0"
	FORMAT_TYPE_ALAW = "8"
)

type Formats []string

func NewFormats(fmts ...string) Formats {
	return Formats(fmts)
}

//	If the <proto> sub-field is "RTP/AVP" or "RTP/SAVP" the <fmt>//
//
// sub-fields contain RTP payload type numbers.
func (fmts Formats) ToNumeric() (nfmts []int, err error) {
	nfmt := make([]int, len(fmts))
	for i, f := range fmts {
		nfmt[i], err = strconv.Atoi(f)
		if err != nil {
			return
		}
	}
	return nfmt, nil
}
