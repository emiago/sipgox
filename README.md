# sipgox

is experimental/extra area to add more functionality on top [sipgo lib](https://github.com/emiago/sipgo)

If use it in your projects consider that this repo will not have stable code until it is considered merging to `sipgo stack`

If you find useful, support/sponsor [sipgo lib](https://github.com/emiago/sipgo), open issue etc...

Here you can find [docs](https://pkg.go.dev/github.com/emiago/sipgox)

Tools using this lib:
- [gophone](https://github.com/emiago/gophone)

Features:
- [x] Simple API for UA/phone build with dial answer register actions
- [x] Dialog setup and small SDP with alaw and ulaw codec
- [x] RTP/RTCP receiving and logging
- [x] Extendable MediaSession handling for RTP/RTCP handling (ex microphone,speaker)
- [x] Hangup control on caller
- [x] Timeouts handling
- [x] Digest auth
- [ ] Transfers on answer, dial
- [ ] SDP codec fields manipulating
- [ ] SDP negotiation fail
- [ ] DTMF passing


Checkout `echome` example to see more. 


## Phone

Phone is wrapper that can make you easy build phone, create/receive SIP call, handle RTP/RTCP.

### Dialer

```go
    ua, _ := sipgo.NewUA()
    defer ua.Close()

    // Create a phone
	phone := sipgox.NewPhone(ua) 

    // Run dial
	ctx, _ := context.WithTimeout(context.Background(), 60*time.Second)
	dialog, err := phone.Dial(ctx, sip.Uri{User:"bob", Host: "localhost", Port:5060}, sipgox.DialOptions{})
	if err != nil {
		// handle error
        return
	}
	defer dialog.Close() // Close dialog for cleanup

    select {
    case <-dialog.Done():
        return
    case <-time.After(5 *time.Second):
        dialog.Hangup(context.TODO())
    }
```

### Receiver

```go
    ua, _ := sipgo.NewUA()
    defer ua.Close()

    // Create a phone
    phone := sipgox.NewPhone(ua)

	ctx, _ := context.WithCancel(context.Background())
	dialog, err := phone.Answer(ctx, sipgox.AnswerOptions{
		Ringtime:  5* time.Second,
	})
	if err != nil {
		//handle error
        return
	}
    defer dialog.Close() // Close dialog for cleanup

    select {
    case <-dialog.Done():
        return
    case <-time.After(10 *time.Second):
        dialog.Hangup(context.TODO())
    }
```