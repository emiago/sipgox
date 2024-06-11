# sipgox

is experimental/extra area to add more functionality on top [sipgo lib](https://github.com/emiago/sipgo), more specifically, to fill gap for building user agents with media. This allows much more easier 
voip testing or faster way to create UAC/UAS.

To find out more read also article about [E2E testing](https://github.com/emiago/sipgo/wiki/E2E-testing) and check [GO Documentation](https://pkg.go.dev/github.com/emiago/sipgox)

**NOTE**: [Media package (github.com/emiago/media)](https://github.com/emiago/media) is now seperate repo.

If you find useful, support [sipgo lib](https://github.com/emiago/sipgo), open issue etc...

Tools this lib:
- [gophone - CLI phone](https://github.com/emiago/gophone)

Features:
- [x] Simple API for UA/phone build with dial answer register actions
- [x] Minimal SDP package for audio
- [x] RTP/RTCP receiving and logging
- [x] Extendable MediaSession handling for RTP/RTCP handling (ex microphone,speaker)
- [x] Hangup control on caller
- [x] Timeouts handling
- [x] Digest auth
- [x] Transfers on phone answer, dial
- [ ] DTMF on phone with simple API
- [ ] ... who knows



Checkout [echome](/echome/) example to see more. 


## Phone

Phone is wrapper that can make you to build fast phone, create/receive SIP call, handle RTP/RTCP. It uses `sipgo.Dialog` and adds **media handling** on top. 

It has specific design, and it can not be used for full softphone build.

### Dialer

```go
ua, _ := sipgo.NewUA()
defer ua.Close()

// Create a phone
phone := sipgox.NewPhone(ua) 

// Run dial
ctx, _ := context.WithTimeout(context.Background(), 60*time.Second)

// Blocks until call is answered
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
ctx, _ := context.WithCancel(context.Background())

ua, _ := sipgo.NewUA()
defer ua.Close()

// Create a phone
phone := sipgox.NewPhone(ua)

// Blocks until call is answered
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

### Reading/Writing RTP/RTCP on dialog

After you Answer or Dial on phone, you receive dialog.

**RTP**
```go
buf := make([]byte, media.RTPBufSize) // Has MTU size
pkt := rtp.Packet{}
err := dialog.ReadRTP(buf, &pkt)

err := dialog.WriteRTP(pkt)

```

similar is for RTCP