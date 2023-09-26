# sipgox

is experiment area to add extra functionality on top [sipgo lib](https://github.com/emiago/sipgo)

If use it in your projects consider that this repo will not have stable code for now.

If you find useful, support this, open issue etc...
## Phone

Lib provides a simple phone (UA) building
```go 

phone := sipgox.NewPhone(ua,
    sipgox.WithPhoneListenAddr(udpAddr),
)

// Phone register
phone.Register(*username, *password, *dst)

// Dial destination
phone.Dial(recipient)
```

TODO:
- [x] Simple register and dial
- [x] Media receiving
- [ ] Answering
- [ ] Playback Media (probably through custom media)
- [ ] Hangup
- [ ] Timeouts
- [ ] SDP codec fields manipulating
- [ ] SDP negotiation fail
- [ ] Customizing media handling for Dial, hooks...



## Media

Creating media handling

TODO:  
- [x] Custom RTP/RTCP handling
- [ ] RTP/RTCP parsing
- [ ] Passing DTMF

## Bridge (TODO)

B2Bua bridging