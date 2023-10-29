
# PSIP is extension for SIPGO for easy building proxy 

For now this is **idea**, to hide lot of complexity and provide configurable proxy setup.


If you like it and want to happen please support [sipgo project](https://ko-fi.com/emiasupport)


## Controling request and relay

```go 
ua, _ := sipgo.NewUA()
srv, _ := sipgo.NewServer(ua)

p := NewProxy(
    srv,
    "",
    WithProxyInboundTarget(sip.Uri{Host: "127.0.0.200", Port: 5060}),
)
go p.s.ListenAndServe(ctx, "udp", "127.0.0.1:5060")
go p.s.ListenAndServe(ctx, "tcp", "127.0.0.1:5060")


proxy.OnRequest(func(rc RequestContext) {

    req := rc.Request()

    // ROUTE LOGIC
    // This only makes sense for some custom logic
    // req.SetDestination() should be called
  
    

    // Is this request part of dialog
    // Applies only for INVITE, ACK, BYE
    if d := rc.Dialog(); d != nil{
        // Set some dialog vars ?
        // It has mutex protected
        d.SetVar("test", "test")
    }

    // Check headers

    // Topoh for topology hidding.
    // Creates and new request and removes any internal topology
    // - Changes Via
    // - Updates recipient
    req := rc.Topoh(req)
    // When RequestContext is dead it will trigger TOPOS cleanup (database) ext


    // RelayRequest will:
    // - Check registrar 
    // - Detect call direction. Src IP is compared to Inbound(internal) IP Targets ranges
    // - Relay reqeust
    // req.SetDestination() will skip above checking
    respCh, err := rc.RelayRequest(req)
    // err means some relay error, network error


    for _, res := range respCH {

        // Handle failure
        switch res.StatusCode {
            // Handle bad codes
            case 401, 403, 505, 600:
                req.SetDestination("failcarrier.com")
                respCh, err := rc.RelayRequest(req)
                // Check again ...
            default:
                // relay all

        }
        err := rc.RelayResponse(res)
        // handler err
    }
})
```

With this simple logic proxy builder can do:
- Any logic before processing request:
    - blacklisting, whitelisting
- IP auth based on `req.Source()`  TODO provide some simple module
- Digest auth out of box 
- Dialog routing out of box

## Inbound Outbound targets

Here how to configure proxy inbound/outbound targets.

```go
WithProxyInboundTarget(
    sip.Uri{Host: "my.asterisk.xy", Port: 5060},
    // MatchIP should be defined in case URI is host name, otherwise it will be DNS resolved each time
    gsip.MatchIP( 
        "10.1.1.0/24", // With range ips to match in case this is dynamic
        "10.2.2.1", // With static ips
    ),
)
```

```go
WithProxyOutboundTarget(
    sip.Uri{Host: "sip.carrier.com", Port: 5060},
    gsip.ToPrefix("49"), // or gsip.ToRegex("^49(1-2)"),
    0.5 // In case multiple matching carrier  < 1.0 request is loadbalanced
)
```
## RelayRequest

`RelayRequest` flow:
- If no destination is set with `req.SetDestination` then
- Check registrar if used as registrar
- Detect call direction Src IP is compared to Inbound `MatchIP`
- Filter all with matching Destination via Prefix, Regex
- Load balance unless target has weight 1.0
- Relay reqeust


`RelayRequest` internally:
- creates client transaction 
- sends request and returns all responses
- responses can be manipulated but mostly they should be relayed to originator
- IN case 200 response for INVITE it creates dialog which can be accessed via `rc.Dialog()`


### SBC and RTP proxy integration features

Minimum set of features to be provided.

SBC:
- `Topoh` is topology hidding for you SIP signaling and can be called in RequestContext
- Source address IP auth via inbound/outbound matchIP
- RTP proxy integrated
- Rate limiting

RTP Proxy signaling:
- Reads INVITE SDP
- Setups RTP/RTCP ports for proxy external and internal interface (interface call as it can be seperate Service)
- Applies new SDP with internal IP RTP/RTCP ports
- Relays request
- Reads Response (only 200)
- Changes SDP to external interface 
- Changes SDP port to external PORTs
- Returns response
- When `RequestContext` dies RTP/RTCP will be closed


## RelayResponse

`RelayResponse` 
- relays response to called `RelayRequest`
- returns err:
    - Not found destination
    - network issue, dns resolving etc.
- 


# Unit testing your route handler

TODO!


