A pure Nim client Domain Name System (DNS) implemented with [dnsprotocol](https://github.com/rockcavera/nim-dnsprotocol).

This implementation has synchronous and asynchronous (async) procedures (procs) for transmitting data over the internet, using both UDP and TCP protocol.
# Install
`nimble install ndns`

or

`nimble install https://github.com/rockcavera/nim-ndns.git`
# Basic Use
Resolving IPv4 addresses for nim-lang.org (**not async**):
```nim
import ndns

let client = initDnsClient()

echo resolveIpv4(client, "nim-lang.org")
```

Resolving IPv4 addresses for nim-lang.org (**async**):
```nim
import asyncdispatch, ndns

let client = initDnsClient()

echo waitFor asyncResolveIpv4(client, "nim-lang.org")
```
# Advanced Use
Creating a `Message` object with a `QType.A` query for the domain name nim-lang.org, transmitting the `Message` and receiving the response (**not async**):
```nim
import ndns

let header = initHeader(randId(), rd = true)

let question = initQuestion("nim-lang.org", QType.A, QClass.IN)
  # If the last character of "nim-lang.org" is not a '.', the initializer will
  # add, as it is called the DNS root.

let msg = initMessage(header, @[question])
  # The initializer automatically changes `header.qdcount` to `1'u16`

let client = initDnsClient()

var rmsg = dnsQuery(client, msg)

echo repr(rmsg)
```

Creating a `Message` object with a `QType.A` query for the domain name nim-lang.org, transmitting the `Message` and receiving the response (**async**):
```nim
import asyncdispatch, ndns

let header = initHeader(randId(), rd = true)

let question = initQuestion("nim-lang.org", QType.A, QClass.IN)
  # If the last character of "nim-lang.org" is not a '.', the initializer will
  # add, as it is called the DNS root.

let msg = initMessage(header, @[question])
  # The initializer automatically changes `header.qdcount` to `1'u16`

let client = initDnsClient()

var rmsg = waitFor dnsAsyncQuery(client, msg)

echo repr(rmsg)
```
# Documentation
https://rockcavera.github.io/nim-ndns/theindex.html