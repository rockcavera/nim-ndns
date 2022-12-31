## A pure Nim Domain Name System (DNS) client implemented with
## [dnsprotocol](https://github.com/rockcavera/nim-dnsprotocol).
##
## This implementation has synchronous and asynchronous (async) procedures
## (procs) for transmitting data over the internet, using both UDP and TCP
## protocol.
##
## Basic Use
## =========
## Resolving IPv4 addresses for nim-lang.org (**not async**):
## ```nim
## import ndns
##
## let client = initDnsClient()
##
## echo resolveIpv4(client, "nim-lang.org")
## ```
##
## Resolving IPv4 addresses for nim-lang.org (**async**):
## ```nim
## import asyncdispatch, ndns
##
## let client = initDnsClient()
##
## echo waitFor asyncResolveIpv4(client, "nim-lang.org")
## ```
##
## Advanced Use
## ============
## Creating a `Message` object with a `QType.A` query for the domain name
## nim-lang.org, transmitting the `Message` and receiving the response (**not
## async**):
## ```nim
## import ndns
##
## let header = initHeader(randId(), rd = true)
##
## let question = initQuestion("nim-lang.org", QType.A, QClass.IN)
##   # If the last character of "nim-lang.org" is not a '.', the initializer will
##   # add, as it is called the DNS root.
##
## let msg = initMessage(header, @[question])
##   # The initializer automatically changes `header.qdcount` to `1'u16`
##
## let client = initDnsClient()
##
## var rmsg = dnsQuery(client, msg)
##
## echo repr(rmsg)
## ```
##
## Creating a `Message` object with a `QType.A` query for the domain name
## nim-lang.org, transmitting the `Message` and receiving the response
## (**async**):
## ```nim
## import asyncdispatch, ndns
##
## let header = initHeader(randId(), rd = true)
##
## let question = initQuestion("nim-lang.org", QType.A, QClass.IN)
##   # If the last character of "nim-lang.org" is not a '.', the initializer will
##   # add, as it is called the DNS root.
##
## let msg = initMessage(header, @[question])
##   # The initializer automatically changes `header.qdcount` to `1'u16`
##
## let client = initDnsClient()
##
## var rmsg = waitFor dnsAsyncQuery(client, msg)
##
## echo repr(rmsg)
## ```
##
## Using System DNS Server
## =======================
## You can initialize the DNS client with the DNS resolver server used by the
## system. To do this, start the client with `initSystemDnsClient`.
## ```nim
## import ndns
##
## let client = initSystemDnsClient()
##
## echo resolveIpv4(client, "nim-lang.org")
## ```

# Std imports
import std/[asyncdispatch, asyncnet, nativesockets, net, random]

# Nimble packages imports
import pkg/[dnsprotocol, stew/endians2]

export dnsprotocol, TimeoutError, Port

# Internal
when defined(nimdoc):
  import ./ndns/platforms/winapi
  import ./ndns/platforms/resolv except getSystemDnsServer
else:
  when defined(windows):
    import ./ndns/platforms/winapi
  elif defined(linux) or defined(bsd):
    import ./ndns/platforms/resolv

type
  DnsClient* = object ## Contains information about the DNS server.
    ip*: string ## Dns server IP.
    port*: Port ## DNS server listening port.
    domain: Domain

  UnexpectedDisconnectionError* = object of CatchableError
    ## Raised if an unexpected disconnect occurs (only TCP).
  ResponseIpNotEqualError* = object of CatchableError
    ## Raised if the IP that sent the response is different from the IP that
    ## received the query (only UDP).
  ResponsePortNotEqualError* = object of CatchableError
    ## Raised if the Port that sent the response is different from the Port that
    ## received the query (only UDP).
  ResponseIdNotEqualError* = object of CatchableError
    ## Raised if the query ID does not match the response ID.
  IsNotAnResponseError* = object of CatchableError
    ## Raised if not a response (!= QR.Response).
  OpCodeNotEqualError* = object of CatchableError
    ## Raised if the OpCode is different between the query and the response.

const
  ipv4Arpa = "in-addr.arpa"
    ## Special domain reserved for reverse IP lookup for IPv4
  ipv6Arpa = "ip6.arpa"
    ## Special domain reserved for IP reverse query for IPv6
  defaultIpDns* = "8.8.8.8"
    ## Default dns server ip for DNS queries. The Google server was chosen due
    ## to its uptime, with the same IP.

randomize()

proc initDnsClient*(ip: string = defaultIpDns, port: Port = Port(53)): DnsClient =
  ## Returns a created `DnsClient` object.
  ##
  ## **Parameters**
  ## - `ip` is a DNS server IP. It can be IPv4 or IPv6. It cannot be a domain
  ##   name.
  ## - `port` is a DNS server listening port.
  let tmp = parseIpAddress(ip)

  result.ip = ip
  result.port = port
  case tmp.family
  of IpAddressFamily.IPv6:
    result.domain = AF_INET6
  of IpAddressFamily.IPv4:
    result.domain = AF_INET

proc initSystemDnsClient*(): DnsClient =
  ## Returns a `DnsClient` object, in which the dns server IP is the first one
  ## used by the system. If it is not possible to determine a dns server IP by
  ## the system, it will be initialized with `defaultIpDns`.
  ##
  ## Currently implemented for:
  ## - Windows
  ## - Linux and Bsd
  ##
  ## Notes:
  ## - It just creates a `DnsClient` object with the IPv4 used by the system.
  ##   Does not use the system's native DNS resolution implementation unless the
  ##   system provides a proxy.
  ## - The `ip` field in the `DnsClient` object does not change automatically if
  ##   the IP used by the system changes.
  when declared(getSystemDnsServer):
    var ipServDns = getSystemDnsServer()

    if ipServDns == "":
      ipServDns = defaultIpDns

    initDnsClient(ipServDns)
  else:
    initDnsClient()

template newSocketTmpl(sockType: SockType, protocol: Protocol) =
  when socket is AsyncSocket:
    socket = newAsyncSocket(client.domain, sockType, protocol, false)
  elif socket is Socket:
    socket = newSocket(client.domain, sockType, protocol, false)

template checkResponse(protocol: Protocol) =
  when IPPROTO_UDP == protocol:
    if fromIp != client.ip:
      raise newException(ResponseIpNotEqualError,
                         "The IP that sent the response is different from the IP that received the query")

    if fromPort != client.port:
      raise newException(ResponsePortNotEqualError,
                         "The Port that sent the response is different from the Port that received the query")

  result = parseMessage(rBinMsg)

  if result.header.id != msg.header.id:
    raise newException(ResponseIdNotEqualError,
                       "The query ID does not match the response ID")

  if result.header.flags.qr != QR.Response:
    raise newException(IsNotAnResponseError, "Not a response (!= QR.Response)")

  if result.header.flags.opcode != msg.header.flags.opcode:
    raise newException(OpCodeNotEqualError,
                       "The OpCode is different between the query and the response")

proc dnsTcpQuery*(client: DnsClient, msg: Message, timeout: int = -1): Message =
  ## Returns a `Message` of the DNS query response performed using the TCP
  ## protocol.
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `msg` is a `Message` object that contains the DNS query.
  ## - `timeout` is the maximum waiting time, in milliseconds, to connect to the
  ##   DNS server. When it is `-1`, it will try to connect for an unlimited
  ##   time.
  let qBinMsg = toBinMsg(msg, true)

  var socket: Socket

  newSocketTmpl(SOCK_STREAM, IPPROTO_TCP)

  setSockOpt(socket, OptNoDelay, true, cint(IPPROTO_TCP))

  setBlocking(getFd(socket), false)

  try:
    connect(socket, client.ip, client.port, timeout)
  except TimeoutError:
    close(socket)

    raise newException(TimeoutError,  "Connection timeout has been reached")
  except:
    close(socket)

    raise

  send(socket, qBinMsg)

  let lenRecv = recv(socket, 2)

  if "" == lenRecv:
    close(socket)

    raise newException(UnexpectedDisconnectionError,
                       "An unexpected disconnect occurs")

  var
    remaiderRecv = int(fromBytes(uint16, [uint8(ord(lenRecv[0])),
                                          uint8(ord(lenRecv[1]))], bigEndian))
    rBinMsg = newStringOfCap(remaiderRecv)

  while remaiderRecv >= BufferSize:
    let recv = recv(socket, BufferSize)

    if recv == "":
      close(socket)

      raise newException(UnexpectedDisconnectionError,
                         "An unexpected disconnect occurs")

    add(rBinMsg, recv)

    remaiderRecv = remaiderRecv - len(recv)

  while remaiderRecv > 0:
    let recv = recv(socket, remaiderRecv)

    if recv == "":
      close(socket)

      raise newException(UnexpectedDisconnectionError,
                         "An unexpected disconnect occurs")

    add(rBinMsg, recv)

    remaiderRecv = remaiderRecv - len(recv)

  close(socket)

  checkResponse(IPPROTO_TCP)

proc dnsQuery*(client: DnsClient, msg: Message, timeout: int = -1,
               retransmit = false): Message =
  ## Returns a `Message` of the DNS query response performed using the UDP
  ## protocol
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `msg` is a `Message` object that contains the DNS query.
  ## - `timeout` is the maximum waiting time, in milliseconds, to receive the
  ##   response from the DNS server. When it is `-1`, it will try to receive the
  ##   response for an unlimited time.
  ## - `retransmit` when `true`, determine the retransmission of the query to
  ##   TCP protocol when the received response is truncated
  ##   (`header.flags.tc == true`).
  let qBinMsg = toBinMsg(msg)

  var socket: Socket

  newSocketTmpl(SOCK_DGRAM, IPPROTO_UDP)

  sendTo(socket, client.ip, client.port, qBinMsg)

  var
    sRead = @[getFd(socket)]
    rBinMsg = newString(512)
    fromIp: string
    fromPort: Port

  if selectRead(sRead, timeout) > 0:
    discard recvFrom(socket, rBinMsg, 512, fromIp, fromPort)
  else:
    close(socket)

    raise newException(TimeoutError, "Response timeout has been reached")

  close(socket)

  checkResponse(IPPROTO_UDP)

  if result.header.flags.tc and retransmit:
    result = dnsTcpQuery(client, msg, timeout)

proc dnsAsyncTcpQuery*(client: DnsClient, msg: Message, timeout: int = 500):
                      owned(Future[Message]) {.async.} =
  ## Returns a `Message` of the DNS query response performed using the TCP
  ## protocol
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `msg` is a `Message` object that contains the DNS query.
  ## - `timeout` is the maximum waiting time, in milliseconds, to connect to the
  ##   DNS server. When it is negative (less than 0), it will try to connect for
  ##   an unlimited time.
  let qBinMsg = toBinMsg(msg, true)

  var socket: AsyncSocket

  newSocketTmpl(SOCK_STREAM, IPPROTO_TCP)

  setSockOpt(socket, OptNoDelay, true, cint(IPPROTO_TCP))

  var fut = connect(socket, client.ip, client.port)

  if (timeout < 0):
    yield fut
  else:
    let waiting = await withTimeout(fut, timeout)

    if not waiting:
      close(socket)

      raise newException(TimeoutError, "Connection timeout has been reached")

  if fut.failed:
    close(socket)

    raise fut.readError()

  await send(socket, qBinMsg)

  let lenRecv = await recv(socket, 2)

  if "" == lenRecv:
    close(socket)

    raise newException(UnexpectedDisconnectionError,
                       "An unexpected disconnect occurs")

  var
    remaiderRecv = int(fromBytes(uint16, [uint8(ord(lenRecv[0])),
                                          uint8(ord(lenRecv[1]))], bigEndian))
    rBinMsg = newStringOfCap(remaiderRecv)

  while remaiderRecv >= BufferSize:
    let recv = await recv(socket, BufferSize)

    if recv == "":
      close(socket)

      raise newException(UnexpectedDisconnectionError,
                         "An unexpected disconnect occurs")

    add(rBinMsg, recv)

    remaiderRecv = remaiderRecv - len(recv)

  while remaiderRecv > 0:
    let recv = await recv(socket, remaiderRecv)

    if recv == "":
      close(socket)

      raise newException(UnexpectedDisconnectionError,
                         "An unexpected disconnect occurs")

    add(rBinMsg, recv)

    remaiderRecv = remaiderRecv - len(recv)

  close(socket)

  checkResponse(IPPROTO_TCP)

proc dnsAsyncQuery*(client: DnsClient, msg: Message, timeout: int = 500,
                    retransmit = false): owned(Future[Message]) {.async.} =
  ## Returns a `Message` of the DNS query response performed using the UDP
  ## protocol.
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `msg` is a `Message` object that contains the DNS query.
  ## - `timeout` is the maximum waiting time, in milliseconds, to receive the
  ##   response from the DNS server. When it is negative (less than 0), it will
  ##   try to receive the response for an unlimited time.
  ## - `retransmit` when `true`, determine the retransmission of the query to
  ##   TCP protocol when the received response is truncated
  ##   (`header.flags.tc == true`).
  let qBinMsg = toBinMsg(msg)

  var socket: AsyncSocket

  newSocketTmpl(SOCK_DGRAM, IPPROTO_UDP)

  await sendTo(socket, client.ip, client.port, qBinMsg)

  var fut = recvFrom(socket, 512)

  if timeout < 0:
    yield fut
  else:
    let waiting = await withTimeout(fut, timeout)

    if not waiting:
      close(socket)

      raise newException(TimeoutError, "Response timeout has been reached")

  if fut.failed:
    close(socket)

    raise fut.readError()

  let (rBinMsg, fromIp, fromPort) = fut.read()

  close(socket)

  checkResponse(IPPROTO_UDP)

  if result.header.flags.tc and retransmit:
    result = await dnsAsyncTcpQuery(client, msg, timeout)

template domainNameRDns(domainV4, domainV6: string) =
  let ip = parseIpAddress(ip)

  case ip.family
  of IpAddressFamily.IPv4:
    # 15 characters for IPv4 +
    # 1 character for the dot of connection between IPv4 and `domainV4` +
    # `len(domainV4)`
    result = newStringOfCap(16 + len(domainV4))

    for i in countdown(3, 0):
      result.add($ip.address_v4[i])
      result.add('.')

    result.add(domainV4)
  of IpAddressFamily.IPv6:
    const hexDigits = "0123456789ABCDEF"
    # 63 characters for IPv6 +
    # 1 character for the dot of connection between IPv6 and `domainV6` +
    # `len(domainV6)`
    result = newStringOfCap(64 + len(domainV6))

    for i in countdown(15, 0):
      let
        hi = (ip.address_v6[i] shr 4) and 0xF
        lo = ip.address_v6[i] and 0xF

      add(result, hexDigits[lo])
      add(result, '.')
      add(result, hexDigits[hi])
      add(result, '.')

    result.add(domainV6)

proc prepareRDns*(ip: string): string =
  ## Returns a domain name for reverse DNS lookup.
  ##
  ## **Parameters**
  ## - `ip` is the IP address you want to query. It can be an IPv4 or IPv6. It
  ##   cannot be a domain name.
  domainNameRDns(ipv4Arpa, ipv6Arpa)

proc prepareDnsBL*(ip, dnsbl: string): string =
  ## Returns a domain name for DnsBL query.
  ##
  ## **Parameters**
  ## - `ip` is the IP address you want to query. It can be an IPv4 or IPv6. It
  ##   cannot be a domain name.
  ## - `dnsbl` is the domain name that maintains the blacklist.
  domainNameRDns(dnsbl, dnsbl)

proc randId*(): uint16 {.inline.} =
  ## Returns a `uint16`, randomly generated, to be used as an id.
  rand(1 .. 65535).uint16

template resolveIpv4(async: bool) =
  let
    msg = initMessage(initHeader(id = randId(), rd = true),
                      @[initQuestion(domain, QType.A, QClass.IN)])
    rmsg = when async: await dnsAsyncQuery(client, msg, timeout, true)
      else: dnsQuery(client, msg, timeout, true)

  if rmsg.header.flags.rcode == RCode.NoError:
    for rr in rmsg.answers:
      if rr.name != msg.questions[0].qname or rr.`type` != Type.A or
        rr.class != Class.IN: continue

      let ip = IpAddress(family: IpAddressFamily.IPv4,
                         address_v4: RDataA(rr.rdata).address)

      add(result, $ip)

template resolveIpv6(async: bool) =
  let
    msg = initMessage(initHeader(id = randId(), rd = true),
                      @[initQuestion(domain, QType.AAAA, QClass.IN)])
    rmsg = when async: await dnsAsyncQuery(client, msg, timeout, true)
      else: dnsQuery(client, msg, timeout, true)

  if rmsg.header.flags.rcode == RCode.NoError:
    for rr in rmsg.answers:
      if rr.name != msg.questions[0].qname or rr.`type` != Type.AAAA or
        rr.class != Class.IN: continue

      let ip = IpAddress(family: IpAddressFamily.IPv6,
                         address_v6: RDataAAAA(rr.rdata).address)

      add(result, $ip)

template resolveRdns(async: bool) =
  let
    msg = initMessage(initHeader(id = randId(), rd = true),
                      @[initQuestion(prepareRDns(ip), QType.PTR, QClass.IN)])
    rmsg = when async: await dnsAsyncQuery(client, msg, timeout, true)
      else: dnsQuery(client, msg, timeout, true)

  if rmsg.header.flags.rcode == RCode.NoError:
    for rr in rmsg.answers:
      if rr.name != msg.questions[0].qname or rr.`type` != Type.PTR or
        rr.class != Class.IN: continue

      add(result, RDataPTR(rr.rdata).ptrdname)

proc resolveIpv4*(client: DnsClient, domain: string, timeout: int = -1):
                 seq[string] =
  ## Returns all IPv4 addresses, in a `seq[string]`, that have been resolved
  ## from `domain`. The `seq[string]` can be empty.
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `domain` is the domain name that you wish to obtain IPv4 addresses.
  ## - `timeout` is the maximum waiting time, in milliseconds, to connect to the
  ##   DNS server or to receive the response from the DNS server. When it is
  ##   `-1`, it will try to connect for an unlimited time or to receive the
  ##   response for an unlimited time.
  resolveIpv4(false)

proc asyncResolveIpv4*(client: DnsClient, domain: string, timeout: int = 500):
                      owned(Future[seq[string]]) {.async.} =
  ## Returns all IPv4 addresses, in a `seq[string]`, that have been resolved
  ## from `domain`. The `seq[string]` can be empty.
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `domain` is the domain name that you wish to obtain IPv4 addresses.
  ## - `timeout` is the maximum waiting time, in milliseconds, to connect to the
  ##   DNS server or to receive the response from the DNS server. When it is
  ##   negative (less than 0), it will try to connect for an unlimited time or
  ##   to receive the response for an unlimited time.
  resolveIpv4(true)

proc resolveIpv6*(client: DnsClient, domain: string, timeout: int = -1):
                 seq[string] =
  ## Returns all IPv6 addresses, in a `seq[string]`, that have been resolved
  ## from `domain`. The `seq[string]` can be empty.
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `domain` is the domain name that you wish to obtain IPv6 addresses.
  ## - `timeout` is the maximum waiting time, in milliseconds, to connect to the
  ##   DNS server or to receive the response from the DNS server. When it is
  ##   `-1`, it will try to connect for an unlimited time or to receive the
  ##   response for an unlimited time.
  resolveIpv6(false)

proc asyncResolveIpv6*(client: DnsClient, domain: string, timeout: int = 500):
                      owned(Future[seq[string]]) {.async.} =
  ## Returns all IPv6 addresses, in a `seq[string]`, that have been resolved
  ## from `domain`. The `seq[string]` can be empty.
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `domain` is the domain name that you wish to obtain IPv6 addresses.
  ## - `timeout` is the maximum waiting time, in milliseconds, to connect to the
  ##   DNS server or to receive the response from the DNS server. When it is
  ##   negative (less than 0), it will try to connect for an unlimited time or
  ##   to receive the response for an unlimited time.
  resolveIpv6(true)

proc resolveRDns*(client: DnsClient, ip: string, timeout: int = -1):
                 seq[string] =
  ## Returns all domain names, in a `seq[string]`, which is obtained by the
  ## "reverse" query of `ip`. The `seq[string]` can be empty.
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `ip` is the IPv4 or IPv6 address that is intended to obtain the domain
  ##   name, which represents the reverse address.
  ## - `timeout` is the maximum waiting time, in milliseconds, to connect to the
  ##   DNS server or to receive the response from the DNS server. When it is
  ##   `-1`, it will try to connect for an unlimited time or to receive the
  ##   response for an unlimited time.
  resolveRdns(false)

proc asyncResolveRDns*(client: DnsClient, ip: string, timeout: int = 500):
                      owned(Future[seq[string]]) {.async.} =
  ## Returns all domain names, in a `seq[string]`, which is obtained by the
  ## "reverse" query of `ip`. The `seq[string]` can be empty.
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `ip` is the IPv4 or IPv6 address that is intended to obtain the domain
  ##   name, which represents the reverse address.
  ## - `timeout` is the maximum waiting time, in milliseconds, to connect to the
  ##   DNS server or to receive the response from the DNS server. When it is
  ##   negative (less than 0), it will try to connect for an unlimited time or
  ##   to receive the response for an unlimited time.
  resolveRdns(true)

proc resolveDnsBL*(client: DnsClient, ip, dnsbl: string, timeout: int = -1):
                  seq[string] =
  ## Returns IPv4 addresses. Usually the loopback address (127.0.0.0/24), in
  ## which the last octet of IPv4 represents something on the black list.
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `ip` is the IPv4 or IPv6 address that you want to know if it is
  ##   blacklisted.
  ## - `dnsbl` is the domain name for DnsBL queries.
  ## - `timeout` is the maximum waiting time, in milliseconds, to connect to the
  ##   DNS server or to receive the response from the DNS server. When it is
  ##   `-1`, it will try to connect for an unlimited time or to receive the
  ##   response for an unlimited time.
  resolveIpv4(client, prepareDnsBL(ip, dnsbl))

proc asyncResolveDnsBL*(client: DnsClient, ip, dnsbl: string,
                        timeout: int = 500): owned(Future[seq[string]])
                       {.async.} =
  ## Returns IPv4 addresses. Usually the loopback address (127.0.0.0/24), in
  ## which the last octet of IPv4 represents something on the black list.
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `ip` is the IPv4 or IPv6 address that you want to know if it is
  ##   blacklisted.
  ## - `dnsbl` is the domain name for DnsBL queries.
  ## - `timeout` is the maximum waiting time, in milliseconds, to connect to the
  ##   DNS server or to receive the response from the DNS server. When it is
  ##   negative (less than 0), it will try to connect for an unlimited time or
  ##   to receive the response for an unlimited time.
  result = await asyncResolveIpv4(client, prepareDnsBL(ip, dnsbl))
