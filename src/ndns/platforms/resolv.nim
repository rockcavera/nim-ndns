## Minimal implementation to get System DNS Server (IPv4 only)
##
## This implementation uses the resolv library, which should work on Linux and
## BSD.
##
## References:
## - https://man7.org/linux/man-pages/man3/resolver.3.html
## - https://www.freebsd.org/cgi/man.cgi?query=resolver
##
## Using this module implies passing `-lresolv` or `-lc` to the linkage process.
##
## To use the interface deprecated by the resolv library, compile with
## `-d:useDeprecatedResolv`.

when defined(nimdoc):
  import std/[net, winlean]
else:
  import std/[net, posix]

when defined(bsd):
  {.passL: "-lc".}
else:
  {.passL: "-lresolv".}

const
  MAXNS = 3
  MAXDNSRCH = 6
  MAXRESOLVSORT = 10

type
  ResSendhookact {.size: 4.} = enum
    ResGoahead, ResNextns, ResModified, ResDone, ResError

  ResSendQhook = proc (ns: ptr ptr Sockaddr_in, query: ptr ptr uint8,
                       querylen: ptr cint, ans: ptr uint8, anssiz: cint,
                       resplen: ptr cint): ResSendhookact {.cdecl.}

  ResSendRhook = proc (ns: ptr Sockaddr_in, query: ptr uint8, querylen: cint,
                       ans: ptr uint8, anssiz: cint, resplen: ptr cint): ResSendhookact {.cdecl.}

  SortListObj = object
    `addr`: InAddr
    mask: cuint

  Ext = object
    nscount: cushort
    nsmap: array[MAXNS, cushort]
    nssocks: array[MAXNS, cint]
    nscount6: cushort
    nsinit: cushort
    nsaddrs: array[MAXNS, ptr Sockaddr_in6]
    initstamp: culonglong

  UUnion {.union.} = object
    pad: array[52, char]
    ext: Ext

  ResState = object
    retrans: cint
    retry: cint
    options: culong
    nscount: cint
    nsaddrList: array[MAXNS, Sockaddr_in]
    id: cushort
    dnsrch: array[MAXDNSRCH + 1, cstring]
    defdname: array[256, char]
    pfcode: culong
    ndots {.bitsize:4.}: cuint
    nsort {.bitsize:4.}: cuint
    ipv6_unavail {.bitsize:1.}: cuint
    unused {.bitsize:23.}: cuint
    sortList: array[MAXRESOLVSORT, SortListObj]
    qhook: ResSendQhook
    rhook: ResSendRhook
    resHRrrno: cint
    vcsock: cint
    flags: cuint
    u: UUnion

proc resNinit(statep: var ResState): cint {.importc: "res_ninit", header: "<resolv.h>".}
proc resNclose(rstatep: var ResState) {.importc: "res_nclose", header: "<resolv.h>".}

when defined(useDeprecatedResolv):
  type
    SResState {.importc: "struct __res_state".} = object

  proc resInit(): cint {.importc: "res_init", header: "<resolv.h>".}
  proc resState(): ptr SResState {.importc: "__res_state".}

proc getSystemDnsServer*(): string =
  ## Returns the IPv4 used by the system for DNS resolution. Otherwise it
  ## returns an empty string `""`.
  var
    ip: IpAddress
    port: Port

  when defined(useDeprecatedResolv):
    if resInit() == 0:
      fromSockAddr(cast[ResState](resState()[]).nsaddrList[0], sizeof(Sockaddr_in).SockLen, ip, port)

      result = $ip
  else:
    var rs: ResState

    if resNinit(rs) == 0:
      fromSockAddr(rs.nsaddrList[0], sizeof(Sockaddr_in).SockLen, ip, port)
      resNclose(rs)

      result = $ip
