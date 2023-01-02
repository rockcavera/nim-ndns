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
## `-d:useDeprecatedResolv`. On OpenBSD it is recommended to define this symbol
## when compiling, since the `resolv.h` used on this platform has its own
## definitions that will only be used when this symbol is defined.

when defined(nimdoc):
  import std/[net, winlean]
else:
  import std/[net, posix]

when defined(bsd):
  {.passL: "-lc".}
else:
  {.passL: "-lresolv".}

const
  useOpenBSDResolv = when defined(useDeprecatedResolv) and defined(openbsd): true
                     else: false
    # The structure of res_state in OpenBSD has several peculiarities, as well
    # as currently adopts the deprecated version with res_init().
    # https://github.com/openbsd/src/blob/e3c5fa921ef394179421471c88eb2be26d8a6692/include/resolv.h

  MAXNS = 3
  MAXDNSRCH = 6
  MAXRESOLVSORT = 10

  RES_INIT = 1

when useOpenBSDResolv:
  {.emit: """/*INCLUDESECTION*/
#include <netinet/in.h>
""".} # See https://github.com/troglobit/inadyn/issues/241

  const MAXDNSLUS = 4

  type
    CulongOrCuint = cuint

    ResTimeSpecObj = object
      resSec: Time
      resNSec: clong
else:
  type CulongOrCuint = culong

type
  # Commented for being currently in disuse
  #ResSendhookact {.size: 4.} = enum
  #  ResGoahead, ResNextns, ResModified, ResDone, ResError

  #ResSendQhook = proc (ns: ptr ptr Sockaddr_in, query: ptr ptr uint8,
  #                     querylen: ptr cint, ans: ptr uint8, anssiz: cint,
  #                     resplen: ptr cint): ResSendhookact {.cdecl.}

  #ResSendRhook = proc (ns: ptr Sockaddr_in, query: ptr uint8, querylen: cint,
  #                     ans: ptr uint8, anssiz: cint, resplen: ptr cint): ResSendhookact {.cdecl.}

  ResSendQhook = pointer
  ResSendRhook = pointer

  SortListObj = object
    `addr`: InAddr
    mask: uint32 # uint32_t

  Ext = object
    nscount: uint16 # u_int16_t
    nsmap: array[MAXNS, uint16]
    nssocks: array[MAXNS, cint]
    nscount6: uint16
    nsinit: uint16
    nsaddrs: array[MAXNS, ptr Sockaddr_in6]
    initstamp: array[2, cuint]

  UUnion {.union.} = object
    pad: array[52, cchar]
    ext: Ext

  ResState = object
    retrans: cint
    retry: cint
    options: CulongOrCuint
    nscount: cint
    when useOpenBSDResolv:
      family: array[2, cint]
    nsaddrList: array[MAXNS, Sockaddr_in]
    id: cushort
    dnsrch: array[MAXDNSRCH + 1, cstring]
    defdname: array[256, cchar]
    pfcode: CulongOrCuint
    ndots {.bitsize:4.}: cuint
    nsort {.bitsize:4.}: cuint
    when useOpenBSDResolv:
      unused: array[3, cchar]
    else:
      ipv6_unavail {.bitsize:1.}: cuint
      unused {.bitsize:23.}: cuint
    sortList: array[MAXRESOLVSORT, SortListObj]
    when useOpenBSDResolv:
      lookups: array[MAXDNSLUS, cchar]
      restimespec: ResTimeSpecObj
      reschktime: Time
    else:
      qhook: ResSendQhook
      rhook: ResSendRhook
      resHErrno: cint
      vcsock: cint
      flags: cuint
      u: UUnion

{.push header: "<resolv.h>".}
type SResState {.importc: "struct __res_state".} = object

when not defined(useDeprecatedResolv):
  proc resNInit(statep: ptr SResState): cint {.importc: "res_ninit".}
  proc resNClose(rstatep: ptr SResState) {.importc: "res_nclose".}
else:
  when useOpenBSDResolv:
    var res {.importc: "_res".}: SResState # currently it is a C macro for `struct __res_state __res_state(void)`
  else:
    proc resState(): ptr SResState {.importc: "__res_state".}

  proc resInit(): cint {.importc: "res_init".}
{.pop.}

proc getSystemDnsServer*(): string =
  ## Returns the IPv4 used by the system for DNS resolution. Otherwise it
  ## returns an empty string `""`.
  var
    rs: ResState
    ip: IpAddress
    port: Port
    rInit = when defined(useDeprecatedResolv): resInit()
            else: resNInit(cast[ptr SResState](addr rs))

  if rInit == 0:
    when useOpenBSDResolv:
      rs = cast[ResState](res)
    elif defined(useDeprecatedResolv):
      rs = cast[ResState](resState()[])

    if (rs.options and RES_INIT) == RES_INIT:
      fromSockAddr(rs.nsaddrList[0], sizeof(Sockaddr_in).SockLen, ip, port)

      result = $ip

    when not defined(useDeprecatedResolv):
      resNClose(cast[ptr SResState](addr rs))
