## Minimal implementation to get System DNS Server (IPv4 and IPv6). This implementation is heavily
## influenced by glibc.
##
## Implements a parser to capture the first nameserver in the resolver configuration file, which is,
## by default, /etc/resolv.conf. You can change this file by passing to compile
## `-d:ndnsPathResConf=/etc/myresolv.conf`.
##
## Checking for changes in the `ndnsPathResConf` file performed at each new `getSystemDnsServer()`
## call makes the code 2x faster, if there is no change.
##
## This implementation should work for systems that adopt resolver. Currently this implementation is
## imported into Linux and BSD. If your platform uses a resolver configuration file, compile with
## `-d:ndnsUseResolver`.
##
## References:
## - https://man7.org/linux/man-pages/man5/resolv.conf.5.html
import std/[os, parseutils, times]

type
  FileChangeDetection = object
    ## Object for `ndnsPathResConf` file information.
    fileId: FileId ## Serial ID
    size: BiggestInt ## Size
    lastWriteTime: Time ## Last write time
    creationTime: Time ## Creation time

  ResolvConfGlobal = object
    ## Object for global resolver information.
    nameserver: string ## The first nameserver caught in the last parse of `ndnsPathResConf`
    fileResolvConf: FileChangeDetection ## `ndnsPathResConf` file information during last parse.
    initialized: bool ## Determines whether the `ndnsPathResConf` file has already been parsed

const ndnsPathResConf* {.strdefine.} = "/etc/resolv.conf"
  ## Resolver configuration file. You can change by compiling with
  ## `-d:ndnsPathResConf=/etc/myresolv.conf`.

var resolvGlobal: ResolvConfGlobal
  ## Keeps information from the `ndnsPathResConf` file and if it has already been parsed.

proc fileResolvIsUnchanged(): bool =
  ## Returns `true` if the `ndnsPathResConf` file has not changed since the last parse.
  let fileInfo = getFileInfo(ndnsPathResConf)

  result = (fileInfo.id.file == resolvGlobal.fileResolvConf.fileId) and
           (fileInfo.size == resolvGlobal.fileResolvConf.size) and
           (fileInfo.creationTime == resolvGlobal.fileResolvConf.creationTime) and
           (fileInfo.lastWriteTime == resolvGlobal.fileResolvConf.lastWriteTime)

proc getSystemDnsServer*(): string =
  ## Returns the first nameserver found in the `ndnsPathResConf` file. Will return `""` if not
  ## found.
  const
    comments = { ';', '#' }
    whiteSpaces = { ' ', '\t', '\v', '\r', '\n', '\f' }
    commentsAndWhiteSpaces = comments + whiteSpaces

  if resolvGlobal.initialized and fileResolvIsUnchanged():
    result = resolvGlobal.nameserver
  else:
    if fileExists(ndnsPathResConf):
      let fileInfo = getFileInfo(ndnsPathResConf)

      for line in lines(ndnsPathResConf):
        if line == "": continue # skipe empty line
        if line[0] in comments: continue # skip comments

        var strConf: string

        let count = parseUntil(line, strConf, whiteSpaces)

        if count > 0:
          case strConf
          of "nameserver":
            if parseUntil(line, result, commentsAndWhiteSpaces, count + skipWhitespace(line, count)) > 0:
              break
          else: # for now there is no interest in implementing: domain, search and options
            discard

      resolvGlobal.nameserver = result
      resolvGlobal.fileResolvConf.fileId = fileInfo.id.file
      resolvGlobal.fileResolvConf.size = fileInfo.size
      resolvGlobal.fileResolvConf.creationTime = fileInfo.creationTime
      resolvGlobal.fileResolvConf.lastWriteTime = fileInfo.lastWriteTime
      resolvGlobal.initialized = true

when false:
  # Discontinued implementation. Reasons:
  # - Systems based on musl libc do not have `res_init()` implemented;
  # - Different implementations of resolv.h.
  # - Operating systems using deprecated resolv implementation
  # - OpenBSD has its own `struct __res_state`

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
  ## Notes:
  ## - To use the interface deprecated by the resolv library, compile with
  ##   `-d:useDeprecatedResolv`. On **OpenBSD** it is recommended to define this symbol
  ##   when compiling, since the `resolv.h` used on this platform has its own
  ##   definitions that will only be used when this symbol is defined.
  ## - Unfortunately systems based on musl libc do not have `res_init()`
  ##   implemented. Such a libc loads the settings from "/etc/resolv.conf", when
  ##   needed, through `__get_resolv_conf()` which is not compatible with
  ##   `struct __res_state`. Faced with so many divergences found using
  ##   `resolv.h`, I believe it is better to implement a parser for
  ##   "/etc/resolv.conf". TODO
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
        rs = cast[ResState](resState()[]) # If nim compiled with `--threads:on`, on NetBSD it will result in SIGABRT

      if (rs.options and RES_INIT) == RES_INIT:
        fromSockAddr(rs.nsaddrList[0], sizeof(Sockaddr_in).SockLen, ip, port)

        result = $ip

      when not defined(useDeprecatedResolv):
        resNClose(cast[ptr SResState](addr rs))
