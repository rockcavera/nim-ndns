## Minimal implementation to get System DNS Server (IPv4 only)
##
## This implementation uses the winapi function `GetNetworkParams` and should
## work for Windows.
##
## References:
## - https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getnetworkparams

const
  MAX_HOSTNAME_LEN = 128
  MAX_DOMAIN_NAME_LEN = 128
  MAX_SCOPE_ID_LEN = 256

  ERROR_SUCCESS = 0
  ERROR_BUFFER_OVERFLOW = 111

type
  # https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_address_string
  IP_ADDRESS_STRING = object
    `string`: array[16, char]

  IP_MASK_STRING = IP_ADDRESS_STRING

  # https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_addr_string
  IP_ADDR_STRING = object
    next: PIP_ADDR_STRING
    ipAddress: IP_ADDRESS_STRING
    ipMask: IP_MASK_STRING
    context: int32

  PIP_ADDR_STRING = ptr IP_ADDR_STRING

  # https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-fixed_info_w2ksp1
  FIXED_INFO_W2KSP1 = object
    hostName: array[MAX_HOSTNAME_LEN + 4, char]
    domainName: array[MAX_DOMAIN_NAME_LEN + 4, char]
    currentDnsServer: PIP_ADDR_STRING
    dnsServerList: IP_ADDR_STRING
    nodeType: uint32
    scopeId: array[MAX_SCOPE_ID_LEN + 4, char]
    enableRouting: uint32
    enableProxy: uint32
    enableDns: uint32

  FIXED_INFO = FIXED_INFO_W2KSP1
  PFIXED_INFO = ptr FIXED_INFO

# https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getnetworkparams
proc getNetworkParams(pFixedInfo: PFIXED_INFO, pOutBufLen: var uint32): int32 {.importc: "GetNetworkParams", stdcall, dynlib: "Iphlpapi.dll".}

proc getSystemDnsServer*(): string =
  ## Returns the IPv4 used by the system for DNS resolution. Otherwise it
  ## returns an empty string `""`.
  var
    bufLen = uint32(sizeof(FIXED_INFO) and 0xFFFFFFFF)
    buf = cast[PFIXED_INFO](alloc0(int(bufLen)))

  if isNil(buf):
    raise newException(CatchableError, "Error allocating memory needed to call GetNetworkParams")

  var success = getNetworkParams(buf, bufLen)

  if success == ERROR_BUFFER_OVERFLOW:
    buf = cast[PFIXED_INFO](realloc0(buf, sizeof(FIXED_INFO), int(bufLen)))

    if isNil(buf):
      raise newException(CatchableError, "Error allocating memory needed to call GetNetworkParams")

    success = getNetworkParams(buf, bufLen)

  if success  == ERROR_SUCCESS:
    result = $cast[cstring](addr buf.dnsServerList.ipAddress.`string`)

  dealloc(buf)
