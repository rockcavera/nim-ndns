# Usage: resolver domain.com [domain2.com ... domainN.com]
#
# For those who don't quite understand the async workflow in Nim, you can compile
# with `-d:showLoopLog`.
#
# It is important to understand that within the infinite loop of events you can perform other
# operations that may or may not block the thread.
# Examples:
# 1) you can change the code to resolve 2 domains at a time;
# 2) you can resolve a domain and maintain an IRC connection;
# 3) you can have an HTTP server and a domain resolution.
#
# There are several possibilities.

import std/[asyncdispatch, os, strformat] # Importing modules from stdlib

import ndns # pkg/ndns - Importing the `ndns` package

var isResolvingAnyDns = false # A boolean to know if there is already a domain being resolved

proc resolveDomain(client: DnsClient, strDomain: string) {.async.} =
  # Declaring an asynchronous procedure to perform resolution of `strDomain`  and print the IPv4
  # received as a response. See https://nim-lang.org/docs/asyncdispatch.html#asynchronous-procedures
  isResolvingAnyDns = true # Setting to `true` to resolve only one at a time

  echo fmt"Resolving `{strDomain}`..."

  let allIpv4 = await asyncResolveIpv4(client, strDomain) # Calls the procedure `asyncResolveIpv4`,
                                                          # asynchronously, using `await`, which
                                                          # also doesn't lock the thread, but makes
                                                          # return here when `Future[seq[string]]`
                                                          # is ready, which is the return value of
                                                          # called procedure.
  when defined(showLoopLog):
    let domainName = fmt"`{strDomain}`"
  else:
    let domainName = fmt" "

  if len(allIpv4) == 0:
    echo fmt"{domainName} did not return IPv4. Possibly it does not exist.{'\n'}"
  elif len(allIpv4) == 1:
    echo fmt"{domainName} Address:{'\n'}    {allIpv4[0]}{'\n'}"
  else:
    echo fmt"{domainName} Addresses:"
    for ip in allIpv4: # Print all IPv4 returned in `allIpv4`
      echo fmt"    {ip}"

    echo ""

  isResolvingAnyDns = false # Setting it to `false`, so the event loop can resolve the next domain

proc main() =
  let argsCount = paramCount() # https://nim-lang.org/docs/os.html#paramCount

  if argsCount == 0:
    echo fmt"""Usage:
       {getAppFilename().extractFilename} domain.com [domain2.com ... domainN.com]"""
    quit(0)

  let client = initSystemDnsClient() # https://rockcavera.github.io/nim-ndns/ndns.html#initSystemDnsClient

  echo fmt"DNS client initialized using DNS Server: {getIp(client)}{'\n'}"

  var
    countLoop = 0 # Counter of how many loops it will take to resolve all domains
    x = 1 # Current index of passed arguments

  while true: # Infinite loop of events. It will resolve only one DNS at a time asynchronously, but
              # the loop will continue...
    when defined(showLoopLog):
      inc(countLoop) # Increasing the counter
      echo fmt"Starting loop {countLoop}"

    if not isResolvingAnyDns: # If it's not resolving any domain...
      while (x <= argsCount) and (paramStr(x) == ""): inc(x) # Skip empty `paramStr(x)`.

      if x <= argsCount: # If the index is less than or equal to the number of arguments passed
        when defined(showLoopLog):
          echo "Before calling `resolveDomain`"
        asyncCheck resolveDomain(client, paramStr(x)) # Calls the async procedure `resolveDomain`,
                                                      # without blocking the thread, to resolve the
                                                      # domain present in `paramStr(x)`.
        when defined(showLoopLog):
          echo "After calling `resolveDomain`"

        inc(x) # Increase index
      else:
        when defined(showLoopLog):
          echo fmt"Work finished in loop {countLoop}"
        break # Exits the infinite loop of events as it has no more domains to resolve

    if hasPendingOperations(): # https://nim-lang.org/docs/asyncdispatch.html#hasPendingOperations
      when defined(showLoopLog):
        echo "Calling `poll`..."
      poll(15) # https://nim-lang.org/docs/asyncdispatch.html#poll%2Cint

    when defined(showLoopLog):
      echo fmt"Ending loop {countLoop}{'\n'}"

main()
