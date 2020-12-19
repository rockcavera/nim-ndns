import asyncdispatch, ndns

let client = initDnsClient()

echo waitFor asyncResolveIpv4(client, "nim-lang.org")