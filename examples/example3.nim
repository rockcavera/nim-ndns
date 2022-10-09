import ndns

let client = initDnsClient()

echo resolveIpv4(client, "nim-lang.org")
