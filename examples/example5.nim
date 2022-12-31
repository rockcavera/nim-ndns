import ndns

let client = initSystemDnsClient()

echo resolveIpv4(client, "nim-lang.org")
