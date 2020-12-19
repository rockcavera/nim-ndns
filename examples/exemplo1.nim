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