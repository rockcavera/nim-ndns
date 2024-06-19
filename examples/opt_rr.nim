import ndns

import std/[asyncdispatch, macros]

# code taken from std/enumutils
macro enumFullRange(a: typed): untyped =
  newNimNode(nnkBracket).add(a.getType[1][1..^1])

proc dumpDnsMessage(msg: Message) =
  echo "Header: ", msg.header
  echo "Questions: ", msg.questions
  echo "Authorities: ", msg.authorities
  echo "Additionals: ", msg.additionals
  echo "Answers:"

  for res in msg.answers:
    if res.`type` in enumFullRange(Type):
      echo res
    else:
      echo "Unknown `Type`: ", cast[int](res.`type`)

proc udpPayloadSize() =
  let
    header = initHeader(randId(), rd = true)
    question = initQuestion("google.com", QType.ANY, QClass.IN)
    opt = initOptRR(1280, 0, 0, false, 0, nil)
    msg = initMessage(header, @[question], additionals = @[opt])
    client = initDnsClient()
    smsg = dnsQuery(client, msg)

  echo "---------Synchronous----------"
  dumpDnsMessage(smsg)

  echo "---------Asynchronous----------"
  let amsg = waitFor dnsAsyncQuery(client, msg, 5000)
  dumpDnsMessage(amsg)

udpPayloadSize()
