# Palantir

## Overview

Palantir is a DNS resolver that supports caching DNS answers. This project is currently a work in progress.

In the current state, after receiving a DNS message, Palantir will reply with a hard coded response that includes a
single IN A answer resource record for google.com. The end goal is to lookup the associated IP address in a database and
reply with the correct answer record.

Once requests and responses are working with a local database the next step will be to retrieve unknown records from
authoritative sources.

## Reference
[RFC 1035 - Domain Implementation and Specification](https://datatracker.ietf.org/doc/html/rfc1035)

## Building
Running cmake

```shell
$ /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_MAKE_PROGRAM=/Applications/CLion.app/Contents/bin/ninja/mac/ninja -G Ninja /Users/$USER/workspace/palantir
-- Configuring done
-- Generating done
-- Build files have been written to: /Users/$USER/workspace/palantir/cmake-build-debug
```

Building

```shell
/Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake --build /Users/$USER/workspace/palantir/cmake-build-debug --target palantir
```

## Testing

Run palantir and wait for it to start listening on port 53

```shell
$ ./palantir
Bind finished
Listening on port 53
```

Then send a DNS query using `dig`

```shell
dig @localhost google.com
```

## Examples

Once a DNS query is received, the message will be printed out before the reply is sent

```text
Received 39 bytes from host: ::ffff:127.0.0.1
DNS Headers: {
  id: 65455,
  qr: 0,
  opcode: 0,
  aa: 0,
  tc: 0,
  rd: 1,
  ra: 0,
  z: 2,
  rcode: 0,
  qdcount: 1,
  ancount: 0,
  nscount: 0,
  arcount: 1
}
DNS Question: {
  qname: google.com.
  qtype: A (0001)
  qclass: IN (0001)
}
DNS Resource: {
  name: 00 	|
  type: Unknown (41)
  class: Unknown (4096)
  ttl: 0
  rdlength: 0
  rdata: 0
Message received.

Sent 38 of 38 bytes
Reply bytes:
04 16 81 80 00 00 00 01 00 00 00 00 06 67 6F 6F 67 6C 65 03 63 6F 6D 00 00 01 00 01 00 00 00 00 00 04 8E FB 10 66 

Reply sent.
```

Dig will show the hard coded reply that was automatically sent
```shell
 $ dig @localhost google.com

; <<>> DiG 9.10.6 <<>> @localhost google.com
; (2 servers found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 63324
;; flags: qr rd ra; QUERY: 0, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; ANSWER SECTION:
google.com.		0	IN	A	142.251.16.102

;; Query time: 9 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Wed Jul 27 11:00:49 EDT 2022
;; MSG SIZE  rcvd: 38
```


## TODO

- Add debug flag
- Fix memory allocation
- Add address lookup table
- Persist lookup table
- Customize response after finding record
- Clean up bitwise operations
- Handle errors (unknown domain)
- Query authoritative NS for DNS queries