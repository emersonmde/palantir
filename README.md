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
```


## TODO

- Add address lookup table
- Persist lookup table
- Customize response after finding record
- Handle errors (unknown domain)
- Query authoritative NS for DNS queries