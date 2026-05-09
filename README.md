# chkdns

Resolves a domain by walking the DNS delegation chain from a root
server to the authoritative servers, then queries each authoritative
server for the requested record type.

Goes directly to root, TLD, and authoritative servers picked from
the previous referral, so no resolver cache sits between you and the
authoritative answer. Useful for verifying a record right after
changing it.

## Usage

    chkdns <domain> [type]

`type` defaults to `A`. Other types: `AAAA`, `NS`, `MX`, `TXT`,
`CNAME`, `SOA`, `PTR`, `SRV`, `CAA`. `ANY` is accepted but most
servers refuse it (RFC 8482).

Examples:

    chkdns example.com
    chkdns example.com NS
    chkdns example.com TXT

## How it works

Phase 1 walks the delegation chain. One query per hop: pick a root
at random, query for `NS <domain>`, follow the referral by picking a
nameserver at random from the response, repeat until a server returns
the apex `NS` RRset. On timeout, fail over to the next candidate at
that hop.

Phase 2 queries each authoritative server (from the apex `NS` set)
for the requested type, sequentially. If the parent's delegation `NS`
set differs from the apex `NS` set, the difference is printed.

## License

Dual-licensed under either of MIT or Apache-2.0, at your option.
