# chkdns

Queries all 13 DNS root servers for a given domain and prints each
referral response (TLD nameservers and glue records).

The longer-term goal is a DNS check tool that bypasses resolver caches
by talking to authoritative servers directly, for verifying records
right after you change them.

## Usage

    chkdns example.com

## License

Dual-licensed under either of MIT or Apache-2.0, at your option.
