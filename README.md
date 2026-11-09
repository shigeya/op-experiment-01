# op-experiment-01

Tools for an experiment with the OPKEY DNS resource record,
`draft-shigeya-dns-opkey-00` ("Using Secure DNS for Originator Profile").

## opkey-dig

`opkey-dig` looks up the records that the draft places under the `_op` label
for a name and shows how a verifier would read them, with a trace of every
query.

```
go run ./cmd/opkey-dig [flags] <name>
```

For `<name>` it queries:

| Name | Type | Record (draft section) |
|---|---|---|
| `_op.<name>` | SVCB | Issuer Pinning Record (§8.2) |
| `_issuer-key._op.<name>` | TLSA, read as OPKEY | Issuer Key Record (§3.1) |
| `_issuer-key._op.<issuer>` for each pinned CP issuer (`-follow-pin`, on by default) | TLSA, read as OPKEY | Issuer Key Record (§3.1) |
| `-originator-key <arg>`: below `_originator-key._op.<name>` | TLSA, read as OPKEY | Originator Key Record (§3.2) |
| `-revocation <arg>`: below `_revocation._op.<name>` | TXT | Revocation Record (§8.3) |

`<arg>` is either a full name, which must lie below the node, or a bare record
label, which is placed directly below it. Both flags can be repeated.

### OPKEY in the TLSA form

The OPKEY type value is not allocated, so the records are published and read as
TLSA RRsets carrying OPKEY RDATA (draft §4.1, §4.3). `opkey-dig` sends only
TLSA, SVCB and TXT queries; it never sends a query of a private-use type
(RFC 6895). The RDATA is decoded with the OPKEY support of
[dnsdata-go](https://github.com/shigeya/dnsdata-go), and each RR is shown as
usable or unusable with the reason (draft §2.1).

### DNSSEC state

`opkey-dig` does not validate DNSSEC. The state it shows is the AD bit of the
resolver's answers, and the output says which resolver and channel it came
from:

- `-transport doh` (default): DNS over HTTPS (RFC 8484) to `-server`, or to
  the default providers of dnsdata-go, first that answers. `-server` must be
  an `https` URL; plain `http` is refused.
- `-transport dot -server <addr>`: DNS over TLS (RFC 7858).
- `-transport udp -server <addr>`: plain DNS over UDP with TCP fallback. The
  channel is not authenticated, so the AD bit is not protected in transit.

Each answer is classified as:

| Status | Meaning |
|---|---|
| `secure-present` | NOERROR, the RRset at the queried name, AD set |
| `secure-absent` | NXDOMAIN or NODATA, AD set |
| `not-secure` | NOERROR or NXDOMAIN without AD: Insecure, or not validated by the resolver (the two cannot be told apart) |
| `alias` | NOERROR or NXDOMAIN reached through an alias (CNAME, DNAME, or the RRset at another owner name); the records at the alias target are never used |
| `failure` | no response, or an RCODE other than NOERROR and NXDOMAIN |

Only `secure-*` answers lead to a conclusion; `not-secure` is reported as
`no-assurance` and `failure` as `failure` (draft §6.1). An `alias` answer is a
`failure` at the Issuer Key Record, an Originator Key Record and a Revocation
Record (draft §6.1). At the Issuer Pinning Record, draft §8 reads it as an
Insecure answer: with the AD bit set it is reported as `unpinned`, and without
it as `no-assurance`, since an answer without AD cannot exclude Bogus or
Indeterminate.

### Output

The default output is for people. `-json` writes the same report as JSON. The
trace lists, for each query, the name, type, RCODE, AD bit, number of answer
RRs, elapsed time, status and outcome, followed by the number of queries and
the total time.

## Known limitations and open points

- **Answers without the AD bit, at the Issuer Pinning Record.** Draft §8.2
  reads an Insecure answer as leaving the originator unpinned, while §6.1 says
  that an answer from a resolver that does not validate must not be read as
  Insecure. Without its own validation, `opkey-dig` cannot tell the two apart:
  it reports `no-assurance` and states both readings in the detail.
- **AliasMode at the Issuer Pinning Record.** An RRset holding only an
  AliasMode RR with TargetName `.` (the declaration that the originator has no
  Originator Profile) and an RRset holding another AliasMode RR, or AliasMode
  mixed with ServiceMode (read as that declaration, and a verification
  failure), both have the outcome `no-op-declared`; only the detail text tells
  them apart.
- **Time in a Revocation Record.** The time of revocation is shown only for a
  single RR with a single character-string of the exact form
  `v=op1; revoked=<time>`. Otherwise the record is still reported as revoked,
  without a time; the outcome depends on presence alone, as in draft §8.3.
- **Bare record labels.** `-originator-key` and `-revocation` accept a bare
  record label as a convenience and place it directly below the node. A
  verifier uses the full name carried in the document; pass the full name to
  do the same.
- **Internationalized names.** Only A-labels are accepted; U-labels are not
  converted.

## Tests

```
go test ./...
```

The DNS is reached through an interface, and the unit tests run on fixed
records without network access.

## References

- draft-shigeya-dns-opkey-00
- RFC 6698, RFC 7218, RFC 7671 (TLSA)
- RFC 9460 (SVCB)
- RFC 4033, RFC 4035 (DNSSEC)
- RFC 7858 (DNS over TLS), RFC 8484 (DNS over HTTPS)
- RFC 6895 (RRTYPE allocation)

## License

MIT. See [LICENSE](LICENSE).
