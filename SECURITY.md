# Security

## Reporting

Please report vulnerabilities privately to **security@openctem.io** or through
GitHub's private vulnerability reporting on this repository. Do not open a
public issue.

If you run a program listed in the feed and want it corrected or removed,
write to the same address.

## Threat model

A bundle tells every OpenCTEM platform which public programs exist and what
they cover. A forged, stale or poisoned bundle could point subscribers'
monitoring at organisations that never invited it, hide a program's closure
or its new out-of-scope entries, or carry hostile strings into the platform.
The collector itself talks to many third-party hosts and must not become a
way to reach internal services.

### Integrity and freshness (same scheme as the OpenCTEM vulnerability feed)

- **Offline root.** An Ed25519 root key, kept offline by the maintainer,
  only signs *key sets*. Platforms pin its key id (`keys/root-keyid.txt`).
  The root is not shared with any other feed, and the key set payload type
  is specific to this feed, so a key set or manifest of another feed is
  refused.
- **Key set.** `keys/keyset.dsse.json` lists the online signing keys, is
  valid for at most 180 days and has a version that only goes up. A
  platform refuses a key set whose version is below one it has accepted.
- **Online key.** The signing key is a secret of the `publish` GitHub
  environment, which only the default branch can deploy to. Only the
  publish job runs there; it signs, verifies and uploads what the build job
  produced. The build job, which talks to the sources, never sees the key.
- **Rollback.** Every bundle has a sequence number. A platform refuses a
  sequence it has already applied, and a delta whose base is not the
  sequence it has.
- **Freeze.** Every manifest and pointer expires 7 days after it was made.
- **Integrity.** The signed manifest holds the SHA-256, size and record
  count of every file; a mismatch refuses the whole bundle.
- **Size.** Manifests are capped at 1 MiB, files at 128 MiB compressed and
  1 GiB decompressed, records at 4 MiB, and a bundle at 100,000 programs.

### Poisoned data

- Every record is validated before signing and again by the importer:
  strict JSON (unknown fields refused), id grammar, http(s) URLs without
  credentials, bounded strings without control or bidi characters, enums,
  timestamps in order.
- Every scope entry is normalised; public suffixes and wildcards over them,
  reserved names, private/reserved/documentation addresses and ranges,
  CIDRs wider than /16 (IPv4) or /48 (IPv6), and malformed entries are
  moved to the program's `rejected` list with the reason. A bundle with a
  scope entry the rules refuse is refused whole by the verifier.
- Out of scope wins over in scope.
- Targets the collector derived (`confidence: inferred`) are marked as such;
  the feed never presents a guess as a program's published scope.
- An adapter can only write programs under its own id prefix.
- **Outage guard.** A source that suddenly reports fewer than half of the
  programs it had (from at least 20) is treated as broken for that run and
  its previous records are kept; a maintainer can override after checking
  the source. A host that does not answer keeps its previous record instead
  of being closed. A closed program stays visible for 180 days before it is
  dropped.

### The collector on the network

- Connections only to public unicast addresses, checked at connect time
  (after DNS), so neither a seed list entry nor a redirect can reach
  loopback, private ranges or cloud metadata addresses.
- https only, at most 3 redirects, each re-checked against robots.txt.
- Size caps on every response; timeouts on every request.
- No credentials, cookies or tokens are ever sent to a source.
- The HTTP cache between runs only feeds conditional requests; every body
  served from it goes through the same parsing and validation.

## Key ceremony (maintainers)

See `keys/README.md`. Never commit a private key; the repository holds only
public material (`root-keyid.txt`, `keyset.dsse.json`).
