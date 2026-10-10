# programfeed

The public program collector of [OpenCTEM](https://github.com/openctemio/openctem).
Once a day it reads open, machine-readable sources of **public bug-bounty and
vulnerability-disclosure programs**, normalises them into one record format,
validates every record and every scope entry, signs the result and publishes
it as a GitHub Release. OpenCTEM platforms never call the sources
themselves: they download (or, air-gapped, upload) a bundle, verify it and
import it into their public program monitor.

The feed says **who runs a program, where its policy is, whether it pays,
what scope it publishes and how that changed**. It is not an authorisation to
test anything: a subscriber reads and accepts a program's terms before any
active testing, and targets marked `inferred` are suggestions only.

## Sources

Every source has a **status**: *ingest* (the collector reads it) and
*publish* (its records go into the signed public feed). Publishing is
decided per original platform by the [publish policy](#publish-policy), not
per source.

| Source | Adapter | What it gives | Licence / terms | Ingest | Publish |
|---|---|---|---|---|---|
| [disclose.io diodb](https://github.com/disclose/diodb) `program-list.json` | `diodb` | ~2,400 programs: name, policy URL, contact, bounty yes/no, safe harbour, disclosure timeline, languages. No structured scope; the host of a program's own security.txt becomes an `inferred` target. | CC0-1.0 | yes | self-hosted programs only; programs hosted on a platform follow that platform's policy |
| [security.txt](https://www.rfc-editor.org/rfc/rfc9116) (RFC 9116) over a seed list | `securitytxt` | A domain whose `/.well-known/security.txt` has a `Contact` and a `Policy` is a self-hosted disclosure program; the domain is an `inferred` target, the file's SHA-256 is the terms hash. Expired files give a `paused` program. | files published for automated retrieval | yes | yes (self-hosted) |
| Seed: [CISA dotgov-data](https://github.com/cisagov/dotgov-data) `current-federal.csv` | `securitytxt` seed | US federal .gov domains and their organisations (vulnerability disclosure policies under BOD 20-01). | CC0-1.0 | yes | yes (self-hosted) |
| Seed: `seeds/securitytxt.txt` | `securitytxt` seed | Extra domains added by pull request. | n/a | yes | yes (self-hosted) |
| [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) `data/*_data.json` | `bounty-targets` | Public program listings of HackerOne, Bugcrowd, Intigriti and YesWeHack with their published scope (targets marked `published_by_platform`). Read at one resolved commit; each record names the dataset, the commit, the original platform and the original program page. | repository MIT; the records stay subject to each platform's terms | with `--local-only` | **no**: every platform is `publish=false` until it gives written permission |
| [public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs) `dist/data.json` | `pd-bounty` | A community-curated list of program pages and the domains each covers (domains are `inferred` targets). | MIT (list) | yes | self-hosted programs only; with `--local-only` also platform-hosted ones |

Platforms and the reason each is not published (the machine-readable
version is [`policy/platforms.json`](policy/platforms.json)):

| Platform | Publish | Reason |
|---|---|---|
| self-hosted | yes | the policy page is the program owner's own |
| HackerOne | no | general terms allow use only as permitted; no redistribution grant. Permission letter drafted. |
| Bugcrowd | no | website terms forbid redistributing any portion of the website. Permission letter drafted. |
| Intigriti | no | no redistribution grant; the official API needs an account token. Permission letter drafted. |
| YesWeHack | no | legal notices forbid redistributing the platform's data. Permission letter drafted. |
| Immunefi | no | terms forbid automated access without written consent. Permission letter drafted. |
| HackenProof | no | no official machine-readable listing. Permission letter drafted. |
| Federacy, Open Bug Bounty, huntr, WhiteHub, BugBase, Zerocopter, Hackrate | no | no redistribution grant found |
| any platform not in the policy | no | unlisted means not published |

The drafts to the platforms are in [`docs/outreach/`](docs/outreach/); nothing
has been sent. A platform is switched to `publish: true` only after written
permission, with the attribution text it asks for.

Not collected at all (pull requests that scrape these will be declined):

| Source | Reason |
|---|---|
| Open Bug Bounty | listing is behind bot protection; the feed does not bypass it |
| Platform websites and undocumented endpoints | the collector reads official files and public datasets, never a platform's site |
| Account-token APIs | the feed never logs in |

A source moves to "publish" when it offers an official machine-readable
listing whose terms allow collection and redistribution (or gives written
permission).

### Publish policy

`policy/platforms.json` lists every original platform with:

```json
"hackerone": {"publish": false, "attribution": "...", "takedown_contact": "security@openctem.io", "reason": "..."}
```

- `publish`: only `true` puts the platform's records in the signed feed. A
  platform that is not listed is not published. `publish: true` requires an
  `attribution` text; it is added to the source entry of the signed manifest
  together with the takedown contact.
- A signed build does not even fetch dataset platforms that are not
  published, applies the policy to the finished snapshot (a record is
  published only if both its platform and its original platform are), and
  applies it to the previous release too: switching a platform to
  `publish: false` removes its programs on the next run with a
  `program_dropped` change. Tests assert that restricted platforms never
  reach the signed output.
- Removal requests: see [TAKEDOWN.md](TAKEDOWN.md).

### Local-only bundle (self-hosters)

```sh
./programfeed build --local-only --out local-bundle --cache httpcache
```

`--local-only` ignores the publish policy and reads every source, including the
platform datasets, and writes an **unsigned** bundle marked
`collector.local_only` in its manifest. `programfeed sign` refuses such a
bundle, so the project's signing key never signs unfiltered data. It is meant
for an organisation that points its **own** OpenCTEM platform at the bundle
for its own use: you are responsible for the terms of the platforms whose data
it contains, and the bundle must not be redistributed. A local bundle is
rebuilt from scratch every time (`--prev` is refused).

### How the collector behaves on the network

- User-Agent `openctem-programfeed/<version> (+https://github.com/openctemio/programfeed; security@openctem.io)`
  and a `From: security@openctem.io` header;
- `robots.txt` honoured for every origin (product token `openctem-programfeed`;
  an unreachable robots.txt means "do not fetch", RFC 9309);
- at most one request per second per host; conditional requests
  (`If-None-Match`, `If-Modified-Since`) from a cache kept between runs;
- response size caps (32 KiB for a security.txt, 32 MiB for a list);
- connections only to public unicast addresses (a seed list or redirect
  cannot point it at internal services); https only, at most 3 redirects;
- no login, no cookies, no JavaScript, no bot-protection bypass.

## What a release contains

| Asset | Content |
|---|---|
| `latest.dsse.json` | signed pointer: sequence, tag, snapshot and delta manifests, expiry |
| `snapshot.manifest.dsse.json` | signed manifest of the full snapshot (files, SHA-256, sizes, record counts, sources with licence and as-of time, stats) |
| `snapshot-programs.jsonl.gz` | every program |
| `snapshot-changes.jsonl.gz` | the change log of this run |
| `delta.manifest.dsse.json`, `delta-programs.jsonl.gz`, `delta-changes.jsonl.gz` | the programs that changed since the previous sequence (complete new records) and the same change log |
| `keyset.dsse.json` | the key set the manifests are signed under |

A platform reads
`https://github.com/openctemio/programfeed/releases/latest/download/latest.dsse.json`
and the files of the release it names.

## Record format

One JSON object per line. The JSON Schemas are in [`schema/`](schema/):
[`program.schema.json`](schema/program.schema.json) and
[`change.schema.json`](schema/change.schema.json).

```json
{"id":"securitytxt:agency.gov","source":"securitytxt","platform":"self-hosted","name":"Agency (agency.gov)",
 "url":"https://agency.gov/vulnerability-disclosure-policy","type":"vdp","status":"open","offers_bounty":false,
 "scope_published":false,
 "in_scope":[{"type":"domain","value":"agency.gov","confidence":"inferred","notes":"Domain whose security.txt names this policy; not a published scope."}],
 "out_of_scope":[],"rejected":[],
 "rules":{"testing_restrictions":[],"required_headers":[],"safe_harbour":"unknown","languages":["en"]},
 "terms":{"url":"https://agency.gov/.well-known/security.txt","sha256":"…","fetched_at":"2026-10-10T03:41:00Z"},
 "contact":{"email":"security@agency.gov"},
 "provenance":{"source":"securitytxt","source_url":"https://agency.gov/.well-known/security.txt","fetched_at":"2026-10-10T03:41:00Z"},
 "first_seen":"2026-10-10T03:41:00Z","last_seen":"2026-10-10T03:41:00Z","last_changed":"2026-10-10T03:41:00Z"}
{"sequence":2,"program":"securitytxt:agency.gov","kind":"target_added","scope":"in","target":{"type":"domain","value":"agency.gov","confidence":"inferred"}}
```

Key rules:

- `id` is `<source>:<slug>`, stable, owned by one adapter.
- `type` is `bounty` or `vdp`; `status` is `open`, `paused` (listed but not
  accepting: dead policy link, expired security.txt) or `closed` (the source
  no longer lists it). A closed program stays 180 days, then a
  `program_dropped` change removes it.
- Scope entries are typed (`domain`, `wildcard`, `ip`, `cidr`, `url`,
  `mobile_app`, `source_repo`, `other`), canonical, sorted and deduplicated;
  out of scope wins over in scope.
- `confidence`: `published` (the program's own scope), `published_by_platform`
  (scope the hosting platform published, read through a public dataset; the
  record's `provenance` names the dataset, commit, original platform and
  original program page) or `inferred` (derived by the collector). `scope_published` says whether the source carries the
  program's own structured scope at all.
- `terms.sha256` is the SHA-256 of the exact terms document the collector
  read, when it read one.
- `rejected` lists what a program listed that the scope rules refused, with
  the reason.

### Scope rules

A scope entry is refused (moved to `rejected`) when it is: a public suffix or
a wildcard over one (`com`, `*.co.uk`, `*.github.io`); a reserved or
non-public name (`localhost`, `.local`, `.internal`, `.test`, `example.com`
…); a private, loopback, link-local, CGNAT, documentation, multicast or
otherwise reserved address or range; a CIDR wider than /16 (IPv4) or /48
(IPv6); a URL that is not http(s), has credentials, or whose host fails the
rules above; malformed, over 512 bytes, or carrying control or bidi
characters. Each list is capped at 2,000 entries.

## Verifying a bundle yourself

```sh
go build -o programfeed ./cmd/programfeed
gh release download --repo openctemio/programfeed --dir bundle
./programfeed verify --dir bundle --root-key-id "$(cat keys/root-keyid.txt)"
```

The envelopes, key set, sequence, expiry and caps follow the same
conventions as the OpenCTEM vulnerability feed; only the payload types
(`application/vnd.openctem.programfeed.*`) and record files differ, so a
key set or manifest of one feed is never accepted by the other.

## Building locally

```sh
go test ./...                           # recorded fixtures, no network
go build -o programfeed ./cmd/programfeed
./programfeed build --out out --cache httpcache                     # every source
./programfeed build --out out --sources diodb                       # one source
./programfeed build --out out --policy my-policy.json               # your own publish policy
```

A key is needed only to sign; see `keys/README.md`.

## Security

Removal requests: [TAKEDOWN.md](TAKEDOWN.md). See [SECURITY.md](SECURITY.md) for the trust model and how to report a
problem. Adding a source: [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

Apache-2.0 (the code). The data keeps its sources' terms; see `NOTICE`.
