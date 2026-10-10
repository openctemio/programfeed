# Contributing

Thanks for helping. Two kinds of contributions are common: adding seed
domains for the security.txt adapter, and adding a new source adapter.

## Adding seed domains

Add lines to `seeds/securitytxt.txt` (`domain [organisation name]`). Only add
domains whose owner publishes a vulnerability disclosure policy for public
use. The domain must already serve `/.well-known/security.txt` with a
`Contact` and a `Policy` field, or the collector skips it.

## Adding a source adapter

### 1. Check that the source may be collected

Before writing code, open an issue with:

- the official API or machine-readable listing (documentation link);
- whether it needs authentication (the feed never logs in, uses cookies or
  tokens, runs JavaScript or bypasses bot protection: a source that needs
  any of that is not accepted);
- its terms of service and robots.txt, quoted: they must allow automated
  collection **and redistribution**, since the feed is published openly
  (or the publisher must have given written permission, linked in the
  issue);
- the licence of the data and the attribution it requires;
- its rate limits.

### 2. Write the adapter

An adapter is one file in `internal/source/` implementing `source.Source`:

```go
type Source interface {
	Meta() Meta                                             // name, URL, terms, licence, attribution
	Collect(ctx context.Context, c *fetch.Client) (*Result, error)
}
```

Rules:

- Use only the `*fetch.Client` it is given (it handles the User-Agent,
  robots.txt, rate limits, conditional requests, size caps and the
  public-address check). Pass a size cap that fits the source.
- Program ids are `<Meta().Name>:<slug>`; use `source.UniqueSlugs` for names.
  Ids must be stable across runs. The collector refuses programs outside the
  adapter's own prefix.
- Fill `Provenance` (source, source URL, fetched-at time). Leave
  `first_seen`, `last_seen`, `last_changed` and `closed_at` to the collector.
- Put the program's own scope in `InScope`/`OutOfScope` with
  `Confidence: published` and set `ScopePublished`. Anything the adapter
  derives itself is `Confidence: inferred`, with a note saying how.
- Do not filter scope yourself: the collector normalises every target and
  records refused ones with the reason.
- Return an error only when the source as a whole could not be read (the
  collector then keeps every previous record). Put ids whose state is
  unknown this run (a host that did not answer) in `Result.Unknown`.
- Hostile input is expected: decode defensively, cap counts, never trust a
  field's type.

Register it in `cmd/programfeed/main.go` (`sources`), and add its row to the
sources table in `README.md` and its terms to `NOTICE`.

### 3. Test it with recorded fixtures

Tests never touch the network. Record a small, representative response
under `internal/source/testdata/` (trimmed, no personal data beyond what the
source publishes), serve it with `httptest`, and point the fetch client at
it (`fetch.Options{AllowPrivate: true, DialOverride: ...}`, see
`source_test.go`). Include poisoned entries: malformed records, wrong field
types, control characters, public-suffix or private-range scope.

### 4. Check before opening the pull request

```sh
gofmt -l .
go vet ./...
go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Pull requests target `main`.
