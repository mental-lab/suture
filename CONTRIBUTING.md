# Contributing

Thanks for your interest in suture.

## Development

Requires Go 1.24+.

```sh
go build ./...   # build
go test ./...    # tests
gofmt -l .       # should print nothing
go vet ./...     # should pass
```

CI enforces gofmt, vet, tests, and Trivy scanning on every PR.

## Ground rules

- **Tests for behavior changes.** Parser, filter, and decision-logic changes
  need table tests; the feed client has an httptest harness to copy from.
- **Small, focused commits.** One logical change per commit; imperative
  subject lines.
- **Update the changelog.** User-facing changes get an entry under an
  "Unreleased" heading in CHANGELOG.md.
- **Fail loudly.** Never silently swallow a misconfiguration — a security
  tool that degrades quietly is worse than one that errors.

## Scope

Suture is intentionally narrow: OpenVEX feed → remediation advice → policy
gate. Features that turn it into a scanner, a dashboard, or a platform are
out of scope. Features that sharpen the remediation story (better scoping,
richer asset context, more feed shapes) are in scope — open an issue first
for anything larger than a bug fix.

## Reporting security issues

See [SECURITY.md](SECURITY.md).
