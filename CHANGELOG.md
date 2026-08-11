# Changelog

All notable changes to suture. Format follows [Keep a Changelog](https://keepachangelog.com/);
this project adheres to [Semantic Versioning](https://semver.org/).

## [v0.5.1] — 2026-08-10

### Changed — advisor / `suture fix`
- Advisor rows gain a structured `fix_purl` field (e.g.
  `pkg:pypi/werkzeug@2.2.3%2Bcgr.1`). Automation must read this;
  `chainguard_fix` remains a display string for humans.
- `suture fix` now covers the Chainguard Libraries ecosystems: PyPI
  (`requirements*.txt`), npm (`package.json` exact pins), Maven (`pom.xml`
  literal dependency versions). It derives name/version from `fix_purl`
  (ecosystem-generic) instead of parsing the display string. Patchers sit
  behind a registry — a new ecosystem is one `Patcher`.
- Pins rewrite only when the manifest still matches the scanned version
  (idempotent; never touches a pin that has already moved).

## [v0.5.0] — 2026-08-10

### Added — `suture fix`
- Dependabot-style backport application. Consumes the advisor's JSON output
  (`suture advise --format json`), takes every `backport` row, and rewrites
  the pins in dependency manifests discovered under `--dir`
  (requirements*.txt, up to two levels deep). Same-version `+cgr.N` pins
  only — upgrades and exceptions stay advisory. Dry-run by default;
  `--write` applies. Emits a markdown/JSON summary for the PR body.
- New `internal/manifest` package: parse/rewrite preserving everything
  except changed pins, plus repo manifest discovery.

## [v0.4.1] — 2026-08-10

### Fixed
- Trivy findings now carry the package purl (`PkgIdentifier.PURL`). Without
  it the advisor could not key Trivy findings to the feed cache (Trivy
  reports only CVE IDs), silently found zero fixes, and never emitted
  `backport` — which also made the thin gate fail open on Trivy scans.
  Grype input was unaffected (grype reports purls natively).

## [v0.4.0] — 2026-08-10

### Changed — advisor
- New `upgrade` action: findings with no Chainguard backport but an upstream
  fix available are now labeled `upgrade` instead of `exception-review`.
  `exception-review` now strictly means no fix exists anywhere. The markdown
  summary gains a "upgrades available" count.

### Changed — `policy export` (breaking)
- The exported gate is now *thin*: it consumes the advisor's JSON output
  (`suture advise --format json`) and denies only on internet-facing
  CRITICAL/HIGH with an unapplied Chainguard backport (`action="backport"`).
  Decision logic lives in the advisor; the policy no longer re-derives
  findings from raw scan output, the VEX cache, and the asset inventory.
  The `--asset-key` flag is accepted for compatibility but unused.
  Existing gates using the pre-v0.4.0 policy contract (scan.json input with
  assets/vex data documents) must switch to the advisor JSON contract.

## [v0.3.3] — 2026-08-09

### Changed
- `advise` drops Trivy `os-pkgs` results (Debian/Wolfi system packages).
  They can never have a Chainguard Libraries fix and flooded the report
  when the advisor moved to image scans (~100 noise rows on a debian
  base). OS findings remain visible in the image-scan summary.

## [v0.3.2] — 2026-08-09

### Changed
- `advise` report now surfaces the scanner-reported **upstream fix version**
  (e.g. `msgpack==1.2.1 (upstream)`) when no Chainguard backport exists, in
  both the table and the rationale. Previously those rows read as if no
  patch existed at all.

## [v0.3.1] — 2026-08-09

### Added
- `fetch --write-vex` — shorter spelling of `--write-docs-file` (kept as a
  hidden alias); names what it produces.

## [v0.3.0] — 2026-08-09

### Added
- `fetch --write-docs-file <path>` — writes one merged OpenVEX document
  containing every fetched statement (raw-statement fidelity). Trivy's
  `--vex` accepts a file but not a directory; Grype takes either.

### Changed
- `advise` now prefers the **same-version backport** when recommending a
  fix (e.g. `setuptools==70.3.0+cgr.1` for an installed `70.3.0`) instead
  of always sorting the newest backport first. The same-version pin is the
  non-breaking change and the tool's core recommendation.

## [v0.2.0] — 2026-08-09

### Added
- `suture mcp` — a stdio Model Context Protocol server exposing read-only
  tools (`check_fix`, `list_fixes`, `advise`) so AI coding assistants can
  answer "is there a Chainguard fix for this CVE?" mid-conversation.
- Community health files: LICENSE (Apache-2.0), CONTRIBUTING.md, SECURITY.md,
  CHANGELOG.md, and a docs/ tree.

## [v0.1.3] — 2026-08-09

### Changed
- `advise` now scopes findings to Chainguard Libraries ecosystems
  (pypi, maven, npm, gem, nuget, cargo, golang). Findings Grype catalogs
  from GitHub Actions workflows, OS binaries, and other non-Libraries
  sources are skipped with an audit line naming what was dropped — they
  can never have a Chainguard backport and were pure report noise.

## [v0.1.2] — 2026-08-09

### Changed
- The `advise` markdown report is now concise: a one-line findings summary,
  an "Action required" section (backports + exposed Critical/High upgrades,
  deduplicated, severity-sorted), and the remainder collapsed in a
  `<details>` block.

### Fixed
- `--assets` pointing at an unreadable or unparseable inventory now fails
  loudly instead of silently treating every finding as internal-facing
  (which downgraded internet-facing Highs to exception-review).

## [v0.1.1] — 2026-08-09

### Added
- `fetch` scoping flags: `--sbom` (Syft/SPDX/CycloneDX, file or `-` stdin),
  `--packages` (comma-separated, `eco/name` or bare name), and
  `--packages-file` (one per line, version pins stripped). Flags compose as
  a union. Unmatched names and zero-match scopes produce warnings.

### Fixed
- VEX documents written by `--write-docs` no longer get a doubled
  `.openvex.json` extension.
- The `policy export` scaffold now documents that conftest requires
  `--all-namespaces` — without it the gate evaluates zero rules and
  silently passes.

## [v0.1.0] — 2026-08-08

Initial release: `fetch`, `advise`, and `policy export` against the
Chainguard Libraries OpenVEX feed. Cosign-signed, SBOM'd releases with
multi-arch binaries and Chainguard-based container images.
