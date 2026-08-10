# Changelog

All notable changes to suture. Format follows [Keep a Changelog](https://keepachangelog.com/);
this project adheres to [Semantic Versioning](https://semver.org/).

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
