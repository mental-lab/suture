# CLI reference

## `suture fetch`

Pull per-package OpenVEX documents from the feed and build the fix cache.

```
suture fetch [flags]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--out` | `data/vex-cache.json` | machine-readable cache output path |
| `--write-docs` | — | also write raw OpenVEX documents to this dir (for `grype --vex`) |
| `--write-vex` | — | write one merged OpenVEX document to this file (for `trivy --vex`, which takes a file not a dir) |
| `--sbom` | — | scope to packages in an SBOM (Syft/SPDX/CycloneDX; `-` reads stdin) |
| `--packages` | — | scope to a comma-separated list (`pypi/werkzeug` or bare `werkzeug`) |
| `--packages-file` | — | scope to packages listed one per line (version pins stripped) |
| `--base-url` | Chainguard feed | feed base URL |
| `--concurrency` | `8` | parallel document fetches |

Scoping flags compose as a union. With none, the full feed is fetched.
Names that match no feed document, and scopes matching nothing, produce
warnings on stderr.

## `suture advise`

Cross-reference scan findings with the feed and recommend a remediation
path per finding.

```
suture advise --scan-dir DIR [flags]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--scan-dir` | — (required) | directory of Trivy/Grype JSON results (auto-detected per file) |
| `--format` | `markdown` | `markdown` or `json` |
| `--out` | stdout | write the report to a file |
| `--assets` | — | asset-inventory.yaml providing exposure context |
| `--asset-key` | — | asset to attribute findings to (defaults to the only asset) |
| `--gate` | `false` | exit 1 on internet-facing Critical/High with an unapplied fix |
| `--index-prefix` | `pypi` | feed ecosystem for purl-less (Trivy) findings |
| `--base-url` | Chainguard feed | feed base URL |

Findings outside Chainguard Libraries ecosystems (pypi, maven, npm, gem,
nuget, cargo, golang) are skipped with an audit line. An unreadable
`--assets` file is a hard error.

## `suture mcp`

Serve suture's feed lookups and remediation evidence as optional read-only MCP
tools over stdio. MCP is intended for interactive investigation; deterministic
automation should consume the advisor JSON directly.

```
suture mcp [--base-url URL]
```

Exposes `check_fix`, `list_fixes`, and `advise`. See
[optional Copilot integration](../guides/ai-assistants.md).

## `suture fix`

Apply the advisor's backport recommendations to dependency manifests.

```
suture advise --scan-dir results/ --format json --out vex-report.json
suture fix --from vex-report.json --write --out summary.md
```

| Flag | Default | Description |
| --- | --- | --- |
| `--from` | `-` (stdin) | advisor JSON report (`suture advise --format json`) |
| `--dir` | `.` | repository root to scan for manifests |
| `--write` | off | rewrite manifests in place (default: dry run) |
| `--format` | `markdown` | summary format: `markdown`\|`json` |
| `--out` | stdout | write the summary to a file |

Only rows with `action="backport"` are applied. Same-upstream-version
backports reduce upgrade risk but are not guaranteed to be non-breaking.
Manifest discovery is Gemnasium-style and at most two directory levels deep.
The built-in patchers handle exact PyPI requirements, exact npm dependency
values, and literal Maven dependency versions. Maven properties, parent POMs,
BOMs, transitive overrides, Gradle files, and version catalogs are not changed.
Everything except supported changed pins is preserved byte-for-byte.
