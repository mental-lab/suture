# CLI reference

## `suture fetch`

Pull per-package OpenVEX documents from the feed and build the fix cache.

```
suture fetch [flags]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--out` | `data/vex-cache.json` | cache output path (OPA data document) |
| `--write-docs` | — | also write raw OpenVEX documents to this dir (for `grype --vex`) |
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

Serve suture's feed lookups and remediation advice as read-only MCP tools
over stdio, for AI coding assistants.

```
suture mcp [--base-url URL]
```

Exposes `check_fix`, `list_fixes`, and `advise`. See
[AI coding assistants](../guides/ai-assistants.md).

## `suture policy export`

Scaffold the default remediation gate as Rego.

```
suture policy export --dir policy/vex --asset-key my-service
```

| Flag | Default | Description |
| --- | --- | --- |
| `--dir` | `policy/vex` | output directory for the .rego file |
| `--asset-key` | — | asset the gate applies to |

The exported policy is `package remediation`; evaluate it with
`conftest test --all-namespaces` — conftest only evaluates `package main`
by default, and without the flag the gate silently passes.
