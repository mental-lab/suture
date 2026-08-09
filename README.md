# suture

**Scanners tell you a CVE exists. Suture tells you there's a same-version fix.**

[![ci](https://github.com/mental-lab/suture/actions/workflows/ci.yml/badge.svg)](https://github.com/mental-lab/suture/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/mental-lab/suture)](https://github.com/mental-lab/suture/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/mental-lab/suture)](https://goreportcard.com/report/github.com/mental-lab/suture)

OpenVEX-aware remediation tooling for Chainguard Libraries. Cross-references
Trivy/Grype findings against the Chainguard OpenVEX feed to find
**same-version backports** (`+cgr.N`) that generic scanners never surface,
recommends a remediation path per finding, and gates merges on unapplied
fixes.

Not tied to Chainguard the company — tied to the **feed shape**: any OpenVEX
feed laid out like Chainguard Libraries' works via `--base-url`. The reason
this tool exists at all is that Chainguard is unusually transparent here:
it publishes its remediation data as a **public, machine-readable OpenVEX
feed**, where other backport vendors keep theirs behind a sales call. If
another vendor publishes an equivalent feed tomorrow, suture serves it with
one flag.

## See it in action

[chainguard-swag-shop](https://github.com/mental-lab/chainguard-swag-shop) is
an intentionally vulnerable Flask shop wired to suture in CI. The advisor
report on `main` looks like this — one actionable backport, pulled out of
the noise:

```
**19 findings** — 🔧 1 with a Chainguard fix ready · ⬆️ 2 need an upstream upgrade · 📋 16 exception-review

| CVE | Severity | Package | Chainguard fix | Action |
| --- | --- | --- | --- | --- |
| GHSA-2g68-c3qc-8985 | HIGH | `werkzeug 2.2.3` | werkzeug==3.0.2+cgr.1 | **backport** |
```

The repo walks the full story: build → test → scan → advise → policy gate
(red on vulnerable `main`), then green on the remediated branch.

## Status

🚧 Early, and moving fast. Working today:

- **fetch** — pull per-package OpenVEX documents into an OPA-consumable fix
  cache, scoped to what you ship (`--sbom` / `--packages` / `--packages-file`)
  or the full feed
- **advise** — per-finding remediation recommendation (backport /
  upgrade-or-replace / exception-review / already-fixed), reading Trivy and
  Grype output interchangeably, scoped to Chainguard Libraries ecosystems
- **policy export** — scaffold the same gate as declarative Rego for
  Conftest/OPA
- **Releases** — cosign keyless-signed, SBOM'd, multi-arch binaries and
  Chainguard-based container images

Roadmap: manifest auto-detection for scoping, richer asset context in the gate.

## Install

```sh
# Release binary
curl -sSfL https://github.com/mental-lab/suture/releases/latest/download/suture_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz | tar xz suture
sudo install suture /usr/local/bin/

# Container (CI-friendly, runs on Wolfi-based Chainguard images)
docker run --rm -v "$PWD":/work -w /work ghcr.io/mental-lab/suture:latest --help

# From source
go install github.com/mental-lab/suture@latest
```

## Execution flow

### `fetch`

```mermaid
sequenceDiagram
    participant CI as You / CI
    participant Suture as suture fetch
    participant Feed as Chainguard OpenVEX feed

    opt scope resolution
        CI ->> Suture: --sbom sbom.json, --packages, --packages-file
        Note over Suture: parse SBOM purls / normalize names,<br/>union into wanted doc keys
    end

    Suture ->>+ Feed: GET /all.json
    Feed -->>- Suture: entry IDs (pypi/werkzeug.openvex.json, ...)
    Note over Suture: MatchKeys filter,<br/>warn on unmatched names<br/>and on zero matches

    loop per matched document (--concurrency N)
        Suture ->>+ Feed: GET entry.openvex.json
        Feed -->>- Suture: OpenVEX document
        Note over Suture: index status=fixed statements<br/>keyed by every vuln ID + alias
    end

    Suture -->> CI: data/vex-cache.json (OPA data document)
    Suture -->> CI: vex-documents/ (raw docs for grype --vex)
```

### `advise`

```mermaid
sequenceDiagram
    participant CI as You / CI
    participant Suture as suture advise
    participant Scan as scan results dir
    participant Cache as vex-cache.json

    CI ->> Suture: advise --scan-dir results/ --cache data/vex-cache.json
    Suture ->>+ Scan: read *.json
    Note over Scan: auto-detect per file:<br/>Trivy (Results) vs Grype (matches)
    Scan -->>- Suture: normalized findings
    Suture ->>+ Cache: load fix mappings
    Cache -->>- Suture: pkg, vuln ID, fixed purls

    loop each finding
        Note over Suture: identifiers = primary ID + aliases,<br/>package key from purl
        alt fixed statement found
            Note over Suture: recommend remediated purl<br/>werkzeug 2.2.3 to 2.2.3+cgr.1
        else no cache entry
            Note over Suture: no Chainguard fix known,<br/>upstream fix only if any
        end
    end

    Suture -->> CI: remediation report (markdown / JSON)
```

## Commands

### `fetch` — build the fix cache

```sh
suture fetch --out data/vex-cache.json
suture fetch --out data/vex-cache.json --write-docs vex-documents

# Scope the fetch to the packages you ship (flags compose as a union):
suture fetch --sbom sbom.json --write-docs vex-documents        # Syft/SPDX/CycloneDX
syft . -o syft-json | suture fetch --sbom -                     # or via stdin
suture fetch --packages werkzeug,flask                          # bare names, any ecosystem
suture fetch --packages pypi/werkzeug,npm/lodash                # eco/name pins one
suture fetch --packages-file requirements.txt                   # one per line; pins stripped
```

Fetches every per-package OpenVEX document and emits an OPA-consumable cache:

```json
{ "pkg:pypi/werkzeug": { "CVE-2023-25577": ["pkg:pypi/werkzeug@2.2.3%2Bcgr.1"] } }
```

Only `status: fixed` statements are indexed, keyed by **every** vulnerability
identifier (CVE, GHSA, …) so both Trivy- and Grype-reported IDs match.
`--write-docs` also materializes the raw documents for Grype's `--vex <dir>`
(VEX-aware scanning that suppresses fixed findings).

Without a scoping flag the whole feed is fetched. With one, only documents
for your packages are pulled; requested names that match nothing in the feed
are warned about, and a zero-match scope warns loudly since an empty cache
leaves the gate with nothing to enforce.

### `advise` — recommend a remediation path per finding

```sh
suture advise --scan-dir results/ --format markdown --out vex-report.md
suture advise --scan-dir results/ --assets security/asset-inventory.yaml --gate
```

Reads **Trivy and Grype** JSON (auto-detected per file — drop both scanners'
output in the same directory), looks each finding up in the feed, and decides:

- **backport** — Chainguard-built patched package exists (`status=fixed`); remediate
  without a breaking upstream upgrade
- **upgrade-or-replace** — no backport coverage; internet-facing Critical/High
- **exception-review** — no backport, lower risk context
- **none** — the backport is already applied (installed == fixed version)

`--gate` exits 1 when an internet-facing Critical/High finding has a Chainguard
fix available but not applied — the red→green flip when you adopt the backport.

### `policy export` — scaffold the Rego gate

```sh
suture policy export --dir policy/vex --asset-key my-service
```

Writes the default declarative gate (same logic as `advise --gate`, as Rego)
for evaluation with Conftest/OPA. Policy lives in your repo; the tool only
scaffolds it.

## CI usage (GitHub Actions)

```yaml
- name: Install suture
  run: |
    curl -sSfL https://github.com/mental-lab/suture/releases/latest/download/suture_linux_amd64.tar.gz \
      | tar xz suture
    sudo install suture /usr/local/bin/

- name: Build OpenVEX fix cache (scoped to the app's packages)
  run: suture fetch --sbom sbom.json --out data/vex-cache.json --write-docs vex-documents

- name: Remediation advisor
  run: suture advise --scan-dir results/ --assets security/asset-inventory.yaml --out vex-report.md

- name: Policy gate
  # --all-namespaces matters: conftest only evaluates the `main` package by
  # default and the exported policy is `package remediation` — without it
  # the gate silently passes.
  run: |
    yq -o=json '{"assets": .}' security/asset-inventory.yaml > assets.json
    jq '{vex_cache: .}' data/vex-cache.json > vex.json
    conftest test results/fs-scan.json \
      --policy policy/vex --all-namespaces \
      --data assets.json --data vex.json
```

## Supply chain

Every release ships with what you'd expect from a security tool:

- **Cosign keyless-signed** checksums (`checksums.txt.sig` / `.pem` per release)
- **SBOM** attached to every archive
- **Container images** built on `cgr.dev/chainguard/static` — multi-arch,
  minimal, zero-CVE base

## What suture doesn't promise

A green gate means no *in-scope* finding has an unapplied Chainguard fix. It
says nothing about ecosystems outside the feed, scanners' blind spots, or
packages you didn't scan. Suture is a remediation advisor, not a scanner and
not a guarantee. See [scope and disclaimer](docs/trust/scope-and-disclaimer.md).

## Documentation

[Full documentation index →](docs/README.md)

- [Quickstart](docs/getting-started/quickstart.md) — install, first fetch, first gate
- [Concepts](docs/concepts/decision-framework.md) — OpenVEX backports, the fix cache, the decision framework
- [CLI reference](docs/reference/cli.md) — every command and flag
- [AI coding assistants](docs/guides/ai-assistants.md) — the MCP server and its read-only tools
- [Changelog](CHANGELOG.md) — user-facing release notes
- [Scope & disclaimer](docs/trust/scope-and-disclaimer.md) — what suture does and does not claim
