# Concepts

## The remediation gap

Scanners report CVEs against version numbers. Vendors that backport security
fixes — Red Hat and Canonical at the OS layer, Chainguard Libraries for
language packages — ship a **patched build of the version you already run**
(`werkzeug 2.2.3+cgr.1`), but the scanner can't see it: the NVD record still
names 2.2.3 as vulnerable. Teams then face a breaking upstream upgrade
(2.2.3 → 3.x) when a same-version fix existed all along.

Suture closes that gap by reading the vendor's **OpenVEX feed** — statements
of the form "CVE-x is `fixed` in product `pkg:pypi/werkzeug@2.2.3%2Bcgr.1`" —
and cross-referencing it against your scanner output.

## The fix cache

`suture fetch` turns the feed's per-package documents into one cache:

```json
{ "pkg:pypi/werkzeug": { "CVE-2023-25577": ["pkg:pypi/werkzeug@2.2.3%2Bcgr.1"] } }
```

- Only `status: fixed` statements are indexed — `not_affected` and
  `under_investigation` are not fixes.
- Statements are keyed by **every** vulnerability identifier (CVE, GHSA, …),
  because Trivy reports the CVE and Grype often reports the GHSA.
- The cache is a plain JSON data document, consumable by OPA/Conftest for
  the declarative gate.
- Scope the fetch (`--sbom`, `--packages`, `--packages-file`) to pull only
  the packages you ship.

## The decision framework

`advise` weighs each finding as severity × exposure × fix availability:

| Action | When |
| --- | --- |
| **backport** | Chainguard feed has `status=fixed` for the finding — adopt the `+cgr.N` build; same test suite must pass |
| **upgrade-or-replace** | No backport coverage; internet-facing Critical/High — pursue a compatible upstream upgrade, else evaluate replacement |
| **exception-review** | No backport and lower risk context — a time-boxed compensating-control exception may be acceptable |
| **none** | The backport is already applied (installed version matches a fixed release) |

Findings outside Chainguard Libraries ecosystems (OS packages, GitHub
Actions, …) are filtered before any of this — the advisor only reports what
the feed could remediate.

## The gate

`--gate` (or the exported Rego) fails only on the highest-signal condition:
an internet-facing Critical/High with a Chainguard fix available but not
applied. Everything else is advisory. The gate is designed to be red exactly
once — the day you adopt the backport, it flips green without any allowlist
edits.
