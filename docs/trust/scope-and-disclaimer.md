# Scope and disclaimer

## What suture is

An OpenVEX remediation bridge: it cross-references vulnerability scanner
output (Trivy, Grype) against a supplier OpenVEX feed and emits deterministic
evidence about available backports. It helps existing scanners, policy engines,
dependency bots, coding agents, and pull-request workflows act on supplier
remediation data.

## What suture is not

- **Not a scanner.** If your scanner missed a finding, suture has nothing
  to advise on.
- **Not an artifact verifier.** A `status: fixed` package URL is evidence from
  the feed operator. Before applying it, CI must authenticate to the intended
  repository and resolve the exact artifact.
- **Not a compatibility guarantee.** Keeping the upstream base version reduces
  upgrade risk, but a backported binary can still change behavior. Normal
  build, test, scan, and review requirements still apply.
- **Not a complete Maven or Gradle updater.** The built-in Maven patcher only
  changes literal versions in dependency blocks. It does not currently update
  properties, parent POMs, imported BOMs, transitive constraints, Gradle build
  files, or version catalogs.
- **Not full coverage.** The feed covers Chainguard Libraries ecosystems
  (pypi, maven, npm, gem, nuget, cargo, golang), and within those, the
  packages Chainguard remediates. A finding outside that scope is reported
  as having no Chainguard fix — that is a statement about the feed, not
  about the world.
- **Not a guarantee.** A green gate means no in-scope internet-facing
  Critical/High finding has an unapplied Chainguard fix. It is silent about
  everything else: lower severities, internal assets, unscanned artifacts,
  feed lag, scanner blind spots.

## Feed trust

Suture consumes a vendor-published feed over HTTPS. You are trusting the
feed operator's statements about which builds fix which CVEs — that trust
relationship is the product. The `--base-url` flag exists so you can point
at a mirror or a differently-operated feed with the same layout; the same
trust consideration applies to whoever operates it.

## MCP trust boundary

The optional MCP server exposes read-only lookups and advice. It does not apply
changes or authorize remediation, and an MCP annotation is metadata rather
than an enforcement boundary. Enterprise operators should allowlist the server
and individual tools, constrain the process to the intended workspace, and
avoid placing private scan results into model context unless their data policy
allows it. CI and policy should consume the CLI's JSON output directly rather
than depend on model interpretation.

## License

Apache-2.0, provided without warranty. Remediation decisions remain yours.
