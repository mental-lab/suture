# Scope and disclaimer

## What suture is

A remediation advisor: it cross-references vulnerability scanner output
(Trivy, Grype) against the Chainguard Libraries OpenVEX feed and tells you
where a same-version, vendor-built fix exists. It helps you act on scan
results; it does not produce them.

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

## License

Apache-2.0, provided without warranty. Remediation decisions remain yours.
