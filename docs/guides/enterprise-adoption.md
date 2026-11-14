# Enterprise adoption

Suture complements an enterprise's existing scanner, dependency bot,
repository manager, and pull-request controls. Start read-only and adopt only
the integration surface the organization needs.

## Architecture boundary

```text
scanner/SBOM + supplier OpenVEX
                |
                v
       Suture remediation plan
          /        |        \
         v         v         v
  policy/report  advisory   optional manifest change
                  bridge            |
                     \              v
                      existing dependency bot or draft PR
                                    |
                                    v
                         CI + human approval
```

The CLI's JSON remediation plan is authoritative. An AI model may explain the
plan or repair a compatibility failure, but it should not select or invent a
fixed version.

## Adoption levels

### 1. Observe

Run `fetch` and `advise` read-only. Compare recommendations with the existing
SCA platform and vulnerability-management process. No repository write token
is required.

### 2. Enforce policy

Use `advise --gate` or `policy export` to enforce a narrow rule, such as an
internet-facing Critical/High finding with an unapplied same-base backport.
Keep broader vulnerability policy in the organization's existing platform.

### 3. Integrate with GitHub-native controls

For GitHub Enterprise Cloud customers with GitHub Code Security or GitHub
Advanced Security, enterprise-scoped innersource advisories are a promising
native integration. GitHub accepts OSV advisory payloads and may ask Dependabot
to open a security-update pull request when the fixed version exists in an
accessible package registry. See GitHub's
[innersource advisory documentation](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/manage-innersource-advisories).

OpenVEX-to-OSV export and Dependabot behavior for Chainguard's Maven
`-0.cgr.N` versions must be validated before production use. In particular,
test registry authentication, direct dependencies, properties, BOMs, and
transitive findings. Until that adapter is implemented and tested, use the
remediation plan as evidence rather than hand-authoring enterprise advisories.

### 4. Propose changes

Use `suture fix` only for its documented exact-pin cases, or connect the plan
to a Maven/Gradle-aware updater such as OpenRewrite. Verify the exact artifact
through the authenticated repository before writing a branch. Create a draft
pull request with a narrowly scoped GitHub App or equivalent service identity;
never push directly to the default branch.

### 5. Add an approved coding agent

The optional MCP server gives Copilot and other approved agents read-only
access to Suture evidence. Use enterprise MCP policies to allowlist the server
and individual tools. Keep credentials, complete private dependency graphs,
and unredacted scanner output out of model context unless organizational data
policy explicitly permits them. See GitHub's
[MCP management guidance](https://docs.github.com/en/copilot/concepts/enterprise/mcp-management).

## Required review controls

Every proposed dependency change should retain the repository's normal:

- build and test suite;
- dependency resolution and SBOM generation;
- vulnerability scan with supplier VEX;
- changed-file allowlist or review;
- CODEOWNER or security review where required; and
- branch protection or ruleset approval.

A same-upstream-version backport reduces migration scope. It does not prove
that application behavior is unchanged.

## Public-reference safety

Do not publish customer SBOMs, private package names, internal registry hosts,
organization identifiers, tokens, or complete dependency graphs in issues or
example artifacts. Public examples should use public package coordinates and
placeholder identities. Store real plans and SBOMs as access-controlled
artifacts with an explicit retention period.
