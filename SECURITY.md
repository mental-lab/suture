# Security Policy

## Reporting a vulnerability

Please report security issues privately via
[GitHub Security Advisories](https://github.com/mental-lab/suture/security/advisories/new)
rather than opening a public issue.

Include: the affected version, a description of the issue, and steps to
reproduce. Expect an acknowledgement within a few days.

## Scope notes

Suture consumes remote data (the OpenVEX feed, scanner output files) and
writes local files (caches, reports, policy scaffolds). Issues we care
about most: path traversal in output paths, unsafe handling of feed or
scanner data, and anything that would let crafted input alter the gate's
verdict.

## Verifying releases

Release binaries are cosign keyless-signed and ship with SBOMs. See the
[quickstart](docs/getting-started/quickstart.md) for the verification
commands.
