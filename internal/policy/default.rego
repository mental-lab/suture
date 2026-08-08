# Declarative remediation gate — the OpenVEX-aware version of the advisor's
# decision logic, evaluated by Conftest/OPA against three documents:
#
#   conftest test --policy policy/vex --data data/ \
#     --data data/asset-inventory.json --data data/vex-cache.json scan.json
#
# Inputs:
#   scan.json             Trivy fs scan output (the conftest input)
#   asset-inventory.json  data.assets.assets — generated:
#                           yq -o=json security/asset-inventory.yaml
#   vex-cache.json        data.vex_cache — generated:
#                           suture fetch --out data/vex-cache.json
package remediation

import rego.v1

denied_severities := {"CRITICAL", "HIGH"}

# ── findings ────────────────────────────────────────────────────────────────
# Flatten Trivy results into individual findings with asset context.
findings contains finding if {
	some report in input.Results
	some vuln in report.Vulnerabilities
	asset := object.get(data.assets.assets, "__ASSET_KEY__", {})
	finding := {
		"id": vuln.VulnerabilityID,
		"severity": upper(vuln.Severity),
		"pkg": vuln.PkgName,
		"installed": vuln.InstalledVersion,
		"target": report.Target,
		"internet_facing": object.get(asset, "internet_exposed", false),
		"tier": object.get(asset, "tier", "unclassified"),
	}
}

# ── Chainguard fix availability (from cached OpenVEX feed) ──────────────────
# vex-cache.json shape:
#   {"pkg:pypi/flask": {"CVE-XXXX-YYYY": ["pkg:pypi/flask@3.1.3%2Bcgr.1"]}}
chainguard_fix[finding] := fix if {
	some finding in findings
	purl := sprintf("pkg:%s/%s", [ecosystem_of(finding.target), lower(finding.pkg)])
	fix := data.vex_cache[purl][finding.id]
}

# Default policy targets a Python service; extend for other ecosystems.
ecosystem_of(target) := "pypi" if contains(target, "requirements")
ecosystem_of(target) := "pypi" if contains(target, "pip")
ecosystem_of(target) := "pypi" if endswith(target, ".py")

# ── decisions ───────────────────────────────────────────────────────────────
recommendation[finding.id] := rec if {
	some finding in findings
	chainguard_fix[finding]
	rec := {
		"action": "backport",
		"fix": chainguard_fix[finding][0],
		"reason": "Chainguard-built patched package exists (OpenVEX status=fixed)",
	}
}

recommendation[finding.id] := rec if {
	some finding in findings
	not chainguard_fix[finding]
	finding.severity in denied_severities
	finding.internet_facing
	rec := {
		"action": "upgrade-or-replace",
		"reason": "No backport in feed; internet-facing denied severity",
	}
}

high_risk_facing(finding) if {
	finding.severity in denied_severities
	finding.internet_facing
}

recommendation[finding.id] := rec if {
	some finding in findings
	not chainguard_fix[finding]
	not high_risk_facing(finding)
	rec := {
		"action": "exception-review",
		"reason": "No backport; lower risk context — time-boxed exception possible",
	}
}

# ── gate ────────────────────────────────────────────────────────────────────
# The version portion of a fixed purl, e.g. "2.2.3+cgr.1" from
# "pkg:pypi/werkzeug@2.2.3%2Bcgr.1". OpenVEX url-encodes the local ("+cgr.N")
# segment as %2B.
fix_version(purl) := v if {
	v := replace(split(purl, "@")[1], "%2B", "+")
}

# True when the installed version is already one of the Chainguard-fixed
# versions for this finding — i.e. the backport has been applied.
fix_applied(finding) if {
	some f in chainguard_fix[finding]
	finding.installed == fix_version(f)
}

# Deny on internet-facing CRITICAL/HIGH with an available-but-unapplied
# Chainguard fix. Once the backport is applied (installed == fixed version),
# the gate goes green.
deny contains msg if {
	some finding in findings
	finding.internet_facing
	finding.severity in denied_severities
	chainguard_fix[finding]
	not fix_applied(finding)
	msg := sprintf("%s in %s (%s) has an unapplied Chainguard fix: %s", [
		finding.id, finding.pkg, finding.installed, chainguard_fix[finding][0],
	])
}
