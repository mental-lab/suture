# Declarative remediation gate — thin enforcement over the advisor's decision
# output. suture owns the decision framework (backport / upgrade-or-replace /
# upgrade / exception-review); this policy only encodes what blocks a merge,
# so new advisor actions never require policy changes.
#
#   suture advise --scan-dir results/ --format json --out vex-report.json
#   conftest test vex-report.json --policy policy/vex --all-namespaces
#
# --all-namespaces is required: conftest only evaluates the `main` package by
# default, and this policy is `package remediation`. Without it the gate
# silently passes.
package remediation

import rego.v1

denied_severities := {"CRITICAL", "HIGH"}

# Deny on internet-facing CRITICAL/HIGH with an available-but-unapplied
# Chainguard backport. The advisor emits action="backport" exactly when a
# fix exists and is not applied; everything else (upstream upgrades,
# exception review) is advisory and lives in the advisor report.
deny contains msg if {
	some row in input.remediation_recommendations
	row.internet_facing
	upper(row.severity) in denied_severities
	row.action == "backport"
	msg := sprintf("%s in %s (%s) has an unapplied Chainguard fix: %s", [
		row.id, row.pkg, row.installed, row.chainguard_fix,
	])
}
