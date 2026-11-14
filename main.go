// Command suture is the OpenVEX-aware remediation tool for Chainguard
// Libraries: it builds the fix cache, advises on scanner findings, and emits
// deterministic remediation plans and gate results.
package main

import "github.com/mental-lab/suture/cmd"

func main() {
	cmd.Execute()
}
