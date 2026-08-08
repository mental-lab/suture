// Command suture is the OpenVEX-aware remediation tool for Chainguard
// Libraries: it builds the fix cache, advises on scanner findings, and
// exports the default gate policy.
package main

import "github.com/mental-lab/suture/cmd"

func main() {
	cmd.Execute()
}
