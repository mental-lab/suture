# AI coding assistants (MCP)

Suture ships a stdio [Model Context Protocol](https://modelcontextprotocol.io)
server, so an AI coding assistant can answer remediation questions while you
work — no CI run required.

## Setup

Point your assistant at the binary. For MCP clients that read `.mcp.json`:

```json
{
  "mcpServers": {
    "suture": { "command": "suture", "args": ["mcp"] }
  }
}
```

Any equivalent "command + args" server configuration works. `--base-url`
points the server at a different feed if you operate a mirror.

## Tools

All tools are **read-only** (`readOnlyHint: true`) — the server never writes
files, executes code, or mutates state.

| Tool | What it answers |
| --- | --- |
| `check_fix` | "Is there a Chainguard backport for CVE-x in package y?" → fixed versions (e.g. `2.2.2+cgr.1`), newest first, or that no coverage exists |
| `list_fixes` | "What CVEs have fixed builds for this package?" → vulnerability → newest fixed version |
| `advise` | "What should I do about these scan results?" → the CLI's full decision framework on a directory of Trivy/Grype JSON |

Example conversation the tools enable:

> **You:** `werkzeug 2.2.3` is flagged for CVE-2023-25577. Can I fix it without upgrading to 3.x?
> **Assistant** *(calls `check_fix`)*: Yes — the Chainguard feed records
> `werkzeug 2.2.2+cgr.1` as fixed. Pin to the Chainguard build instead of
> doing the breaking upgrade.

## Notes

- The server talks to the live OpenVEX feed; answers reflect what the feed
  operator publishes at call time.
- Findings outside Chainguard Libraries ecosystems are out of scope by
  design — the `advise` tool skips them, as the CLI does.
