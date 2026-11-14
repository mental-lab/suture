# Optional Copilot and coding-agent integration (MCP)

Suture ships an optional stdio [Model Context Protocol](https://modelcontextprotocol.io)
server so an approved coding assistant can query structured remediation
evidence instead of interpreting raw OpenVEX. MCP is an interactive adapter;
it is not the authoritative automation path. CI, gates, and dependency updates
should consume `suture advise --format json` directly.

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
files, executes code, or mutates state. The hint helps compatible clients but
must not be treated as a security boundary by itself.

| Tool | What it answers |
| --- | --- |
| `check_fix` | "Is there a Chainguard backport for CVE-x in package y?" → fixed versions (e.g. `2.2.2+cgr.1`), newest first, or that no coverage exists |
| `list_fixes` | "What CVEs have fixed builds for this package?" → vulnerability → newest fixed version |
| `advise` | "What should I do about these scan results?" → the CLI's full decision framework on a directory of Trivy/Grype JSON |

Example conversation the tools enable:

> **You:** `werkzeug 2.2.3` is flagged for CVE-2023-25577. Can I fix it without upgrading to 3.x?
> **Assistant** *(calls `check_fix`)*: The Chainguard feed records
> `werkzeug 2.2.2+cgr.1` as fixed. Verify that exact artifact through your
> authenticated repository, then use the normal test and review process.

## Notes

- The server talks to the live OpenVEX feed; answers reflect what the feed
  operator publishes at call time.
- Findings outside Chainguard Libraries ecosystems are out of scope by
  design — the `advise` tool skips them, as the CLI does.
- The server does not verify registry availability and must not tell an agent
  that a change is safe to merge.
- `advise` reads the scan directory supplied by the caller. Configure the MCP
  process and client so it cannot be used to expose files outside the intended
  workspace.
- GitHub Enterprise and other managed clients can disable or allowlist MCP
  servers and tools. Operators should use those controls instead of enabling
  every available tool.
