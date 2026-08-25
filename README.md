# OpsPulse-CLI
# OpsPulse-CLI 🛠️⚡

> Automated, zero-dependency IT incident response, security auditing, and Model Context Protocol (MCP) server for mixed infrastructure.

## MCP Client Configuration (Claude Desktop / Host)

Add this configuration to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "opspulse": {
      "command": "node",
      "args": ["<PATH-TO-OPSPULSE>/dist/index.js"],
      "env": {
        "VT_API_KEY": "<OPTIONAL_VIRUSTOTAL_KEY>"
      }
    }
  }
}
