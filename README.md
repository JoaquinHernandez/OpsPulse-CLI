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

******chmod +x linux/opspulse.sh
./linux/opspulse.sh check-all          # Human readable terminal report
./linux/opspulse.sh check-all --json   # Machine-readable JSON output**

Set-ExecutionPolicy Bypass -Scope Process -Force
.\windows\opspulse.ps1 -Mode All
.\windows\opspulse.ps1 -Mode All -AsJson


<ElicitationsGroup message="Next actions for enterprise deployment:">
  <Elicitation label="Generate Docker container setup for MCP" query="Create a Dockerfile and docker-compose.yml to run OpsPulse MCP server in an isolated container."/>
  <Elicitation label="Add Prometheus metric exporter" query="Show how to convert OpsPulse JSON telemetry into a Prometheus metrics endpoint."/>
  <Elicitation label="Configure automated Slack/PagerDuty webhooks" query="Add a webhook notification engine to OpsPulse for alerting Slack and PagerDuty during critical failures."/>
</ElicitationsGroup>
