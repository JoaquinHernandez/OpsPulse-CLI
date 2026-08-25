#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import * as os from "node:os";
import * as path from "node:path";
import { Client as SSHClient } from "ssh2";

const execAsync = promisify(exec);

const server = new Server(
  {
    name: "opspulse-mcp-server",
    version: "2.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Built-in Knowledge Base for Diagnostic Correlation
const ROOT_CAUSE_KB: Record<string, { desc: string; fix_linux: string; fix_windows: string }> = {
  "EADDRINUSE": {
    desc: "Target listening port is locked by another running process.",
    fix_linux: "sudo kill -9 $(lsof -t -i:<PORT>)",
    fix_windows: "Get-NetTCPConnection -LocalPort <PORT> | Stop-Process -Id {$_.OwningProcess} -Force"
  },
  "DNS_FAILURE": {
    desc: "Nameserver unreachable or DNS resolver timeout.",
    fix_linux: "echo 'nameserver 1.1.1.1' | sudo tee /etc/resolv.conf",
    fix_windows: "Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses ('1.1.1.1','8.8.8.8')"
  },
  "OOM_EXHAUSTION": {
    desc: "Host RAM exhausted; risk of kernel panic or process drops.",
    fix_linux: "sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile",
    fix_windows: "Get-Process | Sort-Object WorkingSet -Descending | Select -First 5"
  }
};

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "run_local_diagnostic",
        description: "Executes native OpsPulse on the local machine and returns structured telemetry.",
        inputSchema: {
          type: "object",
          properties: {
            scope: {
              type: "string",
              enum: ["check-all", "net", "sec", "perf", "web"],
              description: "Diagnostic scope to execute."
            },
            as_json: {
              type: "boolean",
              description: "Set to true for structured JSON output."
            }
          },
          required: ["scope"]
        }
      },
      {
        name: "run_remote_ssh_diagnostic",
        description: "Executes OpsPulse over SSH on a remote host to gather telemetry or triage outages.",
        inputSchema: {
          type: "object",
          properties: {
            host: { type: "string", description: "Target IP or hostname" },
            port: { type: "number", default: 22 },
            username: { type: "string", description: "SSH username" },
            password: { type: "string", description: "SSH password (optional if key provided)" },
            privateKey: { type: "string", description: "Raw OpenSSH Private Key (optional)" },
            scope: { type: "string", default: "check-all" }
          },
          required: ["host", "username"]
        }
      },
      {
        name: "check_virustotal_threat",
        description: "Queries VirusTotal API v3 to evaluate IP addresses or domains identified during socket audits.",
        inputSchema: {
          type: "object",
          properties: {
            endpoint: { type: "string", description: "IP address or domain to verify" },
            type: { type: "string", enum: ["ip_addresses", "domains"], description: "Entity type" },
            api_key: { type: "string", description: "VirusTotal API Key (defaults to VT_API_KEY env var)" }
          },
          required: ["endpoint", "type"]
        }
      },
      {
        name: "correlate_incident_and_remediate",
        description: "Analyzes system error traces, identifies root cause, and generates targeted fix commands.",
        inputSchema: {
          type: "object",
          properties: {
            log_output: { type: "string", description: "Log, error trace, or telemetry string." },
            os_target: { type: "string", enum: ["linux", "windows"] }
          },
          required: ["log_output", "os_target"]
        }
      }
    ]
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "run_local_diagnostic": {
        const scope = (args?.scope as string) || "check-all";
        const asJson = Boolean(args?.as_json);
        const isWindows = os.platform() === "win32";
        let cmd = "";

        if (isWindows) {
          const scriptPath = path.resolve(process.cwd(), "windows", "opspulse.ps1");
          cmd = `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "${scriptPath}" -Mode ${scope === "check-all" ? "All" : scope} ${asJson ? "-AsJson" : ""}`;
        } else {
          const scriptPath = path.resolve(process.cwd(), "linux", "opspulse.sh");
          cmd = `bash "${scriptPath}" ${scope} ${asJson ? "--json" : ""}`;
        }

        const { stdout, stderr } = await execAsync(cmd, { timeout: 30000 });
        return {
          content: [{ type: "text", text: stdout || stderr || "Execution returned empty response." }]
        };
      }

      case "run_remote_ssh_diagnostic": {
        const host = args?.host as string;
        const sshPort = (args?.port as number) || 22;
        const username = args?.username as string;
        const password = args?.password as string | undefined;
        const privateKey = args?.privateKey as string | undefined;
        const scope = (args?.scope as string) || "check-all";

        return new Promise((resolve) => {
          const conn = new SSHClient();
          conn.on("ready", () => {
            conn.exec(`curl -sSL https://raw.githubusercontent.com/OpsPulse-CLI/main/linux/opspulse.sh | bash -s -- ${scope} --json`, (err, stream) => {
              if (err) {
                conn.end();
                return resolve({
                  isError: true,
                  content: [{ type: "text", text: `SSH Command execution error: ${err.message}` }]
                });
              }
              let output = "";
              let errorOutput = "";
              stream.on("data", (data: Buffer) => { output += data.toString(); });
              stream.stderr.on("data", (data: Buffer) => { errorOutput += data.toString(); });
              stream.on("close", () => {
                conn.end();
                resolve({
                  content: [{ type: "text", text: output || errorOutput || "SSH Exec complete." }]
                });
              });
            });
          }).on("error", (err) => {
            resolve({
              isError: true,
              content: [{ type: "text", text: `SSH Connection Failed: ${err.message}` }]
            });
          }).connect({
            host,
            port: sshPort,
            username,
            password,
            privateKey,
            readyTimeout: 20000
          });
        });
      }

      case "check_virustotal_threat": {
        const endpoint = args?.endpoint as string;
        const type = args?.type as string;
        const apiKey = (args?.api_key as string) || process.env.VT_API_KEY;

        if (!apiKey) {
          return {
            isError: true,
            content: [{ type: "text", text: "VirusTotal API key missing. Supply via param or VT_API_KEY env." }]
          };
        }

        const url = `https://www.virustotal.com/api/v3/${type}/${endpoint}`;
        const response = await fetch(url, {
          headers: { "x-apikey": apiKey }
        });

        if (!response.ok) {
          return {
            isError: true,
            content: [{ type: "text", text: `VirusTotal lookup failed: HTTP ${response.statusText}` }]
          };
        }

        const json: any = await response.json();
        const stats = json?.data?.attributes?.last_analysis_stats || {};
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                queried_target: endpoint,
                malicious_votes: stats.malicious || 0,
                suspicious_votes: stats.suspicious || 0,
                harmless_votes: stats.harmless || 0,
                reputation_score: json?.data?.attributes?.reputation || 0
              }, null, 2)
            }
          ]
        };
      }

      case "correlate_incident_and_remediate": {
        const log = (args?.log_output as string) || "";
        const targetOs = (args?.os_target as string) || "linux";

        const matchedIssues: Array<{ issue: string; description: string; remediation: string }> = [];

        if (/address already in use|bind failed|EADDRINUSE/i.test(log)) {
          matchedIssues.push({
            issue: "Port Conflict",
            description: ROOT_CAUSE_KB["EADDRINUSE"].desc,
            remediation: targetOs === "linux" ? ROOT_CAUSE_KB["EADDRINUSE"].fix_linux : ROOT_CAUSE_KB["EADDRINUSE"].fix_windows
          });
        }
        if (/temporary failure in name resolution|DNS resolution failed|server can't find/i.test(log)) {
          matchedIssues.push({
            issue: "DNS Failure",
            description: ROOT_CAUSE_KB["DNS_FAILURE"].desc,
            remediation: targetOs === "linux" ? ROOT_CAUSE_KB["DNS_FAILURE"].fix_linux : ROOT_CAUSE_KB["DNS_FAILURE"].fix_windows
          });
        }
        if (/out of memory|oom-killer|segfault/i.test(log)) {
          matchedIssues.push({
            issue: "Memory Exhaustion (OOM)",
            description: ROOT_CAUSE_KB["OOM_EXHAUSTION"].desc,
            remediation: targetOs === "linux" ? ROOT_CAUSE_KB["OOM_EXHAUSTION"].fix_linux : ROOT_CAUSE_KB["OOM_EXHAUSTION"].fix_windows
          });
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                status: matchedIssues.length > 0 ? "Correlated" : "Undetermined",
                detections: matchedIssues
              }, null, 2)
            }
          ]
        };
      }

      default:
        throw new Error(`Tool not found: ${name}`);
    }
  } catch (err: any) {
    return {
      isError: true,
      content: [{ type: "text", text: `OpsPulse MCP Failure: ${err.message}` }]
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);
