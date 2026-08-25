<#
.SYNOPSIS
    OpsPulse - Windows Diagnostic & JSON Telemetry Engine.
.PARAMETER Mode
    Diagnostic scope: All, Network, Security, Performance.
.PARAMETER AsJson
    Switch to output machine-readable JSON for SIEM / MCP consumption.
#>
[CmdletBinding()]
param (
    [ValidateSet("All", "Network", "Security", "Performance")]
    [string]$Mode = "All",
    [switch]$AsJson
)

function Get-OpsDiagnosticData {
    $dnsTest = $true
    try {
        $null = Resolve-DnsName -Name "google.com" -ErrorAction Stop
    } catch {
        $dnsTest = $false
    }

    $networkInfo = @{
        Interfaces = Get-NetAdapter | Select-Object Name, Status, LinkSpeed
        IPv4Addresses = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object InterfaceAlias, IPAddress
        DefaultGateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue).NextHop
        DnsResolving = $dnsTest
    }

    $securityInfo = @{
        FirewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction
        ListeningPorts = Get-NetTCPConnection -State Listen | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                LocalAddress = $_.LocalAddress
                LocalPort    = $_.LocalPort
                ProcessID    = $_.OwningProcess
                ProcessName  = $proc.ProcessName
            }
        }
    }

    $perfInfo = @{
        VolumesAlert = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and ($_.SizeRemaining / $_.Size) -lt 0.20 } | Select-Object DriveLetter, FileSystemLabel, SizeRemaining, Size
        TopProcessesByRAM = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 5 ProcessName, Id, @{Name="WorkingSetMB";Expression={[math]::Round($_.WorkingSet/1MB,2)}}
        LastBootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    }

    return [PSCustomObject]@{
        Timestamp   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        Hostname    = $env:COMPUTERNAME
        OS          = "Windows"
        Network     = $networkInfo
        Security    = $securityInfo
        Performance = $perfInfo
    }
}

if ($AsJson) {
    $data = Get-OpsDiagnosticData
    $data | ConvertTo-Json -Depth 4
} else {
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host ">> OpsPulse Windows Diagnostic: Mode [$Mode]" -ForegroundColor Yellow
    Write-Host "=====================================================" -ForegroundColor Cyan
    $data = Get-OpsDiagnosticData
    $data | Format-Custom
}
