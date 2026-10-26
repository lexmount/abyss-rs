#requires -Version 7.0
<#
Tests an already-running Windows WFP broker with a real WorkBuddy runtime and
controlled scripts representing daemon, extensionless CLI, and an unmatched
sibling entry. The Host must redirect this executable to the supplied broker.
No model credentials or prompts are used. Restores the original TLS policy.
#>
param(
    [Parameter(Mandatory)][string]$BrokerStartupInfo,
    [Parameter(Mandatory)][string]$WorkBuddyExePath,
    [Parameter(Mandatory)][string]$RootCertificatePath,
    [uri]$ProbeUrl = 'https://example.com/',
    [Parameter(Mandatory)][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($ProbeUrl.Scheme -ne 'https') { throw 'The probe requires HTTPS.' }
$startup = Get-Content -Raw -LiteralPath $BrokerStartupInfo | ConvertFrom-Json
$headers = @{ Authorization = 'Bearer ' + (Get-Content -Raw -LiteralPath $startup.auth_token_file).Trim() }
$api = 'http://' + $startup.api_addr
$executable = (Resolve-Path -LiteralPath $WorkBuddyExePath).Path
$certificate = (Resolve-Path -LiteralPath $RootCertificatePath).Path
$runtimeName = [IO.Path]::GetFileName($executable)
if ($runtimeName -notin @('WorkBuddy.exe', 'WorkBuddyAI.exe')) { throw 'Supply the real WorkBuddy runtime.' }
$directory = Join-Path ([IO.Path]::GetTempPath()) ('abyss-entry-' + [guid]::NewGuid().ToString('N'))
$results = [Collections.Generic.List[object]]::new()
$original = Invoke-RestMethod -Uri "$api/v1/mitm/config" -Headers $headers -TimeoutSec 5
$policyChanged = $false
try {
    $daemon = [IO.Path]::GetFullPath((Join-Path $directory '应用 Test/main/daemon-app-server-entry.js'))
    $cli = [IO.Path]::GetFullPath((Join-Path $directory '应用 Test/cli/bin/codebuddy'))
    $other = [IO.Path]::GetFullPath((Join-Path $directory 'Other/cli/bin/codebuddy'))
    foreach ($entry in @($daemon, $cli, $other)) {
        New-Item -ItemType Directory -Path (Split-Path -Parent $entry) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows_entry_tls_probe.cjs') -Destination $entry
    }
    $policy = @{ tls_decryption = @{
        default_action = 'passthrough'; missing_sni_action = 'passthrough'
        rules = @(
            @{id='test-workbuddy-daemon'; enabled=$true; action='passthrough'; process_names=@($runtimeName); process_entry_points=@($daemon)},
            @{id='test-workbuddy-cli'; enabled=$true; action='intercept'; process_names=@($runtimeName); process_entry_points=@($cli)}
        )
    }}
    # Even a failed response may follow a committed update; always restore after sending.
    $policyChanged = $true
    Invoke-RestMethod -Method Put -Uri "$api/v1/mitm/config" -Headers $headers -ContentType 'application/json' -Body ($policy | ConvertTo-Json -Depth 10) -TimeoutSec 10 | Out-Null
    foreach ($case in @(
        @{entry=$daemon; role='daemon'; intercepted=$false; rule='test-workbuddy-daemon'},
        @{entry=$cli; role='cli'; intercepted=$true; rule='test-workbuddy-cli'},
        @{entry=$other; role='unmatched-sibling'; intercepted=$false; rule=$null}
    )) {
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $executable
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        if ($case.role -eq 'cli') {
            $start.ArgumentList.Add('--optimize-for-size')
            $start.ArgumentList.Add('--max-semi-space-size=2')
        }
        $start.ArgumentList.Add($case.entry)
        foreach ($key in @('NODE_OPTIONS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY')) {
            [void]$start.Environment.Remove($key)
        }
        $start.Environment['ELECTRON_RUN_AS_NODE'] = '1'
        $start.Environment['NODE_EXTRA_CA_CERTS'] = $certificate
        $start.Environment['ABYSS_ENTRY_TEST_CA'] = $certificate
        $start.Environment['ABYSS_ENTRY_TEST_URL'] = $ProbeUrl.AbsoluteUri
        $process = [Diagnostics.Process]::Start($start)
        try {
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(25000)) { $process.Kill(); $process.WaitForExit(); throw 'TLS probe timed out.' }
            if ($process.ExitCode -ne 0) { throw ('TLS probe failed: ' + $stderr.GetAwaiter().GetResult()) }
            $probe = $stdout.GetAwaiter().GetResult().Trim() | ConvertFrom-Json
        } finally { $process.Dispose() }
        if (-not $probe.authorized -or $probe.signedByBroker -ne $case.intercepted) { throw ('Unexpected certificate for ' + $case.role) }
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        $flow = $null
        do {
            $diagnostics = Invoke-RestMethod -Uri "$api/v1/support/diagnostics" -Headers $headers -TimeoutSec 5
            $flow = $diagnostics.flow.recent_flows | Where-Object { $_.source_process -and $_.source_process.pid -eq $probe.pid } | Select-Object -First 1
            if ($null -eq $flow) { Start-Sleep -Milliseconds 100 }
        } while ($null -eq $flow -and [DateTime]::UtcNow -lt $deadline)
        if ($null -eq $flow) { throw 'No WFP diagnostic flow for the probe PID.' }
        $expectedDecision = if ($case.intercepted) { 'intercepted' } else { 'passthrough' }
        if ($flow.ingress.source -ne 'windows_wfp' -or $flow.source_process.entry_point -cne $case.entry -or $flow.decision -ne $expectedDecision) {
            throw ('Unexpected WFP attribution: ' + ($flow | ConvertTo-Json -Depth 10 -Compress))
        }
        $results.Add([pscustomobject]@{role=$case.role; pid=$probe.pid; entry=$case.entry; decision=$flow.decision; configuredRule=$case.rule; authorized=$probe.authorized; signedByBroker=$probe.signedByBroker; issuer=$probe.issuer; status=$probe.status})
    }
    $results | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding utf8
    $results | Select-Object role,pid,decision,configuredRule,authorized,signedByBroker | Format-Table
} finally {
    try {
        if ($policyChanged) {
            Invoke-RestMethod -Method Put -Uri "$api/v1/mitm/config" -Headers $headers -ContentType 'application/json' -Body ($original | ConvertTo-Json -Depth 20) -TimeoutSec 10 | Out-Null
        }
    } finally {
        $resolved = [IO.Path]::GetFullPath($directory)
        $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        if (-not $resolved.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notmatch '^abyss-entry-[0-9a-f]{32}$') { throw 'Unsafe temporary directory.' }
        if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    }
}
