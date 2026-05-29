[CmdletBinding()]
param(
    [ValidateSet("empty-trace", "cpu-only-trace", "pktmon-capture-trace")]
    [string[]]$Fixture = @("empty-trace", "cpu-only-trace", "pktmon-capture-trace"),
    [int]$DurationSeconds = 3,
    [string]$OutputRoot,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$FixtureRoot = if ($OutputRoot) {
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputRoot)
} else {
    Join-Path $RepoRoot "tests\fixtures"
}

function Resolve-Xperf {
    $candidate = Get-Command xperf.exe -ErrorAction SilentlyContinue
    if ($candidate) { return $candidate.Source }

    $paths = @(
        "C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe",
        "C:\Program Files\Windows Kits\10\Windows Performance Toolkit\xperf.exe"
    )
    foreach ($path in $paths) {
        if (Test-Path $path) { return $path }
    }
    throw "xperf.exe was not found. Install Windows Performance Toolkit."
}

function Resolve-Wpr {
    $candidate = Get-Command wpr.exe -ErrorAction SilentlyContinue
    if ($candidate) { return $candidate.Source }

    $paths = @(
        "C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\wpr.exe",
        "C:\Program Files\Windows Kits\10\Windows Performance Toolkit\wpr.exe"
    )
    foreach ($path in $paths) {
        if (Test-Path $path) { return $path }
    }
    throw "wpr.exe was not found. Install Windows Performance Toolkit."
}

function Initialize-FixturePath([string]$Name) {
    $dir = Join-Path $FixtureRoot $Name
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $etl = Join-Path $dir "$Name.etl"
    if ((Test-Path $etl) -and -not $Force) {
        throw "$etl already exists. Pass -Force to overwrite it."
    }
    if (Test-Path $etl) {
        Remove-Item $etl -Force
    }
    return $etl
}

function Invoke-XperfStop {
    param([string]$Xperf, [string]$Output)
    & $Xperf -d $Output | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "xperf -d failed with exit code $LASTEXITCODE"
    }
}

$xperf = $null
if ($Fixture -contains "empty-trace") {
    $xperf = Resolve-Xperf
}
$wpr = $null
if ($Fixture -contains "cpu-only-trace") {
    $wpr = Resolve-Wpr
}

foreach ($name in $Fixture) {
    $etl = Initialize-FixturePath $name
    Write-Host "Collecting $name -> $etl"

    if ($name -eq "empty-trace") {
        & $xperf -on PROC_THREAD+LOADER -f $etl | Out-Null
        Start-Sleep -Seconds ([Math]::Max(1, $DurationSeconds))
        Invoke-XperfStop -Xperf $xperf -Output $etl
        continue
    }

    if ($name -eq "cpu-only-trace") {
        $job = $null
        try {
            & $wpr -start CPU.light -filemode | Out-Null
            $job = Start-Job -ScriptBlock {
                $deadline = [DateTime]::UtcNow.AddSeconds($using:DurationSeconds)
                $value = 0
                while ([DateTime]::UtcNow -lt $deadline) {
                    for ($i = 0; $i -lt 250000; $i++) { $value = ($value + $i) % 1000003 }
                }
                $value
            }
            Wait-Job $job | Out-Null
            Receive-Job $job | Out-Null
        }
        finally {
            if ($job) {
                Remove-Job $job -Force -ErrorAction SilentlyContinue
            }
            & $wpr -stop $etl | Out-Null
        }
        continue
    }

    if ($name -eq "pktmon-capture-trace") {
        if (-not (Get-Command pktmon.exe -ErrorAction SilentlyContinue)) {
            throw "pktmon.exe was not found on PATH."
        }
        pktmon stop 2>$null | Out-Null
        pktmon start --capture --pkt-size 0 --file-name $etl | Out-Null
        try {
            Test-NetConnection 127.0.0.1 -Port 9 -InformationLevel Quiet | Out-Null
            Start-Sleep -Seconds ([Math]::Max(1, $DurationSeconds))
        }
        finally {
            pktmon stop | Out-Null
        }
        if (-not (Test-Path $etl)) {
            throw "pktmon did not produce $etl"
        }
    }
}
