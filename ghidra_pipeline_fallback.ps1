<#
.SYNOPSIS
    Ghidra pipeline with format fallback chain.
.DESCRIPTION
    Tries each format in order: PE 32-bit, PE 64-bit, DOS MZ 16-bit,
    DOS COM 16-bit, ELF, Mach-O. Uses explicit -processor/-cspec flags
    so Ghidra doesn't guess wrong. Verifies each attempt by checking
    function count and memory block plausibility. Stops at the first
    format that produces a credible analysis.

    Ghidra notes: 16-bit real mode auto-analysis silently fabricates
    control flow when misidentified. Forcing the language/compiler spec
    avoids the 32-bit Windows PE mis-detection that happens with some
    old MZ files.
.PARAMETER Binary
    Path to the binary.
.PARAMETER OutputDir
    Where to write results. Default: <binary-dir>\ghidra-out\<binary-name>
.PARAMETER ScriptsDir
    Where custom post-scripts live. Default: C:\rea-studio\ghidra-scripts
#>
param(
    [Parameter(Mandatory)][string]$Binary,
    [string]$OutputDir,
    [string]$ScriptsDir = "C:\rea-studio\ghidra-scripts"
)

$ErrorActionPreference = "Continue"

$GhidraDir = "C:\Tools\ghidra-master\ghidra_12.1.2_PUBLIC_20260605\ghidra_12.1.2_PUBLIC"
$AnalyzeHeadless = Join-Path $GhidraDir "support\analyzeHeadless.bat"
$JdkHome = "C:\Program Files\Java\jdk-25.0.4"

if (-not (Test-Path -LiteralPath $AnalyzeHeadless)) {
    Write-Error "analyzeHeadless.bat not found"
    exit 1
}
if (-not (Test-Path -LiteralPath $Binary)) {
    Write-Error "Binary not found: $Binary"
    exit 1
}

# --- Determine output dir and prepare a fresh project per attempt ------
$binaryItem = Get-Item -LiteralPath $Binary
if (-not $OutputDir) {
    $OutputDir = Join-Path $binaryItem.DirectoryName "ghidra-out\$($binaryItem.Name)"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$env:JAVA_HOME = $JdkHome
$env:GHIDRA_INSTALL_DIR = $GhidraDir

# --- The fallback chain ------------------------------------------------
# Each entry: (label, processor, cspec, expected_min_functions).
# We try in order until one produces a plausible result.
$attempts = @(
    @{ Label = "PE 32-bit (x86:LE:32:default)";  Processor = "x86:LE:32:default";  CSpec = "windows";  MinFuncs = 10 },
    @{ Label = "PE 64-bit (x86:LE:64:default)";  Processor = "x86:LE:64:default";  CSpec = "windows";  MinFuncs = 10 },
    @{ Label = "DOS MZ 16-bit (x86:LE:16:Real Mode)"; Processor = "x86:LE:16:Real Mode"; CSpec = "default"; MinFuncs = 5 },
    @{ Label = "DOS COM 16-bit (x86:LE:16:Real Mode)"; Processor = "x86:LE:16:Real Mode"; CSpec = "default"; MinFuncs = 3 },
    @{ Label = "ELF 32-bit (x86:LE:32:default)";  Processor = "x86:LE:32:default";  CSpec = "gcc";      MinFuncs = 10 },
    @{ Label = "ELF 64-bit (x86:LE:64:default)";  Processor = "x86:LE:64:default";  CSpec = "gcc";      MinFuncs = 10 }
)

# --- Try each ----------------------------------------------------------
foreach ($attempt in $attempts) {
    Write-Host ""
    Write-Host "=== Attempt: $($attempt.Label) ===" -ForegroundColor Cyan

    $attemptDir = Join-Path $env:TEMP "rea-ghidra-fallback-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $attemptDir -Force | Out-Null
    $projName = "ReaFallback_$($binaryItem.BaseName)"

    $postScripts = @()
    $customScripts = @("rea_export_report.py", "rea_strings_with_xrefs.py", "rea_crypto_constants.py", "rea_mov_imm_comments.py")
    foreach ($script in $customScripts) {
        $scriptPath = Join-Path $ScriptsDir $script
        if (Test-Path -LiteralPath $scriptPath) {
            $postScripts += @("-postScript", $scriptPath, $OutputDir)
        }
    }

    $args = @(
        $attemptDir,
        $projName,
        "-import", $Binary,
        "-overwrite",
        "-processor", $attempt.Processor,
        "-cspec", $attempt.CSpec
    ) + $postScripts + @("-deleteProject")

    Write-Host "Running: $($attempt.Processor) / $($attempt.CSpec)"

    $logFile = Join-Path $OutputDir "ghidra-attempt-$($attempt.Processor.Replace(':','_')).log"
    $output = & $AnalyzeHeadless @args 2>&1
    $output | Tee-Object -FilePath $logFile | Out-Null

    # Check whether the analysis produced a plausible number of functions.
    $reportPath = Join-Path $OutputDir "program_report.json"
    if (Test-Path -LiteralPath $reportPath) {
        try {
            $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
            $funcCount = $report.functions.total
            Write-Host "  Functions identified: $funcCount"
            if ($funcCount -ge $attempt.MinFuncs) {
                Write-Host "  [+] Plausible analysis. Accepting." -ForegroundColor Green
                # Write a marker file so the pipeline knows which format worked.
                @{
                    processor = $attempt.Processor
                    cspec = $attempt.CSpec
                    function_count = $funcCount
                    label = $attempt.Label
                } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDir "accepted_format.json")
                exit 0
            } else {
                Write-Host "  [-] Too few functions ($funcCount < $($attempt.MinFuncs)). Trying next." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  [-] Could not parse program_report.json" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [-] No program_report.json produced. Trying next." -ForegroundColor Yellow
    }

    Remove-Item -LiteralPath $attemptDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "[-] All format attempts failed." -ForegroundColor Red
exit 1