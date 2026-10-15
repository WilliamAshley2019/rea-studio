<#
.SYNOPSIS
    Runs a standard Ghidra headless analysis pipeline against a binary.
.DESCRIPTION
    Imports the binary into a temporary Ghidra project, runs analysis,
    invokes a sequence of post-scripts, exports the decompiled output
    and a structured JSON report. Cleans up the project afterward.

.PARAMETER Binary
    Path to the binary to analyze.

.PARAMETER OutputDir
    Where to write results. Default: <binary-dir>\ghidra-out\<binary-name>

.PARAMETER ScriptsDir
    Where custom post-scripts live. Default: C:\rea-studio\ghidra-scripts

.PARAMETER KeepProject
    Keep the temporary Ghidra project after analysis.
#>
param(
    [Parameter(Mandatory)][string]$Binary,
    [string]$OutputDir,
    [string]$ScriptsDir = "C:\rea-studio\ghidra-scripts",
    [switch]$KeepProject
)

$ErrorActionPreference = "Continue"

# --- Config --------------------------------------------------------------
$GhidraDir = "C:\Tools\ghidra-master\ghidra_12.1.2_PUBLIC_20260605\ghidra_12.1.2_PUBLIC"
$AnalyzeHeadless = Join-Path $GhidraDir "support\analyzeHeadless.bat"
$JdkHome = "C:\Program Files\Java\jdk-25.0.4"

if (-not (Test-Path -LiteralPath $AnalyzeHeadless)) {
    Write-Error "analyzeHeadless.bat not found at $AnalyzeHeadless"
    exit 1
}

if (-not (Test-Path -LiteralPath $Binary)) {
    Write-Error "Binary not found: $Binary"
    exit 1
}

# --- Prepare output ------------------------------------------------------
$binaryItem = Get-Item -LiteralPath $Binary
if (-not $OutputDir) {
    $OutputDir = Join-Path $binaryItem.DirectoryName "ghidra-out\$($binaryItem.Name)"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$projectDir = Join-Path $env:TEMP "rea-ghidra-pipeline-$([guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $projectDir -Force | Out-Null
$projectName = "ReaPipeline_$($binaryItem.BaseName)"

Write-Host ""
Write-Host "=== Ghidra Pipeline ===" -ForegroundColor Cyan
Write-Host "  Binary:      $Binary"
Write-Host "  Output:      $OutputDir"
Write-Host "  Project:     $projectDir\$projectName"
Write-Host "  ScriptsDir:  $ScriptsDir"
Write-Host ""

# --- Ensure custom scripts directory ------------------------------------
if (-not (Test-Path -LiteralPath $ScriptsDir)) {
    New-Item -ItemType Directory -Path $ScriptsDir -Force | Out-Null
}

# --- Set environment -----------------------------------------------------
$env:JAVA_HOME = $JdkHome
$env:GHIDRA_INSTALL_DIR = $GhidraDir
$env:REA_GHIDRA_OUT = $OutputDir

# --- Build the analyzeHeadless argument list -----------------------------
# Post-scripts run in the order given. Custom scripts take the output
# directory as their first argument.
$postScripts = @()
# Old:
$customScripts = @(
    "rea_export_report.py",
    "rea_strings_with_xrefs.py",
    "rea_crypto_constants.py",
    "rea_mov_imm_comments.py"
)

# New: prefer .java over .py
$customScripts = @()
foreach ($base in @("rea_export_report", "rea_strings_with_xrefs", "rea_crypto_constants", "rea_mov_imm_comments")) {
    $java = Join-Path $ScriptsDir "$base.java"
    $py = Join-Path $ScriptsDir "$base.py"
    if (Test-Path -LiteralPath $java) {
        $customScripts += "$base.java"
    } elseif (Test-Path -LiteralPath $py) {
        $customScripts += "$base.py"
    }
}
foreach ($script in $customScripts) {
    $scriptPath = Join-Path $ScriptsDir $script
    if (Test-Path -LiteralPath $scriptPath) {
        $postScripts += @("-postScript", $scriptPath, $OutputDir)
    }
}

# Then run Ghidra's built-in quality scripts (if present).
$ghidraScripts = Join-Path $GhidraDir "Ghidra\Features\Base\ghidra_scripts"
foreach ($name in @(
    "FindPotentialDecompilerProblems.java",
    "FixupNoReturnFunctionsScript.java"
)) {
    $path = Join-Path $ghidraScripts $name
    if (Test-Path -LiteralPath $path) {
        $postScripts += @("-postScript", $path)
    }
}

# --- Run ---------------------------------------------------------------
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$logFile = Join-Path $OutputDir "ghidra-headless.log"

# --- Build the analyzeHeadless argument list -----------------------------
# -scriptPath adds our custom directory to the script search list.
# -postScript then takes just the script name.
$args = @(
    $projectDir,
    $projectName,
    "-import", $Binary,
    "-overwrite",
    "-scriptPath", $ScriptsDir
)

# Custom scripts: pass the filename only, plus the output dir as an argument.
$customScripts = @(
    "rea_export_report.java"
)
foreach ($script in $customScripts) {
    $scriptPath = Join-Path $ScriptsDir $script
    if (Test-Path -LiteralPath $scriptPath) {
        $args += @("-postScript", $script, $OutputDir)
    }
}

# Ghidra's built-in quality scripts (still full paths is fine, but scriptPath
# makes them discoverable too if we reference them by name).
$ghidraScriptsDir = Join-Path $GhidraDir "Ghidra\Features\Base\ghidra_scripts"
foreach ($name in @("FixupNoReturnFunctionsScript.java")) {
    $path = Join-Path $ghidraScriptsDir $name
    if (Test-Path -LiteralPath $path) {
        $args += @("-postScript", $path)
    }
}

if (-not $KeepProject) {
    $args += "-deleteProject"
}

if (-not $KeepProject) {
    $args += "-deleteProject"
}

Write-Host "Running: analyzeHeadless.bat $($args -join ' ')"
Write-Host ""

& $AnalyzeHeadless @args 2>&1 | Tee-Object -FilePath $logFile
$exitCode = $LASTEXITCODE

$sw.Stop()

Write-Host ""
Write-Host "Exit: $exitCode | Elapsed: $([Math]::Round($sw.Elapsed.TotalSeconds, 1))s"
Write-Host "Log:  $logFile"
Write-Host ""

# --- Clean up the project if we kept it --------------------------------
if ($KeepProject) {
    Write-Host "Project kept: $projectDir\$projectName"
} else {
    Remove-Item -LiteralPath $projectDir -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Collect what the scripts produced ---------------------------------
Write-Host "=== Outputs in $OutputDir ===" -ForegroundColor Cyan
Get-ChildItem -LiteralPath $OutputDir | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize

exit $exitCode