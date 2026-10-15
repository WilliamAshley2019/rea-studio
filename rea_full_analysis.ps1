<#
.SYNOPSIS
    Full automatic analysis pipeline for any binary.

.DESCRIPTION
    1. Sniffs the binary header to determine format
    2. Detects packing (UPX) via PE section names
    3. Unpacks UPX if detected
    4. Runs Ghidra headless analysis with the correct processor spec
    5. Runs custom Java post-scripts and Ghidra's built-in quality scripts
    6. Renders a human-readable Markdown summary
    7. Optionally opens everything in Notepad++
    8. Cleans up the temporary Ghidra project

.PARAMETER Binary
    Path to the binary to analyze.

.PARAMETER OutputDir
    Where to write results. Default: <binary-dir>\ghidra-out\<binary-name>

.PARAMETER ScriptsDir
    Custom post-scripts directory. Default: C:\rea-studio\ghidra-scripts

.PARAMETER Open
    Open the summary and JSON files in Notepad++ when done.

.PARAMETER KeepProject
    Keep the temporary Ghidra project (useful for interactive follow-up).

.PARAMETER SkipUnpack
    Skip the UPX auto-unpack step even if packing is detected.
#>
param(
    [Parameter(Mandatory)][string]$Binary,
    [string]$OutputDir,
    [string]$ScriptsDir = "C:\rea-studio\ghidra-scripts",
    [switch]$Open,
    [switch]$KeepProject,
    [switch]$SkipUnpack
)

$ErrorActionPreference = "Continue"

# ============================================================================
# Configuration
# ============================================================================
$GhidraDir = "C:\Tools\ghidra-master\ghidra_12.1.2_PUBLIC_20260605\ghidra_12.1.2_PUBLIC"
$AnalyzeHeadless = Join-Path $GhidraDir "support\analyzeHeadless.bat"
$JdkHome = "C:\Program Files\Java\jdk-25.0.4"
$UpxCandidates = @(
    "C:\Tools\upx\upx.exe",
    "C:\Tools\upx-5.2.1-win64\upx.exe",
    "C:\ProgramData\chocolatey\bin\upx.exe"
)
$NotepadPp = "C:\Program Files\Notepad++\notepad++.exe"

# ============================================================================
# Logging
# ============================================================================
function Head { param([string]$T) Write-Host ""; Write-Host ("=" * 72) -ForegroundColor DarkCyan; Write-Host " $T" -ForegroundColor Cyan; Write-Host ("=" * 72) -ForegroundColor DarkCyan }
function Info { param([string]$T) Write-Host "  [*] $T" -ForegroundColor Gray }
function Ok   { param([string]$T) Write-Host "  [+] $T" -ForegroundColor Green }
function Warn { param([string]$T) Write-Host "  [!] $T" -ForegroundColor Yellow }
function Fail { param([string]$T) Write-Host "  [-] $T" -ForegroundColor Red }

# ============================================================================
# Sanity checks
# ============================================================================
if (-not (Test-Path -LiteralPath $AnalyzeHeadless)) {
    Fail "analyzeHeadless.bat not found at $AnalyzeHeadless"
    exit 1
}
if (-not (Test-Path -LiteralPath $Binary)) {
    Fail "Binary not found: $Binary"
    exit 1
}
if (-not (Test-Path -LiteralPath $ScriptsDir)) {
    New-Item -ItemType Directory -Path $ScriptsDir -Force | Out-Null
}
$env:JAVA_HOME = $JdkHome
$env:GHIDRA_INSTALL_DIR = $GhidraDir

# ============================================================================
# Header sniffing
# ============================================================================
function Get-BinaryFormat {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64) { return @{ kind = "too-small"; processor = $null } }

    # ELF
    if ($bytes[0] -eq 0x7F -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0x4C -and $bytes[3] -eq 0x46) {
        $bits = if ($bytes[4] -eq 1) { 32 } else { 64 }
        $machine = [BitConverter]::ToUInt16($bytes, 0x12)
        $arch = switch ($machine) {
            0x03 { "i386" }
            0x3E { "x86-64" }
            0x28 { "ARM" }
            0xB7 { "ARM64" }
            default { "unknown-0x$($machine.ToString('X4'))" }
        }
        return @{
            kind = "ELF $bits-bit $arch"
            processor = if ($bits -eq 32) { "x86:LE:32:default" } else { "x86:LE:64:default" }
            cspec = "gcc"
            isUpx = $false
        }
    }

    # MZ
    if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
        $peOff = [BitConverter]::ToUInt32($bytes, 0x3C)
        $hasPe = ($peOff -gt 0 -and $peOff + 24 -lt $bytes.Length -and
                  $bytes[$peOff] -eq 0x50 -and $bytes[$peOff + 1] -eq 0x45)
        if ($hasPe) {
            $machine = [BitConverter]::ToUInt16($bytes, $peOff + 4)
            $optMagic = [BitConverter]::ToUInt16($bytes, $peOff + 24)
            $bits = switch ($optMagic) { 0x010B { 32 } 0x020B { 64 } default { 32 } }
            $numSections = [BitConverter]::ToUInt16($bytes, $peOff + 6)
            $sectionTableOffset = $peOff + 24 + [BitConverter]::ToUInt16($bytes, $peOff + 20)

            $sections = @()
            $isUpx = $false
            for ($i = 0; $i -lt $numSections; $i++) {
                $secOff = $sectionTableOffset + ($i * 40)
                if ($secOff + 8 -gt $bytes.Length) { break }
                $nameBytes = $bytes[$secOff..($secOff + 7)]
                $name = ($nameBytes | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) -join ""
                $sections += $name
                if ($name -like "UPX*" -or $name -like ".UPX*") { $isUpx = $true }
            }

            $arch = switch ($machine) {
                0x014C { "i386" }
                0x8664 { "x86-64" }
                0x01C0 { "ARM" }
                0xAA64 { "ARM64" }
                default { "unknown-0x$($machine.ToString('X4'))" }
            }
            return @{
                kind = "PE $bits-bit $arch"
                processor = if ($bits -eq 32) { "x86:LE:32:default" } else { "x86:LE:64:default" }
                cspec = "windows"
                isUpx = $isUpx
                sections = $sections
                machine = $machine
                bits = $bits
            }
        } else {
            # DOS MZ, no PE
            $ip = [BitConverter]::ToUInt16($bytes, 0x14)
            $cs = [BitConverter]::ToUInt16($bytes, 0x16)
            return @{
                kind = "DOS MZ 16-bit real mode (CS:IP=$($cs.ToString('X4')):$($ip.ToString('X4')))"
                processor = "x86:LE:16:Real Mode"
                cspec = "default"
                isUpx = $false
            }
        }
    }

    # Mach-O
    if ($bytes[0] -eq 0xCF -and $bytes[1] -eq 0xFA -and $bytes[2] -eq 0xED -and $bytes[3] -eq 0xFE) {
        return @{ kind = "Mach-O 64-bit"; processor = "x86:LE:64:default"; cspec = "default"; isUpx = $false }
    }
    if ($bytes[0] -eq 0xCE -and $bytes[1] -eq 0xFA -and $bytes[2] -eq 0xED -and $bytes[3] -eq 0xFE) {
        return @{ kind = "Mach-O 32-bit"; processor = "x86:LE:32:default"; cspec = "default"; isUpx = $false }
    }

    # Possible COM (small, no magic)
    if ($bytes.Length -lt 65536) {
        return @{ kind = "unknown (small, possibly DOS COM)"; processor = "x86:LE:16:Real Mode"; cspec = "default"; isUpx = $false }
    }

    return @{ kind = "unknown"; processor = "x86:LE:32:default"; cspec = "default"; isUpx = $false }
}

# ============================================================================
# UPX unpacking
# ============================================================================
function Find-Upx {
    foreach ($candidate in $UpxCandidates) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    $cmd = Get-Command upx -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Invoke-UpxUnpack {
    param([string]$InputPath, [string]$OutputPath)
    $upx = Find-Upx
    if (-not $upx) {
        Warn "UPX not found. Install to C:\Tools\upx\upx.exe or PATH."
        return $false
    }
    Info "Unpacking with $upx"
    & $upx -d $InputPath -o $OutputPath -f 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $OutputPath)) {
        return $true
    }
    Warn "UPX unpack failed (exit $LASTEXITCODE)."
    return $false
}

# ============================================================================
# Main
# ============================================================================
Head "Full Analysis Pipeline"

$binaryItem = Get-Item -LiteralPath $Binary
Info "Binary:      $Binary"
Info "Size:        $('{0:N0}' -f $binaryItem.Length) bytes"

$format = Get-BinaryFormat -Path $Binary
Ok "Detected:    $($format.kind)"
Info "Processor:   $($format.processor)"
Info "CSpec:       $($format.cspec)"

# ---------------------------------------------------------------------------
# Unpack if needed
# ---------------------------------------------------------------------------
$workingBinary = $Binary
if ($format.isUpx -and -not $SkipUnpack) {
    Warn "UPX packing detected (sections: $($format.sections -join ', '))"
    $upxOut = [System.IO.Path]::Combine(
        $binaryItem.DirectoryName,
        [System.IO.Path]::GetFileNameWithoutExtension($Binary) + "_unpacked" + [System.IO.Path]::GetExtension($Binary)
    )
    if (Invoke-UpxUnpack -InputPath $Binary -OutputPath $upxOut) {
        Ok "Unpacked to: $upxOut"
        $workingBinary = $upxOut
        # Re-sniff the unpacked binary
        $format = Get-BinaryFormat -Path $workingBinary
        Info "Re-detected: $($format.kind)"
    }
} elseif ($format.isUpx) {
    Warn "UPX detected but -SkipUnpack given. Analyzing packed binary."
} else {
    Ok "No packing detected."
}

# ---------------------------------------------------------------------------
# Prepare output directory
# ---------------------------------------------------------------------------
if (-not $OutputDir) {
    $OutputDir = Join-Path $binaryItem.DirectoryName "ghidra-out\$([System.IO.Path]::GetFileName($workingBinary))"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
Info "Output:      $OutputDir"

# ---------------------------------------------------------------------------
# Build the analyzeHeadless argument list
# ---------------------------------------------------------------------------
$projectDir = Join-Path $env:TEMP "rea-full-analysis-$([guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $projectDir -Force | Out-Null
$projName = "ReaFull_$([System.IO.Path]::GetFileNameWithoutExtension($workingBinary))"

$args = @(
    $projectDir,
    $projName,
    "-import", $workingBinary,
    "-overwrite",
    "-processor", $format.processor,
    "-cspec", $format.cspec,
    "-scriptPath", $ScriptsDir
)

# Custom post-scripts (Java)
foreach ($base in @("rea_export_report", "rea_strings_with_xrefs", "rea_crypto_constants", "rea_mov_imm_comments")) {
    $java = Join-Path $ScriptsDir "$base.java"
    if (Test-Path -LiteralPath $java) {
        $args += @("-postScript", "$base.java", $OutputDir)
    }
}

# Ghidra's built-in quality scripts
$ghidraScriptsDir = Join-Path $GhidraDir "Ghidra\Features\Base\ghidra_scripts"
foreach ($name in @("FixupNoReturnFunctionsScript.java", "FindPotentialDecompilerProblems.java")) {
    $path = Join-Path $ghidraScriptsDir $name
    if (Test-Path -LiteralPath $path) {
        $args += @("-postScript", $name)
    }
}

if (-not $KeepProject) {
    $args += "-deleteProject"
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
Head "Running Ghidra analysis"
Info "This takes 15-90 seconds depending on binary size."
Write-Host ""

$logFile = Join-Path $OutputDir "ghidra-headless.log"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
& $AnalyzeHeadless @args 2>&1 | Tee-Object -FilePath $logFile | Out-Null
$sw.Stop()

$exitCode = $LASTEXITCODE
Write-Host ""
Ok "Analysis complete: exit $exitCode, elapsed $([Math]::Round($sw.Elapsed.TotalSeconds, 1))s"
Info "Log: $logFile"

# ---------------------------------------------------------------------------
# Render the Markdown summary
# ---------------------------------------------------------------------------
Head "Rendering summary"

$reportPath = Join-Path $OutputDir "program_report.json"
$summaryPath = Join-Path $OutputDir "SUMMARY.md"
$filesToOpen = @()

if (Test-Path -LiteralPath $reportPath) {
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json

    $md = New-Object System.Collections.ArrayList
    [void]$md.Add("# $($report.name)")
    [void]$md.Add("")
    [void]$md.Add("- **Format:** $($format.kind)")
    [void]$md.Add("- **Processor:** $($format.processor) / $($format.cspec)")
    [void]$md.Add("- **Image base:** $($report.image_base)")
    [void]$md.Add("- **Functions:** $($report.functions.total)")
    [void]$md.Add("- **Symbols:** $($report.symbols.total)")
    if ($format.isUpx) {
        [void]$md.Add("- **Note:** this binary was UPX-packed; analysis ran on the unpacked version.")
    }
    [void]$md.Add("")
    [void]$md.Add("## Segments")
    [void]$md.Add("")
    [void]$md.Add("| Name | Start | End | Size | Perms |")
    [void]$md.Add("|---|---|---|---|---|")
    foreach ($seg in $report.segments) {
        $perms = @()
        if ($seg.r) { $perms += "r" }
        if ($seg.w) { $perms += "w" }
        if ($seg.x) { $perms += "x" }
        $permStr = ($perms -join "")
        [void]$md.Add("| ``$($seg.name)`` | $($seg.start) | $($seg.end) | $('{0:N0}' -f $seg.size) | $permStr |")
    }
    [void]$md.Add("")
    [void]$md.Add("## Top 40 strings (by length)")
    [void]$md.Add("")
    [void]$md.Add("```")
    $n = [Math]::Min(40, $report.top_strings.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $s = $report.top_strings[$i]
        [void]$md.Add("$($s.address)  [$($s.length)]  $($s.value)")
    }
    [void]$md.Add("```")
    [void]$md.Add("")
    [void]$md.Add("## Output files")
    [void]$md.Add("")
    Get-ChildItem -LiteralPath $OutputDir -File | Sort-Object Name | ForEach-Object {
        [void]$md.Add("- ``$($_.Name)`` ($('{0:N0}' -f $_.Length) bytes)")
    }

    $md -join "`n" | Set-Content -LiteralPath $summaryPath -Encoding UTF8
    Ok "Wrote summary: $summaryPath"
    $filesToOpen += $summaryPath
    $filesToOpen += $reportPath
} else {
    Warn "program_report.json not produced."
}

# ---------------------------------------------------------------------------
# Open in Notepad++
# ---------------------------------------------------------------------------
if ($Open -and $filesToOpen.Count -gt 0 -and (Test-Path -LiteralPath $NotepadPp)) {
    Info "Opening in Notepad++..."
    & $NotepadPp -nosession @filesToOpen
}

# ---------------------------------------------------------------------------
# Cleanup / summary
# ---------------------------------------------------------------------------
if (-not $KeepProject) {
    Remove-Item -LiteralPath $projectDir -Recurse -Force -ErrorAction SilentlyContinue
} else {
    Info "Project kept: $projectDir\$projName"
}

Head "Done"

Write-Host ""
Get-ChildItem -LiteralPath $OutputDir -File | Sort-Object Name |
    Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize

Write-Host ""
Ok "Output directory: $OutputDir"