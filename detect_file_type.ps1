<#
.SYNOPSIS
    Detect the type of an arbitrary file from its magic bytes.
.DESCRIPTION
    Reads the first bytes, checks against a table of known magics,
    and reports what the file likely is. Covers executables, archives,
    filesystems, media, images, documents, databases, and crypto blobs.
.PARAMETER Path
    File to inspect.
.PARAMETER Detailed
    Also print first 64 bytes in hex and ASCII.
#>
param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$Detailed
)

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Error "File not found: $Path"
    exit 1
}

$item = Get-Item -LiteralPath $Path
$bytes = [System.IO.File]::ReadAllBytes($Path)
$len = $bytes.Length
if ($len -lt 4) {
    Write-Host "File too small to identify ($len bytes)."
    exit 1
}

function Hex { param($b, $off, $n)
    ($b[$off..($off + $n - 1)] | ForEach-Object { $_.ToString("X2") }) -join " "
}
function AsciiSafe { param($b, $off, $n)
    ($b[$off..($off + $n - 1)] | ForEach-Object {
        if ($_ -ge 0x20 -and $_ -le 0x7E) { [char]$_ } else { "." }
    }) -join ""
}
function Match { param($b, $off, $sig)
    if ($off + $sig.Length -gt $b.Length) { return $false }
    for ($i = 0; $i -lt $sig.Length; $i++) {
        if ($b[$off + $i] -ne $sig[$i]) { return $false }
    }
    return $true
}

# --- Detection -----------------------------------------------------------
$result = @{ Type = "unknown"; Extra = @() }

# Executables / binaries
if (Match $bytes 0 @(0x4D,0x5A)) {
    $peOff = [BitConverter]::ToUInt32($bytes, 0x3C)
    $hasPe = ($peOff -gt 0 -and $peOff + 4 -lt $len -and $bytes[$peOff] -eq 0x50 -and $bytes[$peOff+1] -eq 0x45)
    if ($hasPe) {
        $machine = [BitConverter]::ToUInt16($bytes, $peOff + 4)
        $optMagic = [BitConverter]::ToUInt16($bytes, $peOff + 24)
        $bits = switch ($optMagic) { 0x010B { 32 } 0x020B { 64 } default { "?" } }
        $arch = switch ($machine) {
            0x014C { "i386" }
            0x8664 { "x86-64" }
            0x01C0 { "ARM" }
            0xAA64 { "ARM64" }
            default { "0x$($machine.ToString('X4'))" }
        }
        $numSections = [BitConverter]::ToUInt16($bytes, $peOff + 6)
        $isDotNet = $false
        # .NET detection: optional header data directory entry 14 (CLI) nonzero
        $numDirsOff = $peOff + 24 + 92
        if ($bits -eq 32 -and $peOff + 24 + 96 + 14*8 + 4 -lt $len) {
            $cliRva = [BitConverter]::ToUInt32($bytes, $peOff + 24 + 96 + 14*8)
            if ($cliRva -ne 0) { $isDotNet = $true }
        } elseif ($bits -eq 64 -and $peOff + 24 + 112 + 14*8 + 4 -lt $len) {
            $cliRva = [BitConverter]::ToUInt32($bytes, $peOff + 24 + 112 + 14*8)
            if ($cliRva -ne 0) { $isDotNet = $true }
        }

        $result.Type = "PE $bits-bit $arch" + $(if ($isDotNet) { " (.NET managed)" } else { "" })
        $result.Extra += "Sections: $numSections"
        $result.Extra += "Optional header magic: 0x$($optMagic.ToString('X4'))"
    } else {
        $result.Type = "DOS MZ executable (16-bit real mode)"
    }
}
elseif (Match $bytes 0 @(0x7F,0x45,0x4C,0x46)) {
    $bits = if ($bytes[4] -eq 1) { 32 } else { 64 }
    $machine = [BitConverter]::ToUInt16($bytes, 0x12)
    $arch = switch ($machine) { 0x03 { "i386" } 0x3E { "x86-64" } 0x28 { "ARM" } 0xB7 { "ARM64" } default { "0x$($machine.ToString('X4'))" } }
    $result.Type = "ELF $bits-bit $arch"
}
elseif (Match $bytes 0 @(0xCF,0xFA,0xED,0xFE)) { $result.Type = "Mach-O 64-bit" }
elseif (Match $bytes 0 @(0xCE,0xFA,0xED,0xFE)) { $result.Type = "Mach-O 32-bit" }
elseif (Match $bytes 0 @(0xCA,0xFE,0xBA,0xBE)) { $result.Type = "Mach-O fat binary" }
elseif (Match $bytes 0 @(0xFE,0xED,0xFA,0xCE)) { $result.Type = "Mach-O 32-bit (big-endian)" }
elseif (Match $bytes 0 @(0xFE,0xED,0xFA,0xCF)) { $result.Type = "Mach-O 64-bit (big-endian)" }

# Java class
elseif (Match $bytes 0 @(0xCA,0xFE,0xBA,0xBE)) { $result.Type = "Java .class or Mach-O fat" }

# Scripts (shebang)
elseif (Match $bytes 0 @(0x23,0x21)) {
    $line = AsciiSafe $bytes 0 ([Math]::Min(120, $len))
    $result.Type = "Script: $line"
}

# Archives and containers
elseif (Match $bytes 0 @(0x50,0x4B,0x03,0x04)) { $result.Type = "ZIP archive (or JAR/APK/DOCX/XLSX/etc.)" }
elseif (Match $bytes 0 @(0x50,0x4B,0x05,0x06)) { $result.Type = "ZIP archive (empty)" }
elseif (Match $bytes 0 @(0x50,0x4B,0x07,0x08)) { $result.Type = "ZIP archive (spanned)" }
elseif (Match $bytes 0 @(0x1F,0x8B)) { $result.Type = "GZip stream" }
elseif (Match $bytes 0 @(0x42,0x5A,0x68)) { $result.Type = "BZip2 archive" }
elseif (Match $bytes 0 @(0xFD,0x37,0x7A,0x58,0x5A)) { $result.Type = "XZ compressed stream" }
elseif (Match $bytes 0 @(0x37,0x7A,0xBC,0xAF)) { $result.Type = "7-Zip archive" }
elseif (Match $bytes 0 @(0x52,0x61,0x72,0x21,0x1A,0x07)) { $result.Type = "RAR archive (v1.5-4.x)" }
elseif (Match $bytes 0 @(0x52,0x61,0x72,0x21,0x1A,0x07,0x01,0x00)) { $result.Type = "RAR archive (v5+)" }
elseif (Match $bytes 0 @(0x28,0x00,0x00,0x00) -and (Match $bytes 4 @(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))) { $result.Type = "Windows Installer (MSI) or CAB" }
elseif (Match $bytes 0 @(0x4D,0x53,0x43,0x46)) { $result.Type = "Microsoft CAB archive" }
elseif (Match $bytes 0 @(0x75,0x73,0x74,0x61,0x72)) { $result.Type = "tar archive (ustar)" }
elseif (Match $bytes 257 @(0x75,0x73,0x74,0x61,0x72)) { $result.Type = "tar archive" }
elseif (Match $bytes 0 @(0x7B)) { try { $j = [System.Text.Encoding]::UTF8.GetString($bytes[0..4095]) | ConvertFrom-Json; $result.Type = "JSON text" } catch { } }

# Filesystems
elseif (Match $bytes 0x438 @(0x53,0xEF)) { $result.Type = "ext2/ext3/ext4 filesystem" }
elseif (Match $bytes 3 @(0x4E,0x54,0x46,0x53)) { $result.Type = "NTFS filesystem" }
elseif (Match $bytes 3 @(0x4D,0x53,0x44,0x4F,0x53)) { $result.Type = "FAT12/16 filesystem" }
elseif (Match $bytes 3 @(0x46,0x41,0x54,0x33,0x32)) { $result.Type = "FAT32 filesystem" }
elseif (Match $bytes 0 @(0x53,0x51,0x4C,0x69,0x74,0x65,0x20,0x66,0x6F,0x72,0x6D,0x61,0x74,0x20,0x33,0x00)) { $result.Type = "SQLite 3 database" }

# Media
elseif (Match $bytes 0 @(0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A)) { $result.Type = "PNG image" }
elseif (Match $bytes 0 @(0xFF,0xD8,0xFF)) { $result.Type = "JPEG image" }
elseif (Match $bytes 0 @(0x47,0x49,0x46,0x38)) { $result.Type = "GIF image" }
elseif (Match $bytes 0 @(0x42,0x4D)) { $result.Type = "BMP image" }
elseif (Match $bytes 0 @(0x49,0x49,0x2A,0x00)) { $result.Type = "TIFF image (little-endian)" }
elseif (Match $bytes 0 @(0x4D,0x4D,0x00,0x2A)) { $result.Type = "TIFF image (big-endian)" }
elseif (Match $bytes 0 @(0x52,0x49,0x46,0x46)) {
    $subtype = AsciiSafe $bytes 8 4
    $result.Type = "RIFF container ($subtype)"  # WAVE, AVI, WEBP, etc.
}
elseif (Match $bytes 0 @(0x66,0x4C,0x61,0x43)) { $result.Type = "FLAC audio" }
elseif (Match $bytes 0 @(0x49,0x44,0x33) -or (Match $bytes 0 @(0xFF,0xFB))) { $result.Type = "MP3 audio" }
elseif (Match $bytes 4 @(0x66,0x74,0x79,0x70)) { $result.Type = "ISO Base Media (MP4/MOV/M4A)" }
elseif (Match $bytes 0 @(0x1A,0x45,0xDF,0xA3)) { $result.Type = "Matroska / WebM video" }
elseif (Match $bytes 0 @(0x4F,0x67,0x67,0x53)) { $result.Type = "Ogg container" }
elseif (Match $bytes 0 @(0x00,0x00,0x01,0xBA) -or (Match $bytes 0 @(0x00,0x00,0x01,0xB3))) { $result.Type = "MPEG program stream" }

# Documents
elseif (Match $bytes 0 @(0x25,0x50,0x44,0x46)) { $result.Type = "PDF document" }
elseif (Match $bytes 0 @(0xD0,0xCF,0x11,0xE0)) { $result.Type = "OLE2 compound document (DOC/XLS/PPT legacy)" }
elseif (Match $bytes 0 @(0x7B,0x5C,0x72,0x74,0x66)) { $result.Type = "RTF document" }

# Crypto / encoding
elseif (Match $bytes 0 @(0x2D,0x2D,0x2D,0x2D,0x2D,0x42,0x45,0x47,0x49,0x4E)) { $result.Type = "PEM-encoded crypto" }
elseif (Match $bytes 0 @(0x30,0x82)) { $result.Type = "DER-encoded ASN.1 (possibly X.509 or PKCS)" }
elseif (Match $bytes 0 @(0x53,0x61,0x6C,0x74,0x65,0x64,0x5F,0x5F)) { $result.Type = "OpenSSL salted encrypted data" }

# Cryptocurrency / databases
elseif (Match $bytes 0 @(0xF9,0xBE,0xB4,0xD9)) { $result.Type = "Bitcoin blockchain data" }
elseif (Match $bytes 0 @(0x00,0x61,0x73,0x6D)) { $result.Type = "WebAssembly binary (.wasm)" }
elseif (Match $bytes 0 @(0x00,0x61,0x73,0x6D,0x01,0x00,0x00,0x00)) { $result.Type = "WebAssembly binary v1 (.wasm)" }

# Fallback: hex/ASCII dump hint
if ($result.Type -eq "unknown") {
    $result.Type = "unknown (see hex dump)"
}

# --- Output --------------------------------------------------------------
Write-Host ""
Write-Host "=== File Type ===" -ForegroundColor Cyan
Write-Host "  Path:  $($item.FullName)"
Write-Host "  Size:  $('{0:N0}' -f $len) bytes"
Write-Host "  Type:  $($result.Type)" -ForegroundColor Green
foreach ($x in $result.Extra) {
    Write-Host "         $x"
}

if ($Detailed) {
    Write-Host ""
    Write-Host "=== First 64 bytes ===" -ForegroundColor Cyan
    Write-Host "  Hex:   $(Hex $bytes 0 ([Math]::Min(64, $len)))"
    Write-Host "  ASCII: $(AsciiSafe $bytes 0 ([Math]::Min(64, $len)))"
}

# Check for the FCExporter magic as a bonus
Write-Host ""
if ($bytes.Length -ge 4) {
    $head = [BitConverter]::ToUInt32($bytes, 0)
    if ($head -eq 0xD3010401) {
        Write-Host "  [+] File has FCExporter/Crypto++ archive magic (0xD3010401)!" -ForegroundColor Yellow
    }
}

Write-Host ""