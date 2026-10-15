@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Calman 5 for Business 5.17.6.7 - offline Ultimate license patch

REM ============================================================================
REM  Calman 5 for Business 5.17.6.7 - permanent offline Calman Ultimate license
REM
REM  In-place byte edits (two files). Only method bodies change, no metadata is
REM  rewritten, file sizes stay identical. Pristine copies are kept next to each
REM  file as <name>.orig
REM
REM  Offsets are specific to build 5.17.6.7. The 5.17.5.3 script is a separate
REM  file (calman-ultimate-patch.bat). Every edit verifies the original bytes
REM  first and only writes when they match, so aiming the wrong script at the
REM  wrong build stops with a message instead of corrupting anything.
REM
REM  STAGE 1 - CalMAN_Workflow.dll (managed licensing)
REM
REM  1a) CalMAN_Workflow.LicenseDescription::get_Value()
REM      file offset 0x00046A47
REM      tiny IL header (code size 7) + ldarg.0 / ldfld 0x0400089D / ret
REM      becomes
REM      tiny IL header (code size 3) + ldc.i4.s 81 / ret
REM      Every LicenseDescription then reports catalog value 81, so
REM      GetActiveLicensePermissions and SetBaseLicense resolve the permission
REM      set and the base license from "Calman Ultimate for Business".
REM      (5.17.5.3 had the same body at 0x467B7 with field token 0x0400089A.)
REM
REM  1b) CalMAN_Workflow.ApplicationLicensing::SiteLicense()
REM      file offset 0x00044884
REM      fat IL header (flags 0x301B, maxstack 5, code size 0x228)
REM      becomes
REM      tiny IL header (code size 2) + ldc.i4.1 / ret
REM      returns true, so the constructor and RefreshLicenses() take the
REM      site-license early-out and never reach LicenseWrapper.Validate() /
REM      RefreshLicense() / ClearAllLicenses() / ClearRegistryKeys().
REM
REM  STAGE 2 - Common\calmanv5.dll (native per-item license gates)
REM
REM  Each gate walks Config\cat01.cff as
REM      FeaturesRoot -> License[Value=..] -> <Section> -> <Item>[Value=..] -> Enabled
REM  Stage 1 only changes the managed view of the license, so the native gates
REM  keep answering "no" and CalMAN logs, for every instrument,
REM      Error: 26 - ERR_LICENSE_METER: Meter license not found;
REM      Defaulting to Simulated meter
REM  Gate entry points are replaced by   mov eax,1 ; retn 8:
REM
REM  2a) Meters   RVA 0x0043B530  (file 0x0043A930)  prologue 55 8B EC 81 EC 08 01 00 00
REM  2b) Sources  RVA 0x0043C300  (file 0x0043B700)  prologue 55 8B EC 81 EC 0C 01 00 00
REM  2c) Displays RVA 0x00438FC0  (file 0x004383C0)  prologue 55 8B EC 81 EC 0C 01 00 00
REM      (its debug message says "SourceLicense" - copy/paste in the vendor's
REM       code; the XML elements it reads are Displays/Display)
REM
REM  Untouched on purpose: the catalog integrity check that compares
REM  FeaturesRoot/@Version with "5.25.1".
REM
REM  Stages are independent and each edit is checked separately: already patched
REM  edits are skipped, the remaining ones are still applied.
REM
REM  Usage:  calman-ultimate-patch-5.17.6.7.bat            apply (all stages)
REM          calman-ultimate-patch-5.17.6.7.bat restore    roll back from .orig
REM          calman-ultimate-patch-5.17.6.7.bat ?          usage
REM
REM  Set CALMAN_DIR to patch an installation in a non-default location
REM  (e.g. a copy extracted with: msiexec /a Calman_Business.msi /qn TARGETDIR=...).
REM ============================================================================

net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

set "CALMAN_ARG=%~1"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=[IO.File]::ReadAllText('%~f0');$s=$s.Substring($s.LastIndexOf('#PS#'));Invoke-Expression $s"
set "RC=%ERRORLEVEL%"
echo.
pause
exit /b %RC%

REM #PS#
$ErrorActionPreference = 'Stop'

$dir = $env:CALMAN_DIR
if (-not $dir) { $dir = 'C:\Program Files (x86)\Portrait Displays\Calman 5 for Business' }

# build fingerprint of 5.17.6.7 - only a warning, the byte signatures decide
$expectedSizes = @{ 'CalMAN_Workflow.dll' = 984240; 'Common\calmanv5.dll' = 12719280 }

function File-Hash([string]$path) {
    # Get-FileHash lives in Microsoft.PowerShell.Utility, which is not always
    # loadable (seen on stripped PowerShell hosts: "Get-FileHash is not
    # recognized"). Use the crypto API directly instead.
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $fs = [IO.File]::OpenRead($path)
        try { return [BitConverter]::ToString($sha.ComputeHash($fs)) } finally { $fs.Dispose() }
    } finally { $sha.Dispose() }
}

function Match([byte[]]$buf, [int]$off, [byte[]]$sig) {
    if ($off -lt 0 -or $off + $sig.Length -gt $buf.Length) { return $false }
    for ($i = 0; $i -lt $sig.Length; $i++) { if ($buf[$off + $i] -ne $sig[$i]) { return $false } }
    return $true
}

function Get-PeFileOffset([byte[]]$buf, [uint32]$va) {
    $e       = [BitConverter]::ToInt32($buf, 0x3C)
    $nsec    = [BitConverter]::ToUInt16($buf, $e + 6)
    $optSize = [BitConverter]::ToUInt16($buf, $e + 20)
    $secTab  = $e + 24 + $optSize
    $imgBase = [BitConverter]::ToUInt32($buf, $e + 24 + 28)
    $rva     = [uint32]($va - $imgBase)
    for ($i = 0; $i -lt $nsec; $i++) {
        $o     = $secTab + 40 * $i
        $vsize = [BitConverter]::ToUInt32($buf, $o + 8)
        $sva   = [BitConverter]::ToUInt32($buf, $o + 12)
        $rsize = [BitConverter]::ToUInt32($buf, $o + 16)
        $raw   = [BitConverter]::ToUInt32($buf, $o + 20)
        if ($rva -ge $sva -and $rva -lt ($sva + [Math]::Max($vsize, $rsize))) {
            return [int]($raw + ($rva - $sva))
        }
    }
    return -1
}

# ---------------------------------------------------------------------------
# STAGE 1: CalMAN_Workflow.dll, method-body edits at fixed file offsets
# ---------------------------------------------------------------------------
$stage1 = @{
    Title   = 'license (CalMAN_Workflow.dll)'
    RelPath = 'CalMAN_Workflow.dll'
    Patches = @(
        [pscustomobject]@{
            Name = 'LicenseDescription::get_Value'
            Off  = 0x00046A47
            Rva  = [uint32]0
            Orig = [byte[]](0x1E,0x02,0x7B,0x9D,0x08,0x00,0x04,0x2A)
            New  = [byte[]](0x0E,0x1F,0x51,0x2A)
            Note = 'now returns 81 (Calman Ultimate for Business)'
        }
        [pscustomobject]@{
            Name = 'ApplicationLicensing::SiteLicense'
            Off  = 0x00044884
            Rva  = [uint32]0
            Orig = [byte[]](0x1B,0x30,0x05,0x00,0x28,0x02,0x00,0x00)
            New  = [byte[]](0x0A,0x17,0x2A)
            Note = 'now returns true (skips online validation)'
        }
    )
}

# ---------------------------------------------------------------------------
# STAGE 2: Common\calmanv5.dll, native per-item license gates
#   entry: push ebp; mov ebp,esp; sub esp,10[8|c]h  ->  mov eax,1 ; retn 8
# ---------------------------------------------------------------------------
$gateNew = [byte[]](0xB8,0x01,0x00,0x00,0x00,0xC2,0x08,0x00)
$stage2 = @{
    Title   = 'item licenses (Common\calmanv5.dll)'
    RelPath = 'Common\calmanv5.dll'
    Patches = @(
        [pscustomobject]@{
            Name = 'Meters gate'
            Off  = -1
            Rva  = [uint32]0x1043B530
            Orig = [byte[]](0x55,0x8B,0xEC,0x81,0xEC,0x08,0x01,0x00,0x00)
            New  = $gateNew
            Note = 'every meter licensed (ERR_LICENSE_METER gone)'
        }
        [pscustomobject]@{
            Name = 'Sources gate'
            Off  = -1
            Rva  = [uint32]0x1043C300
            Orig = [byte[]](0x55,0x8B,0xEC,0x81,0xEC,0x0C,0x01,0x00,0x00)
            New  = $gateNew
            Note = 'every source licensed'
        }
        [pscustomobject]@{
            Name = 'Displays gate'
            Off  = -1
            Rva  = [uint32]0x10438FC0
            Orig = [byte[]](0x55,0x8B,0xEC,0x81,0xEC,0x0C,0x01,0x00,0x00)
            New  = $gateNew
            Note = 'every display licensed'
        }
    )
}

$mode = 'patch'
if ($env:CALMAN_ARG) { $mode = $env:CALMAN_ARG.Trim().ToLowerInvariant() }
if ($mode -eq '?') { Write-Host 'usage: calman-ultimate-patch-5.17.6.7.bat [patch | restore | ?]'; exit 0 }

Write-Host "Calman 5.17.6.7 licensing patch - mode: $mode" -ForegroundColor Cyan
Write-Host "Target: $dir"
if (-not (Test-Path -LiteralPath $dir)) { Write-Host 'ERROR: Calman installation not found (set CALMAN_DIR).' -ForegroundColor Red; exit 2 }

function Get-BackupPath([string]$dll) {
    $b = "$dll.orig"
    if (Test-Path -LiteralPath $b) { return $b }
    return $b
}

function Stop-Calman {
    $running = @(Get-Process -ErrorAction SilentlyContinue |
                 Where-Object { $_.ProcessName -like 'Calman*' -or $_.ProcessName -like 'CalMAN*' })
    if ($running.Count -gt 0) {
        Write-Host ('  closing running Calman: ' + (($running | ForEach-Object { $_.ProcessName }) -join ', ')) -ForegroundColor Yellow
        $running | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
}

if ($mode -eq 'restore') {
    foreach ($stage in @($stage1, $stage2)) {
        $dll = Join-Path $dir $stage.RelPath
        Write-Host ("-- restoring " + $stage.Title) -ForegroundColor Cyan
        if (-not (Test-Path -LiteralPath $dll)) { Write-Host ('  not found: ' + $dll) -ForegroundColor Yellow; continue }
        $bak = Get-BackupPath $dll
        if (-not (Test-Path -LiteralPath $bak)) { Write-Host '  no backup, skipped' -ForegroundColor Yellow; continue }
        if ((File-Hash $dll) -eq (File-Hash $bak)) {
            Write-Host '  already original' -ForegroundColor Green
            continue
        }
        Stop-Calman
        try { Copy-Item -LiteralPath $bak -Destination $dll -Force } catch {
            Write-Host '  file is LOCKED - close Calman and any debugger, then rerun' -ForegroundColor Red
            exit 1
        }
        Write-Host ('  restored from ' + (Split-Path $bak -Leaf)) -ForegroundColor Green
    }
    Write-Host ''
    Write-Host 'Rollback done. Start Calman to verify.' -ForegroundColor Green
    exit 0
}

$exitCode = 0
foreach ($stage in @($stage1, $stage2)) {
    $dll = Join-Path $dir $stage.RelPath
    Write-Host ("== " + $stage.Title) -ForegroundColor Cyan
    Write-Host ("   file: " + $dll)
    if (-not (Test-Path -LiteralPath $dll)) {
        Write-Host '   missing file, skipped' -ForegroundColor Yellow
        $exitCode = 2
        continue
    }
    $size = (Get-Item -LiteralPath $dll).Length
    if ($expectedSizes.ContainsKey($stage.RelPath) -and $size -ne $expectedSizes[$stage.RelPath]) {
        Write-Host ("   WARNING: size $size, expected " + $expectedSizes[$stage.RelPath] + " for 5.17.6.7") -ForegroundColor Yellow
    }

    $buf = [IO.File]::ReadAllBytes($dll)
    foreach ($p in $stage.Patches) {
        if ($p.Rva -ne [uint32]0) { $p.Off = Get-PeFileOffset $buf $p.Rva }
    }

    $todo   = @()
    $broken = @()
    $done   = @()
    foreach ($p in $stage.Patches) {
        if (Match $buf $p.Off $p.New)   { $done   += $p; continue }
        if (Match $buf $p.Off $p.Orig)  { $todo   += $p; continue }
        $broken += $p
    }
    foreach ($p in $done) { Write-Host ("   {0} : already patched" -f $p.Name) -ForegroundColor Gray }
    foreach ($p in $broken) {
        Write-Host ("   {0} : unexpected bytes at 0x{1:X} - not the 5.17.6.7 build?" -f $p.Name, $p.Off) -ForegroundColor Red
        $exitCode = 1
    }
    if ($todo.Count -eq 0) {
        if ($done.Count -eq $stage.Patches.Count) { Write-Host '   stage complete, next stage' -ForegroundColor Green }
        continue
    }

    $bak = Get-BackupPath $dll
    if (-not (Test-Path -LiteralPath $bak)) {
        $fullyFresh = ($todo.Count -eq $stage.Patches.Count)
        if ($fullyFresh) {
            Copy-Item -LiteralPath $dll -Destination $bak -Force
            Write-Host ('   backup: ' + (Split-Path $bak -Leaf)) -ForegroundColor Gray
        } else {
            Write-Host '   WARNING: no pristine backup and the file is partially patched' -ForegroundColor Yellow
            Write-Host '            (a backup is created only from a fully original file)' -ForegroundColor Yellow
        }
    }

    Stop-Calman

    try {
        $fs = [IO.File]::Open($dll, 'Open', 'ReadWrite', 'None')
        try {
            foreach ($p in $todo) { $fs.Position = $p.Off; $fs.Write($p.New, 0, $p.New.Length) }
        } finally { $fs.Dispose() }
    } catch {
        Write-Host '   file is LOCKED - close Calman and any debugger, then rerun' -ForegroundColor Red
        exit 1
    }

    $buf = [IO.File]::ReadAllBytes($dll)
    foreach ($p in $stage.Patches) {
        if (Match $buf $p.Off $p.New) { Write-Host ("   {0} : {1}" -f $p.Name, $p.Note) -ForegroundColor Green }
        else { Write-Host ("   {0} : VERIFY FAILED" -f $p.Name) -ForegroundColor Red; $exitCode = 1 }
    }
}

Write-Host ''
if ($exitCode -ne 0) { Write-Host 'FAILED - see messages above.' -ForegroundColor Red; exit $exitCode }
Write-Host 'Done. Start Calman: header should read "Calman Ultimate for Business",' -ForegroundColor Green
Write-Host 'no instrument should fall back to "Simulated meter", meters/sources/displays' -ForegroundColor Green
Write-Host 'should no longer report missing licenses.' -ForegroundColor Green
exit 0
