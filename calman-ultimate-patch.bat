@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Calman 5 for Business - offline Ultimate license patch

REM ============================================================================
REM  Calman 5 for Business 5.17.5.3 - permanent offline Calman Ultimate license
REM
REM  In-place byte edits (two files). Only method bodies change, no metadata is
REM  rewritten, file sizes stay identical. Pristine copies are kept next to each
REM  file as <name>.orig
REM
REM  STAGE 1 - CalMAN_Workflow.dll (managed licensing)
REM
REM  1a) CalMAN_Workflow.LicenseDescription::get_Value()
REM      file offset 0x000467B7   ldarg.0 / ldfld / ret   becomes   ldc.i4.s 81 / ret
REM      Every LicenseDescription then reports catalog value 81, so
REM      GetActiveLicensePermissions and SetBaseLicense resolve the permission
REM      set and the base license from "Calman Ultimate for Business".
REM      The activation prompt disappears with it: the native enumeration returns
REM      "000000,0", which resolves to the catalog entry Value="0" / Key="EVAL" /
REM      IsEval="true" ("Calman Trial Evaluation"), and that is what used to set
REM      LicensePermissions.IsEval. Value 81 carries IsEval="false".
REM
REM  1b) CalMAN_Workflow.ApplicationLicensing::SiteLicense()
REM      file offset 0x000444DC   fat header replaced by a 2 byte tiny header
REM      returns true, so the constructor and RefreshLicenses() take the
REM      site-license early-out and never reach LicenseWrapper.Validate() /
REM      RefreshLicense() / ClearAllLicenses() / ClearRegistryKeys().
REM
REM  STAGE 2 - Common\calmanv5.dll (native per-item license gates)
REM
REM  Each gate opens Config\cat01.cff and answers "is this item enabled under
REM  license <value>" by walking
REM      FeaturesRoot -> License[Value=..] -> <Section> -> <Item>[Value=..] -> Enabled
REM  Stage 1 only changes the *managed* view of the license, so the native
REM  resolver kept answering "no" and CalMAN logged, for every meter,
REM      Error: 26 - ERR_LICENSE_METER: Meter license not found;
REM      Defaulting to Simulated meter
REM  (meters shown in red / falling back to the simulated meter). The three gate
REM  entry points are replaced by    mov eax,1 ; retn 8   so every item reports
REM  as enabled:
REM
REM  2a) sub_1043B4F0  RVA 0x0043B4F0  Meters   -> Meter   [Value].Enabled
REM  2b) sub_1043C2C0  RVA 0x0043C2C0  Sources  -> Source  [Value].Enabled
REM  2c) sub_10438F80  RVA 0x00438F80  Displays -> Display [Value].Enabled
REM      (its debug message says "SourceLicense" - copy/paste in the vendor's
REM       code; the XML elements it reads are Displays/Display)
REM
REM  Untouched on purpose: sub_1043C400 (RVA 0x0043C400) validates
REM  FeaturesRoot/@Version against "5.25.1" - the catalog integrity check.
REM
REM  Stages are independent and each edit is checked separately: already patched
REM  edits are skipped, the remaining ones are still applied. Nothing is written
REM  when everything is already in place.
REM
REM  Usage:  calman-ultimate-patch.bat            apply (all stages)
REM          calman-ultimate-patch.bat restore    roll back from the .orig files
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
$dir = 'C:\Program Files (x86)\Portrait Displays\Calman 5 for Business'

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
            Off  = 0x000467B7
            Rva  = [uint32]0
            Orig = [byte[]](0x1E,0x02,0x7B,0x9A,0x08,0x00,0x04,0x2A)
            New  = [byte[]](0x0E,0x1F,0x51,0x2A)
            Note = 'now returns 81 (Calman Ultimate for Business)'
        }
        [pscustomobject]@{
            Name = 'ApplicationLicensing::SiteLicense'
            Off  = 0x000444DC
            Rva  = [uint32]0
            Orig = [byte[]](0x1B,0x30,0x05,0x00,0xF9,0x00,0x00,0x00)
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
            Name = 'sub_1043B4F0 - Meters'
            Off  = -1
            Rva  = [uint32]0x1043B4F0
            Orig = [byte[]](0x55,0x8B,0xEC,0x81,0xEC,0x08,0x01,0x00,0x00)
            New  = $gateNew
            Note = 'every meter licensed (ERR_LICENSE_METER gone)'
        }
        [pscustomobject]@{
            Name = 'sub_1043C2C0 - Sources'
            Off  = -1
            Rva  = [uint32]0x1043C2C0
            Orig = [byte[]](0x55,0x8B,0xEC,0x81,0xEC,0x0C,0x01,0x00,0x00)
            New  = $gateNew
            Note = 'every source licensed'
        }
        [pscustomobject]@{
            Name = 'sub_10438F80 - Displays'
            Off  = -1
            Rva  = [uint32]0x10438F80
            Orig = [byte[]](0x55,0x8B,0xEC,0x81,0xEC,0x0C,0x01,0x00,0x00)
            New  = $gateNew
            Note = 'every display licensed'
        }
    )
}

$mode = 'patch'
if ($env:CALMAN_ARG) { $mode = $env:CALMAN_ARG.Trim().ToLowerInvariant() }
if ($mode -eq '?') { Write-Host 'usage: calman-ultimate-patch.bat [patch | restore]'; exit 0 }

Write-Host "Calman licensing patch - mode: $mode" -ForegroundColor Cyan
Write-Host "Target: $dir"
if (-not (Test-Path -LiteralPath $dir)) { Write-Host 'ERROR: Calman installation not found.' -ForegroundColor Red; exit 2 }

function Get-BackupPath([string]$dll) {
    $b = "$dll.orig"
    if (Test-Path -LiteralPath $b) { return $b }
    foreach ($alt in @("$dll.orig-before-meter-patch", "$dll.orig-before-item-patch")) {
        if (Test-Path -LiteralPath $alt) { return $alt }
    }
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

    $buf = [IO.File]::ReadAllBytes($dll)
    foreach ($p in $stage.Patches) {
        if ($p.Rva -ne [uint32]0) { $p.Off = Get-PeFileOffset $buf $p.Rva }
    }

    # per-edit decision: already done / ready to patch / unexpected bytes
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
        Write-Host ("   {0} : unexpected bytes at 0x{1:X} - not the 5.17.5.3 build?" -f $p.Name, $p.Off) -ForegroundColor Red
        $exitCode = 1
    }
    if ($todo.Count -eq 0) {
        if ($done.Count -eq $stage.Patches.Count) { Write-Host '   stage complete, next stage' -ForegroundColor Green }
        continue
    }

    # backup: only a fully original file may become the canonical .orig
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
Write-Host 'no meter should fall back to "Simulated meter", sources and displays' -ForegroundColor Green
Write-Host 'should no longer report missing licenses.' -ForegroundColor Green
exit 0
