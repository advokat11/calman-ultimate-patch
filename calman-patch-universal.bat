@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Calman universal license patch (any build with the same shape)

REM ============================================================================
REM  Calman universal license patch - no per-version offsets.
REM
REM  Targets are located from the files themselves:
REM    managed  CalMAN_Workflow.dll : .NET metadata (ECMA-335)
REM      * type LicenseDescription   -> method get_Value   -> body 1E 02 7B .. .. .. .. 2A
REM      * type ApplicationLicensing -> method SiteLicense -> fat header 1B 30 .. ..
REM    native   Common\calmanv5.dll : xrefs to the licensing debug strings
REM      * "XML MeterLicense failed, pXMLDoc_FEATURES"  -> meters gate
REM      * "XML SourceLicense failed, pXMLDoc_FEATURES" -> sources / displays gate
REM        (classified by the XML element literal each one pushes)
REM
REM  Tested against 5.17.4.16, 5.17.5.3 and 5.17.6.7. Every edit verifies the
REM  original bytes first; a target that cannot be located or does not match is
REM  reported and skipped, never guessed. Backups are <file>.orig
REM
REM  Usage:  calman-patch-universal.bat            apply
REM          calman-patch-universal.bat restore    roll back from .orig
REM          calman-patch-universal.bat ?          usage
REM
REM  CALMAN_DIR overrides the install path (for a copy extracted from the MSI).
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
$Mode = if ($env:CALMAN_ARG) { $env:CALMAN_ARG.Trim().ToLowerInvariant() } else { 'patch' }
$ErrorActionPreference = 'Stop'
$enc = [Text.Encoding]::GetEncoding(28591)   # byte <-> char, 1:1

$root = $env:CALMAN_DIR
if (-not $root) { $root = 'C:\Program Files (x86)\Portrait Displays\Calman 5 for Business' }
if ($Mode -eq '?') { Write-Host 'usage: patch.ps1 [patch|restore]  (CALMAN_DIR overrides the install path)'; exit 0 }

# ---------------------------------------------------------------- PE helpers
function Get-PeInfo([byte[]]$b) {
    $pe = [BitConverter]::ToInt32($b, 0x3C)
    $nsec = [BitConverter]::ToUInt16($b, $pe + 6)
    $optSize = [BitConverter]::ToUInt16($b, $pe + 20)
    $magic = [BitConverter]::ToUInt16($b, $pe + 24)
    $base = [BitConverter]::ToUInt32($b, $pe + 24 + 28)
    $st = $pe + 24 + $optSize
    $secs = @()
    for ($i = 0; $i -lt $nsec; $i++) {
        $o = $st + 40 * $i
        $secs += [pscustomobject]@{
            Name = $enc.GetString($b, $o, 8).TrimEnd([char]0)
            VS   = [BitConverter]::ToUInt32($b, $o + 8)
            VA   = [BitConverter]::ToUInt32($b, $o + 12)
            RS   = [BitConverter]::ToUInt32($b, $o + 16)
            RA   = [BitConverter]::ToUInt32($b, $o + 20)
        }
    }
    return [pscustomobject]@{ PE = $pe; OptSize = $optSize; Magic = $magic; Base = $base; Sections = $secs }
}

function RvaToOff($pe, [uint32]$rva) {
    foreach ($s in $pe.Sections) {
        if ($rva -ge $s.VA -and $rva -lt ($s.VA + [Math]::Max($s.VS, $s.RS))) { return [int]($s.RA + ($rva - $s.VA)) }
    }
    return -1
}

function OffToVa($pe, [int]$off) {
    foreach ($s in $pe.Sections) {
        if ($off -ge $s.RA -and $off -lt ($s.RA + $s.RS)) { return [uint32]($pe.Base + $s.VA + ($off - $s.RA)) }
    }
    return [uint32]0
}

function Test-Bytes([byte[]]$b, [int]$off, [byte[]]$sig) {
    if ($off -lt 0 -or $off + $sig.Length -gt $b.Length) { return $false }
    for ($i = 0; $i -lt $sig.Length; $i++) { if ($b[$off + $i] -ne $sig[$i]) { return $false } }
    return $true
}

# ---------------------------------------------------------------- .NET metadata
function Get-MetaInfo([byte[]]$b, $pe) {
    $dd = $pe.PE + 24 + $(if ($pe.Magic -eq 0x10B) { 96 } else { 112 })
    $cmdOff = RvaToOff $pe ([BitConverter]::ToUInt32($b, $dd + 14 * 8))
    $mdOff = RvaToOff $pe ([BitConverter]::ToUInt32($b, $cmdOff + 8))
    $vlen = [BitConverter]::ToUInt32($b, $mdOff + 12)
    $p = $mdOff + 16 + $vlen + 2
    $nstreams = [BitConverter]::ToUInt16($b, $p); $p += 2
    $streams = @{}
    for ($i = 0; $i -lt $nstreams; $i++) {
        $off = [BitConverter]::ToUInt32($b, $p); $size = [BitConverter]::ToUInt32($b, $p + 4); $p += 8
        $name = ''
        while ($b[$p] -ne 0) { $name += [char]$b[$p]; $p++ }
        $p++
        $p = ($p + 3) -band (-bnot 3)
        $streams[$name] = @([int]($mdOff + $off), [int]$size)
    }
    $tblOff = $streams['#~'][0]
    $strOff = $streams['#Strings'][0]
    $heapSizes = $b[$tblOff + 6]
    $valid = [BitConverter]::ToUInt64($b, $tblOff + 8)
    $bits = [Convert]::ToString($valid, 2).PadLeft(64, '0')
    $present = @{}
    $p = $tblOff + 24
    for ($t = 0; $t -lt 64; $t++) {
        if ($bits[63 - $t] -eq '1') { $present[$t] = [BitConverter]::ToUInt32($b, $p); $p += 4 }
    }
    $strIdx = if ($heapSizes -band 1) { 4 } else { 2 }
    $blobIdx = if ($heapSizes -band 4) { 4 } else { 2 }
    $guidIdx = if ($heapSizes -band 2) { 4 } else { 2 }
    $simple = { param($t) if ($present.ContainsKey($t) -and $present[$t] -ge 0x10000) { 4 } else { 2 } }
    $coded = {
        param($tabs)
        $nbits = 0; while ((1 -shl $nbits) -lt $tabs.Count) { $nbits++ }
        $max = 0
        foreach ($t in $tabs) { if ($present.ContainsKey($t) -and $present[$t] -gt $max) { $max = $present[$t] } }
        if ($max -ge [Math]::Pow(2, 16 - $nbits)) { 4 } else { 2 }
    }
    $typeDefOrRef = & $coded @(0x02, 0x01, 0x1B)
    $resolutionScope = & $coded @(0x00, 0x02, 0x01, 0x1A)
    $fieldIdx = & $simple 0x04
    $methodIdx = & $simple 0x06
    $paramIdx = & $simple 0x08
    $rowSizes = @{
        0x00 = 2 + $strIdx + 3 * $guidIdx
        0x01 = $resolutionScope + 2 * $strIdx
        0x02 = 4 + 2 * $strIdx + $typeDefOrRef + $fieldIdx + $methodIdx
        0x03 = $fieldIdx
        0x04 = 2 + $strIdx + $blobIdx
        0x05 = $methodIdx
        0x06 = 4 + 2 + 2 + $strIdx + $blobIdx + $paramIdx
    }
    $tables = @{}
    $q = $tblOff + 24 + 4 * ($present.Keys.Count)
    for ($t = 0; $t -lt 64; $t++) {
        if (-not $present.ContainsKey($t)) { continue }
        $tables[$t] = @($q, $present[$t], $(if ($rowSizes.ContainsKey($t)) { [int]$rowSizes[$t] } else { $null }))
        if ($rowSizes.ContainsKey($t)) { $q += [int]$rowSizes[$t] * $present[$t] }
    }
    return [pscustomobject]@{
        TblOff = $tblOff; StrOff = $strOff; StrIdx = $strIdx
        Tables = $tables; FieldIdx = $fieldIdx; MethodIdx = $methodIdx
    }
}

function Get-CString([byte[]]$b, [int]$off) {
    $e = $off
    while ($b[$e] -ne 0) { $e++ }
    return $enc.GetString($b, $off, $e - $off)
}

function Read-Index([byte[]]$b, [int]$off, [int]$width) {
    if ($width -eq 4) { return [int][BitConverter]::ToUInt32($b, $off) }
    return [int][BitConverter]::ToUInt16($b, $off)
}

function Find-ManagedTargets([byte[]]$b) {
    $pe = Get-PeInfo $b
    $meta = Get-MetaInfo $b $pe
    $strOff = $meta.StrOff; $strIdx = $meta.StrIdx
    $toff, $tcnt, $tsize = $meta.Tables[0x02]
    $moff, $mcnt, $msz = $meta.Tables[0x06]
    $types = @{}
    for ($i = 0; $i -lt $tcnt; $i++) {
        $o = $toff + $i * $tsize
        $nm = Get-CString $b ($strOff + (Read-Index $b ($o + 4) $strIdx))
        $ml = Read-Index $b ($o + 4 + 2 * $strIdx + 2 + $meta.FieldIdx) $meta.MethodIdx
        $types[$nm] = $ml
    }
    $methods = @{}
    for ($i = 0; $i -lt $mcnt; $i++) {
        $o = $moff + $i * $msz
        $rva = [BitConverter]::ToUInt32($b, $o)
        $nm = Get-CString $b ($strOff + (Read-Index $b ($o + 8) $strIdx))
        $methods[$i + 1] = @($nm, $rva)
    }
    # method lists are ranges over 1-based row indexes: rebuild the ordered name list
    $ordered = @()
    for ($i = 1; $i -le $mcnt; $i++) { $ordered += $methods[$i][0] }
    $result = @{}
    foreach ($pair in @(@('LicenseDescription', 'get_Value'), @('ApplicationLicensing', 'SiteLicense'))) {
        $type = $pair[0]; $meth = $pair[1]
        if (-not $types.ContainsKey($type)) { continue }
        $start = $types[$type]
        $ends = @($types.Keys | Where-Object { $types[$_] -gt $start } | ForEach-Object { $types[$_] } | Sort-Object)
        $end = if ($ends.Count -gt 0) { $ends[0] } else { $mcnt + 1 }
        for ($row = $start; $row -lt $end; $row++) {
            if ($ordered[$row - 1] -eq $meth) {
                $rva = $methods[$row][1]
                if ($rva -ne 0) {
                    $fo = RvaToOff $pe $rva
                    $result["$type.$meth"] = $fo
                }
                break
            }
        }
    }
    return [pscustomobject]@{ Targets = $result; Pe = $pe }
}

# ---------------------------------------------------------------- native gates
function Find-NativeGates([byte[]]$b) {
    $pe = Get-PeInfo $b
    $text = $pe.Sections | Where-Object { $_.Name -eq '.text' } | Select-Object -First 1
    $traw = [int]$text.RA; $trs = [int]$text.RS
    $code = $enc.GetString($b, $traw, $trs)
    $found = @{}
    foreach ($anchor in @(
            @('meters', 'XML MeterLicense failed, pXMLDoc_FEATURES'),
            @('other', 'XML SourceLicense failed, pXMLDoc_FEATURES'))) {
        $so = $enc.GetString($b).IndexOf($anchor[1] + [char]0)
        if ($so -lt 0) { continue }
        $sva = OffToVa $pe $so
        $pushBytes = [byte[]]@(0x68) + [BitConverter]::GetBytes([uint32]$sva)
        $pushStr = $enc.GetString($pushBytes)
        $pos = $code.IndexOf($pushStr)
        while ($pos -ge 0) {
            $e = $traw + $pos
            $start = -1
            for ($i = $e - 1; $i -gt [Math]::Max($e - 6000, $traw); $i--) {
                # pristine gate entry: push ebp; mov ebp,esp; sub esp,10[8|c]h
                if ($b[$i] -eq 0x55 -and $b[$i + 1] -eq 0x8B -and $b[$i + 2] -eq 0xEC -and
                    $b[$i + 3] -eq 0x81 -and $b[$i + 4] -eq 0xEC) { $start = $i; break }
                # already patched entry: mov eax,1 ; retn 8
                if ($b[$i] -eq 0xB8 -and $b[$i + 1] -eq 0x01 -and $b[$i + 2] -eq 0 -and $b[$i + 3] -eq 0 -and
                    $b[$i + 4] -eq 0 -and $b[$i + 5] -eq 0xC2 -and $b[$i + 6] -eq 0x08 -and $b[$i + 7] -eq 0) { $start = $i; break }
            }
            if ($start -ge 0) {
                $body = $enc.GetString($b, $start, [Math]::Min(4000, $b.Length - $start))
                $kind = $null
                foreach ($el in @('Meters', 'Sources', 'Displays')) {
                    $o = 0
                    while (($o = $enc.GetString($b).IndexOf($el + [char]0, $o)) -ge 0) {
                        $va = OffToVa $pe $o
                        if ($va -ne 0) {
                            $needle = $enc.GetString([byte[]]@(0x68) + [BitConverter]::GetBytes([uint32]$va))
                            if ($body.IndexOf($needle) -ge 0) { $kind = $el; break }
                        }
                        $o++
                    }
                    if ($kind) { break }
                }
                if ($kind) { $found[$kind] = $start }
            }
            $pos = $code.IndexOf($pushStr, $pos + 1)
        }
    }
    return [pscustomobject]@{ Gates = $found; Pe = $pe }
}

# ---------------------------------------------------------------- patch plan
function New-Edit([string]$name, [int]$off, [byte[]]$was, [byte[]]$now, [string]$note) {
    return [pscustomobject]@{ Name = $name; Off = $off; Was = $was; Now = $now; Note = $note }
}

function Get-Edits([string]$root) {
    $list = @()
    $wf = Join-Path $root 'CalMAN_Workflow.dll'
    $nv = Join-Path $root 'Common\calmanv5.dll'
    if (Test-Path -LiteralPath $wf) {
        $b = [IO.File]::ReadAllBytes($wf)
        $mt = Find-ManagedTargets $b
        if ($mt.Targets.ContainsKey('LicenseDescription.get_Value')) {
            $off = $mt.Targets['LicenseDescription.get_Value']
            $list += New-Edit 'CalMAN_Workflow.dll : LicenseDescription.get_Value (managed)' $off `
                ([byte[]](0x1E, 0x02, 0x7B)) ([byte[]](0x0E, 0x1F, 0x51, 0x2A)) 'reports license 81 (Calman Ultimate for Business)'
        }
        if ($mt.Targets.ContainsKey('ApplicationLicensing.SiteLicense')) {
            $off = $mt.Targets['ApplicationLicensing.SiteLicense']
            $list += New-Edit 'CalMAN_Workflow.dll : ApplicationLicensing.SiteLicense (managed)' $off `
                ([byte[]](0x1B, 0x30)) ([byte[]](0x0A, 0x17, 0x2A)) 'always true (no online validation)'
        }
    }
    if (Test-Path -LiteralPath $nv) {
        $b = [IO.File]::ReadAllBytes($nv)
        $ng = Find-NativeGates $b
        $gateNow = [byte[]](0xB8, 0x01, 0x00, 0x00, 0x00, 0xC2, 0x08, 0x00)
        foreach ($pair in @(@('Meters', 'meters gate (native)'), @('Sources', 'sources gate (native)'), @('Displays', 'displays gate (native)'))) {
            if ($ng.Gates.ContainsKey($pair[0])) {
                $list += New-Edit ("Common\calmanv5.dll : " + $pair[1]) $ng.Gates[$pair[0]] ([byte[]](0x55, 0x8B, 0xEC)) $gateNow 'every item reports as licensed'
            }
        }
    }
    return $list
}

# ---------------------------------------------------------------- run
if ($Mode -eq 'restore') {
    $rc = 0
    foreach ($item in @(@('CalMAN_Workflow.dll', 'CalMAN_Workflow.dll'), @('Common\calmanv5.dll', 'Common\calmanv5.dll'))) {
        $dll = Join-Path $root $item[0]
        if (-not (Test-Path -LiteralPath $dll)) { Write-Host ("  not found: " + $dll) -ForegroundColor Yellow; continue }
        $bak = "$dll.orig"
        if (-not (Test-Path -LiteralPath $bak)) { Write-Host ("  no backup for " + $item[0]) -ForegroundColor Yellow; continue }
        Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.ProcessName -like 'Calman*' -or $_.ProcessName -like 'CalMAN*' } |
            ForEach-Object { Stop-Process -Id $_.Id -Force }
        Copy-Item -LiteralPath $bak -Destination $dll -Force
        Write-Host ("  restored " + $item[0]) -ForegroundColor Green
    }
    exit 0
}

Write-Host "CalMAN universal patch - locating targets by signature" -ForegroundColor Cyan
Write-Host "Install: $root"
if (-not (Test-Path -LiteralPath $root)) { Write-Host 'ERROR: install not found (set CALMAN_DIR).' -ForegroundColor Red; exit 2 }

$byFile = @{}
foreach ($e in (Get-Edits $root)) {
    $file = if ($e.Name -like 'CalMAN_Workflow*') { 'CalMAN_Workflow.dll' } else { 'Common\calmanv5.dll' }
    if (-not $byFile.ContainsKey($file)) { $byFile[$file] = @() }
    $byFile[$file] += $e
}

$exit = 0
foreach ($file in $byFile.Keys) {
    $dll = Join-Path $root $file
    Write-Host ("== " + $file) -ForegroundColor Cyan
    $buf = [IO.File]::ReadAllBytes($dll)
    $todo = @(); $done = @(); $bad = @()
    foreach ($e in $byFile[$file]) {
        if (Test-Bytes $buf $e.Off $e.Now) { $done += $e }
        elseif (Test-Bytes $buf $e.Off $e.Was) { $todo += $e }
        else { $bad += $e }
    }
    foreach ($e in $done) { Write-Host ("   {0} : already patched (0x{1:X})" -f $e.Name, $e.Off) -ForegroundColor Gray }
    foreach ($e in $bad) { Write-Host ("   {0} : located at 0x{1:X} but bytes are neither original nor patched - skipped" -f $e.Name, $e.Off) -ForegroundColor Red; $exit = 1 }
    if ($todo.Count -eq 0) { continue }

    $bak = "$dll.orig"
    if (-not (Test-Path -LiteralPath $bak)) { Copy-Item -LiteralPath $dll -Destination $bak -Force; Write-Host ("   backup: " + (Split-Path $bak -Leaf)) -ForegroundColor Gray }
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessName -like 'Calman*' -or $_.ProcessName -like 'CalMAN*' } |
        ForEach-Object { Stop-Process -Id $_.Id -Force }
    Start-Sleep -Milliseconds 500
    try {
        $fs = [IO.File]::Open($dll, 'Open', 'ReadWrite', 'None')
        try { foreach ($e in $todo) { $fs.Position = $e.Off; $fs.Write($e.Now, 0, $e.Now.Length) } } finally { $fs.Dispose() }
    } catch {
        Write-Host '   file is LOCKED - close Calman and any debugger, then rerun' -ForegroundColor Red
        exit 1
    }
    $buf = [IO.File]::ReadAllBytes($dll)
    foreach ($e in $byFile[$file]) {
        if (Test-Bytes $buf $e.Off $e.Now) { Write-Host ("   {0} : applied at 0x{1:X} - {2}" -f $e.Name, $e.Off, $e.Note) -ForegroundColor Green }
        else { Write-Host ("   {0} : VERIFY FAILED at 0x{1:X}" -f $e.Name, $e.Off) -ForegroundColor Red; $exit = 1 }
    }
}
Write-Host ''
if ($exit -ne 0) { Write-Host 'Finished with problems - see messages above.' -ForegroundColor Red; exit $exit }
Write-Host 'Done. Start Calman: header should read "Calman Ultimate for Business" and no' -ForegroundColor Green
Write-Host 'instrument should fall back to "Simulated meter".' -ForegroundColor Green
exit 0
