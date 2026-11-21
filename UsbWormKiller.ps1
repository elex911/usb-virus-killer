<#
.SYNOPSIS
    U 盘快捷方式病毒（文件夹伪装蠕虫）查杀与恢复工具。

.DESCRIPTION
    默认只扫描并输出报告，不改动任何文件；加 -Fix 才执行隔离 + 属性恢复。
    与"删所有 .lnk / 直接 attrib 整盘"的粗暴做法不同，本工具：
      1) 校验盘符类型，默认拒绝系统盘/固定磁盘，避免 attrib 打错盘；
      2) 解析每个 .lnk 的目标路径与参数，只隔离确认恶意的，保留合法快捷方式；
      3) 病毒文件先移入隔离区（保留相对路径），可一键回滚，不直接删除；
      4) 属性解除只针对 U 盘根、逐项处理，不递归打整盘命令。

.PARAMETER Drive
    目标盘符，形如 E: 或 E:\。

.PARAMETER Fix
    执行修复。不加则只扫描出报告。

.PARAMETER Force
    允许处理固定磁盘（如被识别为本地盘的移动硬盘）。仍需人工确认盘符。

.PARAMETER Restore
    从该盘最新的隔离目录回滚病毒项。

.EXAMPLE
    .\UsbWormKiller.ps1 -Drive E:
    .\UsbWormKiller.ps1 -Drive E: -Fix
    .\UsbWormKiller.ps1 -Drive E: -Restore

.NOTES
    Windows PowerShell 5.1+。处理系统属性文件建议以管理员身份运行。
    作者注：查杀只覆盖已知"文件夹伪装蠕虫"特征。任何工具都不承诺 100% 清除，
    清除前请自行备份重要文件。
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Drive,

    [switch]$Fix,
    [switch]$Force,
    [switch]$Restore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- 工具函数 ----------
function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 68) -ForegroundColor DarkGray
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ('=' * 68) -ForegroundColor DarkGray
}

function Get-CanonicalDrive([string]$d) {
    $d = $d.Trim().ToUpper()
    if ($d -match '^[A-Z]:') { return $d.Substring(0, 2) }
    throw "盘符格式无效：$d 。应形如 E: 或 E:\"
}

function New-ReportPath([string]$stamp) {
    $dir = Split-Path -Parent $MyInvocation.ScriptName
    if ([string]::IsNullOrEmpty($dir)) { $dir = (Get-Location).Path }
    return (Join-Path $dir ("scan_${stamp}.json"))
}

# ---------- 0. 盘符校验 ----------
$Drive = Get-CanonicalDrive $Drive
$root  = $Drive + '\'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'

$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$Drive'" -ErrorAction SilentlyContinue
if ($null -eq $disk) {
    $avail = (Get-CimInstance Win32_LogicalDisk | ForEach-Object { $_.DeviceID }) -join ' '
    throw "找不到驱动器 $Drive 。当前可用：$avail"
}

$driveType = [int]$disk.DriveType
$typeName  = switch ($driveType) {
    2 { '可移动磁盘(U盘)' }
    3 { '本地固定磁盘' }
    4 { '网络驱动器' }
    5 { '光驱' }
    default { "未知(Type=$driveType)" }
}
$isSystem = ($Drive -eq [System.IO.Path]::GetPathRoot($env:SystemDrive).TrimEnd('\').ToUpper())

Write-Section "目标驱动器 $Drive"
"卷标       : $($disk.VolumeName)"
"类型       : $typeName (DriveType=$driveType)"
"容量/可用  : $([math]::Round($disk.Size/1GB,2)) GB / $([math]::Round($disk.FreeSpace/1GB,2)) GB"
"系统盘     : $isSystem"

# ---------- 0a. 回滚模式 ----------
if ($Restore) {
    $qdirs = @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -like '__WORM_QUARANTINE_*' } |
               Sort-Object Name -Descending)
    if ($qdirs.Count -eq 0) {
        Write-Warning "未在 $Drive 找到隔离目录，无可回滚内容。"
        return
    }
    $q = $qdirs[0]
    "找到隔离目录: $($q.FullName)"
    $files = @(Get-ChildItem -LiteralPath $q.FullName -File -Recurse -Force -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -ne 'README_回滚说明.txt' })
    "隔离项数量: $($files.Count)"

    if (-not $Force) {
        $ans = Read-Host "确认把以上 $($files.Count) 项移回原路径？输入 YES 继续"
        if ($ans -cne 'YES') { "已取消。"; return }
    }

    $ok = 0; $fail = 0
    foreach ($f in $files) {
        $rel  = $f.FullName.Substring($q.FullName.Length).TrimStart('\')
        $dest = Join-Path $root $rel
        try {
            $destDir = Split-Path -Parent $dest
            if (-not (Test-Path -LiteralPath $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }
            Move-Item -LiteralPath $f.FullName -Destination $dest -Force
            $ok++
        } catch {
            Write-Warning "回滚失败 $rel : $($_.Exception.Message)"
            $fail++
        }
    }
    Write-Section "回滚完成"
    "成功 $ok 项，失败 $fail 项。失败项仍保留在隔离目录中。"
    return
}

# ---------- 0b. 非可移动盘拦截 ----------
if ($isSystem -or $driveType -in @(3, 5)) {
    if (-not $Force) {
        throw @"
安全拦截：$Drive 被识别为「$typeName」。
本工具默认只处理可移动磁盘(DriveType=2)，避免 attrib 误伤系统盘或固定磁盘。
若确认目标正确（如移动硬盘被系统识别为本地磁盘），加 -Force 重试。
"@
    }
    Write-Warning "已用 -Force 越过盘符类型拦截，目标 $Drive ($typeName)。请二次确认盘符无误！"
}

# ---------- 1. 只读扫描 ----------
Write-Section "扫描中（只读，不改动任何文件）"

$allItems = @()
try {
    $allItems = @(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction SilentlyContinue)
} catch {
    Write-Warning "枚举失败：$($_.Exception.Message)"
}

# 1a. 隐藏 + 系统属性的项目（疑似被藏起来的原文件）
$hiddenOriginals = @($allItems | Where-Object {
    ($_.Attributes -band [System.IO.FileAttributes]::Hidden) -and
    ($_.Attributes -band [System.IO.FileAttributes]::System)
})

# 1b. 解析 .lnk，区分恶意与合法
$shell = $null
try { $shell = New-Object -ComObject WScript.Shell } catch { Write-Warning "无法创建 WScript.Shell，.lnk 将按文件名粗判。" }

$targetSuspect = 'wscript\.exe|cscript\.exe|cmd\.exe|powershell\.exe|rundll32\.exe|mshta\.exe|regsvr32\.exe'
$argSuspect    = '\.(vbs|vbe|js|jse|bat|cmd|hta|scr|pif)\b|autorun|\.vbs|\.js'

$links = @()
foreach ($lnk in @($allItems | Where-Object { $_.Extension -ieq '.lnk' -and -not $_.PSIsContainer })) {
    $target = ''; $argsText = ''
    if ($null -ne $shell) {
        try {
            $sc = $shell.CreateShortcut($lnk.FullName)
            $target   = [string]$sc.TargetPath
            $argsText = [string]$sc.Arguments
        } catch { }
    }
    $suspect = ($target -match $targetSuspect) -or ($argsText -match $argSuspect)
    $links += [pscustomobject]@{
        Path     = $lnk.FullName
        Target   = $target
        Args     = $argsText
        Suspect  = [bool]$suspect
        Hidden   = [bool]($lnk.Attributes -band [System.IO.FileAttributes]::Hidden)
    }
}
$suspectLinks = @($links | Where-Object { $_.Suspect })
$cleanLinks   = @($links | Where-Object { -not $_.Suspect })

# 1c. autorun.inf
$autoruns = @($allItems | Where-Object { $_.Name -ieq 'autorun.inf' })

# 1d. 可疑脚本：降噪——只报「根目录或一级目录」且「隐藏 或 被可疑 lnk 引用 或 病毒常见名」
#     避免把正常软件/网页目录里成千上万的 .js 全报出来（噪音淹没真问题 = 没门禁）
$virusNames = '^(autorun|desktop\.ini|folder|新文件夹|回收站|recycled|thumbs|system|windows|update|run|start|open|readme|说明)'
$referencedBySuspect = @($suspectLinks | ForEach-Object { $_.Args; $_.Target } | Where-Object { $_ } | ForEach-Object {
    if ($_ -match '([A-Za-z]:\\[^\s"'']+\.(vbs|vbe|js|jse|bat|cmd|hta|scr|pif))') { $matches[1] }
})
$suspectScripts = @($allItems | Where-Object {
    if ($_.PSIsContainer) { return $false }
    if ($_.Extension -notin @('.vbs', '.vbe', '.js', '.jse', '.hta', '.scr', '.pif')) { return $false }
    $rel = $_.FullName.Substring($root.Length)
    $depth = ($rel -split '\\').Count          # 根目录文件 = 1，一级子目录内 = 2
    $isHidden = [bool]($_.Attributes -band [System.IO.FileAttributes]::Hidden)
    $isVirusName = ($_.BaseName -match $virusNames)
    $isReferenced = ($referencedBySuspect -contains $_.FullName)
    return ($depth -le 2) -and ($isHidden -or $isVirusName -or $isReferenced)
})

# ---------- 2. 报告 ----------
$lnkItems = @($allItems | Where-Object { $_.Extension -ieq '.lnk' -and -not $_.PSIsContainer })
Write-Section "扫描结果"
"隐藏+系统属性项（疑似被藏的原文件）: $($hiddenOriginals.Count)"
"快捷方式 .lnk 总数: $($lnkItems.Count)  |  可疑: $($suspectLinks.Count)  |  判定正常(将保留): $($cleanLinks.Count)"
"autorun.inf : $($autoruns.Count)"
"可疑脚本(.vbs/.js/.hta/.scr/.pif): $($suspectScripts.Count)  [仅报告，不自动处理]"

if ($suspectLinks.Count -gt 0) {
    Write-Section "可疑快捷方式（病毒伪装）"
    $suspectLinks | Select-Object -First 40 | ForEach-Object {
        "  $($_.Path)"
        "      目标: $($_.Target)   参数: $($_.Args)"
    }
    if ($suspectLinks.Count -gt 40) { "  ... 另有 $($suspectLinks.Count - 40) 项，详见 JSON 报告" }
}
if ($autoruns.Count -gt 0) {
    Write-Section "autorun.inf"
    $autoruns | Select-Object -First 20 | ForEach-Object { "  $($_.FullName)" }
}
if ($suspectScripts.Count -gt 0) {
    Write-Section "可疑脚本（需人工确认，本工具不自动隔离）"
    $suspectScripts | Select-Object -First 40 | ForEach-Object { "  $($_.FullName)" }
    if ($suspectScripts.Count -gt 40) { "  ... 另有 $($suspectScripts.Count - 40) 项" }
}
if ($cleanLinks.Count -gt 0) {
    Write-Section "判定为正常的快捷方式（本工具不会删除）"
    $cleanLinks | Select-Object -First 15 | ForEach-Object { "  $(Split-Path -Leaf $_.Path) -> $($_.Target)" }
    if ($cleanLinks.Count -gt 15) { "  ... 另有 $($cleanLinks.Count - 15) 项" }
}

$report = [ordered]@{
    scan_time       = (Get-Date).ToString('o')
    drive           = $Drive
    drive_type      = $typeName
    force_used      = [bool]$Force
    summary         = [ordered]@{
        hidden_system_items = $hiddenOriginals.Count
        lnk_total           = $lnkItems.Count
        lnk_suspect         = $suspectLinks.Count
        lnk_clean           = $cleanLinks.Count
        autorun_inf         = $autoruns.Count
        suspicious_scripts  = $suspectScripts.Count
    }
    suspect_links   = @($suspectLinks | Select-Object Path, Target, Args)
    clean_links     = @($cleanLinks   | Select-Object Path, Target, Args)
    autoruns        = @($autoruns     | ForEach-Object { $_.FullName })
    suspect_scripts = @($suspectScripts | ForEach-Object { $_.FullName })
    hidden_sample   = @($hiddenOriginals | Select-Object -First 200 | ForEach-Object { $_.FullName })
}
$reportPath = New-ReportPath $stamp
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath -Encoding UTF8
"报告已保存: $reportPath"

if (-not $Fix) {
    Write-Section "只读模式结束"
    "未改动任何文件。确认报告后，加 -Fix 执行隔离与恢复。"
    return
}

# ---------- 3. 修复 ----------
Write-Section "修复模式"
$toQuarantine = @($suspectLinks | ForEach-Object { $_.Path }) + @($autoruns | ForEach-Object { $_.FullName })
$toQuarantine = @($toQuarantine | Where-Object { -not [string]::IsNullOrEmpty($_) })

"待隔离病毒项 : $($toQuarantine.Count)"
"待解除隐藏项 : $($hiddenOriginals.Count)"
if ($toQuarantine.Count -eq 0 -and $hiddenOriginals.Count -eq 0) {
    "未发现需要处理的项目，退出。"
    return
}

if (-not $Force) {
    $ans = Read-Host "确认执行？输入 YES 继续（其它任意输入取消）"
    if ($ans -cne 'YES') { "已取消，未改动任何文件。"; return }
}

$qdir = Join-Path $root ("__WORM_QUARANTINE_" + $stamp)
New-Item -ItemType Directory -Path $qdir -Force | Out-Null

$moved = 0; $moveFail = 0
foreach ($item in $toQuarantine) {
    if (-not (Test-Path -LiteralPath $item)) { continue }
    try {
        $rel  = $item.Substring($root.Length)
        $dest = Join-Path $qdir $rel
        $destDir = Split-Path -Parent $dest
        if (-not (Test-Path -LiteralPath $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }
        Move-Item -LiteralPath $item -Destination $dest -Force
        $moved++
    } catch {
        Write-Warning "隔离失败 $item : $($_.Exception.Message)"
        $moveFail++
    }
}
"已隔离 $moved 项（失败 $moveFail） -> $qdir"

# 解除 Hidden/System 属性：逐项处理，保留原有 ReadOnly 不动
$clearAttr = [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System
$cleared = 0; $clearFail = 0
foreach ($f in $allItems) {
    if ($f.FullName.StartsWith($qdir, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
    try {
        if (($f.Attributes -band $clearAttr) -ne 0) {
            $f.Attributes = $f.Attributes -band (-bnot $clearAttr)
            $cleared++
        }
    } catch {
        Write-Warning "属性解除失败 $($f.FullName) : $($_.Exception.Message)"
        $clearFail++
    }
}
"已解除隐藏/系统属性 $cleared 项（失败 $clearFail）"

$readme = @"
隔离时间 : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
目标盘符 : $Drive
说明     : 本目录内为病毒伪装文件（.lnk / autorun.inf），按原相对路径存放。
回滚     : 运行  .\UsbWormKiller.ps1 -Drive $Drive -Restore
注意     : 确认系统已全盘杀毒、U 盘无异常后，再删除本目录。
           不要双击本目录内的任何快捷方式。
"@
$readme | Set-Content -LiteralPath (Join-Path $qdir 'README_回滚说明.txt') -Encoding UTF8

Write-Section "修复完成"
"1. 已隔离 $moved 个病毒伪装项，未直接删除，可回滚。"
"2. 已解除 $cleared 个原文件的隐藏/系统属性。"
"3. 请务必再用杀毒软件对电脑全盘扫描（病毒常驻主机，只清 U 盘会复发）。"
"4. 安全弹出 U 盘后再拔下。"
