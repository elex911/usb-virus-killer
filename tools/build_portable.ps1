# Thin wrapper only. All build logic lives in build_portable.py.
#
# Why: this machine's execution policy blocks .ps1 scripts, and ranged
# multi-threaded download is more natural in Python. Keeping the logic in
# one place avoids two implementations drifting apart.
#
# Usage (policy permitting):
#   powershell -File tools\build_portable.ps1 -OutDir .\dist_portable\PortableAV
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$BuildArgs
)
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$py = "python"
& $py "$here\build_portable.py" @BuildArgs
exit $LASTEXITCODE
