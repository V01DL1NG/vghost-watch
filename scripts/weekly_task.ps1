# Optional weekly runner for Windows Task Scheduler. Not installed
# automatically -- this repo has no CI/remote scheduler. To register it:
#
#   schtasks /Create /SC WEEKLY /D MON /ST 06:00 /TN "vghost-watch weekly" ^
#     /TR "powershell.exe -ExecutionPolicy Bypass -File \"C:\path\to\vghost-watch\scripts\weekly_task.ps1\""
#
# Set $env:SHODAN_API_KEY and $env:SENDER_NAME beforehand (e.g. via
# `setx`, so Task Scheduler's own process picks them up), or edit the
# defaults below.
$RepoDir = Split-Path -Parent $PSScriptRoot
Set-Location $RepoDir

$venvActivate = Join-Path $RepoDir ".venv\Scripts\Activate.ps1"
if (Test-Path $venvActivate) {
    & $venvActivate
}

$senderName = if ($env:SENDER_NAME) { $env:SENDER_NAME } else { "[your name]" }
$pyArgs = @("src/run_pipeline.py", "--sender-name", $senderName)
if ($env:SHODAN_QUERY) {
    $pyArgs += @("--shodan-query", $env:SHODAN_QUERY)
}

python $pyArgs
