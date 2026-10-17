# Interactively create/update .env at the repo root with the API keys and
# settings the scripts read from the environment. .env is gitignored --
# nothing here gets committed. Leave a prompt blank to keep the existing
# value (or leave it unset).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\init_env.ps1
#
# To load the values into your current PowerShell session afterward:
#   Get-Content .env | ForEach-Object {
#       if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
#           [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
#       }
#   }

$RepoDir = Split-Path -Parent $PSScriptRoot
$EnvFile = Join-Path $RepoDir ".env"

$Keys = @("SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET", "SENDER_NAME", "SHODAN_QUERY")
$Current = @{}

if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
            $Current[$matches[1]] = $matches[2]
        }
    }
}

Write-Host "Creating/updating $EnvFile -- leave blank to keep current value."
foreach ($key in $Keys) {
    $existing = $Current[$key]
    if ($existing) {
        $masked = "$($existing.Substring(0, [Math]::Min(4, $existing.Length)))...($($existing.Length) chars)"
        $input = Read-Host "$key [$masked]"
    } else {
        $input = Read-Host "$key []"
    }
    if ($input) {
        $Current[$key] = $input
    }
}

$lines = @("# Created by scripts\init_env.ps1 -- do not commit (see .gitignore)")
foreach ($key in $Keys) {
    if ($Current[$key]) {
        $lines += "$key=$($Current[$key])"
    }
}
Set-Content -Path $EnvFile -Value $lines -Encoding UTF8

Write-Host "[+] wrote $EnvFile"
Write-Host "[*] load it into your session with the snippet in this script's header comment"
Write-Host "[*] run_pipeline.py also loads it automatically when run from the repo root"
