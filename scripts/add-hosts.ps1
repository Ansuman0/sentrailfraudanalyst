# Adds the Sentrail local domain to the Windows hosts file. Re-launches itself as Administrator if needed.
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
$line = "127.0.0.1 sentrail.qatech.world api.sentrail.qatech.world auth.sentrail.qatech.world"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}
if (Select-String -Path $hosts -Pattern "sentrail.qatech.world" -Quiet) { "Already present."; Start-Sleep 2; exit }
Add-Content -Path $hosts -Value "`n$line"
"Added: $line"; Start-Sleep 2
