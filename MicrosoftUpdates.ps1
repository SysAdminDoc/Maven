Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module PSWindowsUpdate -Force
Get-WUInstall -Install -AcceptAll -IgnoreReboot -Verbose