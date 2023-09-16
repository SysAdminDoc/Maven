Powershell Set-ExecutionPolicy RemoteSigned

# Enables F8 Advanced Boot Options screen in Windows 10 for Safe Mode access like Windows 7 and sets timeout to 3 seconds
bcdedit /set {bootmgr} displaybootmenu yes
bcdedit /timeout 3

Invoke-WebRequest https://www.dropbox.com/scl/fi/ql8jckimriagmsew2zvfq/MicrosoftUpdates.ps1?rlkey=wn9qli9px90cquoqdna1stx3c&dl=1 -OutFile C:\MTU\MicrosoftUpdates.ps1
# Run the Microsoft Updates.ps1 script
Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass C:\MTU\MicrosoftUpdates.ps1" -Wait
Invoke-WebRequest https://www.dropbox.com/scl/fi/ektkdnxpvaforl48rf21z/DownloadVoyance.ps1?rlkey=1jw2h2zhhircvvgdl7suf5bra&dl=1 -OutFile C:\MTU\DownloadVoyance.ps1
Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass C:\MTU\DownloadVoyance.ps1" -Wait
Invoke-WebRequest https://www.dropbox.com/scl/fi/6g9drfsptkyy1lpokxw9j/DellUpdates.bat?rlkey=cq6917k1sj23poc1qt6t00z4r&dl=1 -OutFile C:\MTU\DellUpdates.bat
# Run the script
Start-Process -FilePath "C:\MTU\DellUpdates.bat" -Wait
Invoke-WebRequest https://www.dropbox.com/scl/fi/bcoa7xh6i3ifg4zuwp3mk/Maven_BGinfo.bgi?rlkey=23pa66c2v8szrfp002gtt40h5&dl=1 -OutFile C:\MTU\Maven_BGinfo.bgi
Invoke-WebRequest https://www.dropbox.com/scl/fi/2qwxaahfu311v4gn8yiip/Voyance_Firewall_Script.ps1?rlkey=4ln141gu7ulplv0neu6dq86mc&dl=1 -OutFile C:\MTU\Voyance_Firewall_Script.ps1
Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass C:\MTU\Voyance_Firewall_Script.ps1" -Wait
Invoke-WebRequest https://www.dropbox.com/scl/fi/vak8wye777vgic5plzwsn/Bginfo64.exe?rlkey=wsj1bbc501ihigw5iu7eoi9yu&dl=1 -OutFile C:\MTU\Bginfo64.exe

# Install Microsoft Store
Add-AppxPackage -Path "https://cdn.winget.microsoft.com/cache/source.msix"
# Download Microsoft Desktop App Installer
Invoke-WebRequest -Uri "https://aka.ms/getwinget" -OutFile "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
Invoke-WebRequest -Uri "https://github.com/microsoft/winget-cli/releases/download/v1.5.2201/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -OutFile "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
# Download and install Microsoft dependencies
Invoke-WebRequest -Uri "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -OutFile "Microsoft.VCLibs.x64.14.00.Desktop.appx"
Invoke-WebRequest -Uri "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.7.3/Microsoft.UI.Xaml.2.7.x64.appx" -OutFile "Microsoft.UI.Xaml.2.7.x64.appx"
Add-AppxPackage -Path "Microsoft.VCLibs.x64.14.00.Desktop.appx"
Add-AppxPackage -Path "Microsoft.UI.Xaml.2.7.x64.appx"
Add-AppxPackage -Path "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"

# Reset and upgrade packages using winget
winget source reset --force
winget upgrade --all --silent --accept-source-agreements --accept-package-agreements --disable-interactivity --include-unknown
winget install -e --id Google.Chrome
# winget install -e --id Adobe.Acrobat.Reader.64-bit
winget install -e --id Dell.CommandUpdate

winget upgrade TeamViewer
winget install -e --id TeamViewer.TeamViewer
# Config for old TeamViewer GUI with Dark Mode enabled
Set-ItemProperty -Path "HKCU:\Software\TeamViewer" -Name "UIVersion" -Value 2 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\Software\TeamViewer" -Name "IntroShown" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\Software\TeamViewer" -Name "ColorScheme" -Value 2 -Type DWORD -Force

Remove-Item -Path "Microsoft.VCLibs.x64.14.00.Desktop.appx"
Remove-Item -Path "Microsoft.UI.Xaml.2.7.x64.appx"
Remove-Item -Path "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"

# Install uBlock Origin adblocker for Chrome
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist" -Name "1" -Value "cjpalhdlnbpafiamejdnhcphjbkeiagm;https://clients2.google.com/service/update2/crx" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlacklist" -Name "1" -Value "efaidnbmnnnibpcajpcglclefindmkaj" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlacklist" -Name "1" -Value "bjicifbhnpakmaekfnphojjehhnifkmc" -Force

# Disable Fast Startup for WOL
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "HiberbootEnabled" -Value 0 -PropertyType DWORD -Force

# Set Windows to never sleep
powercfg.exe -Change -Disk-Timeout-AC 0
powercfg.exe -Change -Disk-Timeout-DC 0
powercfg.exe -Change -Standby-Timeout-AC 0
powercfg.exe -Change -Standby-Timeout-DC 0
powercfg.exe -Change -Hibernate-Timeout-AC 0
powercfg.exe -Change -Hibernate-Timeout-DC 0

# Set the Monitor timeout to 20 minutes
powercfg.exe -Change -Monitor-Timeout-AC 20

# Disable Require Sign-in on Wakeup for All Users
powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 0
powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 0

# Remove News and Interests icon on Taskbar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Value 2

# Delete "Microsoft Edge" shortcut from Desktop
Remove-Item -Path "$env:USERPROFILE\Desktop\Microsoft Edge.lnk" -Force

# Delete "Your Phone" shortcut from Desktop
Remove-Item -Path "$env:USERPROFILE\Desktop\Your Phone.lnk" -Force

# Disable Slideshow during Lock Screen
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lock Screen" -Name "SlideshowEnabled" -Value 0 -Type DWORD

# Disable Windows Defender SmartScreen Filter
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 0 -Type DWORD

# Disable first login animation
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWORD

# Disable Gamebar
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AudioCaptureEnabled" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "CursorCaptureEnabled" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "MicrophoneCaptureEnabled" -Value 0 -Type DWORD -Force

Get-AppxPackage -AllUsers | where-object {$_.name –notlike "*store*"} | Remove-AppxPackage

# Disable Lockscreen
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Value 1 -Type DWORD -Force

# Disable Lockscreen Background
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLogonBackgroundImage" -Value 1 -Type DWORD -Force

# Disable Secure Sign-in
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DisableCAD" -Value 1 -Type DWORD -Force
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DisableCAD" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 1 -Type DWORD -Force
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -ErrorAction SilentlyContinue

# Script to download xray icons from dropbox
Invoke-WebRequest https://www.dropbox.com/s/ggd2rf9tnos9ztd/mavenusericon.zip?dl=1 -OutFile C:\MTU\mavenusericon.zip 
Expand-Archive C:\MTU\mavenusericon.zip -DestinationPath C:\MTU\mavenusericon
# Replaces User Account Pictures with Maven xray icon
Copy-Item -Path 'C:\MTU\mavenusericon\mavenusericon\*' -recurse -destination 'C:\ProgramData\Microsoft\User Account Pictures\' -force
Remove-Item C:\MTU\mavenusericon.zip -recurse
# Make Logo default for all accounts
# Add or modify the registry value
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "UseDefaultTile" -Value 1 -Type DWORD -Force
# Remove the C:\MTU\mavenusericon directory (including its subdirectories and files)
Remove-Item -Path "C:\MTU\mavenusericon" -Recurse -Force

# Download Wallpaper
New-Item -Path 'C:\MTU' -ItemType Directory
Invoke-WebRequest https://www.dropbox.com/s/3denp8jubpxnn02/Maven_Wallpaper-nn.jpg?dl=1 -OutFile C:\MTU\Maven_Wallpaper-nn.jpg
Invoke-WebRequest https://www.dropbox.com/s/z76esv9agbvll24/ApplyWallpaper.ps1?dl=1 -OutFile C:\MTU\ApplyWallpaper.ps1
# Run the ApplyWallpaper.ps1 script
Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass C:\MTU\ApplyWallpaper.ps1" -Wait
# Modify the registry value
Set-ItemProperty -Path "HKCU:\control panel\desktop" -Name "WallpaperStyle" -Value 2 -Type String -Force
# Set the registry value
Set-ItemProperty -Path "HKU\.DEFAULT\Software\Sysinternals\BGInfo" -Name "EulaAccepted" -Value 1 -Type DWORD -Force
# Run BGInfo
Start-Process -FilePath "C:\MTU\Bginfo64.exe" -ArgumentList "C:\MTU\Maven_BGinfo.bgi", "/TIMER:00", "/nolicprompt" -Wait
reg add HKU\.DEFAULT\Software\Sysinternals\BGInfo /v EulaAccepted /t REG_DWORD /d 1 /f
C:\MTU\Bginfo64.exe C:\MTU\Maven_BGinfo.bgi /TIMER:00 /nolicprompt

# Disable Transparency
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Type DWORD -Force

# Turn On Show Accent Color on Title Bars and Window Borders
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "ColorPrevalence" -Value 1 -Type DWORD -Force

# Disable Meet Now
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1 -Type DWORD -Force

# Disable Recently Added Programs in Start Menu
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Value 1 -Type DWORD -Force

# Enable Firewall for all Profiles
Set-NetFirewallProfile -Enabled True
netsh advfirewall set allprofiles state on
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass C:\MTU\Voyance_Firewall_Script.ps1" -Wait

# Disable IPV6 on all ethernet adapters
Get-NetAdapter | ForEach-Object { Disable-NetAdapterBinding -InterfaceAlias $_.Name -ComponentID ms_tcpip6 }

# Disable 'Hey' first logon animation
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWORD -Force

# Additional Registry Changes
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarEnabled" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -Value 1 -Type DWORD -Force

# Remove Multitask View Button
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultiTaskingView\AllUpView" -Name "Enabled" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Type DWORD -Force

# Disable Windows Tips
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1 -Type DWORD -Force

# Hide People Bar
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "HidePeopleBar" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HidePeopleBar" -Value 1 -Type DWORD -Force

# Disable Ink Workspace
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value 0 -Type DWORD -Force

# Disable People Button
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Force

# Disables Windows 10 Default Printer Behavior
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LegacyDefaultPrinterMode" -Value 1 -Type DWORD -Force

# Set owner and organization of machine
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "RegisteredOwner" -Value "Xray" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "RegisteredOrganization" -Value "Maven" -Type String -Force

# Disable Tips
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0 -Type DWORD -Force

# Turn off Sticky Keys when Shift is pressed 5 times
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506" -Type String -Force

# Disable News and Weather
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 1 -Type DWORD -Force

# Turn Off Get even more out of Windows Suggestions in Windows 10
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value 0 -Type DWORD -Force

# Disable Xbox Game Bar
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "GameDVR_Enabled" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 0 -Type DWORD -Force

# Disable Search Highlights
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "EnableDynamicContentInWSB" -Value 0 -Type DWORD -Force

# File Explorer opens to This PC
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Type DWORD -Force

# Disable Aero Shake
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Value 1 -Type DWORD -Force

# Disable Cortana
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "AllowSearchToUseLocation" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Windows Search" -Name "CortanaConsent" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -Type DWORD -Force

# Disable online tips in Settings
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Value 0 -Type DWORD -Force

# Disable search history in File Explorer
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1

# Set File Explorer starting folder to This PC
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1

# Remove OneDrive from Navigation Pane
Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0

# Disable suggested apps in Windows Ink WorkSpace
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceAppSuggestionsEnabled" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0

# Disable Sharing of handwriting data
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1

# Disable Sharing of handwriting error reports
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value 1

# Disable Advertising ID
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Id" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Id" -ErrorAction SilentlyContinue

# Disable Microsoft conducting experiments with this machine
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\System" -Name "AllowExperimentation" -Value 0

# Disable advertisements via Bluetooth
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Bluetooth" -Name "AllowAdvertising" -Value 0

# Disable Windows Customer Experience Improvement Program
Set-ItemProperty -Path "HKLM:\Software\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0

# Disable telemetry
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\dmwappushservice" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" -Name "Start" -Value 0
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0

# Disable Input Personalization
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicyy" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0

# Disable ads in File Explorer and OneDrive
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0

# Disable feedback reminders
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 0

# Remove Task View button from taskbar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0

# Remove People button from taskbar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0

# Disable Timeline
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0

# Disable Microsoft Edge prelaunching
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowPrelaunch" -PropertyType DWORD -Value 0 -Force

# Disable Microsoft Edge tab preloading
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowTabPreloading" -PropertyType DWORD -Value 0 -Force

# Allow Wifi and Ethernet at Same Time
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value 0 -Type DWORD -Force

Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass C:\MTU\Voyance_Firewall_Script.ps1" -Wait
Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass C:\MTU\MicrosoftUpdates.ps1" -Wait
Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass C:\MTU\DownloadVoyance.ps1" -Wait

# Delete Files
Remove-Item -Path "C:\MTU\ApplyWallpaper.ps1" -Force
Remove-Item -Path "C:\MTU\Voyance_Firewall_Script.ps1" -Force
Remove-Item -Path "C:\MTU\Clean_Start.ps1" -Force
Remove-Item -Path "C:\MTU\DeleteApps.ps1" -Force
Remove-Item -Path "C:\MTU\Essential.ps1" -Force
Remove-Item -Path "C:\MTU\Voyance_Firewall_Script.ps1" -Force
Remove-Item -Path "C:\MTU\MicrosoftUpdates.ps1" -Force
Remove-Item -Path "C:\MTU\DownloadVoyance.ps1" -Force
Remove-Item -Path "C:\MTU\DellUpdates.bat" -Force