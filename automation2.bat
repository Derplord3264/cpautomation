@echo off
:: This sequel script further hardens Windows 10 with additional security settings.

:: Elevate the script if not run as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo This script must be run as administrator. Please run again with elevated privileges.
    exit /b
)

:: Disable unnecessary services that might pose security risks
sc config "Fax" start= disabled
sc config "XblGameSave" start= disabled
sc config "WMPNetworkSvc" start= disabled
sc config "HomeGroupListener" start= disabled
sc config "HomeGroupProvider" start= disabled

:: Disable Windows 10 Telemetry
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "AllowTelemetry" /t REG_DWORD /d 0 /f

:: Configure User Account Control (UAC) for maximum security
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d 1 /f

:: Disable unnecessary scheduled tasks
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Scheduled Start" /Disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\AU" /Disable

:: Disable SMBv1 and ensure SMBv2/v3 is enabled
powershell -Command "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
powershell -Command "Set-SmbServerConfiguration -EnableSMB2Protocol $true"

:: Configure Windows Defender to scan removable drives
powershell -Command "Set-MpPreference -DisableRemovableDriveScanning $false"

:: Set Windows Defender to perform full scans regularly
powershell -Command "Set-MpPreference -ScanScheduleDay 0"
powershell -Command "Set-MpPreference -ScanScheduleTime 120"

:: Disable Windows Defender Cloud Protection
powershell -Command "Set-MpPreference -DisableBlockAtFirstSeen $true"

:: Disable access to Control Panel and Settings
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoControlPanel" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoSettings" /t REG_DWORD /d 1 /f

:: Disable Windows Store for more security
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "RemoveWindowsStore" /t REG_DWORD /d 1 /f

:: Configure Internet Explorer security settings
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyEnable" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyServer" /t REG_SZ /d "" /f

:: Configure security options for password policies
secedit /set /cfg "C:\Windows\Temp\secpol.cfg" /areas SECURITYPOLICY
secedit /import /cfg "C:\Windows\Temp\secpol.cfg" /areas SECURITYPOLICY
del "C:\Windows\Temp\secpol.cfg"

:: Enable auditing of sensitive file access
auditpol /set /subcategory:"File System" /success:enable /failure:enable

:: Configure additional Windows Firewall rules
powershell -Command "New-NetFirewallRule -DisplayName 'Block Inbound ICMP' -Direction Inbound -Action Block -Protocol ICMP"
powershell -Command "New-NetFirewallRule -DisplayName 'Block Inbound PING' -Direction Inbound -Action Block -Protocol ICMPv4"

:: Disable Windows Error Reporting
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f

:: Configure Group Policy settings for security
powershell -Command "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\System' -Name 'InactivityTimeoutSecs' -Value 600"

:: Set secure permissions on critical system directories
icacls "C:\Windows\System32\*" /inheritance:r
icacls "C:\Windows\System32\*" /grant:r Administrators:F
icacls "C:\Windows\System32\*" /grant:r Users:R

:: Final notification
echo Further hardening of Windows 10 is complete!
pause
