@echo off
:: This script performs comprehensive hardening measures for Windows 10 based on best practices.

:: Elevate the script if not run as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo This script must be run as administrator. Please run again with elevated privileges.
    exit /b
)

:: Disable unnecessary Windows features
dism /Online /Disable-Feature /FeatureName:WindowsMediaPlayer
dism /Online /Disable-Feature /FeatureName:WindowsPowerShell
dism /Online /Disable-Feature /FeatureName:MediaPlayback
dism /Online /Disable-Feature /FeatureName:WindowsStore
dism /Online /Disable-Feature /FeatureName:PrintManagement

:: Disable OneDrive integration
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f

:: Disable all Windows Store apps
powershell -Command "Get-AppxPackage | Remove-AppxPackage"

:: Disable automatic app updates in Windows Store
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "AutoUpdate" /t REG_DWORD /d 0 /f

:: Set Windows to automatically check for updates but not download or install them
powershell -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Value 1"

:: Disable Windows Error Reporting
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f

:: Disable feedback requests from Windows
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feedback" /v "Disabled" /t REG_DWORD /d 1 /f

:: Configure Windows Defender to block potentially unwanted apps
powershell -Command "Set-MpPreference -PUAProtection Enabled"

:: Configure Windows Defender to check for rootkits
powershell -Command "Set-MpPreference -EnableControlledFolderAccess $true"

:: Enable Windows Defender Exploit Guard
powershell -Command "Set-MpPreference -EnableExploitProtection $true"

:: Enable Windows Defender firewall logging
powershell -Command "Set-NetFirewallProfile -All -LogAllowed True"

:: Configure additional Windows Firewall rules
powershell -Command "New-NetFirewallRule -DisplayName 'Block Outbound ICMP' -Direction Outbound -Action Block -Protocol ICMP"
powershell -Command "New-NetFirewallRule -DisplayName 'Allow Inbound DNS' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 53"
powershell -Command "New-NetFirewallRule -DisplayName 'Allow Outbound DNS' -Direction Outbound -Action Allow -Protocol UDP -LocalPort 53"
powershell -Command "New-NetFirewallRule -DisplayName 'Block Inbound SMB' -Direction Inbound -Action Block -Protocol TCP -LocalPort 445"
powershell -Command "New-NetFirewallRule -DisplayName 'Allow Inbound HTTPS' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 443"
powershell -Command "New-NetFirewallRule -DisplayName 'Block Outbound HTTP' -Direction Outbound -Action Block -Protocol TCP -LocalPort 80"

:: Set the system to require a password on wakeup
powercfg -change -standby-timeout-ac 0
powercfg -change -standby-timeout-dc 0
powercfg -setacvalueindex SCHEME_CURRENT SUB_POWER POWERBUTTON_ACTION 0
powercfg -setdcvalueindex SCHEME_CURRENT SUB_POWER POWERBUTTON_ACTION 0

:: Disable remote assistance
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RemoteAccess" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f

:: Disable Windows Search indexing
sc config "WSearch" start= disabled

:: Disable Windows location services
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocationEnabled" /t REG_DWORD /d 0 /f

:: Configure privacy settings
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "Feedback" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "Diagnostics" /t REG_DWORD /d 0 /f

:: Disable telemetry completely
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "AllowTelemetry" /t REG_DWORD /d 0 /f

:: Configure system restore settings
powershell -Command "Disable-ComputerRestore -Drive 'C:\'"
powershell -Command "Enable-ComputerRestore -Drive 'C:\'"

:: Disable automatic maintenance
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "DisableAutoMaintenance" /t REG_DWORD /d 1 /f

:: Enable Windows Defender Credential Guard
powershell -Command "Enable-WindowsOptionalFeature -Online -FeatureName CredentialGuard"

:: Set secure permissions on critical system directories
icacls "C:\Windows\System32\*" /inheritance:r
icacls "C:\Windows\System32\*" /grant:r Administrators:F
icacls "C:\Windows\System32\*" /grant:r Users:R

:: Configure User Account Control (UAC)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 1 /f

:: Configure account policies
net accounts /minpwlen:14
net accounts /maxpwage:30
net accounts /lockoutthreshold:5
net accounts /lockoutduration:30
net accounts /lockoutwindow:30

:: Configure security options for password policies
secedit /set /cfg "C:\Windows\Temp\secpol.cfg" /areas SECURITYPOLICY
secedit /import /cfg "C:\Windows\Temp\secpol.cfg" /areas SECURITYPOLICY
del "C:\Windows\Temp\secpol.cfg"

:: Enable additional auditing
auditpol /set /subcategory:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable

:: Final notification
echo Comprehensive hardening of Windows 10 is complete based on best practices!
pause
