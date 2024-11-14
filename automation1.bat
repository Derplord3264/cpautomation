@echo off
:: This script hardens Windows 10 with extensive security settings.

:: Elevate the script if not run as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo This script must be run as administrator. Please run again with elevated privileges.
    exit /b
)

:: Disable unnecessary services
sc config "wuauserv" start= disabled
sc config "BITS" start= disabled
sc config "RemoteRegistry" start= disabled
sc config "Spooler" start= disabled
sc config "Fax" start= disabled
sc config "XblGameSave" start= disabled

:: Disable guest account
net user guest /active:no

:: Disable unnecessary Windows features
dism /Online /Disable-Feature /FeatureName:MediaPlayback
dism /Online /Disable-Feature /FeatureName:WindowsMediaPlayer
dism /Online /Disable-Feature /FeatureName:WindowsPowerShell

:: Enable Windows Firewall
netsh advfirewall set allprofiles state on

:: Set User Account Control to the highest level
powershell -Command "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2"
powershell -Command "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1"

:: Clear DNS cache
ipconfig /flushdns

:: Disable SMBv1
powershell -Command "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"

:: Set Windows Update settings
powershell -Command "Set-Service -Name wuauserv -StartupType Disabled"
powershell -Command "Set-Service -Name bits -StartupType Disabled"

:: Disable remote access
powershell -Command "Set-NetFirewallRule -DisplayGroup 'Remote Desktop' -Enabled False"

:: Disable unnecessary Startup programs
taskkill /F /IM "SomeUnnecessaryApp.exe"

:: Enable Data Execution Prevention
bcdedit /set {current} nx AlwaysOn

:: Set password policy for local accounts
powershell -Command "Set-LocalUser -Name 'Administrator' -Password (ConvertTo-SecureString 'NewPassword' -AsPlainText -Force)"
net accounts /maxpwage:90
net accounts /lockoutthreshold:5
net accounts /lockoutduration:30
net accounts /minpwlen:12

:: Ensure Windows Defender is enabled
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"

:: Disable unnecessary scheduled tasks
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable

:: Enable BitLocker (requires TPM)
powershell -Command "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -UsedSpaceOnly"

:: Configure Windows Defender SmartScreen
powershell -Command "Set-MpPreference -EnableSmartScreen $true"

:: Configure auditing
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"Process Creation" /success:enable /failure:enable

:: Disable Windows Script Host
reg add "HKCU\Software\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d 0 /f

:: Configure User Rights Assignment
secedit /set /category "User Rights Assignment" /user "Administrators" /add "SeDenyInteractiveLogonRight"

:: Disable Remote Assistance connections
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RemoteAccess" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f

:: Disable auto-run
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f

:: Enforce Windows Update settings via Group Policy
powershell -Command "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Value 0"

:: Disable unnecessary network protocols
powershell -Command "Get-NetAdapter | Disable-NetAdapterBinding -DisplayName 'Link-Layer Topology Discovery Mapper I/O Driver'"
powershell -Command "Get-NetAdapter | Disable-NetAdapterBinding -DisplayName 'Link-Layer Topology Discovery Responder'"

:: Set secure local security policies
secedit /set /cfg "C:\Windows\Temp\secpol.cfg" /areas SECURITYPOLICY
secedit /import /cfg "C:\Windows\Temp\secpol.cfg" /areas SECURITYPOLICY
del "C:\Windows\Temp\secpol.cfg"

:: Configure Windows Defender Firewall
powershell -Command "New-NetFirewallRule -DisplayName 'Block Inbound SMB' -Direction Inbound -Action Block -Protocol TCP -LocalPort 445"
powershell -Command "New-NetFirewallRule -DisplayName 'Block Inbound WMI' -Direction Inbound -Action Block -Protocol TCP -LocalPort 135"

:: Configure password complexity requirements
powershell -Command "net accounts /minpwlen:12"
powershell -Command "net accounts /maxpwage:30"

echo Hardening of Windows 10 is complete!
pause
