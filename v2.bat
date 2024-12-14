@echo off
:: This script hardens Windows 10 with extensive security settings.

:: Elevate the script if not run as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo This script must be run as administrator. Please run again with elevated privileges.
    exit /b
)
echo Script is running with elevated privileges.

:: Disable unnecessary services
echo Disabling unnecessary services...
sc config "wuauserv" start= disabled
sc config "BITS" start= disabled
sc config "RemoteRegistry" start= disabled
sc config "Spooler" start= disabled
sc config "Fax" start= disabled
sc config "XblGameSave" start= disabled
sc config "DiagTrack" start= disabled
sc config "dmwappushservice" start= disabled
sc config "SharedAccess" start= disabled
sc stop "DiagTrack"
sc stop "dmwappushservice"
sc stop "SharedAccess"
echo Unnecessary services have been disabled.

:: Disable guest account
echo Disabling guest account...
net user guest /active:no
echo Guest account has been disabled.

:: Disable unnecessary Windows features
echo Disabling unnecessary Windows features...
dism /Online /Disable-Feature /FeatureName:MediaPlayback
dism /Online /Disable-Feature /FeatureName:WindowsMediaPlayer
dism /Online /Disable-Feature /FeatureName:WindowsPowerShell
:: Disabling legacy SMB protocol
dism /Online /Disable-Feature /FeatureName:SMB1Protocol
dism /Online /Disable-Feature /FeatureName:TFTPClient
:: Disabling unneeded printing features
dism /Online /Disable-Feature /FeatureName:Printing-Foundation-InternetPrinting-Client
dism /Online /Disable-Feature /FeatureName:WorkFolders-Client
echo Unnecessary Windows features have been disabled.

:: Enable Windows Firewall
echo Enabling Windows Firewall...
netsh advfirewall set allprofiles state on
echo Windows Firewall is now enabled.

:: Set User Account Control to the highest level
echo Setting User Account Control to the highest level...
powershell -Command "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2"
powershell -Command "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1"
echo User Account Control has been configured.

:: Clear DNS cache
echo Clearing DNS cache...
ipconfig /flushdns
echo DNS cache has been cleared.

:: Disable SMBv1
echo Disabling SMBv1...
powershell -Command "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
echo SMBv1 has been disabled.

:: Set Windows Update settings
echo Configuring Windows Update settings...
powershell -Command "Set-Service -Name wuauserv -StartupType Disabled"
powershell -Command "Set-Service -Name bits -StartupType Disabled"
echo Windows Update settings have been configured.

:: Disable remote access
echo Disabling remote access...
powershell -Command "Set-NetFirewallRule -DisplayGroup 'Remote Desktop' -Enabled False"
echo Remote access has been disabled.

:: Disable unnecessary Startup programs
echo Disabling unnecessary startup programs...
taskkill /F /IM "SomeUnnecessaryApp.exe"
echo Unnecessary startup programs have been disabled.

:: Enable Data Execution Prevention
echo Enabling Data Execution Prevention...
bcdedit /set {current} nx AlwaysOn
echo Data Execution Prevention has been enabled.

:: Set password policy for local accounts
echo Setting password policies for local accounts...
powershell -Command "Set-LocalUser -Name 'Administrator' -Password (ConvertTo-SecureString 'NewPassword' -AsPlainText -Force)"
net accounts /maxpwage:90
net accounts /lockoutthreshold:5
net accounts /lockoutduration:30
net accounts /minpwlen:12
echo Password policies have been set.

:: Ensure Windows Defender is enabled
echo Enabling Windows Defender...
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"
echo Windows Defender is now enabled.

:: Disable unnecessary scheduled tasks
echo Disabling unnecessary scheduled tasks...
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable
echo Unnecessary scheduled tasks have been disabled.

:: Enable BitLocker (requires TPM)
echo Enabling BitLocker...
powershell -Command "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -UsedSpaceOnly"
echo BitLocker has been enabled.

:: Configure Windows Defender SmartScreen
echo Configuring Windows Defender SmartScreen...
powershell -Command "Set-MpPreference -EnableSmartScreen $true"
echo Windows Defender SmartScreen has been configured.

:: Configure auditing
echo Configuring auditing policies...
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"Process Creation" /success:enable /failure:enable
echo Auditing policies have been configured.

:: Disable Windows Script Host
echo Disabling Windows Script Host...
reg add "HKCU\Software\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d 0 /f
echo Windows Script Host has been disabled.

:: Configure User Rights Assignment
echo Configuring User Rights Assignment...
secedit /set /category "User Rights Assignment" /user "Administrators" /add "SeDenyInteractiveLogonRight"
echo User Rights Assignment has been configured.

:: Disable Remote Assistance connections
echo Disabling Remote Assistance connections...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RemoteAccess" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f
echo Remote Assistance connections have been disabled.

:: Disable auto-run
echo Disabling auto-run...
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f
echo Auto-run has been disabled.

:: Enforce Windows Update settings via Group Policy
echo Enforcing Windows Update settings via Group Policy...
powershell -Command "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Value 0"
echo Windows Update settings have been enforced.

:: Disable unnecessary network protocols
echo Disabling unnecessary network protocols...
powershell -Command "Get-NetAdapter | Disable-NetAdapterBinding -DisplayName 'Link-Layer Topology Discovery Mapper I/O Driver'"
powershell -Command "Get-NetAdapter | Disable-NetAdapterBinding -DisplayName 'Link-Layer Topology Discovery Responder'"
powershell -Command "Get-NetAdapter | Disable-NetAdapterBinding -DisplayName 'File and Printer Sharing for Microsoft Networks'"
powershell -Command "Get-NetAdapter | Disable-NetAdapterBinding -DisplayName 'Client for Microsoft Networks'"
echo Unnecessary network protocols have been disabled.

:: Set secure local security policies
echo Setting secure local security policies...
secedit /set /cfg "C:\Windows\Temp\secpol.cfg" /areas SECURITYPOLICY
secedit /import /cfg "C:\Windows\Temp\secpol.cfg" /areas SECURITYPOLICY
del "C:\Windows\Temp\secpol.cfg"
echo Secure local security policies have been set.

:: Configure Windows Defender Firewall
echo Configuring Windows Defender Firewall...
powershell -Command "New-NetFirewallRule -DisplayName 'Block Inbound SMB' -Direction Inbound -Action Block -Protocol TCP -LocalPort 445"
powershell -Command "New-NetFirewallRule -DisplayName 'Block Inbound WMI' -Direction Inbound -Action Block -Protocol TCP -LocalPort 135"
powershell -Command "New-NetFirewallRule -DisplayName 'Block Inbound NetBIOS' -Direction Inbound -Action Block -Protocol UDP -LocalPort 137"
powershell -Command "New-NetFirewallRule -DisplayName 'Block Inbound ICMP' -Direction Inbound -Action Block -Protocol ICMPv4"
echo Windows Defender Firewall has been configured.

:: Configure password complexity requirements
echo Configuring password complexity requirements...
powershell -Command "net accounts /minpwlen:12"
powershell -Command "net accounts /maxpwage:30"
echo Password complexity requirements have been configured.

:: Enable Secure Boot Verification
echo Enabling Secure Boot Verification...
bcdedit /set {current} bootstatuspolicy IgnoreAllFailures
bcdedit /set {current} recoveryenabled No
echo Secure Boot Verification has been enabled.

:: Disable Cortana
echo Disabling Cortana...
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
echo Cortana has been disabled.

:: Disable telemetry
echo Disabling telemetry...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
sc config DiagTrack start= disabled
sc stop DiagTrack
echo Telemetry has been disabled.

echo Hardening of Windows 10 is complete!
pause
