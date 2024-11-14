@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

REM ===========================================
REM Comprehensive Secure Windows 10/11 Batch Script
REM ===========================================

REM 1. View Hidden Files
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideProtectedOSFiles /t REG_DWORD /d 0 /f

REM 2. Clear the DNS Cache
ipconfig /flushdns

REM 3. Disable Network Shares
net share | findstr /i "C$ ADMIN$" >nul && net share C$ /delete
net share IPC$ /delete

REM 4. User and Group Configuration
net user Guest /active:no
net user Administrator /active:no

REM 5. Enable Firewall
netsh advfirewall set allprofiles state on

REM 6. Disable Telnet Client
dism /Online /Disable-Feature /FeatureName:TelnetClient

REM 7. Set User Account Control to max
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f

REM 8. Disable Automatic Restart on System Failure
wmic recoveros set AutoReboot=false

REM 9. Configure Security Policies
REM Note: Security policy settings will typically require manual configuration or tailored scripts.

REM 10. Configure Power Settings
powercfg -change -monitor-timeout-ac 1
powercfg -change -monitor-timeout-dc 1
powercfg -change -sleep-timeout-ac 5
powercfg -change -sleep-timeout-dc 5

REM 11. Set Power Plan to High Performance
powercfg -setactive SCHEME_MIN

REM 12. Disable SMBv1
dism /Online /Disable-Feature /FeatureName:SMB1Protocol

REM 13. Configure Data Execution Prevention
wmic OS set DataExecutionPrevention_SupportPolicy=2

REM 14. Disable Automatic Updates
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 2 /f

REM 15. Clear Windows Credentials
cmdkey /list | findstr "Target" | for /f "tokens=2 delims=:" %%a in ('findstr "Target"') do cmdkey /delete:%%a

REM 16. Disable Windows Error Reporting
sc config "WerSvc" start= disabled

REM 17. Disable Unused Features
dism /Online /Disable-Feature /FeatureName:MediaPlayback
dism /Online /Disable-Feature /FeatureName:Games
dism /Online /Disable-Feature /FeatureName:WindowsPowerShellV2
dism /Online /Disable-Feature /FeatureName:MediaFeatures

REM 18. Disable Windows Search Indexing
sc config "WSearch" start= disabled

REM 19. Configure Event Log Settings
wevtutil sl Security /ms:20480
wevtutil sl Application /ms:20480
wevtutil sl System /ms:20480

REM 20. Clean Temporary Files
del /q /f "%temp%\*"
del /q /f "C:\Windows\Temp\*"

REM 21. Schedule Disk Cleanup
schtasks /create /tn "Disk Cleanup" /tr "cleanmgr.exe /sagerun:1" /sc weekly /d SUN /st 07:00

REM 22. Create a System Restore Point
powershell -Command "Checkpoint-Computer -Description 'Pre-Security Hardening' -RestorePointType 'MODIFY_SETTINGS'"

REM 23. Disable Remote Desktop
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f

REM 24. Disable Unused Network Protocols
netsh interface ipv4 set subinterface "Local Area Connection" mtu=1492 store=persistent
netsh interface ipv6 set subinterface "Local Area Connection" mtu=1492 store=persistent

REM 25. Disable Windows Messenger
sc config "Messenger" start= disabled

REM 26. Disable Automatic Login
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 0 /f

REM 27. Disable Remote Assistance
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v fAllowToGetHelp /t REG_DWORD /d 0 /f

REM 28. Disable NetBIOS over TCP/IP
netsh interface ip set global netbios=disabled

REM 29. Disable IPv6
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TCPIP6" /v DisabledComponents /t REG_DWORD /d 0xFFFFFFFF /f

REM 30. Set Password Policy
net accounts /minpwlen:12
net accounts /maxpwage:60
net accounts /minpwage:1
net accounts /uniquepw:5

REM 31. Configure Windows Update Settings
powershell -Command "Set-WUSettings -AutoDownload"

REM 32. Enable Windows Defender
sc config "WinDefend" start= auto
net start "WinDefend"

REM 33. Enable Security Auditing
auditpol /set /category:"Logon/Logoff" /failure:enable
auditpol /set /category:"Account Logon" /failure:enable
auditpol /set /category:"Account Management" /failure:enable

REM 34. Disable Unused Services
sc config "Fax" start= disabled
sc config "HomeGroupListener" start= disabled
sc config "HomeGroupProvider" start= disabled
sc config "RemoteRegistry" start= disabled
sc config "SSDPSRV" start= disabled

REM 35. Disable Automatic Restart on System Failure (if not set)
wmic recoveros set AutoReboot=false

REM 36. Configure Local Group Policy Settings
REM This requires administrative templates and may need to be set manually or via GPO.

REM 37. Configure Security Options
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f

REM 38. Disable CD/DVD AutoPlay
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f

REM 39. Enable Windows Firewall Logging
netsh advfirewall set allprofiles logging filename "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
netsh advfirewall set allprofiles logging maxsize 4096

REM 40. Configure Account Policy
net accounts /minpwlen:12
net accounts /maxpwage:30
net accounts /minpwage:1
net accounts /uniquepw:5
net accounts /lockoutthreshold:5
net accounts /lockoutduration:30
net accounts /lockoutbadcount:5

REM 41. Configure Security Options
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InheritParentPermissions /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

REM 42. Configure Audit Policy
auditpol /set /subcategory:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Policy Change" /success:enable /failure:enable

REM 43. Disable Sharing of Printers and Files
net share /delete

REM 44. Configure Windows Firewall
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockin,allowout

REM 45. Disable Windows Features
dism /Online /Disable-Feature /FeatureName:WindowsPowerShellV2

REM ===========================================
echo Security measures applied successfully!
ENDLOCAL
pause
