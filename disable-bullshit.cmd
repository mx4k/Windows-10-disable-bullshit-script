@echo off
whoami /priv | find "SeDebugPrivilege" > nul
if not errorlevel == 1 (goto habeadminrechte) else (goto braucheadminrechte)

:habeadminrechte
@echo on
@echo Adminrechte vorhanden.
@echo off
ping -n 5 localhost > NUL
goto deaktivieredienste
:end

:deaktivieredienste
@echo Deaktiviere Dienste
@echo off
::
:: Stoppe Diagnosenachverfolgungsdienst
::
echo ##################################################################
echo ## Stoppe Diagnosenachverfolgungsdienst
echo ##################################################################
@sc stop DiagTrack
if not errorlevel == 1 (echo Gestoppt) else (echo Dienst war nicht gestartet.)
ping -n 3 localhost > NUL
::
:: Deaktiviere Diagnosenachverfolgungsdienst
::
echo ##################################################################
echo ## Deaktiviere Diagnosenachverfolgungsdienst
echo ##################################################################
@sc config DiagTrack start= disabled
if not errorlevel == 1 (echo Deaktiviert) else (echo Fehler)
ping -n 3 localhost > NUL
::
:: Stoppe WAP Push-Nachrichtenroutingdienst
::
echo ##################################################################
echo ## Stoppe WAP Push-Nachrichtenroutingdienst
echo ##################################################################
@sc stop dmwappushservice
if not errorlevel == 1 (echo Gestoppt) else (echo Dienst war nicht gestartet.)
ping -n 3 localhost > NUL
::
:: Deaktiviere WAP Push-Nachrichtenroutingdienst
::
echo ##################################################################
echo ## Deaktiviere WAP Push-Nachrichtenroutingdienst
echo ##################################################################
@sc config dmwappushservice start= disabled
if not errorlevel == 1 (echo Deaktiviert) else (echo Fehler)
ping -n 3 localhost > NUL
::
:: Stoppe Windows Defender-Dienst
::
echo ##################################################################
echo ## Stoppe Windows Defender-Dienst
echo ##################################################################
@sc stop WinDefend
if not errorlevel == 1 (echo Gestoppt) else (echo Dienst war nicht gestartet.)
ping -n 3 localhost > NUL
::
:: Ende
::
goto registry
:end

:registry
::
:: Schalte Diagnose- und Nutzungsdaten in Registry ab
::
echo ##################################################################
echo ## Schalte Diagnose- und Nutzungsdaten in Registry ab
echo ##################################################################
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection /f /v AllowTelemetry /t REG_DWORD /d 0
ping -n 3 localhost > NUL
::
:: Schalte Suchleiste aus
::
echo ##################################################################
echo ## Schalte Suchleiste aus
echo ##################################################################
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search /f /v SearchboxTaskbarMode /t REG_DWORD /d 0
ping -n 3 localhost > NUL
::
:: Schalte Werbungs-Id ab
::
echo ##################################################################
echo ## Schalte Werbungs-Id ab
echo ##################################################################
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo /f /v DisabledByGroupPolicy /t REG_DWORD /d 1
ping -n 3 localhost > NUL
::
:: Schalte SmartScreen ab
::
echo ##################################################################
echo ## Schalte SmartScreen ab
echo ##################################################################
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer /f /v SmartScreenEnabled /t REG_SZ /d Off
ping -n 3 localhost > NUL
::
:: Schalte Windows Defender aus
::
echo ##################################################################
echo ## Schalte Windows Defender aus
echo ##################################################################
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" /f /v DisableAntiSpyware /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" /f /v DisableAntiVirus /t REG_DWORD /d 1
ping -n 3 localhost > NUL
::
:: Schalte OneDrive aus
::
echo ##################################################################
echo ## Schalte OneDrive aus
echo ##################################################################
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Onedrive" /f /v DisableLibrariesDefaultSaveToOneDrive /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Onedrive" /f /v DisableFileSync /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Onedrive" /f /v DisableMeteredNetworkFileSync /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Onedrive" /f /v DisableLibrariesDefaultSaveToOneDrive /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Onedrive" /f /v DisableFileSync /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Onedrive" /f /v DisableMeteredNetworkFileSync /t REG_DWORD /d 1
ping -n 3 localhost > NUL
::
:: Schalte Updates P2P ab
::
echo ##################################################################
echo ## Schalte Updates P2P ab
echo ##################################################################
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config /f /v DODownloadMode /t REG_DWORD /d 0
ping -n 3 localhost > NUL
::
:: Schalte alte Lautstärkeregler ein
::
echo ##################################################################
echo ## Schalte alte Lautstärkeregler ein
echo ##################################################################
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" /f /v EnableMtcUvc /t REG_DWORD /d 0
ping -n 3 localhost > NUL
::
:: Entferne Cortana aus Taskleistensuche
::
echo ##################################################################
echo ## Entferne Cortana aus Taskleistensuche
echo ##################################################################
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f
ping -n 3 localhost > NUL
::
:: Schalte Cortana und BingSearch aus
::
echo ##################################################################
echo ## Schalte Cortana und BingSearch aus
echo ##################################################################
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
ping -n 3 localhost > NUL
::
:: Ende
::
goto uninstall
:end

:uninstall
echo ##################################################################
echo ## Deinstalliere 3d
echo ##################################################################
powershell -Command "Get-AppxPackage *3d* | Remove-AppxPackage"
echo ##################################################################
echo ## Deinstalliere Kamera
echo ##################################################################
powershell -Command "Get-AppxPackage *camera* | Remove-AppxPackage"
echo ##################################################################
echo ## Deinstalliere Mail und Kalender
echo ##################################################################
powershell -Command "Get-AppxPackage *communi* | Remove-AppxPackage"
echo ##################################################################
echo ## Deinstalliere Bing
echo ##################################################################
powershell -Command "Get-AppxPackage *bing* | Remove-AppxPackage"
echo ##################################################################
echo ## Deinstalliere Musik
echo ##################################################################
powershell -Command "Get-AppxPackage *zune* | Remove-AppxPackage"
echo ##################################################################
echo ## Deinstalliere Leute
echo ##################################################################
powershell -Command "Get-AppxPackage *people* | Remove-AppxPackage"
echo ##################################################################
echo ## Deinstalliere Telefon Zeugs
echo ##################################################################
powershell -Command "Get-AppxPackage *phone* | Remove-AppxPackage"
echo ##################################################################
echo ## Deinstalliere "Photos"
echo ##################################################################
powershell -Command "Get-AppxPackage *photo* | Remove-AppxPackage"
echo ##################################################################
echo ## Deinstalliere Solitär
echo ##################################################################
powershell -Command "Get-AppxPackage *solit* | Remove-AppxPackage"
echo ##################################################################
echo ## Deinstalliere Audio-Recorder
echo ##################################################################
powershell -Command "Get-AppxPackage *soundrec* | Remove-AppxPackage"
echo ##################################################################
echo ## Deinstalliere Xbox-App
echo ##################################################################
powershell -Command "Get-AppxPackage *xbox* | Remove-AppxPackage"
goto loescheundueberschreibe
:end

:loescheundueberschreibe
echo ##################################################################
echo ## Überschreibe Telemetriedaten
echo ##################################################################
taskkill /IM explorer.exe /F & explorer.exe
echo. >%programdata%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl
pause
goto :eof
:end

:braucheadminrechte
@echo on
@echo Diese Datei muss mit Adminrechten ausgefhrt werden!
@echo off
pause
goto :eof
:end

pause
exit
