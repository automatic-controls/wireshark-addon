@echo off
setlocal EnableDelayedExpansion
net session >nul 2>&1
if %ErrorLevel% NEQ 0 (
  echo Please run this script as administrator.
  goto :exitLabel
)

:selectWireshark
cls
echo.
set "wireshark=%ProgramFiles%\Wireshark\dumpcap.exe"
if not exist "%wireshark%" (
  echo Please install Wireshark and enter the installation folder below:
  echo For example, %ProgramFiles%\Wireshark
  set /p "wireshark=>"
  set "wireshark=!wireshark!\dumpcap.exe"
  if not exist "!wireshark!" (
    echo Invalid!
    echo Press any key to try again...
    pause >nul
    goto :selectWireshark
  )
)

cls
echo.
echo Please enter the number of the interface you wish to capture data from.
echo Suggestion: choose the interface over which WebCTRL communicates.
echo.
for /F "tokens=1,2,* delims=. " %%i in ('"%wireshark%" -D') do (
  echo %%i. %%k - %%j
  set "interface[%%i]=%%j"
)
echo.
:selectInterface
set /p "interface=>"
set "interface=!interface[%interface%]!"
if "%interface%" EQU "" (
  echo Invalid!
  goto :selectInterface
)

cls
echo.
echo Which filter would you like to use for capturing packets?
echo Suggestion: use 47808 only unless you have a specific reason to monitor other ports.
echo.
echo 1^) udp
echo 2^) udp port 47808
echo.
:selectFilter
set /p "filter=>"
if "%filter%" EQU "1" (
  set "filter=udp"
) else if "%filter%" EQU "2" (
  set "filter=udp port 47808"
) else (
  echo Invalid!
  goto :selectFilter
)

cls
echo.
echo Please enter how many hours that captured PCAP files should be retained for.
echo Suggestion: retain data for at least 72 hours.
:selectRetain
set /p "retain_hours=>"
if "%retain_hours%" EQU "" (
  echo Invalid!
  goto :selectRetain
)
set /a retain_hours_2=%retain_hours% 2>nul
if "%retain_hours%" NEQ "%retain_hours_2%" (
  echo Invalid!
  goto :selectRetain
)

cls
echo.
echo Generating files...
(
  echo set "wireshark=!wireshark!"
  echo set "interface=!interface!"
  echo set "filter=!filter!"
  echo set "retain_hours=!retain_hours!"
)>"%~dp0settings.bat"
(
  echo @echo off
  echo call "%%~dp0settings.bat"
  echo if exist "%%~dp0install.bat" del /F "%%~dp0install.bat" >nul 2>nul
  echo PowerShell -ExecutionPolicy Bypass -NoLogo -NonInteractive -File "%%~dp0clean.ps1"
  echo exit
)>"%~dp0clean.bat"
(
  echo $path = Join-Path -Path $PSScriptRoot -ChildPath 'data\*.pcap'
  echo $files = Get-ChildItem -Path $path -Force -File
  echo $limit = ^(Get-Date^).AddHours^(-$Env:retain_hours^)
  echo foreach ^($f in $files^){
  echo   if ^($f.LastWriteTime -lt $limit^){
  echo     $f ^| Remove-Item -Force
  echo   }
  echo }
)>"%~dp0clean.ps1"
(
  echo @echo off
  echo call "%%~dp0settings.bat"
  echo setlocal EnableDelayedExpansion
  echo if not exist "%%wireshark%%" exit
  echo "%%wireshark%%" -i ^^!interface^^! -f "^!filter^!" -P -b duration:86400 -b filesize:51200 -w "%%~dp0data\data.pcap" -q
  echo exit
)>"%~dp0capture.bat"
(
  echo $name = 'wireshark-clean'
  echo if ^($null -eq ^(Get-ScheduledTask -TaskName $name -ErrorAction 'Ignore'^)^){
  echo   Write-Host "Installing scheduled task $name to run at 1:17AM..."
  echo   $trigger = New-ScheduledTaskTrigger -Daily -At '1:17am'
  echo   $principal = New-ScheduledTaskPrincipal -UserID 'NT AUTHORITY\SYSTEM' -LogonType 'ServiceAccount' -RunLevel 'Highest'
  echo   $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ^(New-TimeSpan -Hours 6^) -MultipleInstances 'IgnoreNew' -Priority 7 -StartWhenAvailable -WakeToRun
  echo   $action = New-ScheduledTaskAction -Execute ^(Join-Path -Path $PSScriptRoot -ChildPath 'clean.bat'^)
  echo   $task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings -Description 'Deletes old PCAP files to save hard drive space.'
  echo   $null = Register-ScheduledTask -InputObject $task -Force -TaskName $name
  echo }else{
  echo   Write-Host "Skipping $name."
  echo }
  echo $name = 'wireshark-capture'
  echo if ^($null -eq ^(Get-ScheduledTask -TaskName $name -ErrorAction 'Ignore'^)^){
  echo   Write-Host "Installing scheduled task $name to run at startup..."
  echo   $trigger = New-ScheduledTaskTrigger -AtStartup
  echo   $principal = New-ScheduledTaskPrincipal -UserID 'NT AUTHORITY\SYSTEM' -LogonType 'ServiceAccount' -RunLevel 'Highest'
  echo   $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances 'IgnoreNew' -Priority 7 -StartWhenAvailable -WakeToRun
  echo   $settings.ExecutionTimeLimit = 'PT0S'
  echo   $action = New-ScheduledTaskAction -Execute ^(Join-Path -Path $PSScriptRoot -ChildPath 'capture.bat'^)
  echo   $task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings -Description 'Passively captures and saves UDP packets to PCAP files.'
  echo   $null = Register-ScheduledTask -InputObject $task -Force -TaskName $name
  echo   Start-ScheduledTask -InputObject ^(Get-ScheduledTask -TaskName $name^)
  echo }else{
  echo   Write-Host "Skipping $name."
  echo }
)>"%~dp0task_creator.ps1"
mkdir "%~dp0data" >nul 2>nul
PowerShell -ExecutionPolicy Bypass -NoLogo -File "%~dp0task_creator.ps1"
del /F "%~dp0task_creator.ps1" >nul 2>nul
echo Done.
echo.

:exitLabel
echo Press any key to exit...
pause >nul
exit