@echo off
echo Yahoo Discord Bridge - Hosts File Setup
echo ==========================================
echo.

:: Run as Administrator check
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Please run this script as Administrator!
    pause
    exit /b 1
)

:: Remove old Yahoo entries first
echo Removing old Yahoo entries...
findstr /v /i "yahoo.com" C:\Windows\System32\drivers\etc\hosts > %TEMP%\hosts.tmp
copy /y %TEMP%\hosts.tmp C:\Windows\System32\drivers\etc\hosts >nul

:: Add all required Yahoo hosts
echo Adding Yahoo hosts pointing to 192.168.1.121...
echo. >> C:\Windows\System32\drivers\etc\hosts
echo # Yahoo Discord Bridge >> C:\Windows\System32\drivers\etc\hosts
echo 192.168.1.121 scs.msg.yahoo.com >> C:\Windows\System32\drivers\etc\hosts
echo 192.168.1.121 scsa.msg.yahoo.com >> C:\Windows\System32\drivers\etc\hosts
echo 192.168.1.121 scsb.msg.yahoo.com >> C:\Windows\System32\drivers\etc\hosts
echo 192.168.1.121 scsc.msg.yahoo.com >> C:\Windows\System32\drivers\etc\hosts
echo 192.168.1.121 login.yahoo.com >> C:\Windows\System32\drivers\etc\hosts
echo 192.168.1.121 vcs1.msg.yahoo.com >> C:\Windows\System32\drivers\etc\hosts
echo 192.168.1.121 vcs2.msg.yahoo.com >> C:\Windows\System32\drivers\etc\hosts
echo 192.168.1.121 cs.yahoo.com >> C:\Windows\System32\drivers\etc\hosts
echo 192.168.1.121 insider.msg.yahoo.com >> C:\Windows\System32\drivers\etc\hosts
echo 192.168.1.121 chat.yahoo.com >> C:\Windows\System32\drivers\etc\hosts
echo 192.168.1.121 chatroom.msg.yahoo.com >> C:\Windows\System32\drivers\etc\hosts

echo.
echo Done! Hosts file updated.
echo.
echo Current Yahoo entries:
findstr /i "yahoo" C:\Windows\System32\drivers\etc\hosts
echo.
ipconfig /flushdns
echo DNS cache flushed.
pause
