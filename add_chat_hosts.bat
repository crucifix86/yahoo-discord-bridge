@echo off
echo Adding Yahoo Chat hosts entries...
echo.

:: Run as Administrator check
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Please run this script as Administrator!
    pause
    exit /b 1
)

:: Add chat-related hosts
echo 192.168.1.121 insider.msg.yahoo.com >> C:\Windows\System32\drivers\etc\hosts
echo 192.168.1.121 chat.yahoo.com >> C:\Windows\System32\drivers\etc\hosts
echo 192.168.1.121 chatroom.msg.yahoo.com >> C:\Windows\System32\drivers\etc\hosts

echo.
echo Done! Yahoo Chat hosts have been added.
echo.
echo Current hosts entries:
type C:\Windows\System32\drivers\etc\hosts | findstr yahoo
echo.
pause
