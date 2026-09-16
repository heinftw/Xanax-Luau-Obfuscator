@echo off
title Xanax Obfuscator
cd /d "%~dp0"
echo Building...
call npm run build
if errorlevel 1 (
    echo Build failed!
    pause
    exit /b 1
)
echo Starting server...
node dist/server.js
pause