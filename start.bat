@echo off
title Xanax Obfuscator
cd /d "%~dp0"

where node >nul 2>&1
if errorlevel 1 (
    echo Node.js is not installed or not on PATH.
    echo Install Node.js 18+ from https://nodejs.org/ and run this again.
    pause
    exit /b 1
)

where npm >nul 2>&1
if errorlevel 1 (
    echo npm is not installed or not on PATH.
    pause
    exit /b 1
)

if not exist "node_modules\typescript\bin\tsc" (
    echo Installing dependencies...
    call npm install
    if errorlevel 1 (
        echo npm install failed!
        pause
        exit /b 1
    )
)

echo Building...
call node node_modules\typescript\bin\tsc
if errorlevel 1 (
    echo Build failed!
    pause
    exit /b 1
)

echo Starting server...
node dist\server.js
pause
