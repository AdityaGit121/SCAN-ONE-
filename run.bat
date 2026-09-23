@echo off
setlocal enabledelayedexpansion

title Safety Downloader - Active Server Console
color 0A

echo ===============================================================================
echo                SAFETY DOWNLOADER PLATFORM - RUNTIME LAUNCHER
echo ===============================================================================
echo.

:: 1. Verify Node.js is installed
where node >nul 2>nul
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Node.js is not installed. Please run setup.bat first or install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

:: 2. Check if node_modules exists, if not trigger setup
if not exist "node_modules\" (
    echo [NOTICE] node_modules not found. Running setup.bat to install dependencies...
    echo.
    call setup.bat
    if %errorlevel% neq 0 (
        exit /b %errorlevel%
    )
)

:: 3. Check environment
if not exist ".env" (
    if exist ".env.example" (
        copy /y ".env.example" ".env" >nul
    )
)

set PORT=3000
for /f "usebackq tokens=1,2 delims==" %%A in (`findstr /R "^PORT=" .env 2^>nul`) do (
    if "%%A"=="PORT" set PORT=%%B
)

echo [INFO] Starting Security Engine on http://localhost:%PORT% ...
echo [INFO] Opening user interface in your default browser...
echo [INFO] Press Ctrl+C in this window at any time to stop the server.
echo.

:: Open default browser after a brief pause
start "" http://localhost:%PORT%

:: Start the Express server
node server.js

if %errorlevel% neq 0 (
    color 0C
    echo.
    echo [ERROR] Server terminated unexpectedly with error code %errorlevel%.
    pause
)
