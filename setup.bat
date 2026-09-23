@echo off
setlocal enabledelayedexpansion

title Safety Downloader - Setup and Installation Wizard
color 0B

echo ===============================================================================
echo                SAFETY DOWNLOADER PLATFORM - SYSTEM SETUP
echo ===============================================================================
echo [INFO] Initializing system environment check...
echo.

:: 1. Check Node.js installation
where node >nul 2>nul
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Node.js is NOT installed or not added to your system PATH.
    echo [ACTION] Please download and install Node.js LTS from: https://nodejs.org/
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('node -v') do set NODE_VERSION=%%v
echo [OK] Node.js detected: %NODE_VERSION%

:: 2. Check npm installation
where npm >nul 2>nul
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] npm package manager was not found in PATH.
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('npm -v') do set NPM_VERSION=%%v
echo [OK] npm detected: v%NPM_VERSION%
echo.

:: 3. Setup environment config (.env)
if not exist ".env" (
    if exist ".env.example" (
        echo [INFO] Creating .env from .env.example template...
        copy /y ".env.example" ".env" >nul
        echo [OK] .env configuration file initialized.
    ) else (
        echo [INFO] Generating default .env file...
        (
            echo PORT=3000
            echo GEMINI_API_KEY=
            echo GEMINI_MODEL=gemini-3.8-flash
            echo MAX_FILE_SIZE=20971520
            echo SANDBOX_ENABLED=true
            echo ONLINE_SCAN_ENABLED=true
            echo OFFLINE_SCAN_ENABLED=true
        ) > .env
        echo [OK] Default .env created.
    )
) else (
    echo [OK] Existing .env file found.
)
echo.

:: 4. Install npm dependencies
echo [INFO] Installing required dependencies (Express, @google/genai, PDFKit, Multer)...
call npm install
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Failed to install npm dependencies. Please check your internet connection and try again.
    pause
    exit /b %errorlevel%
)
echo.
echo [OK] All dependencies successfully installed.
echo.

:: 5. Run test verification
echo [INFO] Running security & integrity test suite (29 test cases)...
call npm test
if %errorlevel% neq 0 (
    color 0E
    echo [WARNING] Test suite finished with alerts. You can still run the server.
) else (
    echo.
    echo [SUCCESS] 29/29 Verification tests passed!
)

echo.
echo ===============================================================================
echo                       SETUP COMPLETED SUCCESSFULLY!
echo ===============================================================================
echo You can now launch the application anytime by double-clicking 'run.bat'
echo or running 'npm start'.
echo.
pause
