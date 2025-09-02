@echo off
echo Starting Rootkit Detection Tool...
echo.

REM Check for administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Administrator privileges confirmed.
    echo.
) else (
    echo ERROR: This application requires administrator privileges.
    echo Please run this script as an administrator.
    echo.
    pause
    exit /b 1
)

REM Check if Python is installed
python --version >nul 2>&1
if %errorLevel% == 0 (
    echo Python found.
) else (
    echo ERROR: Python is not installed or not in PATH.
    echo Please install Python 3.8 or later.
    pause
    exit /b 1
)

REM Install dependencies if requirements.txt has changed
if exist requirements.txt (
    echo Installing/updating dependencies...
    python -m pip install -r requirements.txt
    if %errorLevel% neq 0 (
        echo ERROR: Failed to install dependencies.
        pause
        exit /b 1
    )
)

REM Create necessary directories
if not exist "logs" mkdir logs
if not exist "data" mkdir data
if not exist "config" mkdir config
if not exist "reports" mkdir reports

echo.
echo Starting Rootkit Detection Tool...
python main.py

if %errorLevel% neq 0 (
    echo.
    echo Application exited with error code %errorLevel%
    pause
)