@echo off
setlocal

cd /d "%~dp0"

echo ============================================================
echo  DetectForge Local Environment Startup
echo ============================================================
echo.

echo [1/4] Syncing latest from main...
git pull --ff-only origin main
if errorlevel 1 (
    echo [!] git pull skipped or failed - continuing with local state.
    echo     Resolve manually with 'git status' if this is unexpected.
)
echo.

echo [2/4] Refreshing local dashboard data (rules_index, coverage, health)...
call venv\Scripts\python.exe scripts\generate_rules_index.py
if errorlevel 1 (
    echo [!] Dashboard data refresh failed - dashboard may show stale data.
)
echo.

echo [3/4] Starting Control Panel backend (127.0.0.1:8001)...
start "DetectForge Backend" cmd /k "cd /d "%~dp0control-panel-backend" && ..\venv\Scripts\python.exe main.py"

echo [4/4] Starting Dashboard dev server (localhost:5173)...
start "DetectForge Dashboard" cmd /k "cd /d "%~dp0dashboard" && npm run dev"

echo.
echo ============================================================
echo  Backend and dashboard are starting in separate windows.
echo  Dashboard:     http://localhost:5173
echo  Backend API:   http://127.0.0.1:8001
echo ============================================================
echo.
pause
