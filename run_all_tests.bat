@echo off
setlocal EnableDelayedExpansion
REM Browser Security - Single local entry point
REM Runs CI-equivalent validation pipeline, then optionally opens dashboard

set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

cd /d "%SCRIPT_DIR%"
if errorlevel 1 (
	echo.
	echo ====================================
	echo STARTUP FAILED
	echo ====================================
	echo Could not switch to script directory: "%SCRIPT_DIR%"
	echo.
	pause
	exit /b 1
)

echo.
echo ====================================
echo BROWSER SECURITY - LOCAL VALIDATION
echo ====================================
echo.

set "PYTHON_PATH="
if exist "%SCRIPT_DIR%\.venv\Scripts\python.exe" set "PYTHON_PATH=%SCRIPT_DIR%\.venv\Scripts\python.exe"

if exist "%PYTHON_PATH%" (
	powershell.exe -ExecutionPolicy RemoteSigned -File run_local_ci_validation.ps1 -PythonPath "%PYTHON_PATH%"
) else (
	powershell.exe -ExecutionPolicy RemoteSigned -File run_local_ci_validation.ps1
)

if errorlevel 1 (
	echo.
	echo ====================================
	echo VALIDATION FAILED
	echo ====================================
	echo Check errors above.
	echo.
	pause
	exit /b 1
)

echo.
echo ====================================
echo VALIDATION SUCCESSFUL
echo ====================================
echo.

echo Starting HTTP server...
start "Browser Security Report Server" powershell.exe -ExecutionPolicy RemoteSigned -File "%cd%\http_server.ps1" -Port 8888 -Path "%cd%"

timeout /t 3 /nobreak >nul

echo Opening Browser Security Dashboard: http://localhost:8888/dashboard.html
start "" http://localhost:8888/dashboard.html

echo.
echo Server running. Close the server window to stop.
echo.
pause
exit /b 0
