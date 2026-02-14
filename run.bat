@echo off
setlocal enabledelayedexpansion

REM ------------------------------------------------------------------------------
REM CDP Network Audit Tool - Portable Launcher
REM Version: 2.0
REM ------------------------------------------------------------------------------
REM This launcher provides a professional interface for running the CDP audit
REM with automatic validation, colored output, and helpful diagnostics.
REM 
REM # SPDX-License-Identifier: GPL-3.0-only
REM # Copyright (c) 2026 Christopher Davies
REM
REM ------------------------------------------------------------------------------

set "ROOT=%~dp0"
set "PYTHON=%ROOT%portable_env\Scripts\python.exe"
set "PACKAGE_DIR=%ROOT%cdp_audit"
set "VENV_DIR=%ROOT%portable_env"

REM Enable colors (Windows 10+)
for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do set "ESC=%%b"

cls
echo.
echo ================================================================================
echo                     CDP NETWORK AUDIT TOOL
echo ================================================================================
echo.
echo Starting validation checks...
echo.

REM Check if Python virtual environment exists
if not exist "%VENV_DIR%" (
    echo [!] ERROR: Virtual environment not found
    echo     Expected location: %VENV_DIR%
    echo.
    echo     Please ensure the portable_env folder exists in the same directory
    echo     as this script.
    goto :error
)

REM Check if Python executable exists
if not exist "%PYTHON%" (
    echo [!] ERROR: Python executable not found
    echo     Expected location: %PYTHON%
    echo.
    echo     Please reinstall the portable environment.
    goto :error
)

REM Check if package exists
if not exist "%PACKAGE_DIR%\__init__.py" (
    echo [!] ERROR: Package not found
    echo     Expected location: %PACKAGE_DIR%\__init__.py
    echo.
    echo     Please ensure the cdp_audit package exists in the same directory as this script.
    goto :error
)

REM Display Python version (simple check)
echo [OK] Python Environment: Found at portable_env\Scripts\python.exe

REM Check for required support files
set ERRORS=0
if not exist "%ROOT%ProgramFiles\textfsm\cisco_ios_show_cdp_neighbors_detail.textfsm" set /a ERRORS+=1
if not exist "%ROOT%ProgramFiles\textfsm\cisco_ios_show_version.textfsm" set /a ERRORS+=1
if not exist "%ROOT%ProgramFiles\config_files\1 - CDP Network Audit _ Template.xlsx" set /a ERRORS+=1

if %ERRORS% EQU 0 (
    echo [OK] Required support files found
) else (
    echo.
    echo [WARNING] %ERRORS% required file^(s^) missing. The script may fail.
    echo     Do you want to continue anyway? ^(Y/N^)
    choice /C YN /N /M ""
    if errorlevel 2 goto :cancelled
)

echo [OK] All validation checks passed
echo.
echo ================================================================================
echo.
echo Running CDP Network Audit...
echo.
echo ================================================================================
echo.

REM Activate the virtual environment and run the module
call "%ROOT%portable_env\Scripts\activate.bat"
python -m cdp_audit %*
set EXIT_CODE=%ERRORLEVEL%
call "%ROOT%portable_env\Scripts\deactivate.bat" 2>nul

echo.
echo ================================================================================
echo.

REM Display result based on exit code
if %EXIT_CODE% EQU 0 (
    echo [SUCCESS] Script completed successfully
) else (
    echo [ERROR] Script exited with error code: %EXIT_CODE%
    echo.
    echo Common issues:
    echo   - Check that credentials are correct
    echo   - Verify jump server is reachable
    echo   - Ensure seed devices are accessible
    echo   - Review debug.log for detailed error messages
)

echo.
echo ================================================================================
echo.
pause
endlocal
exit /b %EXIT_CODE%

:error
echo.
echo ================================================================================
echo.
echo [FAILED] Unable to start CDP Network Audit Tool
echo.
echo Please contact support or check the documentation for troubleshooting steps.
echo.
echo ================================================================================
echo.
pause
endlocal
exit /b 1

:cancelled
echo.
echo Operation cancelled by user.
echo.
pause
endlocal
exit /b 2
