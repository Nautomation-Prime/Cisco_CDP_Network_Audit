@echo off
setlocal

REM ------------------------------------------------------------------------------
REM CDP Network Audit Tool - Simple Portable Launcher
REM ------------------------------------------------------------------------------
REM %~dp0 expands to the directory where this .bat file lives.
REM This ensures the paths work no matter where the user runs it from.
REM ------------------------------------------------------------------------------

set "ROOT=%~dp0"
set "PYTHON=%ROOT%portable_env\Scripts\python.exe"
set "MAIN=%ROOT%main.py"

if not exist "%PYTHON%" (
    echo [FAIL] Could not find portable Python: %PYTHON%
    pause
    exit /b 1
)

if not exist "%MAIN%" (
    echo [FAIL] Could not find main script: %MAIN%
    pause
    exit /b 1
)

echo Launching CDP Network Audit Tool...
echo.

"%PYTHON%" "%MAIN%" %*

echo.
echo Script completed.
pause

endlocal
exit /b %ERRORLEVEL%