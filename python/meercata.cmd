@echo off
setlocal
set "MEERCATA_DIR=%~dp0"

rem Elevated batch files can start in C:\Windows\System32. Always anchor the
rem Windows launcher in the application directory so bundled modules and
rem relative evidence paths resolve consistently.
pushd "%MEERCATA_DIR%"
if errorlevel 1 (
    echo [ERR] Unable to enter the Meercata directory: %MEERCATA_DIR% 1>&2
    exit /b 1
)

py.exe -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
if %errorlevel% equ 0 goto run_py

python.exe -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
if %errorlevel% equ 0 goto run_python

echo [ERR] Python 3.10 or newer is required and was not found in PATH. 1>&2
echo [SUGGEST] Install Python from python.org and enable "Add Python to PATH". 1>&2
popd
exit /b 1

:run_py
py.exe -3 "%MEERCATA_DIR%main.py" %*
set "MEERCATA_EXIT_CODE=%errorlevel%"
popd
exit /b %MEERCATA_EXIT_CODE%

:run_python
python.exe "%MEERCATA_DIR%main.py" %*
set "MEERCATA_EXIT_CODE=%errorlevel%"
popd
exit /b %MEERCATA_EXIT_CODE%
