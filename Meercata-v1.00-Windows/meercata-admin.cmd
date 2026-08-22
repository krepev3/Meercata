@echo off
setlocal

if not "%~1"=="" (
    echo [ERR] meercata-admin.cmd starts the interactive UI and does not accept arguments. 1>&2
    echo [SUGGEST] For CLI options, open a terminal with "Run as administrator" and run meercata.cmd. 1>&2
    exit /b 2
)

set "MEERCATA_ADMIN_LAUNCHER=%~dp0meercata.cmd"
set "MEERCATA_ADMIN_DIR=%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "try { $p = Start-Process -FilePath $env:MEERCATA_ADMIN_LAUNCHER -WorkingDirectory $env:MEERCATA_ADMIN_DIR -Verb RunAs -PassThru -Wait; exit $p.ExitCode } catch { Write-Error $_; exit 1 }"

exit /b %errorlevel%
