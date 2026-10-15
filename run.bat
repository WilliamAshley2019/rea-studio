@echo off
rem REA Studio launcher (self-healing, offline-friendly).
cd /d "%~dp0"
set "VPY=%~dp0.venv\Scripts\python.exe"

if not exist "%VPY%" (
    echo Creating virtual environment...
    python -m venv --system-site-packages .venv
    if errorlevel 1 goto :fail
)

"%VPY%" -c "import PySide6.QtWidgets" 2>nul
if errorlevel 1 (
    echo PySide6 is not installed in .venv - installing it now...
    if exist wheels (
        "%VPY%" -m pip install --no-index --find-links wheels pyside6_essentials pyside6_addons shiboken6
    ) else (
        "%VPY%" -m pip install PySide6
    )
    if errorlevel 1 goto :fail
)

"%VPY%" -c "import mcp.client.stdio, yaml" 2>nul
if errorlevel 1 (
    echo Some packages for mcp or pyyaml are missing - checking...
    if exist wheels (
        "%VPY%" -m pip install --no-index --find-links wheels "mcp>=1.2" pyyaml 2>nul
    ) else (
        "%VPY%" -m pip install "mcp>=1.2" pyyaml
    )
    "%VPY%" -c "import mcp.client.stdio, yaml" 2>nul
    if errorlevel 1 (
        "%VPY%" check_deps.py
        goto :fail
    )
)

"%VPY%" main.py %*
goto :eof

:fail
echo.
echo Setup failed - see the message above.
pause
