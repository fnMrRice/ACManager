@echo off
cd /d "%~dp0"
set "PYTHONPATH=%~dp0.tools\python;%~dp0src"
python windows\main.py
if errorlevel 1 pause
