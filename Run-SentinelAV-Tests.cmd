@rem Purpose: Open critical evaluation or forward explicit evaluation CLI arguments.
@rem Works with: tools/evaluation/launch_critical.py; critical_harness.py; lab/qualification/runner.py
@rem Used by: the CLI, desktop launcher, or packaging workflow

@echo off
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%~dp0src;%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo SentinelAV's Python environment is missing. See docs\CRITICAL-EVALUATION.md.
  pause
  exit /b 1
)
if "%~1"=="" (
  start "" ".venv\Scripts\pythonw.exe" -m tools.evaluation.launch_critical
  exit /b 0
)
".venv\Scripts\python.exe" -m tools.evaluation.launch_critical %*
if errorlevel 3 (
  echo Evaluation could not finish normally. Check the newest logs folder.
  pause
)
