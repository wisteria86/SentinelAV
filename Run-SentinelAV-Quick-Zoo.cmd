@rem Purpose: Open the evaluation launcher for one cached Zoo batch.
@rem Works with: Run-SentinelAV-Tests.cmd; tools/evaluation/launch_critical.py
@echo off
call "%~dp0Run-SentinelAV-Tests.cmd" --profile zoo-quick
