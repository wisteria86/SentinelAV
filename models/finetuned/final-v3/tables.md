### Cut-offs (from clean CALIBRATE threshold part + downloaded installers held out; floor 0.98)

| Type | Held-out clean files | Highest clean score, original | Highest clean score, fine-tuned | Proposed cut-off |
|---|---|---|---|---|
| Win32 | 389 | 0.840 | 0.669 | **0.98** |
| Win64 | 1305 | 0.865 | 0.839 | **0.98** |
| Dot_Net | 1021 | 0.834 | 0.638 | **0.98** |

### Test 1: clean REPORT half (4603 files; 4575 have a sha256 not in any training set)

| Files at or above | 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 | At proposed cut-offs | Max |
|---|---|---|---|---|---|---|---|---|
| original | 15 | 12 | 3 | 0 | 0 | 0 | 0 | 0.929 |
| finetuned | 9 | 3 | 0 | 0 | 0 | 0 | 0 | 0.758 |
| original, unseen sha256 only | 15 | 12 | 3 | 0 | 0 | 0 | | |
| finetuned, unseen sha256 only | 9 | 3 | 0 | 0 | 0 | 0 | | |

Rate at ≥0.9: original 0.065%, fine-tuned 0.000% (limit 0.1%).

Top 20 clean REPORT files, fine-tuned model:

| # | Score | Type | Product | Path | sha256 in training |
|---|---|---|---|---|---|
| 1 | 0.7582 | Win32 | comfyui | `F:\ComfyUI-Installs\ComfyUI\ComfyUI\.venv\Lib\site-packages\setuptools\cli.exe` | no |
| 2 | 0.7551 | Dot_Net | gigabyte | `C:\Program Files (x86)\Gigabyte\AppCenter\PreRun.exe` | no |
| 3 | 0.7377 | Win32 | comfyui | `F:\ComfyUI-Installs\ComfyUI\ComfyUI\.venv\Lib\site-packages\setuptools\gui-32.exe` | no |
| 4 | 0.6738 | Win64 | gigabyte | `C:\Program Files (x86)\Gigabyte\@BIOS\ChangeLogoWin64.exe` | no |
| 5 | 0.6427 | Win32 | gigabyte | `C:\Program Files (x86)\Gigabyte\RGBFusion\UTHardwareMonitorCmd\yccV2.dll` | no |
| 6 | 0.6192 | Win64 | git | `C:\Program Files\Git\usr\libexec\getprocaddr64.exe` | no |
| 7 | 0.5549 | Dot_Net | gigabyte | `C:\Program Files (x86)\Gigabyte\AppCenter\AdjustService.exe` | no |
| 8 | 0.5110 | Win64 | wextract.exe | `C:\WINDOWS\System32\wextract.exe` | no |
| 9 | 0.5085 | Win64 | git | `C:\Program Files\Git\usr\bin\cygwin-console-helper.exe` | no |
| 10 | 0.4809 | Win32 | git | `C:\Program Files\Git\usr\libexec\getprocaddr32.exe` | no |
| 11 | 0.4799 | Dot_Net | gigabyte | `C:\Program Files (x86)\Gigabyte\AppCenter\HTTP_LIB.dll` | no |
| 12 | 0.4753 | Win64 | git | `C:\Program Files\Git\usr\bin\ldh.exe` | no |
| 13 | 0.3479 | Win64 | gigabyte | `C:\Program Files\Gigabyte\Smart Backup\RPMExec.exe` | no |
| 14 | 0.3265 | Win64 | gigabyte | `C:\Program Files\Gigabyte\Smart Backup\RPMMgr.exe` | no |
| 15 | 0.2959 | Win64 | gigabyte | `C:\Program Files\Gigabyte\Smart Backup\Sources\RPMRestoreCpl.exe` | no |
| 16 | 0.2806 | Win32 | gigabyte | `C:\Program Files (x86)\Gigabyte\RGBFusion\AtiTool\tools_driver\remtool64.exe` | no |
| 17 | 0.2716 | Win32 | gigabyte | `C:\Program Files (x86)\Gigabyte\RGBFusion\AtiTool\tools_driver\remtool.exe` | no |
| 18 | 0.2668 | Win64 | comfyui | `F:\ComfyUI-Installs\ComfyUI\ComfyUI\.venv\Lib\site-packages\comfy_kitchen\backends\cuda\_C.abi3.pyd` | no |
| 19 | 0.2562 | Win64 | gigabyte | `C:\Program Files\Gigabyte\Smart Backup\SetupReDriver.exe` | no |
| 20 | 0.2464 | Dot_Net | gigabyte | `C:\Program Files (x86)\Gigabyte\RGBFusion\Uninstall.exe` | no |

### Test 2: MalwareBazaar dev (458 PE samples; detection = share at or above cut-off)

| Model | 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 | At proposed cut-offs |
|---|---|---|---|---|---|---|---|
| original | 91.7% | 88.4% | 81.4% | 76.4% | 62.4% | 55.0% | 62.4% |
| finetuned | 92.8% | 90.4% | 86.0% | 79.5% | 70.1% | 60.5% | 70.1% |

By type:

| Type | Model | n | 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 |
|---|---|---|---|---|---|---|---|---|
| Win32 | original | 119 | 84.9% | 77.3% | 70.6% | 67.2% | 43.7% | 32.8% |
| Win32 | finetuned | 119 | 86.6% | 80.7% | 73.1% | 66.4% | 52.9% | 42.0% |
| Win64 | original | 221 | 92.3% | 89.6% | 78.7% | 71.0% | 55.7% | 46.6% |
| Win64 | finetuned | 221 | 93.7% | 91.9% | 86.9% | 77.8% | 67.0% | 53.8% |
| Dot_Net | original | 118 | 97.5% | 97.5% | 97.5% | 95.8% | 94.1% | 93.2% |
| Dot_Net | finetuned | 118 | 97.5% | 97.5% | 97.5% | 95.8% | 93.2% | 91.5% |

Families with samples below 0.98 (fine-tuned; below / total):

wailsloader 8/8, adware.offercore 8/8, valleyrat 7/9, gcleaner 6/7, unlabeled-dll 6/7, connectwise 5/7, stealc 5/12, overlordrat 5/5, nikrat 4/7, remusstealer 3/8, fleetdeck 3/3, lummastealer 3/5, snappyclient 3/4, cloudhaze 3/4, golstastealer 3/3, desktopstreamrat 2/4, rustystealer 2/9, serorat 2/2, aokigaharastealer 2/8, unlabeled-exe 2/8, umbrarat 2/2, sloppyrat 2/2, netsupport 2/3, inc 2/4, masslogger 2/3

Same list, original: wailsloader 8/8, adware.offercore 8/8, valleyrat 7/9, coinminer 7/9, remusstealer 7/8, gcleaner 6/7, vidar 6/8, unlabeled-exe 6/8, connectwise 5/7, phorpiex 5/6, aokigaharastealer 5/8, unlabeled-dll 5/7, overlordrat 4/5, lummastealer 4/5, snappyclient 4/4, cloudhaze 4/4, wardenstealer 3/12, wannacry 3/7, mmtwstealer 3/6, stealc 3/12, lunexloader 3/6, inc 3/4, fleetdeck 3/3, desktopstreamrat 2/4, mopsstealer 2/3

### Test 3: EMBER2024 newest test week (2024-12-08..14)

| Type | Model | AUC | Detection 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 | False alarms 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Win32 | original | 0.99736 | 96.8% | 95.1% | 89.9% | 86.3% | 81.3% | 77.4% | 2.080% | 0.993% | 0.227% | 0.127% | 0.047% | 0.007% |
| Win32 | finetuned | 0.99681 | 94.6% | 92.1% | 87.1% | 84.0% | 79.1% | 75.1% | 1.533% | 0.733% | 0.187% | 0.107% | 0.013% | 0.000% |
| Win64 | original | 0.99840 | 97.9% | 96.9% | 94.4% | 92.6% | 89.0% | 86.0% | 1.360% | 0.840% | 0.280% | 0.200% | 0.080% | 0.040% |
| Win64 | finetuned | 0.99829 | 96.5% | 95.2% | 91.9% | 89.0% | 83.4% | 77.6% | 0.780% | 0.340% | 0.120% | 0.080% | 0.020% | 0.000% |
| Dot_Net | original | 0.99889 | 98.6% | 97.4% | 94.8% | 92.2% | 88.0% | 83.4% | 1.520% | 1.040% | 0.640% | 0.400% | 0.160% | 0.120% |
| Dot_Net | finetuned | 0.99883 | 98.0% | 96.6% | 93.2% | 90.4% | 85.5% | 80.6% | 1.000% | 0.800% | 0.520% | 0.320% | 0.160% | 0.120% |

Rows per type: Win32 30000 malicious / 30000 benign, Win64 10000 malicious / 10000 benign, Dot_Net 5000 malicious / 5000 benign.

### Validation only (not an acceptance test): held-out 10% of training malware (183 rows)

| Model | 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 |
|---|---|---|---|---|---|---|
| original | 90.7% | 89.1% | 84.7% | 82.0% | 72.7% | 59.6% |
| finetuned | 94.0% | 93.4% | 88.5% | 85.8% | 77.0% | 71.6% |
