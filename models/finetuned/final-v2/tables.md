### Cut-offs (from clean CALIBRATE threshold part + downloaded installers held out; floor 0.98)

| Type | Held-out clean files | Highest clean score, original | Highest clean score, fine-tuned | Proposed cut-off |
|---|---|---|---|---|
| Win32 | 389 | 0.840 | 0.794 | **0.98** |
| Win64 | 1305 | 0.865 | 0.964 | **0.98** |
| Dot_Net | 1021 | 0.834 | 0.621 | **0.98** |

### Test 1: clean REPORT half (4603 files; 4575 have a sha256 not in any training set)

| Files at or above | 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 | At proposed cut-offs | Max |
|---|---|---|---|---|---|---|---|---|
| original | 15 | 12 | 3 | 0 | 0 | 0 | 0 | 0.929 |
| finetuned | 14 | 10 | 0 | 0 | 0 | 0 | 0 | 0.895 |
| original, unseen sha256 only | 15 | 12 | 3 | 0 | 0 | 0 | | |
| finetuned, unseen sha256 only | 14 | 10 | 0 | 0 | 0 | 0 | | |

Rate at ≥0.9: original 0.065%, fine-tuned 0.000% (limit 0.1%).

Top 20 clean REPORT files, fine-tuned model:

| # | Score | Type | Product | Path | sha256 in training |
|---|---|---|---|---|---|
| 1 | 0.8950 | Win64 | comfyui | `F:\ComfyUI-Installs\ComfyUI\ComfyUI\.venv\Lib\site-packages\comfy_kitchen\backends\cuda\_C.abi3.pyd` | no |
| 2 | 0.8932 | Win64 | gigabyte | `C:\Program Files (x86)\Gigabyte\@BIOS\ChangeLogoWin64.exe` | no |
| 3 | 0.8621 | Win64 | git | `C:\Program Files\Git\usr\libexec\getprocaddr64.exe` | no |
| 4 | 0.8312 | Win64 | git | `C:\Program Files\Git\usr\bin\cygwin-console-helper.exe` | no |
| 5 | 0.8110 | Win32 | comfyui | `F:\ComfyUI-Installs\ComfyUI\ComfyUI\.venv\Lib\site-packages\setuptools\cli.exe` | no |
| 6 | 0.8019 | Dot_Net | gigabyte | `C:\Program Files (x86)\Gigabyte\AppCenter\PreRun.exe` | no |
| 7 | 0.7960 | Win32 | comfyui | `F:\ComfyUI-Installs\ComfyUI\ComfyUI\.venv\Lib\site-packages\setuptools\gui-32.exe` | no |
| 8 | 0.7915 | Win64 | git | `C:\Program Files\Git\usr\bin\ldh.exe` | no |
| 9 | 0.7307 | Dot_Net | gigabyte | `C:\Program Files (x86)\Gigabyte\AppCenter\AdjustService.exe` | no |
| 10 | 0.7045 | Win32 | gigabyte | `C:\Program Files (x86)\Gigabyte\RGBFusion\UTHardwareMonitorCmd\yccV2.dll` | no |
| 11 | 0.5447 | Dot_Net | gigabyte | `C:\Program Files (x86)\Gigabyte\AppCenter\HTTP_LIB.dll` | no |
| 12 | 0.5149 | Win32 | gigabyte | `C:\Program Files (x86)\Gigabyte\RGBFusion\AtiTool\tools_driver\remtool64.exe` | no |
| 13 | 0.5032 | Win64 | gigabyte | `C:\Program Files\Gigabyte\Smart Backup\Sources\RPMRestoreCpl.exe` | no |
| 14 | 0.5004 | Win32 | gigabyte | `C:\Program Files (x86)\Gigabyte\RGBFusion\AtiTool\tools_driver\remtool.exe` | no |
| 15 | 0.4885 | Win64 | git | `C:\Program Files\Git\mingw64\bin\create-shortcut.exe` | no |
| 16 | 0.4657 | Win32 | git | `C:\Program Files\Git\usr\libexec\getprocaddr32.exe` | no |
| 17 | 0.4099 | Win64 | gigabyte | `C:\Program Files\Gigabyte\Smart Backup\RPMExec.exe` | no |
| 18 | 0.3902 | Win64 | gigabyte | `C:\Program Files\Gigabyte\Smart Backup\RPMMgr.exe` | no |
| 19 | 0.3741 | Win64 | git | `C:\Program Files\Git\mingw64\bin\curl.exe` | no |
| 20 | 0.3700 | Win64 | comfyui | `F:\ComfyUI-Installs\ComfyUI\standalone-env\Lib\venv\scripts\nt\venvwlauncher.exe` | no |

### Test 2: MalwareBazaar dev (458 PE samples; detection = share at or above cut-off)

| Model | 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 | At proposed cut-offs |
|---|---|---|---|---|---|---|---|
| original | 91.7% | 88.4% | 81.4% | 76.4% | 62.4% | 55.0% | 62.4% |
| finetuned | 96.5% | 95.0% | 90.0% | 85.2% | 77.7% | 69.9% | 77.7% |

By type:

| Type | Model | n | 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 |
|---|---|---|---|---|---|---|---|---|
| Win32 | original | 119 | 84.9% | 77.3% | 70.6% | 67.2% | 43.7% | 32.8% |
| Win32 | finetuned | 119 | 94.1% | 91.6% | 79.8% | 72.3% | 58.8% | 45.4% |
| Win64 | original | 221 | 92.3% | 89.6% | 78.7% | 71.0% | 55.7% | 46.6% |
| Win64 | finetuned | 221 | 97.3% | 95.5% | 91.4% | 86.4% | 79.2% | 70.6% |
| Dot_Net | original | 118 | 97.5% | 97.5% | 97.5% | 95.8% | 94.1% | 93.2% |
| Dot_Net | finetuned | 118 | 97.5% | 97.5% | 97.5% | 95.8% | 94.1% | 93.2% |

Families with samples below 0.98 (fine-tuned; below / total):

wailsloader 8/8, connectwise 5/7, valleyrat 5/9, phorpiex 5/6, unlabeled-dll 5/7, gcleaner 4/7, overlordrat 4/5, snappyclient 4/4, aokigaharastealer 3/8, adware.offercore 3/8, fleetdeck 3/3, desktopstreamrat 2/4, unlabeled-exe 2/8, remusstealer 2/8, netsupport 2/3, inc 2/4, lummastealer 2/5, cloudhaze 2/4, masslogger 2/3, n-able 2/2, guloader 2/2, arkeistealer 1/2, spicerat 1/1, mopsstealer 1/3, rustystealer 1/9

Same list, original: wailsloader 8/8, adware.offercore 8/8, valleyrat 7/9, coinminer 7/9, remusstealer 7/8, gcleaner 6/7, vidar 6/8, unlabeled-exe 6/8, connectwise 5/7, phorpiex 5/6, aokigaharastealer 5/8, unlabeled-dll 5/7, overlordrat 4/5, lummastealer 4/5, snappyclient 4/4, cloudhaze 4/4, wardenstealer 3/12, wannacry 3/7, mmtwstealer 3/6, stealc 3/12, lunexloader 3/6, inc 3/4, fleetdeck 3/3, desktopstreamrat 2/4, mopsstealer 2/3

### Test 3: EMBER2024 newest test week (2024-12-08..14)

| Type | Model | AUC | Detection 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 | False alarms 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Win32 | original | 0.99736 | 96.8% | 95.1% | 89.9% | 86.3% | 81.3% | 77.4% | 2.080% | 0.993% | 0.227% | 0.127% | 0.047% | 0.007% |
| Win32 | finetuned | 0.99735 | 96.7% | 94.7% | 89.9% | 86.5% | 81.9% | 78.3% | 1.940% | 1.020% | 0.253% | 0.133% | 0.040% | 0.000% |
| Win64 | original | 0.99840 | 97.9% | 96.9% | 94.4% | 92.6% | 89.0% | 86.0% | 1.360% | 0.840% | 0.280% | 0.200% | 0.080% | 0.040% |
| Win64 | finetuned | 0.99828 | 97.8% | 96.8% | 94.7% | 92.9% | 89.6% | 86.7% | 1.340% | 0.820% | 0.360% | 0.240% | 0.120% | 0.080% |
| Dot_Net | original | 0.99889 | 98.6% | 97.4% | 94.8% | 92.2% | 88.0% | 83.4% | 1.520% | 1.040% | 0.640% | 0.400% | 0.160% | 0.120% |
| Dot_Net | finetuned | 0.99886 | 98.2% | 96.9% | 94.1% | 91.8% | 87.8% | 82.5% | 1.200% | 0.800% | 0.560% | 0.360% | 0.200% | 0.120% |

Rows per type: Win32 30000 malicious / 30000 benign, Win64 10000 malicious / 10000 benign, Dot_Net 5000 malicious / 5000 benign.

### Validation only (not an acceptance test): held-out 10% of training malware (183 rows)

| Model | 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 |
|---|---|---|---|---|---|---|
| original | 90.7% | 89.1% | 84.7% | 82.0% | 72.7% | 59.6% |
| finetuned | 95.6% | 94.5% | 89.1% | 85.8% | 80.3% | 73.2% |
