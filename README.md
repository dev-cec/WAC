# WAC (Windows Artefact Collector) 🛠️  
![version](https://img.shields.io/badge/Architecture-64bit-red)  
![CPP](https://img.shields.io/badge/Microsoft_Visual_C++-2022-blue)

## 🔎 OVERVIEW

The idea behind this tool is to provide a **fast extraction** ⚡ of numerous artefacts and event logs from a running Windows machine.  
The export is in **JSON format** 🧾, making it easy to integrate the data into a monitoring or analysis solution.

## 📄 DESCRIPTION

WAC is a forensic tool for **Windows 10 and later**, written in **C++ (Visual Studio 2022)**.  
It extracts various artefacts in **JSON format**, including:

- **Using the Win32 API** :
  - 🖥️ System information (including timezone and runtime)
  - ⏰ Scheduled tasks  
  - 🔐 Open sessions  
  - ⚙️ Running processes  
  - 👤 User accounts  
  - 🧩 Services  
  - 📑 Event logs (optional)

- **By parsing the registry** :
  - 🧭 UserAssist  
  - 🗂️ MUICache  
  - 🕵️ Background Activity Monitor (BAM)  
  - 🔌 USB devices  
  - 🧳 Shellbags  
  - 📂 MRU entries  
  - 🚀 RUN keys analysis  
  - 🧱 Shimcache  
  - 🗃️ Amcache  
  - 🧷 Jumplists  

- **By parsing disk files** :
  - 📄 Prefetch files  
  - 📝 Recent documents

## ▶️ USAGE

To minimize disk traces, this standalone tool should be run **as administrator** 🔐 from a USB stick using the command:

```
Regparser_cpp --dump --debug
```

### ⚙️ Options :

- `--dump` : Adds a hexadecimal dump of binary registry values to the output file  
- `--debug` : Logs processing errors to a separate JSON error file  
- `--events` : Converts event logs to JSON (may take several minutes)  

All options are optional and **disabled by default**.

## 📚 DOCUMENTATION

The full documentation is available in the repository in **HTML format**.

## 🛡️ FORENSIC SAFETY

Accessing the live registry requires creating a temporary **Volume Shadow Copy**.  
This operation is recorded in the Windows Event Logs 📋.

## 🧪 SAMPLE OUTPUT

Example of extracted system information:

```json
{ 
  "OsArchitecture": "x64 (AMD or Intel)", 
  "OsName": "Windows 10 Professionnel", 
  "ComputerName": "N5-00-00022-P02", 
  "DomainName": "ecole-air.fr", 
  "LocalDateTime": "14/5/2025 13h1m37s", 
  "LocalDateTimeUtc": "14/5/2025 11h1m37s", 
  "CurrentTimeZoneId": "Romance Standard Time", 
  "CurrentTimeZoneCaption": "Paris, Madrid", 
  "CurrentBias": "-120", 
  "DaylightInEffect": "true", 
  "Version": "10.0.19045", 
  "ServicePack": "" 
}
```

Output files are saved in :  
- 📁 The `output` directory for standard results  
- ⚠️ The `errors` directory for logs when using `--debug`

## 🚀 PERFORMANCE

- Without event logs: ~10 seconds ⏱️  
- With event logs: ~10 minutes ⌛

## 🧰 BUILD REQUIREMENTS

- Requires **Windows SDK 10** and **Windows WDK 10**  
- 📥 Download: [Microsoft WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
