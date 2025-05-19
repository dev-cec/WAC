# WAC (Windows Artefact Collector) 🛠️  
![version](https://img.shields.io/badge/Architecture-64bit-red)  
![CPP](https://img.shields.io/badge/Microsoft_Visual_C++-2022-blue)

## :thumbsup: PROVIDER
This tool is developed by the Aerospace Cyber ​​Defense Center of Excellence of the Air and Space School in Salon-de-Provence on air base 701.
 
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
WAC.exe [--dump] [--debug] [--events] [--output=output] [--errorOutput=errors]
```

### ⚙️ Options :

- `--help` or /?` : show this help 
- `--dump` : add std::hexa value in json files for shellbags and LNK files 
- `--debug` : add error output files
- `--events` : converts events to json (long time)
- `--output=[directory name]` : directory name to store output files starting from current directory. By default the directory is 'output'
- `--errorOutput=[directory name]` : directory name to store error output files starting from current directory. By default the directory is 'errors'

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

**Default output files are saved in :** 
- 📁 The `output` directory for standard results  
- ⚠️ The `errors` directory for logs when using `--debug`

## 🚀 PERFORMANCE

|                              **Architecture**                              | **Without events** | **With Events** |
|:--------------------------------------------------------------------------:|:------------------:|:---------------:|
| - Intel Core i7-8750 2.20 GHz<br>- 16 Go RAM<br>- Windows 11 home Edition <br>- Installed since 162 days |         ⌛5s        |   ⌛19 min 37s   |
| - Intel Core i7-8665U 2.11 GHz<br>- 16 Go RAM<br>- Windows 10 Pro 22H2<br>- Installed since 1323 days  |         ⌛9s        |   ⌛1 min 42s   |
 
## 🧰 BUILD REQUIREMENTS

- Requires **Windows SDK 10** and **Windows WDK 10**  
- 📥 Download: [Microsoft WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
- **Include path** and **lib path** of **project properties directories** must be updated with WKD correct path dependent of WDK installed version. Actually, the configured WDK version is 10.0.26100.0.
