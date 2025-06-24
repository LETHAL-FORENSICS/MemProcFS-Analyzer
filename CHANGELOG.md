# Changelog  

All changes to MemProcFS-Analyzer will be documented in this file.  

## [1.2.0] - 2025-06-24
### Added
- EZTools (.NET 9)
- DFIR RECmd Batch File v2.11 (2025-03-31)
- 423 YARA Custom Rules
- FS_Process_Console
- FS_SysInfo_Network: DNS Information
- Digital Signature

## Fixed
- Minor fixes and improvements

## Changed
- CHANGELOG.md

## [1.1.0] - 2024-09-02
### Added
- Updater.ps1
- FS_Sys_Sysinfo
- FS_Forensic_Prefetch
- 376 YARA Custom Rules
- Offline Mode
- MemProcFS.log
- Microsoft Protection Logs (MPLogs)
- ProcessesAndModules-Extended_Info.ps1 (Collect-MemoryDump)

## Fixed
- Minor fixes and improvements

## [1.0.0] - 2023-11-22
### Added
- Improved Hunting for Suspicious Scheduled Tasks
- 318 YARA Custom Rules
- Get-YaraCustomRules
- Kroll RECmd Batch File v1.22 (2023-06-20)
- Checkbox Forensic Timeline (CSV)
- Checkbox Forensic Timeline (XLSX)
- FindEvil: AV_DETECT

## Fixed
- Minor fixes and improvements

## [0.9.0] - 2023-15-25
### Added
- FS_Forensic_Yara (YARA Custom Rules)
- FS_Forensic_Files (incl. ClamAV)
- Checking for suspicious processes with double file extensions
- Checking for Command and Scripting Interpreters
- Recent Folder Artifacts
- Hunting Suspicious Image Mounts
- OpenSaveMRU (OpenSavePidlMRU)
- LastVisitedMRU (LastVisitedPidlMRU)
- Terminal Server Client (RDP)
- Kroll RECmd Batch File v1.21 (2023-03-04)
- Improved Microsoft Defender AntiVirus Handling
- Improved Drive Letter (Mount Point) Handling

## Fixed
- Minor fixes and improvements

## [0.8.0] - 2023-01-23
### Added
- MUICache
- Windows Background Activity Moderator (BAM)
- Check if it's a Domain Controller
- Check if it's a Microsoft Exchange Server
- Checking for processes spawned from suspicious folder locations
- Checking for suspicious processes without any command-line arguments
- Checking for suspicious process lineage
- Checking for processes with suspicious command-line arguments
- Parent Name (proc.csv, Processes.xlsx, and RunningandExited.xlsx)
- Listing of MiniDumps
- Status Bar (User Interface)

## Fixed
- Minor fixes and improvements

## [0.7.0] - 2022-11-21
### Added
- User Interface
- Pagefile Support
- Zircolite - A standalone SIGMA-based detection tool for EVTX
- Event Log Overview
- Checking for Processes w/ Unusual User Context
- Process Tree: Properties View
- Searching for Cobalt Strike Beacons Configuration(s) w/ 1768.py (needs to be installed manually, disabled by default)
- Simple Prefetch View (based on Forensic Timeline)

## Fixed
- Minor fixes and improvements

## [0.6.0] - 2022-10-10
### Added
- Process Tree (TreeView)
- Unusual Number of Process Instances
- Process Path Masquerading
- Process Name Masquerading (Damerau Levenshtein Distance)
- Suspicious Port Numbers

## Fixed
- Minor fixes and improvements

## [0.5.0] - 2022-09-06
### Added
- BitLocker Plugin
- Kroll RECmd Batch File v1.20 (2022-06-01)
- FS_Forensic_CSV + XLSX
- FS_SysInfo_Users
- Windows Shortcut Files (LNK)
- Process Modules (Metadata)
- Number of Sub-Processes (proc.csv, Processes.xlsx, and RunningandExited.xlsx)
- Colorized Running and Exited Processes (RunningandExited.xlsx)

## Fixed
- Minor fixes and improvements

## [0.4.0] - 2022-07-27
### Added
- Web Browser History
- Forensic Timeline (CSV, XLSX)
- JSON to CSV and XLSX output (including Handles)
- Collecting output of pypykatz and regsecrets (MemProcFS Plugins)
- RecentDocs
- Office Trusted Documents
- Adobe RecentDocs
- Startup Folders

## Fixed
- Minor fixes and improvements

## [0.3.0] - 2021-06-17
### Added
- OS Fingerprinting
- Registry Explorer/RECmd
- UserAssist
- Syscache
- ShellBags Explorer/SBECmd
- Registry ASEPs (Auto-Start Extensibility Points)

## Fixed
- Minor fixes and improvements

## [0.2.0] - 2021-05-26
### Added
- IPinfo CLI
- Collecting Registry Hives
- AmcacheParser
- AppCompatCacheParser (ShimCache)
- PowerShell module 'ImportExcel'
- Collection of PE_INJECT (PW: infected)
- Hunting for suspicious Services
- Hunting for suspicious Scheduled Tasks

## Fixed
- Minor fixes and improvements

## [0.1.0] - 2021-05-15
### Added
- Initial Release
