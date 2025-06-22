<img src="https://img.shields.io/badge/Language-Powershell-blue"> <img src="https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen"> ![GitHub Release](https://img.shields.io/github/v/release/evild3ad/MemProcFS-Analyzer) <a href="https://twitter.com/Evild3ad79"><img src="https://img.shields.io/twitter/follow/Evild3ad79?style=social"></a>

# MemProcFS-Analyzer
MemProcFS-Analyzer.ps1 is a PowerShell script utilized to simplify the usage of MemProcFS and to optimize your memory analysis workflow.

MemProcFS - The Memory Process File System by [Ulf Frisk](https://twitter.com/ulffrisk)  
https://github.com/ufrisk/MemProcFS  

Features:
* Fast and easy memory analysis!
* You can mount a memory snapshot (Raw Physical Memory Dump or Microsoft Crash Dump) like a disk image and handle the memory compression feature on Windows
* Auto-Install of MemProcFS, AmcacheParser, AppCompatCacheParser, Elasticsearch, entropy, EvtxECmd, ImportExcel, IPinfo CLI, jq, Kibana, lnk_parser, RECmd, SBECmd, xsv, YARA, and Zircolite  
* Auto-Update of MemProcFS, AmcacheParser, AppCompatCacheParser, Elasticsearch, entropy, EvtxECmd (incl. Maps), ImportExcel, IPinfo CLI, jq, Kibana, lnk_parser, RECmd, SBECmd, xsv, YARA, and Zircolite   
* Update-Info when there's a new version of ClamAV or a new Dokany File System Library Bundle available  
* Pagefile Support
* OS Fingerprinting  
* Scan w/ Custom YARA rules (incl. 423 rules by e.g. [Chronicle](https://github.com/chronicle/GCTI/tree/main/YARA) and [Elastic Security](https://github.com/elastic/protections-artifacts))  
* Multi-Threaded scan w/ ClamAV for Windows  
* Collection of infected files detected by ClamAV for further analysis (PW: infected)
* Collection of injected modules detected by MemProcFS PE_INJECT for further analysis (PW: infected)
* Extracting IPv4/IPv6  
* IP2ASN Mapping and GeoIP w/ [IPinfo CLI](https://github.com/ipinfo/cli) &#8594; Get your token for free at [https://ipinfo.io/signup](https://ipinfo.io/signup)  
* Checking for Suspicious Port Numbers
* [Process Tree](https://github.com/evild3ad/MemProcFS-Analyzer/wiki/Process-Tree) (TreeView) including complete Process Call Chain (Special thanks to [Dominik Schmidt](https://github.com/DaFuqs))
* Checking Processes for Unusual Parent-Child Relationships and Number of Instances  
* Checking Processes for Unusual User Context
* Checking for Process Path Masquerading and Process Name Masquerading (Damerau Levenshtein Distance)
* Web Browser History (Google Chrome, Microsoft Edge and Firefox) 
* Extracting Windows Event Log Files and processing w/ EvtxECmd &#8594; Timeline Explorer ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman) 
* Event Log Overview  
* Processing Windows Event Logs w/ [Zircolite](https://github.com/wagga40/Zircolite) - A standalone SIGMA-based detection tool for EVTX
* Analyzing extracted Amcache.hve w/ Amcacheparser ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Analyzing Application Compatibility Cache aka ShimCache w/ AppCompatcacheParser ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Analyzing Syscache w/ RECmd ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Analyzing UserAssist Artifacts w/ RECmd ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Analyzing ShellBags Artifacts w/ RECmd ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Simple Prefetch View (based on Forensic Timeline)  
* Analyzing Auto-Start Extensibility Points (ASEPs) w/ RECmd ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Analyzing RecentDocs, Office Trusted Document w/ RECmd ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Analyzing Registry w/ Kroll RECmd Batch File ([Kroll Batch File](https://github.com/EricZimmerman/RECmd/projects/1) by Andrew Rathbun)  
* Analyzing Metadata of Recovered Process Modules (experimental)  
* Extracting Windows Shortcut Files (LNK)  
* Hunting Malicious Windows Shortcut Files (LNK)
* Integration of PowerShell module [ImportExcel](https://github.com/dfinke/ImportExcel) by Doug Finke
* CSV output data for analysis w/ Timeline Explorer (e.g. timeline-reverse.csv, findevil.csv, web.csv)  
* Collecting Evidence Files (Secure Archive Container &#8594; PW: MemProcFS)  
* and much more

## Download 
Download the latest version of **MemProcFS-Analyzer** from the [Releases](https://github.com/evild3ad/MemProcFS-Analyzer/releases) section.  

## Usage  
Launch Windows PowerShell (or Windows PowerShell ISE or Visual Studio Code w/ PSVersion: 5.1) as Administrator and open/run MemProcFS-Analyzer.ps1. 

![File-Browser](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0780ec4a5fc62219e12791456f5f1e38d5b10b1a/Screenshots/01.png)  
**Fig 1:** Select your Memory Snapshot and select your pagefile.sys (Optional)

![Auto-Install](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0780ec4a5fc62219e12791456f5f1e38d5b10b1a/Screenshots/02.png)  
**Fig 2:** MemProcFS-Analyzer auto-installs dependencies (First Run)

![Microsoft-Internet-Symbol-Store](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0780ec4a5fc62219e12791456f5f1e38d5b10b1a/Screenshots/03.png)  
**Fig 3:** Accept Terms of Use (First Run)  

![MemProcFS](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0780ec4a5fc62219e12791456f5f1e38d5b10b1a/Screenshots/04.png)  
**Fig 4:** If you find MemProcFS useful, please become a sponsor at: https://github.com/sponsors/ufrisk  

![Mounted](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/05.png)  
**Fig 5:** You can investigate the mounted memory dump by exploring drive letter

![Auto-Update](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0780ec4a5fc62219e12791456f5f1e38d5b10b1a/Screenshots/06.png)  
**Fig 6:** MemProcFS-Analyzer checks for updates (Second Run) 

Note: It's recommended to uncomment/disable the "Updater" function after installation. Check out the "Main" in the bottom of the script.

![FindEvil](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0780ec4a5fc62219e12791456f5f1e38d5b10b1a/Screenshots/07.png)  
**Fig 7:** FindEvil feature and additional analytics

![Processes](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/08.png)  
**Fig 8:** Processes

![RunningAndExited](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/09.png)  
**Fig 9:** Running and Exited Processes

![ProcessTree](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/10.png)  
**Fig 10:** Process Tree (GUI)

![ProcessTreeSearch](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/11.png)  
**Fig 11:** Checking Process Tree (to find anomalies)

![ProcessTreeAlerts](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/12.png)  
**Fig 12:** Process Tree: Alert Messages w/ Process Call Chain

![PropertiesView](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/13.png)  
**Fig 13:** Process Tree: Properties View &#8594; Double-Click on a process or alert message

![IPinfo](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/14.png)  
**Fig 14:** GeoIP w/ IPinfo.io

![MapReport](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/15.png)  
**Fig 15:** Map IPs w/ IPinfo.io

![EVTX](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/16.png)  
**Fig 16:** Processing Windows Event Logs (EVTX)

![Zircolite](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/17.png)  
**Fig 17:** Zircolite - A standalone SIGMA-based detection tool for EVTX (Mini-GUI)

![Amcache](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/18.png)  
**Fig 18:** Processing extracted Amcache.hve &#8594; XLSX  

![ShimCache](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/19.png)  
**Fig 19:** Processing ShimCache &#8594; XLSX  

![Timeline-Explorer](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/20.png)  
**Fig 20:** Analyze CSV output w/ Timeline Explorer (TLE)

![ELK-Import](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/21.png)  
**Fig 21:** ELK Import

![ELK-Timeline](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/22.png)  
**Fig 22:** Happy ELK Hunting!

![Secure-Archive-Container](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0780ec4a5fc62219e12791456f5f1e38d5b10b1a/Screenshots/23.png)  
**Fig 23:** Multi-Threaded ClamAV Scan to help you finding evil! ;-)

![Message-Box](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/24.png)  
**Fig 24:** Press **OK** to shutdown MemProcFS and Elastisearch/Kibana

![Output](https://github.com/evild3ad/MemProcFS-Analyzer/blob/0bb85b553644a29675e4116133e7346b080d07a2/Screenshots/25.png)  
**Fig 25:** Secure Archive Container (PW: MemProcFS)  

## Introduction MemProcFS and Memory Forensics  
Check out [Super Easy Memory Forensics](https://www.slideshare.net/IIJ_PR/super-easy-memory-forensics) by [Hiroshi Suzuki](https://twitter.com/herosi_t) and [Hisao Nashiwa](https://twitter.com/unk0unk0).

## Prerequisites 
1. Download and install the latest Dokany Library Bundle &#8594; DokanSetup.exe  
https://github.com/dokan-dev/dokany/releases/latest  

2. Download and install the latest .NET 6 Desktop Runtime (Requirement for [EZTools](https://ericzimmerman.github.io/))  
https://dotnet.microsoft.com/en-us/download/dotnet/6.0   

3. Download and install the latest Windows package of ClamAV.  
https://www.clamav.net/downloads#otherversions 

4. First Time Set-Up of ClamAV  
Launch Windows PowerShell console as Administrator.  
`cd "C:\Program Files\ClamAV"`  
`copy .\conf_examples\freshclam.conf.sample .\freshclam.conf`  
`copy .\conf_examples\clamd.conf.sample .\clamd.conf`  
`write.exe .\freshclam.conf`  &#8594; Comment or remove the line that says "Example".  
`write.exe .\clamd.conf` &#8594; Comment or remove the line that says "Example".  
https://docs.clamav.net/manual/Usage/Configuration.html#windows  

5. Optimize ClamAV scan speed performance (30% faster)    
Open "C:\Program Files\ClamAV\clamd.conf" with your text editor and search for: "Don't scan files and directories matching regex"  
`ExcludePath "\\heaps\\"`  
`ExcludePath "\\handles\\"`  
`ExcludePath "\\memmap\\vad-v\\"`  
`ExcludePath "\\sys\\pool\\"`  

6. Create your free IPinfo account [approx. 1-2 min]  
https://ipinfo.io/signup?ref=cli  
Open "MemProcFS-Analyzer.ps1" with your text editor, search for "Please insert your Access Token here" and copy/paste your access token.

7. Install the NuGet package provider for PowerShell  
Check if NuGet is available in the package providers by running the following command:  
`Get-PackageProvider -ListAvailable`  
If NuGet is not installed on your system yet, you have to install it.  
`Install-PackageProvider -Name NuGet -Force`  

8. Make sure to comment/uncomment (selectively enable or disable) the functions you want to play with (Elasticsearch and ELKImport are disabled by default). Check out the "Main" in the bottom of the script.  

9.  Done! :smiley:   

Notes: 
- Turn off your antivirus protection temporarily or better exclude your MemProcFS-Analyzer directory from scanning.  
- [Elasticsearch Tips](https://github.com/evild3ad/MemProcFS-Analyzer/wiki/Elasticsearch)

## Dependencies
7-Zip 24.09 Standalone Console (2024-11-29)  
https://www.7-zip.org/download.html  

AmcacheParser v1.5.2.0 (.NET 9)  
https://ericzimmerman.github.io/  

AppCompatCacheParser v1.5.1.0 (.NET 9)  
https://ericzimmerman.github.io/  

ClamAV - Download &#8594; Windows &#8594; clamav-1.4.3.win.x64.msi (2025-06-17)  
https://www.clamav.net/downloads    

Dokany Library Bundle v2.3.0.1000 (2025-04-19)  
https://github.com/dokan-dev/dokany/releases/latest &#8594; DokanSetup.exe  

Elasticsearch 9.0.2 (2025-06-03)  
https://www.elastic.co/downloads/elasticsearch  

entropy v1.1 (2023-07-28)  
https://github.com/merces/entropy  

EvtxECmd v1.5.2.0 (.NET 9)  
https://ericzimmerman.github.io/  

ImportExcel v7.8.10 (2024-10-21)   
https://github.com/dfinke/ImportExcel  

IPinfo CLI 3.3.1 (2024-03-01)    
https://github.com/ipinfo/cli  

jq v1.8.0 (2025-06-01)   
https://github.com/stedolan/jq  

Kibana 9.0.2 (2025-06-03)    
https://www.elastic.co/downloads/kibana  

llnk_parser v0.4.1 (2025-01-02)  
https://github.com/AbdulRhmanAlfaifi/lnk_parser  

MemProcFS v5.14.13 - The Memory Process File System (2025-06-12)    
https://github.com/ufrisk/MemProcFS  

RECmd v2.1.0.0 (.NET 9)  
https://ericzimmerman.github.io/  

SBECmd v2.1.0.0 (.NET 9)  
https://ericzimmerman.github.io/  

xsv v0.13.0 (2018-05-12)  
https://github.com/BurntSushi/xsv  

YARA v4.5.4 (2025-05-27)  
https://virustotal.github.io/yara/  

Zircolite v2.40.0 (2025-04-06)  
https://github.com/wagga40/Zircolite  

## Links
[MemProcFS](https://github.com/ufrisk/MemProcFS)  
[Demo of MemProcFS with Elasticsearch](https://www.youtube.com/watch?v=JcIlowlrvyI)  
[Sponsor MemProcFS Project](https://github.com/sponsors/ufrisk)  
[MemProcFS-Plugins](https://github.com/ufrisk/MemProcFS-Plugins)  
