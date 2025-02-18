<a href="https://github.com/PowerShell/PowerShell"><img src="https://img.shields.io/badge/Language-Powershell-blue"></a> <img src="https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen"> <a href="https://github.com/evild3ad/MemProcFS-Analyzer/releases/latest"><img src="https://img.shields.io/github/v/release/evild3ad/MemProcFS-Analyzer?label=Release"></a> <a href="https://x.com/LETHAL_DFIR"><img src="https://img.shields.io/twitter/follow/LETHAL_DFIR?style=social"></a>

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
* Scan w/ Custom YARA rules (incl. 391 rules by e.g. [Chronicle](https://github.com/chronicle/GCTI/tree/main/YARA) and [Elastic Security](https://github.com/elastic/protections-artifacts))  
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
* Analyzing extracted Amcache.hve w/ AmcacheParser ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Analyzing Application Compatibility Cache aka ShimCache w/ AppCompatcacheParser ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Analyzing Syscache w/ RECmd ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Analyzing UserAssist Artifacts w/ RECmd ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Analyzing ShellBags Artifacts w/ RECmd ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Simple Prefetch View (based on Forensic Timeline)  
* Analyzing Auto-Start Extensibility Points (ASEPs) w/ RECmd ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Analyzing RecentDocs, Office Trusted Document w/ RECmd ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Analyzing Registry w/ RECmd DFIR Batch File ([DFIR Batch File](https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/DFIRBatch.md) by Andrew Rathbun)  
* Analyzing Metadata of Recovered Process Modules (experimental)  
* Analyzing Microsoft Protection Logs (experimental)  
* Extracting Windows Shortcut Files (LNK)  
* Hunting Malicious Windows Shortcut Files (LNK)
* Integration of PowerShell module [ImportExcel](https://github.com/dfinke/ImportExcel) by Doug Finke
* CSV output data for analysis w/ Timeline Explorer (e.g. timeline-reverse.csv, findevil.csv, web.csv)  
* Collecting Evidence Files (Secure Archive Container &#8594; PW: MemProcFS)  
* Offline-Mode  
* and much more

## Download 
Download the latest version of **MemProcFS-Analyzer** from the [Releases](https://github.com/evild3ad/MemProcFS-Analyzer/releases) section.  

## Usage  
Launch Windows PowerShell (or Windows PowerShell ISE or Visual Studio Code w/ PSVersion: 5.1) as Administrator and open/run MemProcFS-Analyzer.ps1. 

![First-Run](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/01.png)  
**Fig 1:** MemProcFS-Analyzer.ps1 (First Run) &#8594; Updater.ps1

![Updater](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/02.png)  
**Fig 2:** Updater.ps1 automatically installs/updates all dependencies (First Run)

![File-Browser](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/03.png)  
**Fig 3:** Select your Memory Snapshot and select your pagefile.sys (Optional)

![Microsoft-Internet-Symbol-Store](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/04.png)  
**Fig 4:** Accept Terms of Use (First Run)  

![MemProcFS](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/05.png)  
**Fig 5:** If you find MemProcFS useful, please become a sponsor at: https://github.com/sponsors/ufrisk  

![MountPoint](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/06.png)  
**Fig 6:** You can investigate the mounted memory dump by exploring drive letter

![FindEvil](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/07.png)  
**Fig 7:** FindEvil feature and additional analytics

![Processes](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/08.png)  
**Fig 8:** Processes

![RunningAndExited](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/09.png)  
**Fig 9:** Running and Exited Processes

![ProcessTree](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/10.png)  
**Fig 10:** Process Tree (GUI)

![ProcessTreeSearch](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/11.png)  
**Fig 11:** Checking Process Tree (to find anomalies)

![ProcessTreeAlerts](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/12.png)  
**Fig 12:** Process Tree: Alert Messages w/ Process Call Chain

![PropertiesView](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/13.png)  
**Fig 13:** Process Tree: Properties View &#8594; Double-Click on a process or alert message

![IPinfo](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/14.png)  
**Fig 14:** GeoIP w/ IPinfo.io

![MapReport](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/15.png)  
**Fig 15:** Map IPs w/ IPinfo.io

![EVTX](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/16.png)  
**Fig 16:** Processing Windows Event Logs (EVTX)

![Zircolite](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/17.png)  
**Fig 17:** Zircolite - A standalone SIGMA-based detection tool for EVTX (Mini-GUI)

![Amcache](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/18.png)  
**Fig 18:** Processing extracted Amcache.hve &#8594; XLSX  

![ShimCache](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/19.png)  
**Fig 19:** Processing ShimCache &#8594; XLSX  

![Timeline-Explorer](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/20.png)  
**Fig 20:** Analyze CSV output w/ Timeline Explorer (TLE)

![ELK-Import](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/21.png)  
**Fig 21:** ELK Import

![ELK-Timeline](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/22.png)  
**Fig 22:** Happy ELK Hunting!

![Secure-Archive-Container](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/23.png)  
**Fig 23:** Multi-Threaded ClamAV Scan to help you finding evil! ;-)

![Message-Box](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/24.png)  
**Fig 24:** Press **OK** to shutdown MemProcFS and Elastisearch/Kibana

![Output](https://github.com/evild3ad/MemProcFS-Analyzer/blob/f68d625bafec260f85d781c90446a9196c5accde/Screenshots/25.png)  
**Fig 25:** Secure Archive Container (PW: MemProcFS)  

## Introduction MemProcFS and Memory Forensics  
Check out [Super Easy Memory Forensics](https://www.slideshare.net/IIJ_PR/super-easy-memory-forensics) by [Hiroshi Suzuki](https://twitter.com/herosi_t) and [Hisao Nashiwa](https://twitter.com/unk0unk0).

## Prerequisites 
1. Download and install the latest Dokany Library Bundle &#8594; DokanSetup.exe  
https://github.com/dokan-dev/dokany/releases/latest  

2. Download and install the latest .NET 6 Desktop Runtime (Requirement for [EZTools](https://ericzimmerman.github.io/))  
https://dotnet.microsoft.com/en-us/download/dotnet/6.0   

3. Download and install the latest Windows package of ClamAV &#8594; .msi  
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
7-Zip 24.08 Standalone Console (2024-08-11)  
https://www.7-zip.org/download.html  

AmcacheParser v1.5.1.0 (.NET 6)  
https://ericzimmerman.github.io/  

AppCompatCacheParser v1.5.0.0 (.NET 6)  
https://ericzimmerman.github.io/  

ClamAV - Download &#8594; Windows &#8594; clamav-1.4.1.win.x64.msi (2024-09-04)  
https://www.clamav.net/downloads    

Dokany File System Library v2.2.0.1000 (2024-08-18)  
https://github.com/dokan-dev/dokany/releases/latest &#8594; DokanSetup.exe  

Elasticsearch 8.16.0 (2024-11-12)  
https://www.elastic.co/downloads/elasticsearch  

entropy v1.1 (2023-07-28)  
https://github.com/merces/entropy  

EvtxECmd v1.5.0.0 (.NET 6)  
https://ericzimmerman.github.io/  

ImportExcel v7.8.10 (2024-10-21)  
https://github.com/dfinke/ImportExcel  

IPinfo CLI 3.3.1 (2024-03-01)    
https://github.com/ipinfo/cli  

jq v1.7.1 (2023-12-13)  
https://github.com/stedolan/jq  

Kibana 8.16.0 (2024-11-12)  
https://www.elastic.co/downloads/kibana  

lnk_parser v0.2.0 (2022-08-10)  
https://github.com/AbdulRhmanAlfaifi/lnk_parser  

MemProcFS v5.12.6 - The Memory Process File System (2024-10-09)      
https://github.com/ufrisk/MemProcFS  

RECmd v2.0.0.0 (.NET 6)  
https://ericzimmerman.github.io/  

SBECmd v2.0.0.0 (.NET 6)  
https://ericzimmerman.github.io/  

xsv v0.13.0 (2018-05-12)  
https://github.com/BurntSushi/xsv  

YARA v4.5.2 (2024-09-10)  
https://virustotal.github.io/yara/  

Zircolite v2.30.1 (2024-10-13)  
https://github.com/wagga40/Zircolite  

## Links
[MemProcFS](https://github.com/ufrisk/MemProcFS)  
[Demo of MemProcFS with Elasticsearch](https://www.youtube.com/watch?v=JcIlowlrvyI)  
[Sponsor MemProcFS Project](https://github.com/sponsors/ufrisk)  
[MemProcFS-Plugins](https://github.com/ufrisk/MemProcFS-Plugins)  
