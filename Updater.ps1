# MemProcFS-Analyzer Updater v0.8
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2026 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2026-11-10
#
#
# ██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
# ██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
# ██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
# ██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
# ███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
# ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
#
#
# Changelog:
# Version 0.1
# Release Date: 2024-09-02
# Initial Release
#
# Version 0.2
# Release Date: 2024-09-15
# Added: Sync for RECmd Batch Files
# Added: Check if the download of the packaged Zircolite binary was successful. Note: Some AV may not like the packaged binaries.
#
# Version 0.3
# Release Date: 2024-10-29
# Added: ClamAV Update
#
# Version 0.4
# Release Date: 2025-06-22
# Added: EZTools (.NET 9)
# Fixed: Minor fixes and improvements
#
# Version 0.5
# Release Date: 2026-04-20
# Fixed: Minor fixes and improvements
#
# Version 0.6
# Release Date: 2026-05-02
# Fixed: Set Invoke-WebRequest Preference to UseBasicParsing (@digitalsleuth)
# Fixed: Minor fixes and improvements
#
# Version 0.7
# Release Date: 2026-08-31
# Added: GitHub API Rate Limit Check
# Fixed: Get-Yara --> Check if the release contains a compiled version for Windows (x64)
# Fixed: Get-Zircolite --> Check if Python is installed
# Fixed: Minor fixes and improvements
#
# Version 0.8
# Release Date: 2026-11-07
# Added: DotNetCheck
# Added: EZTools 2026.10 (.NET 10)
# Added: Zircolite v4 Support
# Fixed: Minor fixes and improvements
#
#
# Tested on Windows 11 Pro (x64) Version 26H2 (10.0.26300.9711) and PowerShell 7.6.9
# Tested on Windows 11 Pro (x64) Version 26H2 (10.0.26300.9711) and PowerShell 5.1 (5.1.26100.9711)
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  MemProcFS-Analyzer Updater v0.8 - Automated Installer/Updater for MemProcFS-Analyzer

.DESCRIPTION
  Updater.ps1 is a PowerShell script utilized to automate the installation and the update process of MemProcFS-Analyzer (incl. all dependencies).

  https://github.com/evild3ad/MemProcFS-Analyzer

.EXAMPLE
  PS> .\Updater.ps1

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Initialisations

# Set Progress Preference to Silently Continue
$OriginalProgressPreference = $Global:ProgressPreference
$Global:ProgressPreference = 'SilentlyContinue'

# Set Invoke-WebRequest Preference to UseBasicParsing
$PSDefaultParameterValues['Invoke-WebRequest:UseBasicParsing'] = $true

#endregion Initialisations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Declarations

# Declarations

# Script Root
if ($PSVersionTable.PSVersion.Major -gt 2)
{
    # PowerShell 3+
    $script:SCRIPT_DIR = $PSScriptRoot
}
else
{
    # PowerShell 2
    $script:SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

# Version
$Version = "v0.8"

# Tools

# 7-Zip

# x64
if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64" -or $env:PROCESSOR_ARCHITEW6432 -eq "AMD64")
{
    $script:7za = "$SCRIPT_DIR\Tools\7-Zip\x64\7za.exe"
}

# x86
if ($env:PROCESSOR_ARCHITECTURE -eq "x86" -and -not $env:PROCESSOR_ARCHITEW6432)
{
    $script:7za = "$SCRIPT_DIR\Tools\7-Zip\x86\7za.exe"
}

# AmcacheParser
$script:AmcacheParser = "$SCRIPT_DIR\Tools\AmcacheParser\AmcacheParser.exe"

# AppCompatCacheParser
$script:AppCompatCacheParser = "$SCRIPT_DIR\Tools\AppCompatCacheParser\AppCompatCacheParser.exe"

# ClamAV
$script:freshclam = "C:\Program Files\ClamAV\freshclam.exe"
$script:clamscan = "C:\Program Files\ClamAV\clamscan.exe"
$script:clamd = "C:\Program Files\ClamAV\clamd.exe"
$script:clamdscan = "C:\Program Files\ClamAV\clamdscan.exe"

# Elasticsearch
$script:Elasticsearch = "$SCRIPT_DIR\Tools\Elasticsearch\bin\elasticsearch.bat"

# entropy
$script:entropy = "$SCRIPT_DIR\Tools\entropy\entropy.exe"

# EvtxECmd
$script:EvtxECmd = "$SCRIPT_DIR\Tools\EvtxECmd\EvtxECmd.exe"

# IPinfo CLI
$script:IPinfo = "$SCRIPT_DIR\Tools\IPinfo\ipinfo.exe"

# jq
$script:jq = "$SCRIPT_DIR\Tools\jq\jq-win64.exe"

# Kibana
$script:Kibana = "$SCRIPT_DIR\Tools\Kibana\bin\kibana.bat"

# lnk_parser
$script:lnk_parser = "$SCRIPT_DIR\Tools\lnk_parser\lnk_parser.exe"

# MemProcFS
$script:MemProcFS = "$SCRIPT_DIR\Tools\MemProcFS\MemProcFS.exe"

# RECmd
$script:RECmd = "$SCRIPT_DIR\Tools\RECmd\RECmd.exe"

# SBECmd
$script:SBECmd = "$SCRIPT_DIR\Tools\SBECmd\SBECmd.exe"

# xsv
$script:xsv = "$SCRIPT_DIR\Tools\xsv\xsv.exe"

# YARA
$script:yara64 = "$SCRIPT_DIR\Tools\YARA\yara64.exe"

# Zircolite
$script:Zircolite = "$SCRIPT_DIR\Tools\Zircolite\Zircolite.exe"

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "MemProcFS-Analyzer Updater $Version - Automated Installer/Updater for MemProcFS-Analyzer"

# Check if the PowerShell script is being run with admin rights
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[Error] This PowerShell script must be run with admin rights." -ForegroundColor Red
    Exit
}

# Create a record of your PowerShell session to a text file
Start-Transcript -Path "$SCRIPT_DIR\Logs\Updater.txt"

# Get Start Time
$startTime = (Get-Date)

# Logo
$Logo = @"
██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
"@

Write-Output ""
Write-Output "$Logo"
Write-Output ""

# Header
Write-Output "MemProcFS-Analyzer Updater $Version - Automated Installer/Updater for MemProcFS-Analyzer"
Write-Output "(c) 2026 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Update date (ISO 8601)
$script:UpdateDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Update date: $UpdateDate UTC"
Write-Output ""

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Updater

Function Updater {

Function InternetConnectivityCheck {

# Internet Connectivity Check (Vista+)
$NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet

# Offline
if (!($NetworkListManager -eq "True"))
{
    Write-Host "[Error] Your computer is NOT connected to the Internet." -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Online
if ($NetworkListManager -eq "True")
{
    # Check if GitHub is reachable
    if (!(Test-NetConnection -ComputerName github.com -Port 443).TcpTestSucceeded)
    {
        Write-Host "[Error] github.com is NOT reachable. Please check your network connection and try again." -ForegroundColor Red
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }

    # Check if ericzimmermanstools.com is reachable
    if (!(Test-NetConnection -ComputerName ericzimmermanstools.com -Port 443).TcpTestSucceeded)
    {
        Write-Host "[Error] ericzimmermanstools.com is NOT reachable. Please check your network connection and try again." -ForegroundColor Red
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}

# GitHub API Rate Limit (60 requests/hour per IP address)
$RateLimit = Invoke-RestMethod -Uri "https://api.github.com/rate_limit"
if ($RateLimit.rate.remaining -eq 0)
{
    $ResetTime = [DateTimeOffset]::FromUnixTimeSeconds($RateLimit.rate.reset).LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss")
    Write-Host "[Info]  GitHub API Rate Limit reached ($($RateLimit.rate.remaining)/$($RateLimit.rate.limit)) — resets at $ResetTime (LocalDateTime)" -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

}

#############################################################################################################################################################################################

Function Get-MemProcFS {

# Check Current Version of MemProcFS
if (Test-Path "$($MemProcFS)")
{
    $CurrentVersion = & $MemProcFS -version | ForEach-Object{($_ -split "MemProcFS v")[1]}
    Write-Output "[Info]  Current Version: MemProcFS v$CurrentVersion"
    Start-Sleep 1
}
else
{
    Write-Output "[Info]  MemProcFS NOT found."
    $CurrentVersion = ""
}

# Determining latest release on GitHub
$Repository = "ufrisk/MemProcFS"
$Releases = "https://api.github.com/repos/$Repository/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)[0]
$Download = ($Response.assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "win_x64" | Where-Object {$_ -notmatch "-latest"} | Out-String).Trim()
$FileName = $Download | ForEach-Object{($_ -split "/")[-1]}
$Version = $FileName | ForEach-Object{($_ -split "_")[4]} | ForEach-Object{($_ -split "-")[0]} | ForEach-Object{($_ -replace "v","")}
$ReleaseDate = ($FileName | ForEach-Object{($_ -split "-")[-1]} | ForEach-Object{($_ -replace "\.zip")}).Insert(4,"-").Insert(7,"-")

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  MemProcFS v$Version ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: MemProcFS v$Version ($ReleaseDate)"
}

# Check if MemProcFS needs to be downloaded/updated
if ($CurrentVersion -ne $Version -Or $null -eq $CurrentVersion)
{
    # Download latest release from GitHub
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Zip = "MemProcFS.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\$Zip"

    if (Test-Path "$SCRIPT_DIR\$Zip")
    {
        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\$Zip" -DestinationPath "$SCRIPT_DIR\Tools\MemProcFS" -Force

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$SCRIPT_DIR\$Zip" -Force
    } 
}
else
{
    Write-Host "[Info]  You are running the most recent version of MemProcFS." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-YaraCustomRules {

# Check Current Version of YARA Custom Rules
if (Test-Path "$SCRIPT_DIR\yara\*")
{
    if (Test-Path "$SCRIPT_DIR\yara\README.md")
    {
        $Content = Get-Content "$SCRIPT_DIR\yara\README.md" | Select-String -Pattern "Last updated:"
        $Pattern = "[0-9]{4}-[0-9]{2}-[0-9]{2}"
        $CurrentVersion = [regex]::Matches($Content, $Pattern).Value
        Write-Output "[Info]  Current Version of YARA Custom Rules: $CurrentVersion"
    }
    else
    {
        Write-Output "[Info]  README.md NOT found."
    }
}
else
{
    Write-Output "[Info]  YARA Custom Rules NOT found."
    $CurrentVersion = ""
}

# Determining latest update on GitHub
$WebRequest = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/evild3ad/yara/main/README.md"
$Content = $WebRequest.Content.Split([Environment]::NewLine) | Select-String -Pattern "Last updated:"
$Pattern = "[0-9]{4}-[0-9]{2}-[0-9]{2}"
$LatestUpdate = [regex]::Matches($Content, $Pattern).Value
Write-Output "[Info]  Latest Update: $LatestUpdate"

# Check if YARA Custom Rules need to be downloaded/updated
if ($CurrentVersion -lt $LatestUpdate -Or $null -eq $CurrentVersion)
{
    # Download latest YARA Custom Rules from GitHub
    Write-Output "[Info]  Downloading YARA Custom Rules ..."
    Invoke-WebRequest "https://github.com/evild3ad/yara/archive/refs/heads/main.zip" -OutFile "$SCRIPT_DIR\yara.zip"

    if (Test-Path "$SCRIPT_DIR\yara.zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\yara")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\yara" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\yara" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\yara.zip" -DestinationPath "$SCRIPT_DIR" -Force

        # Rename Unpacked Directory
        Start-Sleep 10
        Rename-Item "$SCRIPT_DIR\yara-main" "$SCRIPT_DIR\yara" -Force

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$SCRIPT_DIR\yara.zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent YARA Custom Rules." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-Dokany {

# Check Current Version of Dokany File System Library
$Dokany = "$env:SystemDrive\Windows\System32\dokan2.dll"
if (Test-Path "$($Dokany)")
{
    $CurrentVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Dokany).FileVersion
    $LastWriteTime = ((Get-Item $Dokany).LastWriteTime).ToString("yyyy-MM-dd")
    Write-Output "[Info]  Current Version: Dokany File System Library v$CurrentVersion ($LastWriteTime)"
}
else
{
    Write-Output "[Info]  Dokany File System Library NOT found."
    $CurrentVersion = ""
}

# Determining latest release of DokanSetup.exe on GitHub
# Note: Needs possibly a restart of the computer.
$Repository = "dokan-dev/dokany"
$Releases = "https://api.github.com/repos/$Repository/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)[0]
$Tag = $Response.tag_name
$Published = $Response.published_at
if ($Published -is [String])
{
    $ReleaseDate = $Published.split('T')[0] # Windows PowerShell
}
else
{
    $ReleaseDate = $Published.ToString("yyyy-MM-dd") # PowerShell 7
}

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  Dokany File System Library $Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: Dokany File System Library $Tag ($ReleaseDate)"
}

# Check if Dokany File System Library needs to be downloaded/updated
$LatestRelease = $Tag.Substring(1)
if ($CurrentVersion -ne $LatestRelease -Or $null -eq $CurrentVersion)
{
    Write-Host "[Error] Please download/install the latest release of Dokany File System Library manually:" -ForegroundColor Red
    Write-Host "        https://github.com/dokan-dev/dokany/releases/latest (DokanSetup.exe)" -ForegroundColor Red
}
else
{
    Write-Host "[Info]  You are running the most recent version of Dokany File System Library." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function ClamAVUpdate {

# ClamAVUpdate

# freshclam.conf
if (!(Test-Path "C:\Program Files\ClamAV\freshclam.conf"))
{
    Write-Host "[Error] freshclam.conf is missing." -ForegroundColor Red
    Write-Host "        https://docs.clamav.net/manual/Usage/Configuration.html#windows --> First Time Set-Up" -ForegroundColor Red
}

# clamd.conf
if (!(Test-Path "C:\Program Files\ClamAV\clamd.conf"))
{
    Write-Host "[Error] clamd.conf is missing." -ForegroundColor Red
    Write-Host "        https://docs.clamav.net/manual/Usage/Configuration.html#windows --> First Time Set-Up" -ForegroundColor Red
}

# Update
if (Test-Path "$($freshclam)")
{
    # Internet Connectivity Check (Vista+)
    $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet

    if (!($NetworkListManager -eq "True"))
    {
        Write-Host "[Error] Your computer is NOT connected to the Internet. ClamAV cannot check for any updates." -ForegroundColor Red
    }
    else
    {
        # Check if clamav.net is reachable
        if (!(Test-Connection -ComputerName clamav.net -Count 1 -Quiet))
        {
            Write-Host "[Error] clamav.net is NOT reachable. ClamAV cannot check for any updates." -ForegroundColor Red
        }
        else
        {
            Write-Output "[Info]  Checking for ClamAV Updates ..."
            New-Item "$SCRIPT_DIR\Tools\ClamAV" -ItemType Directory -Force | Out-Null
            & $freshclam > "$SCRIPT_DIR\Tools\ClamAV\Update.txt" 2> "$SCRIPT_DIR\Tools\ClamAV\Warning.txt"

            # Update ClamAV Engine
            if (Select-String -Pattern "WARNING: Your ClamAV installation is OUTDATED!" -Path "$SCRIPT_DIR\Tools\ClamAV\Warning.txt" -Quiet)
            {
                Write-Host "[Info]  WARNING: Your ClamAV installation is OUTDATED!" -ForegroundColor Red

                if (Select-String -Pattern "Recommended version:" -Path "$SCRIPT_DIR\Tools\ClamAV\Warning.txt" -Quiet)
                {
                    $WARNING = Get-Content "$SCRIPT_DIR\Tools\ClamAV\Warning.txt" | Select-String -Pattern "Recommended version:"
                    Write-Host "[Info]  $WARNING" -ForegroundColor Red
                }
            }

            # Update Signature Databases
            $Count = (Get-Content "$SCRIPT_DIR\Tools\ClamAV\Update.txt" | Select-String -Pattern "is up to date" | Measure-Object).Count
            if ($Count -match "3")
            {
                Write-Output "[Info]  All ClamAV Virus Databases (CVD) are up-to-date."
            }
            else
            {
                Write-Output "[Info]  Updating ClamAV Virus Databases (CVD) ... "
            }
        }
    }
}
else
{
    Write-Host "[Error] freshclam.exe NOT found." -ForegroundColor Red
}

# Engine Version
if (Test-Path "$($clamscan)")
{
    $Version = & $clamscan -V
    $EngineVersion = $Version.Split('/')[0]
    $Patch = $Version.Split('/')[1]
    Write-Output "[Info]  Engine Version: $EngineVersion (#$Patch)"
}
else
{
    Write-Host "[Error] clamscan.exe NOT found." -ForegroundColor Red
}

}

#############################################################################################################################################################################################

Function Get-Elasticsearch {

# Elasticsearch
# https://github.com/elastic/elasticsearch

# Check Current Version of Elasticsearch
if (Test-Path "$($Elasticsearch)")
{
    $CurrentVersion = & $Elasticsearch --version | ForEach-Object{($_ -split "\s+")[1]} | ForEach-Object{($_ -replace ",","")}
    Write-Output "[Info]  Current Version: Elasticsearch v$CurrentVersion"
    Start-Sleep 1
}
else
{
    Write-Output "[Info]  Elasticsearch NOT found."
    $CurrentVersion = ""
}

# Determining latest release of Elasticsearch on GitHub
$Repository = "elastic/elasticsearch"
$Releases = "https://api.github.com/repos/$Repository/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)
$Versions = $Response.tag_name | Where-Object{($_ -notmatch "-rc")} | Where-Object{($_ -notmatch "-beta")} | ForEach-Object{($_ -replace "v","")}
$Latest = ($Versions | ForEach-Object{[System.Version]$_ } | Sort-Object -Descending | Select-Object -First 1).ToString()
$Item = $Response | Where-Object{($_.tag_name -eq "v$Latest")}
$Tag = $Item.tag_name
$Published = $Item.published_at
if ($Published -is [String])
{
    $ReleaseDate = $Published.split('T')[0] # Windows PowerShell
}
else
{
    $ReleaseDate = $Published.ToString("yyyy-MM-dd") # PowerShell 7
}

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  Elasticsearch $Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: Elasticsearch $Tag ($ReleaseDate)"
}

# Check if Elasticsearch needs to be downloaded/updated
$LatestRelease = $Tag.Substring(1)
if ($CurrentVersion -ne $LatestRelease -Or $null -eq $CurrentVersion)
{
    # Download latest release from elastic.co
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Download = "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$LatestRelease-windows-x86_64.zip"
    $Zip = "Elasticsearch.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\Tools\$Zip"

    if (Test-Path "$SCRIPT_DIR\Tools\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\Elasticsearch")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\Elasticsearch" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\Elasticsearch" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\Tools\$Zip" -DestinationPath "$SCRIPT_DIR\Tools" -Force

        # Rename Unpacked Directory
        Start-Sleep 10
        Rename-Item "$SCRIPT_DIR\Tools\elasticsearch-$LatestRelease" "$SCRIPT_DIR\Tools\Elasticsearch" -Force

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$SCRIPT_DIR\Tools\$Zip" -Force
    } 
}
else
{
    Write-Host "[Info]  You are running the most recent version of Elasticsearch." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-Kibana {

# Kibana
# https://github.com/elastic/kibana

# Check Current Version of Kibana
if (Test-Path "$($Kibana)")
{
    $CurrentVersion = & $Kibana --version | Select-Object -Last 1
    Write-Output "[Info]  Current Version: Kibana v$CurrentVersion"
    Start-Sleep 1
}
else
{
    Write-Output "[Info]  Kibana NOT found."
    $CurrentVersion = ""
}

# Determining latest release of Kibana on GitHub
$Repository = "elastic/kibana"
$Releases = "https://api.github.com/repos/$Repository/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)
$Versions = $Response.tag_name | Where-Object{($_ -notmatch "-rc")} | Where-Object{($_ -notmatch "-beta")} | ForEach-Object{($_ -replace "v","")}
$Latest = ($Versions | ForEach-Object{[System.Version]$_ } | Sort-Object -Descending | Select-Object -First 1).ToString()
$Item = $Response | Where-Object{($_.tag_name -eq "v$Latest")}
$Tag = $Item.tag_name
$Published = $Item.published_at
if ($Published -is [String])
{
    $ReleaseDate = $Published.split('T')[0] # Windows PowerShell
}
else
{
    $ReleaseDate = $Published.ToString("yyyy-MM-dd") # PowerShell 7
}

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  Kibana $Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: Kibana $Tag ($ReleaseDate)"
}

# Check if Kibana needs to be downloaded/updated
$LatestRelease = $Tag.Substring(1)
if ($CurrentVersion -ne $LatestRelease -Or $null -eq $CurrentVersion)
{
    # Download latest release from elastic.co
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Download = "https://artifacts.elastic.co/downloads/kibana/kibana-$LatestRelease-windows-x86_64.zip"
    $Zip = "Kibana.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\Tools\$Zip"

    if (Test-Path "$SCRIPT_DIR\Tools\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\Kibana")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\Kibana" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\Kibana" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        if (Test-Path "$($7za)")
        {
            $DestinationPath = "$SCRIPT_DIR\Tools"
            & $7za x "$SCRIPT_DIR\Tools\$Zip" "-o$DestinationPath" > $null 2>&1
        }
        else
        {
            Write-Host "[Error] 7za.exe NOT found." -ForegroundColor Red
            Stop-Transcript
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }

        # Rename Unpacked Directory
        Start-Sleep 10
        Rename-Item "$SCRIPT_DIR\Tools\kibana-$LatestRelease" "$SCRIPT_DIR\Tools\Kibana" -Force

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$SCRIPT_DIR\Tools\$Zip" -Force
    } 
}
else
{
    Write-Host "[Info]  You are running the most recent version of Kibana." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function DotNetCheck {

# .NET 10 (EZTools)
$Runtime = $null
if (Get-Command -CommandType Application dotnet -ErrorAction SilentlyContinue)
{
    $Runtime = dotnet --list-runtimes | Select-String -Pattern "^Microsoft\.WindowsDesktop\.App (10\.\S+)" | Select-Object -Last 1
}

if ($Runtime)
{
    Write-Output "[Info]  Current Version: .NET Desktop Runtime v$($Runtime.Matches[0].Groups[1].Value)"
    Write-Host "[Info]  .NET 10 is installed (required by EZTools)." -ForegroundColor Green
}
else
{
    Write-Host "[Error] .NET 10 NOT found (required by EZTools). Please download/install .NET 10.0 manually:" -ForegroundColor Red
    Write-Host "        https://dotnet.microsoft.com/en-us/download/dotnet/10.0 (Recommended: .NET Desktop Runtime)" -ForegroundColor Red
}

}

#############################################################################################################################################################################################

Function Get-AmcacheParser {

# AmcacheParser (.NET 10)
# https://ericzimmerman.github.io

# Check Current Version and ETag of AmcacheParser
if (Test-Path "$($AmcacheParser)")
{
    # Current Version
    $CurrentVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($AmcacheParser).FileVersion
    Write-Output "[Info]  Current Version: AmcacheParser v$CurrentVersion"

    # ETag
    if (Test-Path "$SCRIPT_DIR\Tools\AmcacheParser\ETag.txt")
    {
        $CurrentETag = Get-Content "$SCRIPT_DIR\Tools\AmcacheParser\ETag.txt"
    }
    else
    {
        $CurrentETag = ""
    }

    # Determining latest release of AmcacheParser
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://download.ericzimmermanstools.com/net/AmcacheParser.zip"
    $Headers = (Invoke-WebRequest -Uri $URL -UseBasicParsing -Method Head).Headers
    $LatestETag = ($Headers["ETag"]).Replace('"','')
}
else
{
    Write-Output "[Info]  AmcacheParser NOT found."
    $CurrentETag = ""
}

if ($null -eq $CurrentETag -or $CurrentETag -ne $LatestETag)
{
    # Download latest release from ericzimmermanstools.com
    Write-Output "[Info]  Dowloading Latest Release ..."
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://download.ericzimmermanstools.com/net/AmcacheParser.zip"
    $Zip = "AmcacheParser.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $URL -OutFile "$SCRIPT_DIR\Tools\$Zip"

    if (Test-Path "$SCRIPT_DIR\Tools\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\AmcacheParser")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\AmcacheParser" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\AmcacheParser" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\Tools\$Zip" -DestinationPath "$SCRIPT_DIR\Tools\AmcacheParser" -Force

        # Latest ETag of AmcacheParser.zip
        $LatestETag | Out-File "$SCRIPT_DIR\Tools\AmcacheParser\ETag.txt"

        # Remove Downloaded Archive
        Remove-Item "$SCRIPT_DIR\Tools\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of AmcacheParser." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-AppCompatCacheParser {

# AppCompatCacheParser (.NET 10)
# https://ericzimmerman.github.io

# Check Current Version and ETag of AppCompatCacheParser
if (Test-Path "$($AppCompatCacheParser)")
{
    # Current Version
    $CurrentVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($AppCompatCacheParser).FileVersion
    Write-Output "[Info]  Current Version: AppCompatCacheParser v$CurrentVersion"

    # ETag
    if (Test-Path "$SCRIPT_DIR\Tools\AppCompatCacheParser\ETag.txt")
    {
        $CurrentETag = Get-Content "$SCRIPT_DIR\Tools\AppCompatCacheParser\ETag.txt"
    }
    else
    {
        $CurrentETag = ""
    }

    # Determining latest release of AppCompatCacheParser
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://download.ericzimmermanstools.com/net/AppCompatCacheParser.zip"
    $Headers = (Invoke-WebRequest -Uri $URL -UseBasicParsing -Method Head).Headers
    $LatestETag = ($Headers["ETag"]).Replace('"','')
}
else
{
    Write-Output "[Info]  AppCompatCacheParser NOT found."
    $CurrentETag = ""
}

if ($null -eq $CurrentETag -or $CurrentETag -ne $LatestETag)
{
    # Download latest release from ericzimmermanstools.com
    Write-Output "[Info]  Dowloading Latest Release ..."
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://download.ericzimmermanstools.com/net/AppCompatCacheParser.zip"
    $Zip = "AppCompatCacheParser.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $URL -OutFile "$SCRIPT_DIR\Tools\$Zip"

    if (Test-Path "$SCRIPT_DIR\Tools\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\AppCompatCacheParser")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\AppCompatCacheParser" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\AppCompatCacheParser" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\Tools\$Zip" -DestinationPath "$SCRIPT_DIR\Tools\AppCompatCacheParser" -Force

        # Latest ETag of AppCompatCacheParser.zip
        $LatestETag | Out-File "$SCRIPT_DIR\Tools\AppCompatCacheParser\ETag.txt"

        # Remove Downloaded Archive
        Remove-Item "$SCRIPT_DIR\Tools\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of AppCompatCacheParser." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-Entropy {

# entropy
# https://github.com/merces/entropy

# Check Current Version of entropy.exe
if (Test-Path "$($entropy)")
{
    # Current Version
    if (Test-Path "$SCRIPT_DIR\Tools\entropy\Version.txt")
    {
        $CurrentVersion = Get-Content "$SCRIPT_DIR\Tools\entropy\Version.txt"
        $LastWriteTime = ((Get-Item $entropy).LastWriteTime).ToString("yyyy-MM-dd")
        Write-Output "[Info]  Current Version: entropy v$CurrentVersion ($LastWriteTime)"
    }
    else
    {
        $CurrentVersion = ""
    }
}
else
{
    Write-Output "[Info]  entropy.exe NOT found."
    $CurrentVersion = ""
}

# Determining latest release on GitHub
$Repository = "merces/entropy"
$Latest = "https://api.github.com/repos/$Repository/releases/latest"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Latest -UseBasicParsing | ConvertFrom-Json)[0]
$Tag = $Response.tag_name
$Published = $Response.published_at
$Download = ($Response.assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "-win64" | Out-String).Trim()
if ($Published -is [String])
{
    $ReleaseDate = $Published.split('T')[0] # Windows PowerShell
}
else
{
    $ReleaseDate = $Published.ToString("yyyy-MM-dd") # PowerShell 7
}
$LatestRelease = $Tag.Substring(1)

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  entropy $Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: entropy $Tag ($ReleaseDate)"
}

# Check if entropy.exe needs to be downloaded/updated
if ($CurrentVersion -ne $LatestRelease -Or $null -eq $CurrentVersion)
{
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Zip = "entropy.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\$Zip"

    if (Test-Path "$SCRIPT_DIR\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\entropy")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\entropy" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\entropy" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\$Zip" -DestinationPath "$SCRIPT_DIR\Tools" -Force

        # Version
        Write-Output "$LatestRelease" | Out-File "$SCRIPT_DIR\Tools\entropy\Version.txt"

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$SCRIPT_DIR\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of entropy." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-EvtxECmd {

# EvtxECmd (.NET 10)
# https://ericzimmerman.github.io

# Check Current Version and ETag of EvtxECmd
if (Test-Path "$($EvtxECmd)")
{
    # Current Version
    $CurrentVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($EvtxECmd).FileVersion
    Write-Output "[Info]  Current Version: EvtxECmd v$CurrentVersion"

    # ETag
    if (Test-Path "$SCRIPT_DIR\Tools\EvtxECmd\ETag.txt")
    {
        $CurrentETag = Get-Content "$SCRIPT_DIR\Tools\EvtxECmd\ETag.txt"
    }
    else
    {
        $CurrentETag = ""
    }

    # Determining latest release of EvtxECmd
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://download.ericzimmermanstools.com/net/EvtxECmd.zip"
    $Headers = (Invoke-WebRequest -Uri $URL -UseBasicParsing -Method Head).Headers
    $LatestETag = ($Headers["ETag"]).Replace('"','')
}
else
{
    Write-Output "[Info]  EvtxECmd NOT found."
    $CurrentETag = ""
}

if ($null -eq $CurrentETag -or $CurrentETag -ne $LatestETag)
{
    # Download latest release from ericzimmermanstools.com
    Write-Output "[Info]  Dowloading Latest Release ..."
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://download.ericzimmermanstools.com/net/EvtxECmd.zip"
    $Zip = "EvtxECmd.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $URL -OutFile "$SCRIPT_DIR\Tools\$Zip"

    if (Test-Path "$SCRIPT_DIR\Tools\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\EvtxECmd")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\EvtxECmd" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\EvtxECmd" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\Tools\$Zip" -DestinationPath "$SCRIPT_DIR\Tools" -Force

        # Latest ETag of EvtxECmd.zip
        $LatestETag | Out-File "$SCRIPT_DIR\Tools\EvtxECmd\ETag.txt"

        # Remove Downloaded Archive
        Remove-Item "$SCRIPT_DIR\Tools\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of EvtxECmd." -ForegroundColor Green
}

# Updating Event Log Maps
Write-Output "[Info]  Updating Event Log Maps ... "

# Flush Event Log Maps Directory
if (Test-Path "$SCRIPT_DIR\Tools\EvtxECmd\Maps")
{
    Get-ChildItem -Path "$SCRIPT_DIR\Tools\EvtxECmd\Maps" -Recurse | Remove-Item -Force -Recurse
}

# Sync for EvtxECmd Maps
if (Test-Path "$($EvtxECmd)")
{
    & $EvtxECmd --sync > "$SCRIPT_DIR\Tools\EvtxECmd\Maps.log" 2> $null

    # Updates found!
    if (Test-Path "$SCRIPT_DIR\Tools\EvtxECmd\Maps.log")
    {
        if (Get-Content "$SCRIPT_DIR\Tools\EvtxECmd\Maps.log" | Select-String -Pattern "Updates found!" -Quiet)
        {
            Write-Output "[Info]  Event Log Maps updated."
        }
    }
}
else
{
    Write-Host "[Error] EvtxECmd.exe NOT found." -ForegroundColor Red
}

}

#############################################################################################################################################################################################

Function Get-ImportExcel {

# ImportExcel
# https://github.com/dfinke/ImportExcel

# Check installed version(s) of PowerShell module 'ImportExcel' (newest first)
$Installed = @(Get-Module -ListAvailable -Name ImportExcel | Sort-Object Version -Descending)

if ($Installed.Count -gt 0)
{
    $CurrentVersion = $Installed[0].Version.ToString()
    Write-Output "[Info]  Current Version: ImportExcel v$CurrentVersion"
}
else
{
    Write-Output "[Info]  PowerShell module 'ImportExcel' NOT found."
    $CurrentVersion = $null
}

# Determining latest release on PowerShell Gallery
try
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $Latest = Find-Module -Name ImportExcel -Repository PSGallery -ErrorAction Stop
}
catch
{
    Write-Host "[Error] PowerShell Gallery is not reachable. ImportExcel was not updated." -ForegroundColor Red
    Return
}

$LatestRelease = $Latest.Version.ToString()
$ReleaseDate = $Latest.PublishedDate.ToString("yyyy-MM-dd")

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  ImportExcel v$LatestRelease ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: ImportExcel v$LatestRelease ($ReleaseDate)"
}

# Check if ImportExcel needs to be installed or updated
if (($null -eq $CurrentVersion) -or ([version]$CurrentVersion -lt [version]$LatestRelease))
{
    try
    {
        # Install first, so that a failed download doesn't leave the system without ImportExcel
        Write-Output "[Info]  Installing ImportExcel v$LatestRelease ..."
        Install-Module -Name ImportExcel -RequiredVersion $LatestRelease -Scope CurrentUser -Repository PSGallery -Force -ErrorAction Stop

        # Remove older versions (only those known to the current PowerShell edition)
        Get-InstalledModule -Name ImportExcel -AllVersions -ErrorAction SilentlyContinue | Where-Object { [version]$_.Version -lt [version]$LatestRelease } | ForEach-Object {
            Uninstall-Module -Name ImportExcel -RequiredVersion $_.Version -Force -ErrorAction SilentlyContinue
        }
    }
    catch
    {
        Write-Host "[Error] ImportExcel could not be installed: $($_.Exception.Message)" -ForegroundColor Red
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of ImportExcel." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-IPinfo {

# IPinfo CLI
# https://github.com/ipinfo/cli

# Check Current Version of IPinfo CLI
if (Test-Path "$($IPinfo)")
{
    $CurrentVersion = & $IPinfo version
    $LastWriteTime = ((Get-Item $IPinfo).LastWriteTime).ToString("yyyy-MM-dd")
    Write-Output "[Info]  Current Version: IPinfo CLI v$CurrentVersion ($LastWriteTime)"
}
else
{
    Write-Output "[Info]  IPinfo CLI NOT found."
    $CurrentVersion = ""
}

# Determining latest release on GitHub
$Repository = "ipinfo/cli"
$Releases = "https://api.github.com/repos/$Repository/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)

$Asset=0
while($true) {
  $Check = $Response[$Asset].assets | Select-Object @{Name="browser_download_orl"; Expression={$_.browser_download_url}} | Select-String -Pattern "ipinfo_" -Quiet
  if ($Check -eq "True" )
  {
    Break
  }
  else
  {
    $Asset++
  }
}

$TagName = $Response[$Asset].tag_name
$Tag = $TagName.Split("-")[1] 
$Published = $Response[$Asset].published_at
$Download = ($Response[$Asset].assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "windows_amd64" | Out-String).Trim()
if ($Published -is [String])
{
    $ReleaseDate = $Published.split('T')[0] # Windows PowerShell
}
else
{
    $ReleaseDate = $Published.ToString("yyyy-MM-dd") # PowerShell 7
}

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  IPinfo CLI v$Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: IPinfo CLI v$Tag ($ReleaseDate)"
}

# Check if IPinfo CLI needs to be downloaded/updated
if ($CurrentVersion -ne $Tag -Or $null -eq $CurrentVersion)
{
    # Download latest release from GitHub
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Zip = "IPinfo.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\$Zip"

    if (Test-Path "$SCRIPT_DIR\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\IPinfo")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\IPinfo" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\IPinfo" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\$Zip" -DestinationPath "$SCRIPT_DIR\Tools\IPinfo" -Force

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$SCRIPT_DIR\$Zip" -Force

        # Rename Executable
        if (Test-Path "$SCRIPT_DIR\Tools\IPinfo\ipinfo_*")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\IPinfo\ipinfo_*.exe" | Rename-Item -NewName {"ipinfo.exe"}
        }
    } 
}
else
{
    Write-Host "[Info]  You are running the most recent version of IPinfo CLI." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-jq {

# jq - Command-line JSON processor
# https://github.com/stedolan/jq

# Check Current Version of jq
if (Test-Path "$($jq)")
{
    $CurrentVersion = & $jq --version | ForEach-Object{($_ -split "-")[1]}
    Write-Output "[Info]  Current Version: jq v$CurrentVersion"
}
else
{
    Write-Output "[Info]  jq-win64.exe NOT found."
    $CurrentVersion = ""
}

# Determining latest stable release on GitHub
$Repository = "stedolan/jq"
$Latest = "https://api.github.com/repos/$Repository/releases/latest"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Latest -UseBasicParsing | ConvertFrom-Json)[0]
$Tag = $Response.tag_name | ForEach-Object{($_ -split "-")[1]}
$Published = $Response.published_at
$Download = ($Response.assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "jq-win64.exe" | Out-String).Trim()
if ($Published -is [String])
{
    $ReleaseDate = $Published.split('T')[0] # Windows PowerShell
}
else
{
    $ReleaseDate = $Published.ToString("yyyy-MM-dd") # PowerShell 7
}

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  jq v$Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: jq v$Tag ($ReleaseDate)"
}

# Check if jq needs to be downloaded/updated
if ($CurrentVersion -ne $Tag -Or $null -eq $CurrentVersion)
{
    if (Test-Path "$SCRIPT_DIR\Tools\jq\jq-win64.exe")
    {
        Get-ChildItem -Path "$SCRIPT_DIR\Tools\jq" -Recurse | Remove-Item -Force -Recurse
    }
    else
    {
        New-Item "$SCRIPT_DIR\Tools\jq" -ItemType Directory -Force | Out-Null
    }

    # Download latest release from GitHub
    Write-Output "[Info]  Dowloading Latest Release ..."
    $EXE = "jq-win64.exe"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\Tools\jq\$EXE"
}
else
{
    Write-Host "[Info]  You are running the most recent version of jq." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-lnk_parser {

# lnk_parser
# https://github.com/AbdulRhmanAlfaifi/lnk_parser

# Check Current Version of lnk_parser
if (Test-Path "$($lnk_parser)")
{
    $CurrentVersion = & $lnk_parser --version | ForEach-Object{($_ -split "\s+")[1]}
    $LastWriteTime = ((Get-Item $lnk_parser).LastWriteTime).ToString("yyyy-MM-dd")
    Write-Output "[Info]  Current Version: lnk_parser v$CurrentVersion ($LastWriteTime)"
}
else
{
    Write-Output "[Info]  lnk_parser.exe NOT found."
    $CurrentVersion = ""
}

# Determining latest release on GitHub
$Repository = "AbdulRhmanAlfaifi/lnk_parser"
$Latest = "https://api.github.com/repos/$Repository/releases/latest"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Latest -UseBasicParsing | ConvertFrom-Json)[0]
$Tag = $Response.tag_name
$Published = $Response.published_at
$Download = ($Response.assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "lnk_parser_.*\.exe" | Out-String).Trim()
if ($Published -is [String])
{
    $ReleaseDate = $Published.split('T')[0] # Windows PowerShell
}
else
{
    $ReleaseDate = $Published.ToString("yyyy-MM-dd") # PowerShell 7
}

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  lnk_parser $Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: lnk_parser $Tag ($ReleaseDate)"
}

# Check if lnk_parser needs to be downloaded/updated
$LatestRelease = $Tag.Substring(1)
if ($CurrentVersion -ne $LatestRelease -Or $null -eq $CurrentVersion)
{
    if (Test-Path "$SCRIPT_DIR\Tools\lnk_parser\lnk_parser.exe")
    {
        Get-ChildItem -Path "$SCRIPT_DIR\Tools\lnk_parser" -Recurse | Remove-Item -Force -Recurse
    }
    else
    {
        New-Item "$SCRIPT_DIR\Tools\lnk_parser" -ItemType Directory -Force | Out-Null
    }
    
    # Download latest release from GitHub
    Write-Output "[Info]  Dowloading Latest Release ..."
    $EXE = "lnk_parser.exe"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\Tools\lnk_parser\$EXE"
}
else
{
    Write-Host "[Info]  You are running the most recent version of lnk_parser." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-RECmd {

# RECmd (.NET 10)
# https://ericzimmerman.github.io

# Check Current Version and ETag of RECmd
if (Test-Path "$($RECmd)")
{
    # Current Version
    $CurrentVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($RECmd).FileVersion
    Write-Output "[Info]  Current Version: RECmd v$CurrentVersion"

    # SHA1
    if (Test-Path "$SCRIPT_DIR\Tools\RECmd\ETag.txt")
    {
        $CurrentETag = Get-Content "$SCRIPT_DIR\Tools\RECmd\ETag.txt"
    }
    else
    {
        $CurrentETag = ""
    }

    # Determining latest release of RECmd
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://download.ericzimmermanstools.com/net/RECmd.zip"
    $Headers = (Invoke-WebRequest -Uri $URL -UseBasicParsing -Method Head).Headers
    $LatestETag = ($Headers["ETag"]).Replace('"','')
}
else
{
    Write-Output "[Info]  RECmd.exe NOT found."
    $CurrentETag = ""
}

if ($null -eq $CurrentETag -or $CurrentETag -ne $LatestETag)
{
    # Download latest release from ericzimmermanstools.com
    Write-Output "[Info]  Dowloading Latest Release ..."
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://download.ericzimmermanstools.com/net/RECmd.zip"
    $Zip = "RECmd.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $URL -OutFile "$SCRIPT_DIR\Tools\$Zip"

    if (Test-Path "$SCRIPT_DIR\Tools\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\RECmd")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\RECmd" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\RECmd" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\Tools\$Zip" -DestinationPath "$SCRIPT_DIR\Tools" -Force

        # Latest ETag of RECmd.zip
        $LatestETag | Out-File "$SCRIPT_DIR\Tools\RECmd\ETag.txt"

        # Remove Downloaded Archive
        Remove-Item "$SCRIPT_DIR\Tools\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of RECmd." -ForegroundColor Green
}

# Sync for RECmd Batch Files
if (Test-Path "$($RECmd)")
{
    Write-Output "[Info]  Updating RECmd Batch Files ... "
    & $RECmd --sync > "$SCRIPT_DIR\Tools\RECmd\Sync.log" 2> $null

    # No new batch files available
    if (Test-Path "$SCRIPT_DIR\Tools\RECmd\Sync.log")
    {
        if (Get-Content "$SCRIPT_DIR\Tools\RECmd\Sync.log" | Select-String -Pattern "No new batch files available" -Quiet)
        {
            Write-Host "[Info]  No new RECmd Batch Files available." -ForegroundColor Green
        }
    }

    # Updates found!
    if (Test-Path "$SCRIPT_DIR\Tools\RECmd\Sync.log")
    {
        if (Get-Content "$SCRIPT_DIR\Tools\RECmd\Sync.log" | Select-String -Pattern "Updates found!" -Quiet)
        {
            Write-Output "[Info]  RECmd Batch Files updated."
        }
    }
}
else
{
    Write-Output "[Info]  RECmd.exe NOT found."
}

}

#############################################################################################################################################################################################

Function Get-SBECmd {

# SBECmd (.NET 10)
# https://ericzimmerman.github.io

# Check Current Version and ETag of SBECmd
if (Test-Path "$($SBECmd)")
{
    # Current Version
    $CurrentVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($SBECmd).FileVersion
    Write-Output "[Info]  Current Version: SBECmd v$CurrentVersion"

    # ETag
    if (Test-Path "$SCRIPT_DIR\Tools\SBECmd\ETag.txt")
    {
        $CurrentETag = Get-Content "$SCRIPT_DIR\Tools\SBECmd\ETag.txt"
    }
    else
    {
        $CurrentETag = ""
    }

    # Determining latest release of SBECmd
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://download.ericzimmermanstools.com/net/SBECmd.zip"
    $Headers = (Invoke-WebRequest -Uri $URL -UseBasicParsing -Method Head).Headers
    $LatestETag = ($Headers["ETag"]).Replace('"','')
}
else
{
    Write-Output "[Info]  SBECmd NOT found."
    $CurrentETag = ""
}

if ($null -eq $CurrentETag -or $CurrentETag -ne $LatestETag)
{
    # Download latest release from ericzimmermanstools.com
    Write-Output "[Info]  Dowloading Latest Release ..."
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://download.ericzimmermanstools.com/net/SBECmd.zip"
    $Zip = "SBECmd.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $URL -OutFile "$SCRIPT_DIR\Tools\$Zip"

    if (Test-Path "$SCRIPT_DIR\Tools\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\SBECmd")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\SBECmd" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\SBECmd" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\Tools\$Zip" -DestinationPath "$SCRIPT_DIR\Tools\SBECmd" -Force

        # Latest ETag of SBECmd.zip
        $LatestETag | Out-File "$SCRIPT_DIR\Tools\SBECmd\ETag.txt"

        # Remove Downloaded Archive
        Remove-Item "$SCRIPT_DIR\Tools\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of SBECmd." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-XSV {

# xsv
# https://github.com/BurntSushi/xsv

# Check Current Version of xsv
if (Test-Path "$($xsv)")
{
    $CurrentVersion = & $xsv --version
    $LastWriteTime = ((Get-Item $xsv).LastWriteTime).ToString("yyyy-MM-dd")
    Write-Output "[Info]  Current Version: xsv v$CurrentVersion ($LastWriteTime)"
}
else
{
    Write-Output "[Info]  xsv.exe NOT found."
    $CurrentVersion = ""
}

# Determining latest release on GitHub
$Repository = "BurntSushi/xsv"
$Releases = "https://api.github.com/repos/$Repository/releases/latest"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)
$Tag = $Response.tag_name
$Published = $Response.published_at
$Download = ($Response.assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "-x86_64-pc-windows-msvc" | Out-String).Trim()
if ($Published -is [String])
{
    $ReleaseDate = $Published.split('T')[0] # Windows PowerShell
}
else
{
    $ReleaseDate = $Published.ToString("yyyy-MM-dd") # PowerShell 7
}
if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  xsv v$Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: xsv v$Tag ($ReleaseDate)"
}

# Check if xsv needs to be downloaded/updated
if ($CurrentVersion -ne $Tag -Or $null -eq $CurrentVersion)
{
    # Download latest release from GitHub
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Zip = "xsv.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\$Zip"

    if (Test-Path "$SCRIPT_DIR\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\xsv")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\xsv" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\xsv" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\$Zip" -DestinationPath "$SCRIPT_DIR\Tools\xsv" -Force

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$SCRIPT_DIR\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of xsv." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-Yara {

# YARA
# https://github.com/VirusTotal/yara

# Check Current Version of YARA
if (Test-Path "$($yara64)")
{
    $CurrentVersion = & $yara64 --version
    $LastWriteTime = ((Get-Item $yara64).LastWriteTime).ToString("yyyy-MM-dd")
    Write-Output "[Info]  Current Version: YARA v$CurrentVersion ($LastWriteTime)"
}
else
{
    Write-Output "[Info]  yara64.exe NOT found."
    $CurrentVersion = ""
}

# Determining latest release on GitHub that ships a Win64 build
$Repository = "VirusTotal/yara"
$ReleasesUrl = "https://api.github.com/repos/$Repository/releases?per_page=100"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
 
$Releases = (Invoke-WebRequest -Uri $ReleasesUrl -UseBasicParsing | ConvertFrom-Json)
 
$Response = $null
$Download = $null

# Releases are returned newest-first; walk them until one has a -win64 asset
foreach ($Release in $Releases)
{
    if ($Release.prerelease) { continue } # skip pre-releases
 
    $Asset = $Release.assets | Where-Object { $_.browser_download_url -match "-win64" } | Select-Object -First 1
 
    if ($Asset)
    {
        $Response = $Release
        $Download = $Asset.browser_download_url
        break
    }
}

if (-not $Response)
{
    Write-Output "[Error] No release with a -win64 build was found (checked $($Releases.Count) releases)."
    return
}

$Tag = $Response.tag_name
$Published = $Response.published_at
 
if ($Published -is [String])
{
    $ReleaseDate = $Published.split('T')[0] # Windows PowerShell
}
else
{
    $ReleaseDate = $Published.ToString("yyyy-MM-dd") # PowerShell 7
}

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  YARA $Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: YARA $Tag ($ReleaseDate)"
}

# Check if YARA needs to be downloaded/updated
$LatestRelease = $Tag.Substring(1)
if ($CurrentVersion -ne $LatestRelease -Or $null -eq $CurrentVersion)
{
    # Download latest release from GitHub
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Zip = "yara64.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\$Zip"

    if (Test-Path "$SCRIPT_DIR\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\YARA")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\YARA" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\YARA" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\$Zip" -DestinationPath "$SCRIPT_DIR\Tools\YARA" -Force

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$SCRIPT_DIR\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of YARA." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-Zircolite {

# Check Current Version of Zircolite
if (Test-Path "$SCRIPT_DIR\Tools\Zircolite\Zircolite.exe")
{
    $MyLocation = $pwd
    Set-Location "$SCRIPT_DIR\Tools\Zircolite"
    $CurrentVersion = (& $Zircolite --version 2>&1 | Select-String -Pattern "Zircolite -" | ForEach-Object{($_ -split "Zircolite - ")[-1]} | ForEach-Object{($_ -replace "v","")}).Trim()
    Set-Location "$MyLocation"
    Write-Output "[Info]  Current Version: Zircolite v$CurrentVersion"

    # zircolite.log
    if (Test-Path "$SCRIPT_DIR\Tools\Zircolite\zircolite.log")
    {
        Remove-Item -Path "$SCRIPT_DIR\Tools\Zircolite\zircolite.log" -Force
    }
}
else
{
    Write-Output "[Info]  Zircolite NOT found."
    $CurrentVersion = ""
}

# Determining latest stable release on GitHub
$Repository = "https://api.github.com/repos/wagga40/Zircolite/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Release=0
while($false) {
    $Release++
    $Check = (Invoke-WebRequest -Uri $Repository -UseBasicParsing | ConvertFrom-Json)[$Release].prerelease
    if ($Check -eq "False" )
    {
        $Release
        Break
    }
}
    
$Response = (Invoke-WebRequest -Uri $Repository -UseBasicParsing | ConvertFrom-Json)[$Release]
$Tag = $Response.tag_name | ForEach-Object{($_ -replace "v","")}
$Published = $Response.published_at
if ($Published -is [String])
{
    $LatestRelease = $Published.split('T')[0] # PowerShell 5.1
}
else
{
    $LatestRelease = $Published.ToString("yyyy-MM-dd") # PowerShell 7
}

# Packaged Windows binary (x64) - Note: zipball_url contains the source code only (no Zircolite.exe)
$Download = ($Response.assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "Zircolite-.*-windows-x64\.zip$" | Out-String).Trim()
$SHA256SUMS = ($Response.assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "/SHA256SUMS$" | Out-String).Trim()

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  Zircolite v$Tag ($LatestRelease)"
}
else
{
    Write-Output "[Info]  Latest Release: Zircolite v$Tag ($LatestRelease)"
}

# Check if Zircolite needs to be updated
if ($CurrentVersion -ne $Tag -Or $null -eq $CurrentVersion)
{
    # Download latest release from GitHub
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Zip = "Zircolite.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\Tools\$Zip"

    # Verify SHA256 Hash
    if ((Test-Path "$SCRIPT_DIR\Tools\$Zip") -And ($SHA256SUMS))
    {
        $FileName = $Download.Split("/")[-1]
        $Content = (Invoke-WebRequest -Uri $SHA256SUMS -UseBasicParsing).Content
        if ($Content -is [byte[]]) { $Content = [System.Text.Encoding]::UTF8.GetString($Content) } # application/octet-stream
        $Expected = ($Content -split "`n" | Select-String -Pattern ([regex]::Escape($FileName)) | ForEach-Object{($_ -split "\s+")[0]} | Select-Object -First 1)
        $Actual = (Get-FileHash -Path "$SCRIPT_DIR\Tools\$Zip" -Algorithm SHA256).Hash

        if ($Expected -and ($Actual -eq $Expected))
        {
            Write-Output "[Info]  SHA256 Hash verified."
        }
        else
        {
            Write-Host "[Error] SHA256 Hash mismatch: $FileName" -ForegroundColor Red
            Remove-Item "$SCRIPT_DIR\Tools\$Zip" -Force
        }
    }

    if (Test-Path "$SCRIPT_DIR\Tools\$Zip")
    {
        # Unblock Archive File
        Unblock-File -Path "$SCRIPT_DIR\Tools\$Zip"

        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\Zircolite")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\Zircolite" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\Zircolite" -Force
        }

        # Unpacking Archive File
        if (Test-Path "$($7za)")
        {
            Write-Output "[Info]  Extracting Files ..."
            & $7za x "$SCRIPT_DIR\Tools\$Zip" "-o$SCRIPT_DIR\Tools" 2>&1 | Out-Null
        }
        else
        {
            Write-Output "[Info]  7-Zip is NOT installed."
        }

        # Rename Unpacked Directory
        Start-Sleep 5
        if (Test-Path "$SCRIPT_DIR\Tools\Zircolite-*-windows-x64")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\Zircolite-*-windows-x64" | Rename-Item -NewName {"Zircolite"}
        }
        else
        {
            Write-Host "[Error] It seems that the packaged Zircolite binary was blocked by your AV!" -ForegroundColor Red
        }

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$SCRIPT_DIR\Tools\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of Zircolite." -ForegroundColor Green
}

# Update SIGMA Rulesets
if (Test-Path "$SCRIPT_DIR\Tools\Zircolite\Zircolite.exe")
{
    Write-Output "[Info]  Updating SIGMA Rulesets ..."
    $MyLocation = $pwd
    $ConsoleEncoding = [Console]::OutputEncoding
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 # Zircolite v4 writes UTF-8
    $env:COLUMNS = 250 # Prevent line wrapping at 80 characters
    Set-Location "$SCRIPT_DIR\Tools\Zircolite"
    & $Zircolite --update-rules 2>&1 | Out-File "$SCRIPT_DIR\Tools\Zircolite\Update-draft.log"
    Set-Location "$MyLocation"
    Remove-Item Env:\COLUMNS
    [Console]::OutputEncoding = $ConsoleEncoding

    # No newer rulesets found
    if (Test-Path "$SCRIPT_DIR\Tools\Zircolite\Update-draft.log")
    {
        if (Get-Content "$SCRIPT_DIR\Tools\Zircolite\Update-draft.log" | Select-String -Pattern "No newer rulesets" -Quiet)
        {
            Write-Host "[Info]  No newer rulesets found" -ForegroundColor Green
        }
    }

    # Updated
    if (Test-Path "$SCRIPT_DIR\Tools\Zircolite\Update-draft.log")
    {
        if (Get-Content "$SCRIPT_DIR\Tools\Zircolite\Update-draft.log" | Select-String -Pattern "Updated :" -Quiet)
        {
            Write-Output "[Info]  SIGMA Rulesets updated."
        }
    }

    # Remove ANSI Control Characters
    if (Test-Path "$SCRIPT_DIR\Tools\Zircolite\Update-draft.log")
    {
        Get-Content "$SCRIPT_DIR\Tools\Zircolite\Update-draft.log" | ForEach-Object { $_ -replace "\x1b\[[0-9;]*m" } | Out-File "$SCRIPT_DIR\Tools\Zircolite\Update.log"
        Remove-Item "$SCRIPT_DIR\Tools\Zircolite\Update-draft.log"
    }

    # Remove empty lines and add line breaks where needed
    $Clean = Get-Content "$SCRIPT_DIR\Tools\Zircolite\Update.log" | ForEach-Object{($_ -replace "^   ","")} | Where-Object {$_.Trim()} | ForEach-Object {($_ -replace "Finished in", "`nFinished in")} | ForEach-Object {($_ -replace "Sysmon Linux =-", "Sysmon Linux =-`n")}
    @("") + ($Clean) | Set-Content "$SCRIPT_DIR\Tools\Zircolite\Update.log" -Encoding UTF8

    # Cleaning up
    if (Test-Path "$SCRIPT_DIR\Tools\Zircolite\Update.log")
    {
        $Filter = @("^zircolite\.exe","MemProcFS-Analyzer-v.*\.ps1","^\+","\+ CategoryInfo          : NotSpecified:","\+ FullyQualifiedErrorId : NativeCommandError","^tmp-rules-")
        $Clean = Get-Content "$SCRIPT_DIR\Tools\Zircolite\Update.log" | Select-String -Pattern $Filter -NotMatch 
        $Clean | Set-Content "$SCRIPT_DIR\Tools\Zircolite\Update.log" -Encoding UTF8
    }

    # zircolite.log
    if (Test-Path "$SCRIPT_DIR\Tools\Zircolite\zircolite.log")
    {
        Remove-Item -Path "$SCRIPT_DIR\Tools\Zircolite\zircolite.log" -Force
    }
}
else
{
    Write-Host "[Error] zircolite.exe NOT found." -ForegroundColor Red
}

}

#############################################################################################################################################################################################

# Installer/Updater
InternetConnectivityCheck
Get-MemProcFS
Get-YaraCustomRules
Get-Dokany
ClamAVUpdate
Get-Elasticsearch
Get-Kibana
DotNetCheck
Get-AmcacheParser
Get-AppCompatCacheParser
Get-Entropy
Get-EvtxECmd
Get-ImportExcel
Get-IPinfo
Get-jq
Get-lnk_parser
Get-RECmd
Get-SBECmd
Get-XSV
Get-Yara
Get-Zircolite

}

Updater

#endregion Updater

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Footer

# Get End Time
$endTime = (Get-Date)

# Echo Time elapsed
Write-Output ""
Write-Output "FINISHED!"

$Time = ($endTime-$startTime)
$ElapsedTime = ('Overall update duration: {0} h {1} min {2} sec' -f $Time.Hours, $Time.Minutes, $Time.Seconds)
Write-Output "$ElapsedTime"

# Stop logging
Write-Host ""
Stop-Transcript
Start-Sleep 0.5

# Reset Progress Preference
$Global:ProgressPreference = $OriginalProgressPreference

# Reset Windows Title
$Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# SIG # Begin signature block
# MIInkAYJKoZIhvcNAQcCoIIngTCCJ30CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBwXKCWFgW/mto7
# KlX+uj/AcJw/lXjutWc/jYonMIa7EaCCIKQwggYaMIIEAqADAgECAhBiHW0MUgGe
# O5B5FSCJIRwKMA0GCSqGSIb3DQEBDAUAMFYxCzAJBgNVBAYTAkdCMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLTArBgNVBAMTJFNlY3RpZ28gUHVibGljIENvZGUg
# U2lnbmluZyBSb290IFI0NjAeFw0yMTAzMjIwMDAwMDBaFw0zNjAzMjEyMzU5NTla
# MFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxKzApBgNV
# BAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYwggGiMA0GCSqG
# SIb3DQEBAQUAA4IBjwAwggGKAoIBgQCbK51T+jU/jmAGQ2rAz/V/9shTUxjIztNs
# fvxYB5UXeWUzCxEeAEZGbEN4QMgCsJLZUKhWThj/yPqy0iSZhXkZ6Pg2A2NVDgFi
# gOMYzB2OKhdqfWGVoYW3haT29PSTahYkwmMv0b/83nbeECbiMXhSOtbam+/36F09
# fy1tsB8je/RV0mIk8XL/tfCK6cPuYHE215wzrK0h1SWHTxPbPuYkRdkP05ZwmRmT
# nAO5/arnY83jeNzhP06ShdnRqtZlV59+8yv+KIhE5ILMqgOZYAENHNX9SJDm+qxp
# 4VqpB3MV/h53yl41aHU5pledi9lCBbH9JeIkNFICiVHNkRmq4TpxtwfvjsUedyz8
# rNyfQJy/aOs5b4s+ac7IH60B+Ja7TVM+EKv1WuTGwcLmoU3FpOFMbmPj8pz44MPZ
# 1f9+YEQIQty/NQd/2yGgW+ufflcZ/ZE9o1M7a5Jnqf2i2/uMSWymR8r2oQBMdlyh
# 2n5HirY4jKnFH/9gRvd+QOfdRrJZb1sCAwEAAaOCAWQwggFgMB8GA1UdIwQYMBaA
# FDLrkpr/NZZILyhAQnAgNpFcF4XmMB0GA1UdDgQWBBQPKssghyi47G9IritUpimq
# F6TNDDAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUE
# DDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEsGA1Ud
# HwREMEIwQKA+oDyGOmh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1Ymxp
# Y0NvZGVTaWduaW5nUm9vdFI0Ni5jcmwwewYIKwYBBQUHAQEEbzBtMEYGCCsGAQUF
# BzAChjpodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2ln
# bmluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdv
# LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEABv+C4XdjNm57oRUgmxP/BP6YdURhw1aV
# cdGRP4Wh60BAscjW4HL9hcpkOTz5jUug2oeunbYAowbFC2AKK+cMcXIBD0ZdOaWT
# syNyBBsMLHqafvIhrCymlaS98+QpoBCyKppP0OcxYEdU0hpsaqBBIZOtBajjcw5+
# w/KeFvPYfLF/ldYpmlG+vd0xqlqd099iChnyIMvY5HexjO2AmtsbpVn0OhNcWbWD
# RF/3sBp6fWXhz7DcML4iTAWS+MVXeNLj1lJziVKEoroGs9Mlizg0bUMbOalOhOfC
# ipnx8CaLZeVme5yELg09Jlo8BMe80jO37PU8ejfkP9/uPak7VLwELKxAMcJszkye
# iaerlphwoKx1uHRzNyE6bxuSKcutisqmKL5OTunAvtONEoteSiabkPVSZ2z76mKn
# zAfZxCl/3dq3dUNw4rg3sTCggkHSRqTqlLMS7gjrhTqBmzu1L90Y1KWN/Y5JKdGv
# spbOrTfOXyXvmPL6E52z1NZJ6ctuMFBQZH3pwWvqURR8AgQdULUvrxjUYbHHj95E
# jza63zdrEcxWLDX6xWls/GDnVNueKjWUH3fTv1Y8Wdho698YADR7TNx8X8z2Bev6
# SivBBOHY+uqiirZtg0y9ShQoPzmCcn63Syatatvx157YK9hlcPmVoa1oDE5/L9Uo
# 2bC5a4CH2RwwggZrMIIE06ADAgECAhEAjEGek78rzqyIBig7dhm9PDANBgkqhkiG
# 9w0BAQwFADBUMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2MB4X
# DTI0MTExNDAwMDAwMFoXDTI3MTExNDIzNTk1OVowVzELMAkGA1UEBhMCREUxFjAU
# BgNVBAgMDU5pZWRlcnNhY2hzZW4xFzAVBgNVBAoMDk1hcnRpbiBXaWxsaW5nMRcw
# FQYDVQQDDA5NYXJ0aW4gV2lsbGluZzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBANGfbuacjMHp2wkUsx7FBA1F3xoy/vcNOVrrwbpDy75XZNjUlD9niPag
# Ij0BNbcrc/s0A92UTRCa12MLQX/viOx+KX+LwvDG7JPTfjBptWJkpRyh2YqwQWEz
# 1qbxbmRSAu4LkUgrjA06rlN/Nh0dPIm7V5HZe5IOgynTCDjmY64U0FtgHwNUG0fG
# hu9arh4KzeVTFfTvBHdCvZS1v3bDx5Ta8qvZKz3EiH9i8zhTGAGk7Ujo75ba0AHm
# abKciCgJ9fua7qIPcD4CGlD0a/bT0bzfLwU+sUkhZTvtNN6ESts+NnTvjFfCuUSS
# GcZQKTXD4qI21kdpKfRf6+eGonui0HFBlAARKWFZekMoK6eedWdWDC9Va1xwCHFk
# 73l6J/pWyz9SEJoFnbqzOWd4a0V5MKUjj6Teap9a6h21eMdzyiEByVantdXLCWLC
# EIUSwBwWSmQLKK97LSyoR+vCIydHLV6UfVLftdxBpq/n5u3grG0he45UTHe8z0wd
# 2WtpbTLWifkTyLi1qB0jjlMfQtTTzS5tzYwqqrple2mVO7XB0XYKDLeF9JIuQmxx
# FYCm+m847pW1ziNMb8A7qKo3kzpLB36DjRe2zEEP+BKT2QyqSAnWkPUanmCQec/W
# 96635iAn3FZxEMkju9yKz2qxfC1XJt44KHnqtNC8L9N/oEm2KJ4RAgMBAAGjggGz
# MIIBrzAfBgNVHSMEGDAWgBQPKssghyi47G9IritUpimqF6TNDDAdBgNVHQ4EFgQU
# jHJkCYQeXu4B8TBsHifMjwwIItswDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQC
# MAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwSgYDVR0gBEMwQTA1BgwrBgEEAbIxAQIB
# AwIwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNvbS9DUFMwCAYGZ4EM
# AQQBMEkGA1UdHwRCMEAwPqA8oDqGOGh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2Vj
# dGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYuY3JsMHkGCCsGAQUFBwEBBG0wazBE
# BggrBgEFBQcwAoY4aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGlj
# Q29kZVNpZ25pbmdDQVIzNi5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNl
# Y3RpZ28uY29tMCgGA1UdEQQhMB+BHW13aWxsaW5nQGxldGhhbC1mb3JlbnNpY3Mu
# Y29tMA0GCSqGSIb3DQEBDAUAA4IBgQBnR0EwzCW5YZv4wPWsZZo+1pes1meVmo5n
# GBt2swsEoBCvRAZwgsJUhnhJlhp69PnIxHqMUZICOBoW2eTxmlu0bCKD9538L8PU
# 17xJnJ9920Auez/kIfEydTySzu63t2xHrMUPj9uaWO6hSiLnlbr9dT/Wmv62pFpk
# Ym+NIolAI30yEUC9dKk8+pGyPbvN7X4pggEXX8vQFbQdLR31mEZJSgTCowMulB/Z
# 6okXLLLNa3bVVWEsXqaBnV0Tm0ItljsRHPHr+Hk3sXTDfrWiKCLMxsIx1JPb1c5z
# mYHyroLJ7s6YR8zaMHJFZr5x3hHJyw3anbAdG6SmrjyJf609UqYfA0p/66m4o8NA
# B5XgnuBQK168iw62jKILb5qaKa7zWjjbgOX42wDIIvPRJe80CFW+1TvcfrWC2g9r
# 9Jai56bZL5vOnuga8Y+in/2aHgJeSLotV4MfeEMzyFmwmD8ROghaIOjNNzbJarBX
# g7PJ3jHkjHyVyRcyBa7JZzGYsrVGYqkwggaCMIIEaqADAgECAhA2wrC9fBs656Oz
# 3TbLyXVoMA0GCSqGSIb3DQEBDAUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# TmV3IEplcnNleTEUMBIGA1UEBxMLSmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBV
# U0VSVFJVU1QgTmV0d29yazEuMCwGA1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZp
# Y2F0aW9uIEF1dGhvcml0eTAeFw0yMTAzMjIwMDAwMDBaFw0zODAxMTgyMzU5NTla
# MFcxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLjAsBgNV
# BAMTJVNlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcgUm9vdCBSNDYwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCIndi5RWedHd3ouSaBmlRUwHxJBZvM
# WhUP2ZQQRLRBQIF3FJmp1OR2LMgIU14g0JIlL6VXWKmdbmKGRDILRxEtZdQnOh2q
# mcxGzjqemIk8et8sE6J+N+Gl1cnZocew8eCAawKLu4TRrCoqCAT8uRjDeypoGJrr
# uH/drCio28aqIVEn45NZiZQI7YYBex48eL78lQ0BrHeSmqy1uXe9xN04aG0pKG9k
# i+PC6VEfzutu6Q3IcZZfm00r9YAEp/4aeiLhyaKxLuhKKaAdQjRaf/h6U13jQEV1
# JnUTCm511n5avv4N+jSVwd+Wb8UMOs4netapq5Q/yGyiQOgjsP/JRUj0MAT9Yrcm
# XcLgsrAimfWY3MzKm1HCxcquinTqbs1Q0d2VMMQyi9cAgMYC9jKc+3mW62/yVl4j
# nDcw6ULJsBkOkrcPLUwqj7poS0T2+2JMzPP+jZ1h90/QpZnBkhdtixMiWDVgh60K
# mLmzXiqJc6lGwqoUqpq/1HVHm+Pc2B6+wCy/GwCcjw5rmzajLbmqGygEgaj/OLoa
# nEWP6Y52Hflef3XLvYnhEY4kSirMQhtberRvaI+5YsD3XVxHGBjlIli5u+NrLedI
# xsE88WzKXqZjj9Zi5ybJL2WjeXuOTbswB7XjkZbErg7ebeAQUQiS/uRGZ58NHs57
# ZPUfECcgJC+v2wIDAQABo4IBFjCCARIwHwYDVR0jBBgwFoAUU3m/WqorSs9UgOHY
# m8Cd8rIDZsswHQYDVR0OBBYEFPZ3at0//QET/xahbIICL9AKPRQlMA4GA1UdDwEB
# /wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMIMBEG
# A1UdIAQKMAgwBgYEVR0gADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVz
# ZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5j
# cmwwNQYIKwYBBQUHAQEEKTAnMCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2Vy
# dHJ1c3QuY29tMA0GCSqGSIb3DQEBDAUAA4ICAQAOvmVB7WhEuOWhxdQRh+S3OyWM
# 637ayBeR7djxQ8SihTnLf2sABFoB0DFR6JfWS0snf6WDG2gtCGflwVvcYXZJJlFf
# ym1Doi+4PfDP8s0cqlDmdfyGOwMtGGzJ4iImyaz3IBae91g50QyrVbrUoT0mUGQH
# bRcF57olpfHhQEStz5i6hJvVLFV/ueQ21SM99zG4W2tB1ExGL98idX8ChsTwbD/z
# IExAopoe3l6JrzJtPxj8V9rocAnLP2C8Q5wXVVZcbw4x4ztXLsGzqZIiRh5i111T
# W7HV1AtsQa6vXy633vCAbAOIaKcLAo/IU7sClyZUk62XD0VUnHD+YvVNvIGezjM6
# CRpcWed/ODiptK+evDKPU2K6synimYBaNH49v9Ih24+eYXNtI38byt5kIvh+8aW8
# 8WThRpv8lUJKaPn37+YHYafob9Rg7LyTrSYpyZoBmwRWSE4W6iPjB7wJjJpH2930
# 8ZkpKKdpkiS9WNsf/eeUtvRrtIEiSJHN899L1P4l6zKVsdrUu1FX1T/ubSrsxrYJ
# D+3f3aKg6yxdbugot06YwGXXiy5UUGZvOu3lXlxA+fC13dQ5OlL2gIb5lmF6Ii8+
# CQOYDwXM+yd9dbmocQsHjcRPsccUd5E9FiswEqORvz8g3s+jR3SFCgXhN4wz7NgA
# nOgpCdUo4uDyllU9PzCCBqcwggSPoAMCAQICEQCQrAhyIP3Fp8RrXMcN9z0GMA0G
# CSqGSIb3DQEBDAUAMFcxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExp
# bWl0ZWQxLjAsBgNVBAMTJVNlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcgUm9v
# dCBSNDYwHhcNMjYwMzI1MDAwMDAwWhcNNDEwMzI0MjM1OTU5WjBVMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdv
# IFB1YmxpYyBUaW1lIFN0YW1waW5nIENBIFI0MTCCAiIwDQYJKoZIhvcNAQEBBQAD
# ggIPADCCAgoCggIBAK7kSqIBrYIcYvlmLVuaA8zw1RfBhkn4G1CoemzjcYtML6yN
# UvKmwGH7y6/5MuSC1UYP/+9KYDSqvMQt/1hEKHYxMAD9oZpBkoaDQFEKbOJHelsK
# e+BaO0ZcENTKfePcraVkA7wrGAW2XHA5gQCQv4IKori/3PNOXxnDMOk8yIMgVrlM
# eTxqfWJ4XkjT1xc2s9DD7URHWWJOFobTPoWs6mrDFlaY9FlAHDYTfbzvxQHVsvRm
# n3W+5ZmCwyk02I8KgGPT/UX4sTz41GiR+ppwUjQXa1+2tEHZbsdAKUtH3OPEVtZv
# lt7atx4h83IdRR8oYi8wjY3OjFKXFecWpQbzzsPxbUKPwMWiTrzwkrFa8dH/1pDK
# RJt371W62PfqKPayCr/XbnBOlRn8CALSmHnRtGzuAWtTJpcT3BKw6oy8IIL6wSbu
# 938F6ZIbRNIc1dKbIJtr4ULN6R5ZfTdNEhwXctqp3RHDbg4fuOl6LjNoaFwjud92
# EEDhzxFJzE1jqN4csceZIwxOT1aqfsfh0uFQE/lgTBuBs3i6/WL2W1OceWLy3XEd
# XRK1f0EWCuea6dNfX2RRdjUfk5EltFnJkN2+bWhnK14OPRKcyjOv5hKZ0iV4NRNd
# 1+hjtva1rPyzb5Bs7EvFxqEQhgZbOq7qH3nm0rBwA0dxniBOYCFPdu246JCxAgMB
# AAGjggFuMIIBajAfBgNVHSMEGDAWgBT2d2rdP/0BE/8WoWyCAi/QCj0UJTAdBgNV
# HQ4EFgQUOnSlDGfGQlDC/bX8x7spNIL0erkwDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwIwYDVR0gBBwwGjAI
# BgZngQwBBAIwDgYMKwYBBAGyMQECAQMIMEwGA1UdHwRFMEMwQaA/oD2GO2h0dHA6
# Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY1RpbWVTdGFtcGluZ1Jvb3RS
# NDYuY3JsMHwGCCsGAQUFBwEBBHAwbjBHBggrBgEFBQcwAoY7aHR0cDovL2NydC5z
# ZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nUm9vdFI0Ni5wN2Mw
# IwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqGSIb3DQEB
# DAUAA4ICAQAy3lJHZvGeA2b43yhzoarvobHVzbfl+RfuPDwej0wCQkYAN6scTt2G
# wFe22qbOCv/tllqFlLKQZE+E9jVyuPTbyQHwrM7R0oLapAEDC1+CowsqSRf/ptir
# a5Pfd4PoHICnb9coPQtyZmHSQp5y9IGvqWf1qNfq7V2fHZ8DvEQrLUzeoGF9BJRY
# u2OzacW3QQtUum3NOVf0gPRwv6I4991uhncJ6VP4lcpUpHZKB7R3hiIUC09mR9Kj
# zPVnXHvL9n2bAwiUECfK5Zezhiw27F2tgi39DETfU8M4n0N6xLgFzsf05M5GURX8
# C9+IX9V6kpmmKtrUzMti4LD66gtmf+mSm934K81NL6YQeMEk1rpYrWPypcW76Mir
# 6wb1AgseLIHqn/GkeuQm7zOTDf3f5WoX14qVNjZWNHF3JxkutV6ZnhinfCLfdv5b
# nwKWUfceqOajCVntI6uCbHxjBg6SCsexc5AfIGno7gVFvwifT4XONPsSUaJ71XsJ
# +EvciVUVnjOO4qxm0fWJTd8a7jP8mc4ZPqwJvQFtOp7+6G+kUJAF0fnE8YgD8utt
# BReNTa1YmAeFMiqc38e8fI4eLm0zjM/eeGCHasnoqqrbGwcF41iz9HXzFDwN4iD5
# z3QShp6HRiU3UpTwDJiiXcr0z6pjl7PyzJ3/tmWtGehV7CAfc/WlyzCCBuIwggTK
# oAMCAQICEQDnTvJVsFBP+tum3/f8i6MVMA0GCSqGSIb3DQEBDAUAMFUxCzAJBgNV
# BAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3Rp
# Z28gUHVibGljIFRpbWUgU3RhbXBpbmcgQ0EgUjQxMB4XDTI2MDMyNTAwMDAwMFoX
# DTM3MDYyNDIzNTk1OVowcjELMAkGA1UEBhMCR0IxFzAVBgNVBAgTDkdyZWF0ZXIg
# TG9uZG9uMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxMDAuBgNVBAMTJ1NlY3Rp
# Z28gUHVibGljIFRpbWUgU3RhbXBpbmcgU2lnbmVyIFIzNzCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBALL/w21L3FDZRS0FEXfZuPtUrefibnRSqOT/NNyJ
# LOJhXjQfUspqHT+gSSVgbjYThUI/cO+wFQHoOakKQNnSMKdkE8gR69ofXlkk5DAV
# Y/ZlevliOUmlvrw2Vuz4SU28rHfb/Vgd17eqpRIvJuO6XE8vPpPzn4c4iorszUF6
# nwuynKEQ/+rqfDmQbFNKsa+5+Z4f4kXwKdUFxUwUDjQWUhiHRwMlUWGF9N91aAvL
# +9a4sxCgqR/ez8W8HJ/XqvSu1vIeb+J6bDFKKgkv3PJkMMpQ0BsdeXR2FejZXFRX
# Y1w9dZe6gqyMv7px+TpWbYMefECUV0WxoEMgXUk6RKcLo94uUHOdmfZu4Xe8ghgl
# yro3/N4VEKTj8dcPPvOBGxFEx1QH6uHKTkWhloGPDScurcZnd8KUtTHl6zmlQDHM
# 04MwGfsmQViKnYEAYE8RHl5XRE6GTq0ZMb59SIyJX6+CODVic/kW+dhbIS1Z5AP8
# HaGne/PRG+12QzSneKDJp3Ot+k4GrmmlWT9iy6FNCQ/32K+d4cAZ+Ll7uWbEn6Z6
# gE+tEu7MyZvzWvPNsRKMkcyyflFW1zpRyzutwypALXc9Qg7sFsYERNXa58KZXqU9
# Onc/tck6+adQJFM9tW8xOnE//P5I4eDj84IGGKqzgUD37ihC+WST3DfY0YBKWL0Z
# aubnAgMBAAGjggGOMIIBijAfBgNVHSMEGDAWgBQ6dKUMZ8ZCUML9tfzHuyk0gvR6
# uTAdBgNVHQ4EFgQUYRDpehKvUcSF1PLPpHQPUM0gr/gwDgYDVR0PAQH/BAQDAgbA
# MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwSgYDVR0gBEMw
# QTAIBgZngQwBBAIwNQYMKwYBBAGyMQECAQMIMCUwIwYIKwYBBQUHAgEWF2h0dHBz
# Oi8vc2VjdGlnby5jb20vQ1BTMEoGA1UdHwRDMEEwP6A9oDuGOWh0dHA6Ly9jcmwu
# c2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY1RpbWVTdGFtcGluZ0NBUjQxLmNybDB6
# BggrBgEFBQcBAQRuMGwwRQYIKwYBBQUHMAKGOWh0dHA6Ly9jcnQuc2VjdGlnby5j
# b20vU2VjdGlnb1B1YmxpY1RpbWVTdGFtcGluZ0NBUjQxLmNydDAjBggrBgEFBQcw
# AYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIBAAPq
# PY3RrM36GXqTpsoHn9TpW5I6z3dkFvc9zPL1W0Egq7j3jtnkbAvRoWeAjGX4ZK4s
# WsmA+u4EJG8okQmybuS/4tDUI5UIQb21n4hG2vihxShrneWB0VoQ2VLQ3jCCRmRt
# AQ+/7H7WVKNiH5Pgl4v2ZTOdPsStzpKnl1YuRrmww/+bcZmLqgk909ywIpZqAfub
# YfbEMYjIckLk90f2mG+L8qaGSS2JJVM02pV5XltZ1fbOFETpRN/PQhwygIv33qUU
# jJ1fE4ITgw0McMzRqziWdOJP8ocxxw7qXxz1OdRWCalyL1qvUgAFnZTVdSRiMYZK
# f0wLcQcM/1Xf1W4FW9nff8ERX8RZJGt/TtPuMWmUpf6BCv9Q6o8YyUTtknvZRpSQ
# 0nLttWXdtwsrN2mMgfMuR//gxVrVXvDzCoK/lbiA6dEZOW53lQwBFtEzwE/FH8Jd
# hegyYg4PymZOTZrGBEvgsbxe25yEhJ0IdGa1pwCYsarldJhJVMdNcAOU7jyIMqHc
# czav3wtIXp/SwbXZ3xX0mfsLfANSJ47G4qPgx1atb6GIlTaQXzu/p4fTQeAIUVzZ
# XT4K984IyfuO7NLjWMtog1wGUpZD98pv+4Mt9Y5bvfPUjaUVjtePy1DVdi0rl5ES
# NYi0zyOmXVxtA5zzxu1H7RdLZOZugT/XjX69rY9bMYIGQjCCBj4CAQEwaTBUMQsw
# CQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJT
# ZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2AhEAjEGek78rzqyIBig7
# dhm9PDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAA
# MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCM6sykb5s4jQkOekLe579XWTr2VCUg
# ckEXOgDCF1lcmzANBgkqhkiG9w0BAQEFAASCAgBE0seksDG97yBIKjPqRU2dM9+o
# jemxVb6gIVrrdlXqadxcCiR1HvA56pAMowUzKlNp3c7ZFGunXHkPIW+4ApMvUGYK
# qk/sHZBi+k3akI4OawZxOgVVs7WK+8+Ag5ifNY8mxTQ76xNrDhDhAA41XBoTImxd
# R7ITpPldNvzUKurw5PfqOZ/bI5h7e/jRwhCXfKha+jvtpBNwK0+e/AIozbNpF7bz
# m1vTdzfemqHdpeqZfB8V9q07T/Z8vhDnc4aG7/UpyGY3ko8QxzmqMQsB7A5cjDWY
# ifFF0FZEmaqRfGpxBqxa2CluD16YCkaRhQvgJMc2B+P3Xwq//gQnLZFEHsxF3IYb
# dpwsCd7awSRp6TqQScHuxV59STCSdjLodmT6dfg/+YynzO7+kljsxOvfX4mJz/Os
# oFmpcm5zaEAK02gH/te+1IiqbkHUzjFIRVw4RuizqM5pM0XsLfGEi67OEiyrfWCP
# 44PQkSc7nJqvmg1r1rR8oNBiKsC9GM2bD7CTzWJ4IFrdWQpRingU5I1knU19xgo6
# Ecok9KJk7RElhA+BdG3pa176b9iuLMfxbghluMIwvhuKEzsMJvvyoJTEiFasI3JN
# yZoV9gEyAmibP2SDLuK0JmrThb9LJqL3wBl95a6cwz+sGJWsbNJCAu1EhVQLqK2X
# 4P6mOYijgXqI8yajBKGCAyMwggMfBgkqhkiG9w0BCQYxggMQMIIDDAIBATBqMFUx
# CzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMT
# I1NlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcgQ0EgUjQxAhEA507yVbBQT/rb
# pt/3/IujFTANBglghkgBZQMEAgIFAKB5MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTI2MTExMDA1NTEzOVowPwYJKoZIhvcNAQkEMTIE
# MET9FGk5si/nTiQ714XPLPEx6l2QilmSkhQuJ9p/qRpZnFZlshCX/6gGO0IO5uGg
# SzANBgkqhkiG9w0BAQEFAASCAgBpGvPqTWqrQ33vyySe3tCrcs6ZnqUXhDN5scJq
# fEXGmKnOqDe2ZeJiCSa9b0D173nSB6PyFx4WY7v+tFyBbYEPsMcnA6oYc4TWn/i8
# vqyNDLjkU28W/zBMvF4hGFfE2zjIQwHl2HSS+AQEHPi6xpWpeoumNBn+D7wGwUPi
# lPrgxG5QiYq3qYqoExvuR+yTtZa9VACkrtP4kyzNj3OJRxK0IRc/wIVGspVNcDPo
# j91FU1ollpfb7kqJvfPflvxAwxBoY1hJU4zaD16xVbSr4MmlRUs81Ol1alCP3VBt
# 0igtkbeB7fyF9M+vi4n6Mi1GzYAeFWMfL7Op7DQE3tK3Aa9cREdWvDqCM0n5Guhl
# u/2ZJWHr/rlp4jqfv3Rp0gkpT+h9avVp8hrs+f9SRLcySyawjSAkVCnP3HnE4fy/
# TZ+5PtmLN5TNkWN6E4kAfalEAMgQh+1tDyFUVmDxYMgQZfdBTQNuWyO45AQHv0do
# z7kFOZsIQIfMYfqSlv0a85PpWexSms/Z2tRreYVacN2UyXDqNCB5uCeW+w4qK+RE
# hmLAQeo+7vM70+QcSBVeGjJBQvjLb5VAxiL2QXLrefMycsqss4cjI0KPWJoNsXud
# ZAFe1gge7R5bRvQKYnWP1/Sv9ts/4eEq6uagX3VdbuwTtR3g7l906G1XpXfuzcFf
# /ifQ7w==
# SIG # End signature block
