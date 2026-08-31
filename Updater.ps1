# MemProcFS-Analyzer Updater v0.7
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2026 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2026-08-31
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
#
# Tested on Windows 11 Pro (x64) Version 25H2 (10.0.26100.9168) and PowerShell 5.1 (5.1.26100.9168)
# Tested on Windows 11 Pro (x64) Version 25H2 (10.0.26100.9168) and PowerShell 7.6.5
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  MemProcFS-Analyzer Updater v0.7 - Automated Installer/Updater for MemProcFS-Analyzer

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

# Tools

# 7-Zip
$script:7za = "$SCRIPT_DIR\Tools\7-Zip\7za.exe"

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

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "MemProcFS-Analyzer Updater v0.7 - Automated Installer/Updater for MemProcFS-Analyzer"

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
Write-Output "MemProcFS-Analyzer Updater v0.7 - Automated Installer/Updater for MemProcFS-Analyzer"
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

Function Get-AmcacheParser {

# AmcacheParser (.NET 9)
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
    $URL = "https://download.ericzimmermanstools.com/net9/AmcacheParser.zip" # https://download.ericzimmermanstools.com/net9/AmcacheParser.zip
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
    $URL = "https://download.ericzimmermanstools.com/net9/AmcacheParser.zip"
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

# AppCompatCacheParser (.NET 9)
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
    $URL = "https://download.ericzimmermanstools.com/net9/AppCompatCacheParser.zip"
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
    $URL = "https://download.ericzimmermanstools.com/net9/AppCompatCacheParser.zip"
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

# EvtxECmd (.NET 9)
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
    $URL = "https://download.ericzimmermanstools.com/net9/EvtxECmd.zip"
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
    $URL = "https://download.ericzimmermanstools.com/net9/EvtxECmd.zip"
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

# Check if PowerShell module 'ImportExcel' exists
if (Get-Module -ListAvailable -Name ImportExcel) 
{
    # Check if multiple versions of PowerShell module 'ImportExcel' exist
    $Modules = (Get-Module -ListAvailable -Name ImportExcel | Measure-Object).Count

    if ($Modules -eq "1")
    {
        # Check Current Version
        $CurrentVersion = (Get-Module -ListAvailable -Name ImportExcel).Version.ToString()
        Write-Output "[Info]  Current Version: ImportExcel v$CurrentVersion"
    }
    else
    {
        Write-Host "[Info]  Multiple installed versions of PowerShell module 'ImportExcel' found. Uninstalling ..."
        Uninstall-Module -Name ImportExcel -AllVersions -ErrorAction SilentlyContinue
        $CurrentVersion = $null
    }
}
else
{
    Write-Output "[Info]  PowerShell module 'ImportExcel' NOT found."
    $CurrentVersion = $null
}

# Determining latest release on GitHub
$Repository = "dfinke/ImportExcel"
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
$LatestRelease = $Tag.Substring(1)

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  ImportExcel $Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: ImportExcel $Tag ($ReleaseDate)"
}

# Check if ImportExcel needs to be installed
if ($null -eq $CurrentVersion)
{
    Write-Output "[Info]  Installing ImportExcel v$LatestRelease ..."
    Install-Module -Name ImportExcel -Scope CurrentUser -Repository PSGallery -Force
    $CurrentVersion = (Get-Module -ListAvailable -Name ImportExcel).Version.ToString()
}

# Check if ImportExcel needs to be updated
if ($CurrentVersion -ne $LatestRelease)
{
    # Update PowerShell module 'ImportExcel'
    try
    {
        Write-Output "[Info]  Updating PowerShell module 'ImportExcel' ..."
        Uninstall-Module -Name ImportExcel -AllVersions -ErrorAction SilentlyContinue
        Install-Module -Name ImportExcel -Scope CurrentUser -Repository PSGallery -Force
    }
    catch
    {
        Write-Output "PowerShell module 'ImportExcel' is in use. Please close PowerShell session, and run MemProcFS-Analyzer.ps1 again."
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

# RECmd (.NET 9)
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
    $URL = "https://download.ericzimmermanstools.com/net9/RECmd.zip"
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
    $URL = "https://download.ericzimmermanstools.com/net9/RECmd.zip"
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
            Write-Output "[Info]  No new RECmd Batch Files available."
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

# SBECmd (.NET 9)
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
    $URL = "https://download.ericzimmermanstools.com/net9/SBECmd.zip"
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
    $URL = "https://download.ericzimmermanstools.com/net9/SBECmd.zip"
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

# Dependencies:
# https://github.com/wagga40/Zircolite/blob/master/requirements.txt
#
# cd "$SCRIPT_DIR\Tools\Zircolite"
# pip install -r requirements.txt

# Check if Python is installed
if (Get-Command python -ErrorAction SilentlyContinue)
{
    $VersionOutput = (& python --version 2>&1)
    if ($LASTEXITCODE -eq 0 -and $VersionOutput -match "Python \d+\.\d+\.\d+")
    {
        # Check Current Version of Zircolite
        if (Test-Path "$SCRIPT_DIR\Tools\Zircolite\zircolite.py")
        {
            $MyLocation = $pwd
            Set-Location "$SCRIPT_DIR\Tools\Zircolite"
            $CurrentVersion = (python "$SCRIPT_DIR\Tools\Zircolite\zircolite.py" --version 2>&1 | Select-String -Pattern "Zircolite -" | ForEach-Object{($_ -split "Zircolite - ")[-1]} | ForEach-Object{($_ -replace "v","")}).Trim()
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
    }
    else
    {
        Write-Host "[Info]  Python is NOT installed (Store alias stub detected)." -ForegroundColor Red
    }
}
else
{
    Write-Host "[Info]  Python is NOT installed." -ForegroundColor Red
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

$Download = $Response.zipball_url

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
        if (Test-Path "$SCRIPT_DIR\Tools\wagga40-Zircolite-*")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\wagga40-Zircolite-*" | Rename-Item -NewName {"Zircolite"}
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
if (Test-Path "$SCRIPT_DIR\Tools\Zircolite\zircolite.py")
{
    Write-Output "[Info]  Updating SIGMA Rulesets ..."
    $MyLocation = $pwd
    Set-Location "$SCRIPT_DIR\Tools\Zircolite"
    python "$SCRIPT_DIR\Tools\Zircolite\zircolite.py" --update-rules 2>&1 | Out-File "$SCRIPT_DIR\Tools\Zircolite\Update-draft.log"
    Set-Location "$MyLocation"

    # No newer rulesets found
    if (Test-Path "$SCRIPT_DIR\Tools\Zircolite\Update-draft.log")
    {
        if (Get-Content "$SCRIPT_DIR\Tools\Zircolite\Update-draft.log" | Select-String -Pattern "No newer rulesets found" -Quiet)
        {
            Write-Output "[Info]  No newer rulesets found"
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
    @("") + ($Clean) | Set-Content "$SCRIPT_DIR\Tools\Zircolite\Update.log"

    # Cleaning up
    if (Test-Path "$SCRIPT_DIR\Tools\Zircolite\Update.log")
    {
        $Filter = @("^zircolite\.exe","MemProcFS-Analyzer-v.*\.ps1","^\+","\+ CategoryInfo          : NotSpecified:","\+ FullyQualifiedErrorId : NativeCommandError","^tmp-rules-")
        $Clean = Get-Content "$SCRIPT_DIR\Tools\Zircolite\Update.log" | Select-String -Pattern $Filter -NotMatch 
        $Clean | Set-Content "$SCRIPT_DIR\Tools\Zircolite\Update.log"
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
# MIInawYJKoZIhvcNAQcCoIInXDCCJ1gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUcYIOVVT/kZa/GdLjW3E3QyWN
# bCCggiCkMIIGGjCCBAKgAwIBAgIQYh1tDFIBnjuQeRUgiSEcCjANBgkqhkiG9w0B
# AQwFADBWMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0w
# KwYDVQQDEyRTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwHhcN
# MjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5WjBUMQswCQYDVQQGEwJHQjEYMBYG
# A1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBD
# b2RlIFNpZ25pbmcgQ0EgUjM2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKC
# AYEAmyudU/o1P45gBkNqwM/1f/bIU1MYyM7TbH78WAeVF3llMwsRHgBGRmxDeEDI
# ArCS2VCoVk4Y/8j6stIkmYV5Gej4NgNjVQ4BYoDjGMwdjioXan1hlaGFt4Wk9vT0
# k2oWJMJjL9G//N523hAm4jF4UjrW2pvv9+hdPX8tbbAfI3v0VdJiJPFy/7XwiunD
# 7mBxNtecM6ytIdUlh08T2z7mJEXZD9OWcJkZk5wDuf2q52PN43jc4T9OkoXZ0arW
# ZVeffvMr/iiIROSCzKoDmWABDRzV/UiQ5vqsaeFaqQdzFf4ed8peNWh1OaZXnYvZ
# QgWx/SXiJDRSAolRzZEZquE6cbcH747FHncs/Kzcn0Ccv2jrOW+LPmnOyB+tAfiW
# u01TPhCr9VrkxsHC5qFNxaThTG5j4/Kc+ODD2dX/fmBECELcvzUHf9shoFvrn35X
# Gf2RPaNTO2uSZ6n9otv7jElspkfK9qEATHZcodp+R4q2OIypxR//YEb3fkDn3Uay
# WW9bAgMBAAGjggFkMIIBYDAfBgNVHSMEGDAWgBQy65Ka/zWWSC8oQEJwIDaRXBeF
# 5jAdBgNVHQ4EFgQUDyrLIIcouOxvSK4rVKYpqhekzQwwDgYDVR0PAQH/BAQDAgGG
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwGwYDVR0g
# BBQwEjAGBgRVHSAAMAgGBmeBDAEEATBLBgNVHR8ERDBCMECgPqA8hjpodHRwOi8v
# Y3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ1Jvb3RSNDYu
# Y3JsMHsGCCsGAQUFBwEBBG8wbTBGBggrBgEFBQcwAoY6aHR0cDovL2NydC5zZWN0
# aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdSb290UjQ2LnA3YzAjBggr
# BgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQAD
# ggIBAAb/guF3YzZue6EVIJsT/wT+mHVEYcNWlXHRkT+FoetAQLHI1uBy/YXKZDk8
# +Y1LoNqHrp22AKMGxQtgCivnDHFyAQ9GXTmlk7MjcgQbDCx6mn7yIawsppWkvfPk
# KaAQsiqaT9DnMWBHVNIabGqgQSGTrQWo43MOfsPynhbz2Hyxf5XWKZpRvr3dMapa
# ndPfYgoZ8iDL2OR3sYztgJrbG6VZ9DoTXFm1g0Rf97Aaen1l4c+w3DC+IkwFkvjF
# V3jS49ZSc4lShKK6BrPTJYs4NG1DGzmpToTnwoqZ8fAmi2XlZnuchC4NPSZaPATH
# vNIzt+z1PHo35D/f7j2pO1S8BCysQDHCbM5Mnomnq5aYcKCsdbh0czchOm8bkinL
# rYrKpii+Tk7pwL7TjRKLXkomm5D1Umds++pip8wH2cQpf93at3VDcOK4N7EwoIJB
# 0kak6pSzEu4I64U6gZs7tS/dGNSljf2OSSnRr7KWzq03zl8l75jy+hOds9TWSenL
# bjBQUGR96cFr6lEUfAIEHVC1L68Y1GGxx4/eRI82ut83axHMViw1+sVpbPxg51Tb
# nio1lB93079WPFnYaOvfGAA0e0zcfF/M9gXr+korwQTh2Prqooq2bYNMvUoUKD85
# gnJ+t0smrWrb8dee2CvYZXD5laGtaAxOfy/VKNmwuWuAh9kcMIIGazCCBNOgAwIB
# AgIRAIxBnpO/K86siAYoO3YZvTwwDQYJKoZIhvcNAQEMBQAwVDELMAkGA1UEBhMC
# R0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDErMCkGA1UEAxMiU2VjdGlnbyBQ
# dWJsaWMgQ29kZSBTaWduaW5nIENBIFIzNjAeFw0yNDExMTQwMDAwMDBaFw0yNzEx
# MTQyMzU5NTlaMFcxCzAJBgNVBAYTAkRFMRYwFAYDVQQIDA1OaWVkZXJzYWNoc2Vu
# MRcwFQYDVQQKDA5NYXJ0aW4gV2lsbGluZzEXMBUGA1UEAwwOTWFydGluIFdpbGxp
# bmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDRn27mnIzB6dsJFLMe
# xQQNRd8aMv73DTla68G6Q8u+V2TY1JQ/Z4j2oCI9ATW3K3P7NAPdlE0QmtdjC0F/
# 74jsfil/i8LwxuyT034wabViZKUcodmKsEFhM9am8W5kUgLuC5FIK4wNOq5TfzYd
# HTyJu1eR2XuSDoMp0wg45mOuFNBbYB8DVBtHxobvWq4eCs3lUxX07wR3Qr2Utb92
# w8eU2vKr2Ss9xIh/YvM4UxgBpO1I6O+W2tAB5mmynIgoCfX7mu6iD3A+AhpQ9Gv2
# 09G83y8FPrFJIWU77TTehErbPjZ074xXwrlEkhnGUCk1w+KiNtZHaSn0X+vnhqJ7
# otBxQZQAESlhWXpDKCunnnVnVgwvVWtccAhxZO95eif6Vss/UhCaBZ26szlneGtF
# eTClI4+k3mqfWuodtXjHc8ohAclWp7XVywliwhCFEsAcFkpkCyivey0sqEfrwiMn
# Ry1elH1S37XcQaav5+bt4KxtIXuOVEx3vM9MHdlraW0y1on5E8i4tagdI45TH0LU
# 080ubc2MKqq6ZXtplTu1wdF2Cgy3hfSSLkJscRWApvpvOO6Vtc4jTG/AO6iqN5M6
# Swd+g40XtsxBD/gSk9kMqkgJ1pD1Gp5gkHnP1veut+YgJ9xWcRDJI7vcis9qsXwt
# VybeOCh56rTQvC/Tf6BJtiieEQIDAQABo4IBszCCAa8wHwYDVR0jBBgwFoAUDyrL
# IIcouOxvSK4rVKYpqhekzQwwHQYDVR0OBBYEFIxyZAmEHl7uAfEwbB4nzI8MCCLb
# MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUF
# BwMDMEoGA1UdIARDMEEwNQYMKwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEWF2h0
# dHBzOi8vc2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEATBJBgNVHR8EQjBAMD6gPKA6
# hjhodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmlu
# Z0NBUjM2LmNybDB5BggrBgEFBQcBAQRtMGswRAYIKwYBBQUHMAKGOGh0dHA6Ly9j
# cnQuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYuY3J0
# MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAoBgNVHREEITAf
# gR1td2lsbGluZ0BsZXRoYWwtZm9yZW5zaWNzLmNvbTANBgkqhkiG9w0BAQwFAAOC
# AYEAZ0dBMMwluWGb+MD1rGWaPtaXrNZnlZqOZxgbdrMLBKAQr0QGcILCVIZ4SZYa
# evT5yMR6jFGSAjgaFtnk8ZpbtGwig/ed/C/D1Ne8SZyffdtALns/5CHxMnU8ks7u
# t7dsR6zFD4/bmljuoUoi55W6/XU/1pr+tqRaZGJvjSKJQCN9MhFAvXSpPPqRsj27
# ze1+KYIBF1/L0BW0HS0d9ZhGSUoEwqMDLpQf2eqJFyyyzWt21VVhLF6mgZ1dE5tC
# LZY7ERzx6/h5N7F0w361oigizMbCMdST29XOc5mB8q6Cye7OmEfM2jByRWa+cd4R
# ycsN2p2wHRukpq48iX+tPVKmHwNKf+upuKPDQAeV4J7gUCtevIsOtoyiC2+amimu
# 81o424Dl+NsAyCLz0SXvNAhVvtU73H61gtoPa/SWouem2S+bzp7oGvGPop/9mh4C
# Xki6LVeDH3hDM8hZsJg/EToIWiDozTc2yWqwV4Ozyd4x5Ix8lckXMgWuyWcxmLK1
# RmKpMIIGgjCCBGqgAwIBAgIQNsKwvXwbOuejs902y8l1aDANBgkqhkiG9w0BAQwF
# ADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcT
# C0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAs
# BgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcN
# MjEwMzIyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjBXMQswCQYDVQQGEwJHQjEYMBYG
# A1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBU
# aW1lIFN0YW1waW5nIFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAiJ3YuUVnnR3d6LkmgZpUVMB8SQWbzFoVD9mUEES0QUCBdxSZqdTkdizI
# CFNeINCSJS+lV1ipnW5ihkQyC0cRLWXUJzodqpnMRs46npiJPHrfLBOifjfhpdXJ
# 2aHHsPHggGsCi7uE0awqKggE/LkYw3sqaBia67h/3awoqNvGqiFRJ+OTWYmUCO2G
# AXsePHi+/JUNAax3kpqstbl3vcTdOGhtKShvZIvjwulRH87rbukNyHGWX5tNK/WA
# BKf+Gnoi4cmisS7oSimgHUI0Wn/4elNd40BFdSZ1EwpuddZ+Wr7+Dfo0lcHflm/F
# DDrOJ3rWqauUP8hsokDoI7D/yUVI9DAE/WK3Jl3C4LKwIpn1mNzMyptRwsXKrop0
# 6m7NUNHdlTDEMovXAIDGAvYynPt5lutv8lZeI5w3MOlCybAZDpK3Dy1MKo+6aEtE
# 9vtiTMzz/o2dYfdP0KWZwZIXbYsTIlg1YIetCpi5s14qiXOpRsKqFKqav9R1R5vj
# 3NgevsAsvxsAnI8Oa5s2oy25qhsoBIGo/zi6GpxFj+mOdh35Xn91y72J4RGOJEoq
# zEIbW3q0b2iPuWLA911cRxgY5SJYubvjay3nSMbBPPFsyl6mY4/WYucmyS9lo3l7
# jk27MAe145GWxK4O3m3gEFEIkv7kRmefDR7Oe2T1HxAnICQvr9sCAwEAAaOCARYw
# ggESMB8GA1UdIwQYMBaAFFN5v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBT2
# d2rdP/0BE/8WoWyCAi/QCj0UJTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUw
# AwEB/zATBgNVHSUEDDAKBggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAwUAYD
# VR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVz
# dFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMDUGCCsGAQUFBwEBBCkwJzAl
# BggrBgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0B
# AQwFAAOCAgEADr5lQe1oRLjlocXUEYfktzsljOt+2sgXke3Y8UPEooU5y39rAARa
# AdAxUeiX1ktLJ3+lgxtoLQhn5cFb3GF2SSZRX8ptQ6IvuD3wz/LNHKpQ5nX8hjsD
# LRhsyeIiJsms9yAWnvdYOdEMq1W61KE9JlBkB20XBee6JaXx4UBErc+YuoSb1SxV
# f7nkNtUjPfcxuFtrQdRMRi/fInV/AobE8Gw/8yBMQKKaHt5eia8ybT8Y/Ffa6HAJ
# yz9gvEOcF1VWXG8OMeM7Vy7Bs6mSIkYeYtddU1ux1dQLbEGur18ut97wgGwDiGin
# CwKPyFO7ApcmVJOtlw9FVJxw/mL1TbyBns4zOgkaXFnnfzg4qbSvnrwyj1NiurMp
# 4pmAWjR+Pb/SIduPnmFzbSN/G8reZCL4fvGlvPFk4Uab/JVCSmj59+/mB2Gn6G/U
# YOy8k60mKcmaAZsEVkhOFuoj4we8CYyaR9vd9PGZKSinaZIkvVjbH/3nlLb0a7SB
# IkiRzfPfS9T+JesylbHa1LtRV9U/7m0q7Ma2CQ/t392ioOssXW7oKLdOmMBl14su
# VFBmbzrt5V5cQPnwtd3UOTpS9oCG+ZZheiIvPgkDmA8FzPsnfXW5qHELB43ET7HH
# FHeRPRYrMBKjkb8/IN7Po0d0hQoF4TeMM+zYAJzoKQnVKOLg8pZVPT8wgganMIIE
# j6ADAgECAhEAkKwIciD9xafEa1zHDfc9BjANBgkqhkiG9w0BAQwFADBXMQswCQYD
# VQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0
# aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2MB4XDTI2MDMyNTAwMDAw
# MFoXDTQxMDMyNDIzNTk1OVowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGlu
# ZyBDQSBSNDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCu5EqiAa2C
# HGL5Zi1bmgPM8NUXwYZJ+BtQqHps43GLTC+sjVLypsBh+8uv+TLkgtVGD//vSmA0
# qrzELf9YRCh2MTAA/aGaQZKGg0BRCmziR3pbCnvgWjtGXBDUyn3j3K2lZAO8KxgF
# tlxwOYEAkL+CCqK4v9zzTl8ZwzDpPMiDIFa5THk8an1ieF5I09cXNrPQw+1ER1li
# ThaG0z6FrOpqwxZWmPRZQBw2E32878UB1bL0Zp91vuWZgsMpNNiPCoBj0/1F+LE8
# +NRokfqacFI0F2tftrRB2W7HQClLR9zjxFbWb5be2rceIfNyHUUfKGIvMI2NzoxS
# lxXnFqUG887D8W1Cj8DFok688JKxWvHR/9aQykSbd+9Vutj36ij2sgq/125wTpUZ
# /AgC0ph50bRs7gFrUyaXE9wSsOqMvCCC+sEm7vd/BemSG0TSHNXSmyCba+FCzeke
# WX03TRIcF3Laqd0Rw24OH7jpei4zaGhcI7nfdhBA4c8RScxNY6jeHLHHmSMMTk9W
# qn7H4dLhUBP5YEwbgbN4uv1i9ltTnHli8t1xHV0StX9BFgrnmunTX19kUXY1H5OR
# JbRZyZDdvm1oZyteDj0SnMozr+YSmdIleDUTXdfoY7b2taz8s2+QbOxLxcahEIYG
# Wzqu6h955tKwcANHcZ4gTmAhT3btuOiQsQIDAQABo4IBbjCCAWowHwYDVR0jBBgw
# FoAU9ndq3T/9ARP/FqFsggIv0Ao9FCUwHQYDVR0OBBYEFDp0pQxnxkJQwv21/Me7
# KTSC9Hq5MA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMCMGA1UdIAQcMBowCAYGZ4EMAQQCMA4GDCsGAQQBsjEB
# AgEDCDBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLnNlY3RpZ28uY29tL1Nl
# Y3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdSb290UjQ2LmNybDB8BggrBgEFBQcBAQRw
# MG4wRwYIKwYBBQUHMAKGO2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1B1
# YmxpY1RpbWVTdGFtcGluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8v
# b2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEAMt5SR2bxngNm+N8o
# c6Gq76Gx1c235fkX7jw8Ho9MAkJGADerHE7dhsBXttqmzgr/7ZZahZSykGRPhPY1
# crj028kB8KzO0dKC2qQBAwtfgqMLKkkX/6bYq2uT33eD6ByAp2/XKD0LcmZh0kKe
# cvSBr6ln9ajX6u1dnx2fA7xEKy1M3qBhfQSUWLtjs2nFt0ELVLptzTlX9ID0cL+i
# OPfdboZ3CelT+JXKVKR2Sge0d4YiFAtPZkfSo8z1Z1x7y/Z9mwMIlBAnyuWXs4Ys
# NuxdrYIt/QxE31PDOJ9DesS4Bc7H9OTORlEV/AvfiF/VepKZpira1MzLYuCw+uoL
# Zn/pkpvd+CvNTS+mEHjBJNa6WK1j8qXFu+jIq+sG9QILHiyB6p/xpHrkJu8zkw39
# 3+VqF9eKlTY2VjRxdycZLrVemZ4Yp3wi33b+W58CllH3HqjmowlZ7SOrgmx8YwYO
# kgrHsXOQHyBp6O4FRb8In0+FzjT7ElGie9V7CfhL3IlVFZ4zjuKsZtH1iU3fGu4z
# /JnOGT6sCb0BbTqe/uhvpFCQBdH5xPGIA/LrbQUXjU2tWJgHhTIqnN/HvHyOHi5t
# M4zP3nhgh2rJ6Kqq2xsHBeNYs/R18xQ8DeIg+c90Eoaeh0YlN1KU8AyYol3K9M+q
# Y5ez8syd/7ZlrRnoVewgH3P1pcswggbiMIIEyqADAgECAhEA507yVbBQT/rbpt/3
# /IujFTANBgkqhkiG9w0BAQwFADBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2Vj
# dGlnbyBMaW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1w
# aW5nIENBIFI0MTAeFw0yNjAzMjUwMDAwMDBaFw0zNzA2MjQyMzU5NTlaMHIxCzAJ
# BgNVBAYTAkdCMRcwFQYDVQQIEw5HcmVhdGVyIExvbmRvbjEYMBYGA1UEChMPU2Vj
# dGlnbyBMaW1pdGVkMTAwLgYDVQQDEydTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1w
# aW5nIFNpZ25lciBSMzcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCy
# /8NtS9xQ2UUtBRF32bj7VK3n4m50Uqjk/zTciSziYV40H1LKah0/oEklYG42E4VC
# P3DvsBUB6DmpCkDZ0jCnZBPIEevaH15ZJOQwFWP2ZXr5YjlJpb68Nlbs+ElNvKx3
# 2/1YHde3qqUSLybjulxPLz6T85+HOIqK7M1Bep8LspyhEP/q6nw5kGxTSrGvufme
# H+JF8CnVBcVMFA40FlIYh0cDJVFhhfTfdWgLy/vWuLMQoKkf3s/FvByf16r0rtby
# Hm/iemwxSioJL9zyZDDKUNAbHXl0dhXo2VxUV2NcPXWXuoKsjL+6cfk6Vm2DHnxA
# lFdFsaBDIF1JOkSnC6PeLlBznZn2buF3vIIYJcq6N/zeFRCk4/HXDz7zgRsRRMdU
# B+rhyk5FoZaBjw0nLq3GZ3fClLUx5es5pUAxzNODMBn7JkFYip2BAGBPER5eV0RO
# hk6tGTG+fUiMiV+vgjg1YnP5FvnYWyEtWeQD/B2hp3vz0RvtdkM0p3igyadzrfpO
# Bq5ppVk/YsuhTQkP99ivneHAGfi5e7lmxJ+meoBPrRLuzMmb81rzzbESjJHMsn5R
# Vtc6Ucs7rcMqQC13PUIO7BbGBETV2ufCmV6lPTp3P7XJOvmnUCRTPbVvMTpxP/z+
# SOHg4/OCBhiqs4FA9+4oQvlkk9w32NGASli9GWrm5wIDAQABo4IBjjCCAYowHwYD
# VR0jBBgwFoAUOnSlDGfGQlDC/bX8x7spNIL0erkwHQYDVR0OBBYEFGEQ6XoSr1HE
# hdTyz6R0D1DNIK/4MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMEoGA1UdIARDMEEwCAYGZ4EMAQQCMDUGDCsGAQQB
# sjEBAgEDCDAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzBK
# BgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29Q
# dWJsaWNUaW1lU3RhbXBpbmdDQVI0MS5jcmwwegYIKwYBBQUHAQEEbjBsMEUGCCsG
# AQUFBzAChjlodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNUaW1l
# U3RhbXBpbmdDQVI0MS5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3Rp
# Z28uY29tMA0GCSqGSIb3DQEBDAUAA4ICAQAD6j2N0azN+hl6k6bKB5/U6VuSOs93
# ZBb3Pczy9VtBIKu4947Z5GwL0aFngIxl+GSuLFrJgPruBCRvKJEJsm7kv+LQ1COV
# CEG9tZ+IRtr4ocUoa53lgdFaENlS0N4wgkZkbQEPv+x+1lSjYh+T4JeL9mUznT7E
# rc6Sp5dWLka5sMP/m3GZi6oJPdPcsCKWagH7m2H2xDGIyHJC5PdH9phvi/Kmhkkt
# iSVTNNqVeV5bWdX2zhRE6UTfz0IcMoCL996lFIydXxOCE4MNDHDM0as4lnTiT/KH
# MccO6l8c9TnUVgmpci9ar1IABZ2U1XUkYjGGSn9MC3EHDP9V39VuBVvZ33/BEV/E
# WSRrf07T7jFplKX+gQr/UOqPGMlE7ZJ72UaUkNJy7bVl3bcLKzdpjIHzLkf/4MVa
# 1V7w8wqCv5W4gOnRGTlud5UMARbRM8BPxR/CXYXoMmIOD8pmTk2axgRL4LG8Xtuc
# hISdCHRmtacAmLGq5XSYSVTHTXADlO48iDKh3HM2r98LSF6f0sG12d8V9Jn7C3wD
# UieOxuKj4MdWrW+hiJU2kF87v6eH00HgCFFc2V0+CvfOCMn7juzS41jLaINcBlKW
# Q/fKb/uDLfWOW73z1I2lFY7Xj8tQ1XYtK5eREjWItM8jpl1cbQOc88btR+0XS2Tm
# boE/141+va2PWzGCBjEwggYtAgEBMGkwVDELMAkGA1UEBhMCR0IxGDAWBgNVBAoT
# D1NlY3RpZ28gTGltaXRlZDErMCkGA1UEAxMiU2VjdGlnbyBQdWJsaWMgQ29kZSBT
# aWduaW5nIENBIFIzNgIRAIxBnpO/K86siAYoO3YZvTwwCQYFKw4DAhoFAKB4MBgG
# CisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYE
# FBXBuOElvVpDsqWGS3gagprYnr9bMA0GCSqGSIb3DQEBAQUABIICAKNP8r9iaB2r
# 1bQdL1eRB/4RYt5y1ymkPq4VL9sHEO/DGn1AlP2ljRa80G5cqe6jOIMAQymoWWR9
# 5/SyAq53jiL/ISkFLUOhU48helLTm5iyGLKFVEdo/+lK1NHlEabYRP3/bPp7OjEk
# rPUJPTCJrHT0nXzav6x529264ciL+pSC4tOC6oyhSDhPL9R05dJXtU+rFfInaaBt
# PydAbuD45FRCJOVKika6LGzapR3m9xQfDuo9XIw4BXF1PMihEecDWC/Ic0gsQhmz
# EZy4L2YGW0/GJsU/ObP+FUoVdkKFtqNhp2alh9G+Zd35b3WHxMSBnkI+F5Hv2GG6
# 3bVq5Jf/C9dNNnEAf4rT4QHIOBsPBbVmcmL24WeCtXI8zCdJv5NDAlz8NIGTlWTM
# 9OVpNeZnFvG2Tr0qGPcmhjNXb85oBiOci2WA040xQOw/acGmIjfSlW3ZfvV3ZGD4
# z6WR3iQZNLO1XZxsgdHk+DzoRtNyN2ocl8qxiwCm+wtUurft5Ji11Ucb2fwWjmgd
# pLft9UrRNFKbUzj4XQCOYzsPe7ROIzKUBy5XnxtXaXeVUJTteBGIRC/pPFthFGf1
# CoYb77FRURcoTQH0HvTF94rH3nEtlPA3IKpGWo3tEmP7Zd9hfDyocea0skX+wBcG
# 2espARnhZLQd9fZg9Jz4vAhM0m/K6MKqoYIDIzCCAx8GCSqGSIb3DQEJBjGCAxAw
# ggMMAgEBMGowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRl
# ZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBSNDEC
# EQDnTvJVsFBP+tum3/f8i6MVMA0GCWCGSAFlAwQCAgUAoHkwGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwODMxMTAzNzIzWjA/Bgkq
# hkiG9w0BCQQxMgQwHW8D4/H8QBqcvjTEY90g/nJV5Jt4iHEk6Y6t6IqX0bFU5V0j
# IcEo23hqCvlKqmitMA0GCSqGSIb3DQEBAQUABIICAEtkVp0Uy9y/xUZD/O3U7cf4
# bQ0wugs+Y1KT8dyfM/WI3TMGe5yDLXtnCNs4O7fwaNUfWw0AYLSKLRkaQkZ1by9S
# bqG0YkznOU7oWESlttb0uAsbHiacX29dfc97622OPpZWWuzE9bN1EiYyzvhQGRqz
# S+CiIeJKChtIb3HshM1EUOfEtFZ/BJvIZIITVo4bLFyIfmCRYtzh6lBqwocNT+jY
# 35DWVTGk4MUjeY6J+ZWqRrYWxoB11tI6hpg+kc/octYzdg458qfxg0g84JV7+YLH
# ik2gm2Aw3Wq+vyYWGTG4D8b3PCcvyZfUXzU2yXinoq97OC0z2NdbfJvmjifPcJXi
# 2aSwZLoNkKIEXqw6f733TbMP8yDJqVfWHYq+Txepf85+nXByw3xu54KYLYyL4gYj
# 9NM74AaTN0bn2AtOsq78R/fPED0AcDZAxWDmRm+8hHNbYU0IEwYM6ULvtNEv/2Ye
# rX6DZsCINNLw3eyhaA+IqZMMRdMVWWNL/K9C0me5JJU41j2nUApFgvEhWmjrX/04
# 2bseYqlzk13hkCuW47RweCGY1HZagrGNv/bIs9hT1vjAlMRSYJA5XuzEhUI8TF6w
# bCpeSBVT2Crijpgn8pJYgIyuQXgcUPt2WEBlVhDJnj+lXQNtUAceWZ4v1truZSaR
# k+7fwO659TdjIfDScAMz
# SIG # End signature block
