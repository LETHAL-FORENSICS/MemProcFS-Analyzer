# MemProcFS-Analyzer Updater v0.4
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2025 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2025-07-22
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
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5965) and PowerShell 5.1 (5.1.19041.5965)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5965) and PowerShell 7.5.1
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  MemProcFS-Analyzer Updater v0.4 - Automated Installer/Updater for MemProcFS-Analyzer

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

# Zircolite
$script:zircolite = "$SCRIPT_DIR\Tools\Zircolite\zircolite.exe"

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "MemProcFS-Analyzer Updater v0.4 - Automated Installer/Updater for MemProcFS-Analyzer"

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
Write-Output "MemProcFS-Analyzer Updater v0.4 - Automated Installer/Updater for MemProcFS-Analyzer"
Write-Output "(c) 2025 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
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
$NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]‘{DCB00C01-570F-4A9B-8D69-199FDBA5723B}’)).IsConnectedToInternet

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
    $ReleaseDate = $Published # PowerShell 7
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
    $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]‘{DCB00C01-570F-4A9B-8D69-199FDBA5723B}’)).IsConnectedToInternet

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
    $ReleaseDate = $Published # PowerShell 7
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
    $ReleaseDate = $Published # PowerShell 7
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
    $URL = "https://download.ericzimmermanstools.com/net9/AmcacheParser.zip"
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
    $ReleaseDate = $Published # PowerShell 7
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
    $ReleaseDate = $Published # PowerShell 7
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
    $ReleaseDate = $Published # PowerShell 7
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
    $ReleaseDate = $Published # PowerShell 7
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
    $ReleaseDate = $Published # PowerShell 7
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
    $ReleaseDate = $Published # PowerShell 7
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

# Determining latest release on GitHub
$Repository = "VirusTotal/yara"
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
    $ReleaseDate = $Published # PowerShell 7
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
if (Test-Path "$($Zircolite)")
{
    $MyLocation = $pwd
    Set-Location "$SCRIPT_DIR\Tools\Zircolite"
    $CurrentVersion = (& $Zircolite --version 2>&1 | Select-String -Pattern "Zircolite -" | ForEach-Object{($_ -split "\s+")[-1]}).Substring(1)
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
$Tag = $Response.tag_name
$Published = $Response.published_at
if ($Published -is [String])
{
    $LatestRelease = $Published.split('T')[0] # Windows PowerShell
}
else
{
    $LatestRelease = $Published # PowerShell 7
}
$Download = ($Response.assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "zircolite_win_x64" | Out-String).Trim()

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
    $7Zip = "Zircolite.7z"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\Tools\$7Zip"

    if (Test-Path "$SCRIPT_DIR\Tools\$7Zip")
    {
        # Unblock Archive File
        Unblock-File -Path "$SCRIPT_DIR\Tools\$7Zip"

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
            & $7za x "$SCRIPT_DIR\Tools\$7Zip" "-o$SCRIPT_DIR\Tools" 2>&1 | Out-Null
        }
        else
        {
            Write-Output "[Info]  7-Zip is NOT installed."
        }

        # Rename Unpacked Directory
        Start-Sleep 5
        if (Test-Path "$SCRIPT_DIR\Tools\zircolite_win")
        {
            Rename-Item "$SCRIPT_DIR\Tools\zircolite_win" "$SCRIPT_DIR\Tools\Zircolite" -Force
        }
        else
        {
            Write-Host "[Error] It seems that the packaged Zircolite binary was blocked by your AV!" -ForegroundColor Red
        }

        # Rename Binary
        if (Test-Path "$SCRIPT_DIR\Tools\Zircolite\zircolite_*")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\Zircolite\zircolite_*.exe" | Rename-Item -NewName {"zircolite.exe"}
        }

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$SCRIPT_DIR\Tools\$7Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of Zircolite." -ForegroundColor Green
}

# Update SIGMA Rulesets
if (Test-Path "$($Zircolite)")
{
    Write-Output "[Info]  Updating SIGMA Rulesets ..."
    $MyLocation = $pwd
    Set-Location "$SCRIPT_DIR\Tools\Zircolite"
    & $Zircolite --update-rules 2>&1 | Out-File "$SCRIPT_DIR\Tools\Zircolite\Update-draft.log"
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
Start-Sleep 1

# Reset Progress Preference
$Global:ProgressPreference = $OriginalProgressPreference

# Reset Windows Title
$Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################
