# MemProcFS-Analyzer v1.2.0
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2021-2025 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2025-06-24
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
# Dependencies:
# 7-Zip 24.09 Standalone Console (2024-11-29)
# https://www.7-zip.org/download.html --> 7za.exe (x64)
#
# AmcacheParser v1.5.2.0 (.NET 9)
# https://ericzimmerman.github.io/
#
# AppCompatCacheParser v1.5.1.0 (.NET 9)
# https://ericzimmerman.github.io/
#
# ClamAV - Download --> Windows --> clamav-1.4.3.win.x64.msi (2025-06-17)
# https://www.clamav.net/downloads
# https://docs.clamav.net/manual/Usage/Configuration.html#windows --> First Time Set-Up
# https://blog.clamav.net/
#
# Dokany File System Library v2.3.0.1000 (2025-04-19)
# https://github.com/dokan-dev/dokany/releases/latest --> DokanSetup.exe
#
# Elasticsearch 9.0.2 (2025-06-03)
# https://www.elastic.co/downloads/elasticsearch
#
# entropy v1.1 (2023-07-28)
# https://github.com/merces/entropy
#
# EvtxECmd v1.5.2.0 (.NET 9)
# https://ericzimmerman.github.io/
#
# ImportExcel v7.8.10 (2024-10-21)
# https://github.com/dfinke/ImportExcel
#
# IPinfo CLI 3.3.1 (2024-03-01)
# https://github.com/ipinfo/cli
#
# jq v1.8.0 (2025-06-01)
# https://github.com/stedolan/jq
#
# Kibana 9.0.2 (2025-06-03)
# https://www.elastic.co/downloads/kibana
#
# lnk_parser v0.4.1 (2025-01-02)
# https://github.com/AbdulRhmanAlfaifi/lnk_parser
#
# MemProcFS v5.15.0 - The Memory Process File System (2025-06-22)
# https://github.com/ufrisk/MemProcFS
#
# RECmd v2.1.0.0 (.NET 9)
# https://ericzimmerman.github.io/
# https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/DFIRBatch.md
#
# SBECmd v2.1.0.0 (.NET 9)
# https://ericzimmerman.github.io/
#
# xsv v0.13.0 (2018-05-12)
# https://github.com/BurntSushi/xsv
#
# YARA v4.5.4 (2025-05-27)
# https://virustotal.github.io/yara/
#
# Zircolite v2.40.0 (2025-04-06)
# https://github.com/wagga40/Zircolite
#
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5965) and PowerShell 5.1 (5.1.19041.5965)
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  MemProcFS-Analyzer v1.2.0 - Automated Forensic Analysis of Windows Memory Dumps for DFIR

.DESCRIPTION
  MemProcFS-Analyzer.ps1 is a PowerShell script utilized to simplify the usage of MemProcFS and to assist with the memory analysis workflow.

.EXAMPLE
  PS> .\MemProcFS-Analyzer.ps1

.NOTES
  Author - Martin Willing

.LINK
  https://github.com/LETHAL-FORENSICS/MemProcFS-Analyzer
#>

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

# Analysis date (ISO 8601)
$script:Date = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss") # YYYY-MM-DDThh:mm:ss
$script:Timestamp = $Date -replace ":", "" # YYYY-MM-DDThhmmss

# Version
$Version = "v1.2.0"

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

# IPinfo CLI - Access Token
$IPInfoToken = "access_token" # Please insert your Access Token here (Default: access_token)

# jq
$script:jq = "$SCRIPT_DIR\Tools\jq\jq-win64.exe"

# Kibana
$script:Kibana = "$SCRIPT_DIR\Tools\Kibana\bin\kibana.bat"

# lnk_parser
$script:lnk_parser = "$SCRIPT_DIR\Tools\lnk_parser\lnk_parser_x86_64.exe"

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

# Archive Password
$script:PASSWORD = "MemProcFS"

# MemProcFS Logfile
New-Item "$SCRIPT_DIR\Logs" -ItemType Directory -Force | Out-Null
$script:MemProcFSLogfile = "$SCRIPT_DIR\Logs\MemProcFS.log"

# Process Whitelist (Forensic Mode)
# https://github.com/ufrisk/MemProcFS/wiki/_CommandLine#-forensic-process-skip
$script:ForensicProcessWhitelist = "cyserver.exe,MsMpEng.exe,tlaworker.exe"

# MsMpEng.exe   = Microsoft Defender
# cyserver.exe  = Palo Alto Cortex XDR
# tlaworker.exe = Palo Alto Cortex XDR

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Initialisations

# Set Progress Preference to Silently Continue
$OriginalProgressPreference = $Global:ProgressPreference
$Global:ProgressPreference = 'SilentlyContinue'

#endregion Initialisations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

Function Header {

# Windows Title
$script:DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "MemProcFS-Analyzer $Version - Automated Forensic Analysis of Windows Memory Dumps for DFIR"

# Check if MemProcFS.exe exists
if (!(Test-Path "$($MemProcFS)"))
{
    Write-Host "[Error] MemProcFS.exe NOT found." -ForegroundColor Red
    Write-Host "        Note: Please run 'Updater.ps1' to install MemProcFS-Analyzer (incl. all dependencies)." -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check if the PowerShell script is being run with admin rights
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[Error] This PowerShell script must be run with admin rights." -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check IPinfo CLI Access Token 
if ("$Token" -eq "access_token")
{
    Write-Host "[Error] No IPinfo CLI Access Token provided. Please add your personal access token in Line 159." -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Requirements

# Dokany File System Library
$Dokany = "$env:SystemDrive\Windows\System32\dokan2.dll"
if (!(Test-Path "$($Dokany)"))
{
    Write-Host "[Error] Dokany File System Library NOT found." -ForegroundColor Red
    Write-Host "        Please download/install the latest release of Dokany File System Library manually:" -ForegroundColor Red
    Write-Host "        https://github.com/dokan-dev/dokany/releases/latest (DokanSetup.exe)" -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# EZTools
if (Get-Command -CommandType Application dotnet -ErrorAction SilentlyContinue)
{
    # TargetFramework (.NET 9)
    if (!(dotnet --list-runtimes | Select-String -Pattern "^Microsoft\.WindowsDesktop\.App 9" -Quiet))
    {
        Write-Host "[Error] Please download/install at least .NET 9.0 or newer manually:" -ForegroundColor Red
        Write-Host "        https://dotnet.microsoft.com/en-us/download/dotnet/9.0 (Recommended: .NET Desktop Runtime)" -ForegroundColor Red
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}
else
{
    Write-Host "[Error] Please download/install at least .NET 9.0 or newer manually:" -ForegroundColor Red
    Write-Host "        https://dotnet.microsoft.com/en-us/download/dotnet/9.0 (Recommended: .NET Desktop Runtime)" -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Function Get-FileSize
Function script:Get-FileSize {
    Param ([long]$Size)
    If ($Size -gt 1TB) {[string]::Format("{0:0.00} TB", $Size / 1TB)}
    ElseIf ($Size -gt 1GB) {[string]::Format("{0:0.00} GB", $Size / 1GB)}
    ElseIf ($Size -gt 1MB) {[string]::Format("{0:0.00} MB", $Size / 1MB)}
    ElseIf ($Size -gt 1KB) {[string]::Format("{0:0.00} KB", $Size / 1KB)}
    ElseIf ($Size -gt 0) {[string]::Format("{0:0.00} Bytes", $Size)}
    Else {""}
}

# Add the required MessageBox class (Windows PowerShell)
Add-Type -AssemblyName System.Windows.Forms

#############################################################################################################################################################################################

# User Interface

Function Show-UserInterface
{
    # Import Assemblies
    [void][reflection.assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
    [void][reflection.assembly]::Load('System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
    [void][reflection.assembly]::Load('System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')

    # Form Objects
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $FormMemProcFSAnalyzer = New-Object 'System.Windows.Forms.Form'
    $Checkbox1 = New-Object 'System.Windows.Forms.CheckBox'
    $Checkbox2 = New-Object 'System.Windows.Forms.CheckBox'
    $Checkbox3 = New-Object 'System.Windows.Forms.CheckBox'
    $Checkbox4 = New-Object 'System.Windows.Forms.CheckBox'
    $CheckboxOfflineMode = New-Object 'System.Windows.Forms.CheckBox'
    $StatusBar = New-Object 'System.Windows.Forms.StatusBar'
    $StatusBarPanel1 = New-Object 'System.Windows.Forms.StatusBarPanel'
    $LabelMemoryDump = New-Object 'System.Windows.Forms.Label'
    $LabelPageFile = New-Object 'System.Windows.Forms.Label'
    $ButtonBrowse1 = New-Object 'System.Windows.Forms.Button'
    $ButtonBrowse2 = New-Object 'System.Windows.Forms.Button'
    $TextBoxFile1 = New-Object 'System.Windows.Forms.TextBox'
    $TextBoxFile2 = New-Object 'System.Windows.Forms.TextBox'
    $OpenFileDialog1 = New-Object 'System.Windows.Forms.OpenFileDialog'
    $OpenFileDialog2 = New-Object 'System.Windows.Forms.OpenFileDialog'
    $ButtonStart = New-Object 'System.Windows.Forms.Button'
    $ButtonExit = New-Object 'System.Windows.Forms.Button'
    $LinkLabel = New-Object 'System.Windows.Forms.LinkLabel'
    $ToolTip1 = New-Object 'System.Windows.Forms.ToolTip'
    $MenuStrip1 = New-Object 'System.Windows.Forms.MenuStrip'
    $FileToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
    $CheckForUpdatesToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
    $ExitToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
    $HelpToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
    $WikiToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
    $MemProcFSToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
    $MemProcFSWikiToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
    $AboutToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
    $GitHubToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
    $InitialFormWindowState = New-Object 'System.Windows.Forms.FormWindowState'

    # Events
    $ButtonBrowseMemory_Click={
	
        if($OpenFileDialog1.ShowDialog() -eq 'OK')
        {
            $TextBoxFile1.Text = $OpenFileDialog1.FileName
            $ButtonStart.Enabled =$true
            $StatusBar.Text = "Ready"
        }
    }

    $ButtonBrowsePagefile_Click={
	
        if($OpenFileDialog2.ShowDialog() -eq 'OK')
        {
            $TextBoxFile2.Text = $OpenFileDialog2.FileName
        }
    }

    $LinkLabel_LinkClicked=[System.Windows.Forms.LinkLabelLinkClickedEventHandler]{
        Start-Process "https://github.com/LETHAL-FORENSICS/MemProcFS-Analyzer"
    }

    $ButtonExit_Click={
		$FormMemProcFSAnalyzer.Close()
	}

    $ExitToolStripMenuItem_Click={
		$FormMemProcFSAnalyzer.Close()
	}

    $CheckForUpdatesToolStripMenuItem_Click={

        $CurrentVersion = "1.2.0"

        $StatusBar.Text = "Checking latest release on GitHub ..."

        # Check for latest release on GitHub
        $Repository = "LETHAL-FORENSICS/MemProcFS-Analyzer"
        $Releases = "https://api.github.com/repos/$Repository/releases"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if (Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet -ErrorAction SilentlyContinue)
		{
            $Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing -TimeoutSec 30 | ConvertFrom-Json)[0]
            $Tag = $Response.tag_name
            $LatestRelease = $Tag.Substring(1)

            # Outdated
            if ($CurrentVersion -lt $LatestRelease)
            {
                $MessageBody = "Latest Release: MemProcFS-Analyzer v$LatestRelease`n`nNote: You will be automatically redirected."
                $MessageTitle = "MemProcFS-Analyzer v$CurrentVersion - Update available"
                $ButtonType = "OKCancel"
                $MessageIcon = "Warning"
                $StatusBar.Text = "Latest Version: MemProcFS-Analyzer v$LatestRelease"
                $Result = [System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)

                if ($Result -eq "OK")
                {
                    Start-Process "https://github.com/LETHAL-FORENSICS/MemProcFS-Analyzer/releases/latest"
                }
            }
            
            # Up-To-Date
            if ($CurrentVersion -eq $LatestRelease)
            {
                $MessageBody = "MemProcFS-Analyzer v$CurrentVersion`nCopyright (c) 2021-2025 Martin Willing`n`nYou are using the latest version of MemProcFS-Analyzer."
                $MessageTitle = "MemProcFS-Analyzer"
                $ButtonType = "OK"
                $MessageIcon = "Info"
                $StatusBar.Text = "Latest Version: MemProcFS-Analyzer v$LatestRelease"
                [System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)
            }

            # Beta-Tester
            if ($CurrentVersion -gt $LatestRelease)
            {
                $MessageBody = "MemProcFS-Analyzer v$CurrentVersion`nCopyright (c) 2021-2025 Martin Willing`n`nHello Beta-Tester. Happy Testing! ;-)"
                $MessageTitle = "MemProcFS-Analyzer"
                $ButtonType = "OK"
                $MessageIcon = "Info"
                $StatusBar.Text = "Latest Version: MemProcFS-Analyzer v$LatestRelease"
                [System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)

                if(Test-Path $TextBoxFile1.Text)
                {
                    $StatusBar.Text = "Ready"
                }
                else
                {
                    $StatusBar.Text = ""
                }
            }
        }
        else
        {
            $StatusBar.Text = "Session Timeout"
        }
    }
	
	$GitHubToolStripMenuItem_Click = {
		Start-Process "https://github.com/LETHAL-FORENSICS/MemProcFS-Analyzer"
	}
	
	$WikiToolStripMenuItem_Click={
		Start-Process "https://github.com/LETHAL-FORENSICS/MemProcFS-Analyzer/wiki"
	}

    $MemProcFSToolStripMenuItem_Click = {
		Start-Process "https://github.com/ufrisk/MemProcFS"
	}

    $MemProcFSWikiToolStripMenuItem_Click = {
		Start-Process "https://github.com/ufrisk/MemProcFS/wiki"
	}

    $AboutToolStripMenuItem_Click = {
        $MessageBody = "MemProcFS-Analyzer $Version`nCopyright (c) 2021-2025 Martin Willing"
        $MessageTitle = "MemProcFS-Analyzer"
        $ButtonType = "OK"
        $MessageIcon = "Info"
        [System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)
	}

    $Checkbox1_CheckedChanged =
    {
        if($Checkbox1.Checked -eq $true)
	    {
            # Custom YARA Rules - Enabled
            $script:YaraRules = "$SCRIPT_DIR\yara\index.yar"
        }
        
        if($Checkbox1.Checked -eq $false)
        {
            # Custom YARA Rules - Disabled
            $script:YaraRules = $null
        }
    }

    $Checkbox2_CheckedChanged =
    {
        if($Checkbox2.Checked -eq $true)
	    {
            # ClamAV Scan - Enabled
            $script:ClamAV = "Enabled"
        }
        
        if($Checkbox2.Checked -eq $false)
        {
            # ClamAV Scan - Disabled
            $script:ClamAV = $null
        }
    }

    $Checkbox3_CheckedChanged =
    {
        if($Checkbox3.Checked -eq $true)
	    {
            # Forensic Timeline (CSV) - Enabled
            $script:ForensicTimelineCSV = "Enabled"
        }
        
        if($Checkbox3.Checked -eq $false)
        {
            # Forensic Timeline (CSV) - Disabled
            $script:ForensicTimelineCSV = $null
        }
    }

    $Checkbox4_CheckedChanged =
    {
        if($Checkbox4.Checked -eq $true)
	    {
            # Forensic Timeline (XLSX) - Enabled
            $script:ForensicTimelineXLSX = "Enabled"
        }
        
        if($Checkbox4.Checked -eq $false)
        {
            # Forensic Timeline (XLSX) - Disabled
            $script:ForensicTimelineXLSX = $null
        }
    }

    $CheckboxOfflineMode_CheckedChanged =
    {
        if($CheckboxOfflineMode.Checked -eq $true)
	    {
            # Offline Mode - Enabled
            $script:OfflineMode = "Enabled"
        }

        if($CheckboxOfflineMode.Checked -eq $false)
        {
            # Offline Mode - Disabled
            $script:OfflineMode = $null
        }
    }

    $Form_StateCorrection_Load =
    {
        $FormMemProcFSAnalyzer.WindowState = $InitialFormWindowState
    }

    $Form_StoreValues_Closing =
    {
        $script:MemoryDump = $TextBoxFile1.Text
        $script:Pagefile = $TextBoxFile2.Text
    }

    $Form_Cleanup_FormClosed =
    {
        try
        {
            $Checkbox1.remove_CheckedChanged($Checkbox1_CheckedChanged)
            $Checkbox2.remove_CheckedChanged($Checkbox2_CheckedChanged)
            $Checkbox3.remove_CheckedChanged($Checkbox3_CheckedChanged)
            $Checkbox4.remove_CheckedChanged($Checkbox4_CheckedChanged)
            $CheckboxOfflineMode.remove_CheckedChanged($CheckboxOfflineMode_CheckedChanged)
            $ButtonBrowse1.remove_Click($ButtonBrowseMemory_Click)
            $ButtonBrowse2.remove_Click($ButtonBrowsePagefile_Click)
            $ButtonStart.remove_MouseClick($ButtonStart_Click)
            $ButtonExit.remove_MouseClick($ButtonExit_Click)
            $LinkLabel.remove_LinkClicked($LinkLabel_LinkClicked)
            $FormMemProcFSAnalyzer.remove_Load($FormMemProcFSAnalyzer_Load)
            $CheckForUpdatesToolStripMenuItem.remove_Click($checkForUpdatesToolStripMenuItem_Click)
            $ExitToolStripMenuItem.remove_Click($exitToolStripMenuItem_Click)
            $WikiToolStripMenuItem.remove_Click($wikiToolStripMenuItem_Click)
            $MemProcFSToolStripMenuItem.remove_Click($MemProcFSToolStripMenuItem_Click)
            $MemProcFSWikiToolStripMenuItem.remove_Click($MemProcFSWikiToolStripMenuItem_Click)
            $AboutToolStripMenuItem.remove_Click($AboutToolStripMenuItem_Click)
            $GitHubToolStripMenuItem.remove_Click($GitHubToolStripMenuItem_Click)
            $FormMemProcFSAnalyzer.remove_Load($Form_StateCorrection_Load)
            $FormMemProcFSAnalyzer.remove_Closing($Form_StoreValues_Closing)
            $FormMemProcFSAnalyzer.remove_FormClosed($Form_Cleanup_FormClosed)
        }
        catch { Out-Null }
    }

    # Form Code
    $FormMemProcFSAnalyzer.SuspendLayout()
    $MenuStrip1.SuspendLayout()

    # FormMemProcFSAnalyzer
    $FormMemProcFSAnalyzer.Controls.Add($Checkbox1)
    $FormMemProcFSAnalyzer.Controls.Add($Checkbox2)
    $FormMemProcFSAnalyzer.Controls.Add($Checkbox3)
    $FormMemProcFSAnalyzer.Controls.Add($Checkbox4)
    $FormMemProcFSAnalyzer.Controls.Add($CheckboxOfflineMode)
    $FormMemProcFSAnalyzer.Controls.Add($StatusBar)
    $FormMemProcFSAnalyzer.Controls.Add($LabelMemoryDump)
    $FormMemProcFSAnalyzer.Controls.Add($LabelPageFile)
    $FormMemProcFSAnalyzer.Controls.Add($ButtonBrowse1)
	$FormMemProcFSAnalyzer.Controls.Add($ButtonBrowse2)
    $FormMemProcFSAnalyzer.Controls.Add($TextBoxFile1)
    $FormMemProcFSAnalyzer.Controls.Add($TextBoxFile2)
    $FormMemProcFSAnalyzer.Controls.Add($ButtonStart)
    $FormMemProcFSAnalyzer.Controls.Add($ButtonExit)
    $FormMemProcFSAnalyzer.Controls.Add($LinkLabel)
    $FormMemProcFSAnalyzer.Controls.Add($MenuStrip1)
    $FormMemProcFSAnalyzer.AutoScaleDimensions = New-Object System.Drawing.SizeF(6, 13)
    $FormMemProcFSAnalyzer.AutoScaleMode = 'Font'
    $FormMemProcFSAnalyzer.ClientSize = New-Object System.Drawing.Size(626, 262)
	$FormMemProcFSAnalyzer.FormBorderStyle = 'FixedDialog'
    $FormMemProcFSAnalyzer.MainMenuStrip = $Menustrip1
    $FormMemProcFSAnalyzer.MaximizeBox = $False
    $FormMemProcFSAnalyzer.MinimizeBox = $False
    $FormMemProcFSAnalyzer.Name = 'FormMemProcFSAnalyzer'
    $FormMemProcFSAnalyzer.StartPosition = 'CenterScreen'
    $FormMemProcFSAnalyzer.Text = "MemProcFS-Analyzer $Version - Automated Forensic Analysis of Windows Memory Dumps for DFIR"
    $FormMemProcFSAnalyzer.TopLevel = $True
    $FormMemProcFSAnalyzer.TopMost = $True
    $FormMemProcFSAnalyzer.Add_Shown({$FormMemProcFSAnalyzer.Activate()})

    # Checkbox1
    $Checkbox1.Location = New-Object System.Drawing.Point(96, 131)
	$Checkbox1.Name = 'Checkbox1'
	$Checkbox1.Size = New-Object System.Drawing.Size(172, 24)
	$Checkbox1.TabIndex = 9
	$Checkbox1.Text = 'Enable Custom YARA rules'
	$Checkbox1.UseVisualStyleBackColor = $True
    $Checkbox1.add_CheckedChanged($Checkbox1_CheckedChanged)

    # Checkbox2
    $Checkbox2.Location = New-Object System.Drawing.Point(96, 151)
	$Checkbox2.Name = 'Checkbox2'
	$Checkbox2.Size = New-Object System.Drawing.Size(155, 24)
	$Checkbox2.TabIndex = 10
	$Checkbox2.Text = 'Enable ClamAV Scan'
	$Checkbox2.UseVisualStyleBackColor = $True
	$Checkbox2.add_CheckedChanged($Checkbox2_CheckedChanged)

    # Checkbox3
    $Checkbox3.Location = New-Object System.Drawing.Point(270, 131)
	$Checkbox3.Name = 'Checkbox3'
	$Checkbox3.Size = New-Object System.Drawing.Size(200, 24)
    $Checkbox3.TabIndex = 11
    $Checkbox3.Text = 'Enable Forensic Timeline (CSV)'
    $Checkbox3.UseVisualStyleBackColor = $True
    $Checkbox3.add_CheckedChanged($Checkbox3_CheckedChanged)

    # Checkbox4
    $Checkbox4.Location = New-Object System.Drawing.Point(270, 151)
	$Checkbox4.Name = 'Checkbox4'
    $Checkbox4.Size = New-Object System.Drawing.Size(200, 24)
	$Checkbox4.TabIndex = 12
    $Checkbox4.Text = 'Enable Forensic Timeline (XLSX)'
	$Checkbox4.UseVisualStyleBackColor = $True
    $Checkbox4.add_CheckedChanged($Checkbox4_CheckedChanged)

    # CheckBoxOfflineMode
    $CheckboxOfflineMode.Location = New-Object System.Drawing.Point(339, 200)
    $CheckboxOfflineMode.Name = 'CheckboxOfflineMode'
    $CheckboxOfflineMode.Size = New-Object System.Drawing.Size(92, 24)
    $CheckboxOfflineMode.TabIndex = 13
    $CheckboxOfflineMode.Text = 'Offline Mode'
    $CheckboxOfflineMode.UseVisualStyleBackColor = $True
    $CheckboxOfflineMode.add_CheckedChanged($CheckboxOfflineMode_CheckedChanged)
    $ToolTip1.SetToolTip($CheckboxOfflineMode, 'Offline Mode')
    
    # Status Bar
    $StatusBar.Location = New-Object System.Drawing.Point(0, 240)
    $StatusBar.Name = 'StatusBar'
    [void]$StatusBar.Panels.Add($StatusBarPanel1)
    $StatusBar.Size = New-Object System.Drawing.Size(626, 22)
    $StatusBar.SizingGrip = $False
    $StatusBar.TabIndex = 0

    # LabelMemoryDump
    $LabelMemoryDump.AutoSize = $True
    $LabelMemoryDump.Location = New-Object System.Drawing.Point(12, 38)
    $LabelMemoryDump.Name = 'LabelMemoryDump'
    $LabelMemoryDump.Size = New-Object System.Drawing.Size(78, 13)
    $LabelMemoryDump.TabIndex = 4
    $LabelMemoryDump.Text = 'Memory Dump:'

    # LabelPageFile
    $LabelPageFile.AutoSize = $True
    $LabelPageFile.Location = New-Object System.Drawing.Point(36, 87)
    $LabelPageFile.Name = 'LabelPageFile'
    $LabelPageFile.Size = New-Object System.Drawing.Size(54, 13)
    $LabelPageFile.TabIndex = 3
    $LabelPageFile.Text = 'Page File:'

    # ButtonBrowse1
    $ButtonBrowse1.Location = New-Object System.Drawing.Point(539, 33)
    $ButtonBrowse1.Name = 'ButtonBrowse1'
    $ButtonBrowse1.Size = New-Object System.Drawing.Size(75, 23)
    $ButtonBrowse1.TabIndex = 0
    $ButtonBrowse1.Text = 'Browse'
    $ButtonBrowse1.UseVisualStyleBackColor = $True
    $ButtonBrowse1.add_Click($ButtonBrowseMemory_Click)
    $ToolTip1.SetToolTip($ButtonBrowse1, 'Select your Raw Physical Memory Dump')

    # ButtonBrowse2
    $ButtonBrowse2.Location = New-Object System.Drawing.Point(539, 84)
    $ButtonBrowse2.Name = 'ButtonBrowse2'
    $ButtonBrowse2.Size = New-Object System.Drawing.Size(75, 23)
    $ButtonBrowse2.TabIndex = 1
    $ButtonBrowse2.Text = 'Browse'
    $ButtonBrowse2.UseVisualStyleBackColor = $True
    $ButtonBrowse2.add_Click($ButtonBrowsePagefile_Click)
    $ToolTip1.SetToolTip($ButtonBrowse2, 'Select your pagefile.sys (Optional)')

    # TextBoxFile1
    $TextBoxFile1.AccessibleRole = 'None'
    $TextBoxFile1.AutoCompleteMode = 'SuggestAppend'
    $TextBoxFile1.AutoCompleteSource = 'FileSystem'
    $TextBoxFile1.BackColor = [System.Drawing.SystemColors]::Window 
    $TextBoxFile1.Cursor = 'Default'
    $TextBoxFile1.ForeColor = [System.Drawing.SystemColors]::WindowText 
    $TextBoxFile1.Location = New-Object System.Drawing.Point(96, 35)
    $TextBoxFile1.Name = 'TextBoxFile'
    $TextBoxFile1.ReadOnly = $True
    $TextBoxFile1.ShortcutsEnabled = $False
    $TextBoxFile1.Size = New-Object System.Drawing.Size(437, 20)
    $TextBoxFile1.TabIndex = 4
    $TextBoxFile1.TabStop = $False
    $TextBoxFile1.Text = 'Select your Raw Physical Memory Dump'
    $ToolTip1.SetToolTip($TextBoxFile1, 'Select your Raw Physical Memory Dump')

    # TextBoxFile2
    $TextBoxFile2.AccessibleRole = 'None'
    $TextBoxFile2.AutoCompleteMode = 'SuggestAppend'
    $TextBoxFile2.AutoCompleteSource = 'FileSystem'
    $TextBoxFile2.BackColor = [System.Drawing.SystemColors]::Window 
    $TextBoxFile2.Cursor = 'Default'
    $TextBoxFile2.ForeColor = [System.Drawing.SystemColors]::WindowText 
    $TextBoxFile2.Location = New-Object System.Drawing.Point(96, 84)
    $TextBoxFile2.Name = 'TextBoxFile2'
    $TextBoxFile2.ReadOnly = $True
    $TextBoxFile2.Size = New-Object System.Drawing.Size(437, 20)
    $TextBoxFile2.TabIndex = 5
    $TextBoxFile2.TabStop = $False
    $TextBoxFile2.Text = 'Select your pagefile.sys (Optional)'
    $ToolTip1.SetToolTip($TextBoxFile2, 'Select your pagefile.sys (Optional)')

    # OpenFileDialog1
    $OpenFileDialog1.Filter = 'Memory Dump Files (*.001;*.bin;*.dmp;*.img;*.mem;*.raw;*.vmem)|*.001;*.bin;*.dmp;*.img;*.mem;*.raw;*.vmem|All Files (*.*)|*.*'
    $OpenFileDialog1.InitialDirectory = "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}" # MyComputer
    $OpenFileDialog1.ReadOnlyChecked = $True
    $OpenFileDialog1.Title = "MemProcFS-Analyzer $Version - Select your Raw Physical Memory Dump"

    # OpenFileDialog2
    $OpenFileDialog2.Filter = 'Page Files (*.sys)|*.sys|All Files (*.*)|*.*'
    $OpenFileDialog2.ReadOnlyChecked = $True
    $OpenFileDialog2.Title = "MemProcFS-Analyzer $Version - Select your pagefile.sys (Optional)"

    # ButtonStart
    $ButtonStart.DialogResult = 'OK'
    $ButtonStart.Enabled = $False
    $ButtonStart.Location = New-Object System.Drawing.Point(446, 202)
    $ButtonStart.Name = 'ButtonStart'
    $ButtonStart.Size = New-Object System.Drawing.Size(75, 23)
    $ButtonStart.TabIndex = 2
    $ButtonStart.Text = 'Start'
    $ButtonStart.UseCompatibleTextRendering = $True
    $ButtonStart.UseVisualStyleBackColor = $True
    $ButtonStart.Add_Click($ButtonStart_Click)
    $ToolTip1.SetToolTip($ButtonStart, 'Start')

    # ButtonExit
    $ButtonExit.DialogResult = 'Cancel'
    $ButtonExit.Location = New-Object System.Drawing.Point(539, 202)
    $ButtonExit.Name = 'ButtonExit'
    $ButtonExit.Size = New-Object System.Drawing.Size(75, 23)
    $ButtonExit.TabIndex = 3
    $ButtonExit.Text = 'Exit'
    $ButtonExit.UseCompatibleTextRendering = $True
    $ButtonExit.UseVisualStyleBackColor = $True
    $ButtonExit.Add_MouseClick($ButtonExit_Click)
    $ToolTip1.SetToolTip($ButtonExit, 'Exit')

    # LinkLabel
    $LinkLabel.Location = New-Object System.Drawing.Point(12, 204)
    $LinkLabel.Name = 'LinkLabel'
    $LinkLabel.Size = New-Object System.Drawing.Size(269, 23)
    $LinkLabel.TabIndex = 7
    $LinkLabel.TabStop = $True
    $LinkLabel.Text = 'https://github.com/evild3ad/MemProcFS-Analyzer'
    $LinkLabel.Add_LinkClicked($linklabel_LinkClicked)

    # MenuStrip1
    [void]$MenuStrip1.Items.Add($FileToolStripMenuItem)
    [void]$MenuStrip1.Items.Add($HelpToolStripMenuItem)
    $MenuStrip1.Location = New-Object System.Drawing.Point(0, 0)
    $MenuStrip1.Name = 'MenuStrip1'
    $MenuStrip1.Size = New-Object System.Drawing.Size(626, 24)
    $MenuStrip1.TabIndex = 8
    $MenuStrip1.Text = 'MenuStrip1'

    # FileToolStripMenuItem
    [void]$fileToolStripMenuItem.DropDownItems.Add($CheckForUpdatesToolStripMenuItem)
    [void]$FileToolStripMenuItem.DropDownItems.Add($ExitToolStripMenuItem)
    $FileToolStripMenuItem.Name = 'FileToolStripMenuItem'
    $FileToolStripMenuItem.Size = New-Object System.Drawing.Size(37, 20)
    $FileToolStripMenuItem.Text = 'File'

    # HelpToolStripMenuItem
    [void]$HelpToolStripMenuItem.DropDownItems.Add($GitHubToolStripMenuItem)
    [void]$HelpToolStripMenuItem.DropDownItems.Add($WikiToolStripMenuItem)
    [void]$HelpToolStripMenuItem.DropDownItems.Add($MemProcFSToolStripMenuItem)
    [void]$HelpToolStripMenuItem.DropDownItems.Add($MemProcFSWikiToolStripMenuItem)
    [void]$HelpToolStripMenuItem.DropDownItems.Add($AboutToolStripMenuItem)
    $HelpToolStripMenuItem.Name = 'HelpToolStripMenuItem'
    $HelpToolStripMenuItem.Size = New-Object System.Drawing.Size(44, 20)
    $HelpToolStripMenuItem.Text = 'Help'

    # CheckForUpdatesToolStripMenuItem
	$CheckForUpdatesToolStripMenuItem.Name = 'CheckForUpdatesToolStripMenuItem'
    $CheckForUpdatesToolStripMenuItem.Size = New-Object System.Drawing.Size(180, 22)
    $CheckForUpdatesToolStripMenuItem.Text = 'Check for Updates...'
    $CheckForUpdatesToolStripMenuItem.ToolTipText = 'Check for Updates...'
    $CheckForUpdatesToolStripMenuItem.add_Click($CheckForUpdatesToolStripMenuItem_Click)

    # ExitToolStripMenuItem
    $ExitToolStripMenuItem.Name = 'ExitToolStripMenuItem'
    $ExitToolStripMenuItem.Size = New-Object System.Drawing.Size(180, 22)
    $ExitToolStripMenuItem.Text = 'Exit'
    $ExitToolStripMenuItem.ToolTipText = 'Exit'
    $ExitToolStripMenuItem.Add_Click($ExitToolStripMenuItem_Click)

    # GitHubToolStripMenuItem
    $GitHubToolStripMenuItem.Name = 'GitHubToolStripMenuItem'
    $GitHubToolStripMenuItem.Size = New-Object System.Drawing.Size(152, 22)
    $GitHubToolStripMenuItem.Text = 'GitHub'
    $GitHubToolStripMenuItem.ToolTipText = 'GitHub'
    $GitHubToolStripMenuItem.Add_Click($GitHubToolStripMenuItem_Click)

    # WikiToolStripMenuItem
    $WikiToolStripMenuItem.Name = 'WikiToolStripMenuItem'
    $WikiToolStripMenuItem.Size = New-Object System.Drawing.Size(152, 22)
    $WikiToolStripMenuItem.Text = 'GitHub Wiki'
    $WikiToolStripMenuItem.ToolTipText = 'GitHub Wiki'
    $WikiToolStripMenuItem.Add_Click($WikiToolStripMenuItem_Click)

    # MemProcFSToolStripMenuItem
    $MemProcFSToolStripMenuItem.Name = 'MemProcFSToolStripMenuItem'
    $MemProcFSToolStripMenuItem.Size = New-Object System.Drawing.Size(152, 22)
    $MemProcFSToolStripMenuItem.Text = 'MemProcFS'
    $MemProcFSToolStripMenuItem.ToolTipText = 'MemProcFS - The Memory Process File System'
    $MemProcFSToolStripMenuItem.Add_Click($MemProcFSToolStripMenuItem_Click)

    # MemProcFSWikiToolStripMenuItem
    $MemProcFSWikiToolStripMenuItem.Name = 'MemProcFSWikiToolStripMenuItem'
    $MemProcFSWikiToolStripMenuItem.Size = New-Object System.Drawing.Size(152, 22)
    $MemProcFSWikiToolStripMenuItem.Text = 'MemProcFS Wiki'
    $MemProcFSWikiToolStripMenuItem.ToolTipText = 'MemProcFS Wiki'
    $MemProcFSWikiToolStripMenuItem.Add_Click($MemProcFSWikiToolStripMenuItem_Click)

    # AboutToolStripMenuItem
    $AboutToolStripMenuItem.Name = 'AboutToolStripMenuItem'
    $AboutToolStripMenuItem.Size = New-Object System.Drawing.Size(152, 22)
    $AboutToolStripMenuItem.Text = 'About'
    $AboutToolStripMenuItem.ToolTipText = 'About'
    $AboutToolStripMenuItem.Add_Click($AboutToolStripMenuItem_Click)

    $MenuStrip1.ResumeLayout()
    $FormMemProcFSAnalyzer.ResumeLayout()

    # Save the initial state of the form
    $InitialFormWindowState = $FormMemProcFSAnalyzer.WindowState
    $FormMemProcFSAnalyzer.Add_Load($Form_StateCorrection_Load)
    $FormMemProcFSAnalyzer.Add_FormClosed($Form_Cleanup_FormClosed)
    $FormMemProcFSAnalyzer.Add_Closing($Form_StoreValues_Closing)
    return $FormMemProcFSAnalyzer.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true}))
}

$Result = Show-UserInterface

if($Result -eq "OK")
{
    if ($Pagefile -eq "Select your pagefile.sys (Optional)")
    {
        $script:Pagefile = $null
    }
}
else
{
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

#############################################################################################################################################################################################

# FileName
$script:FileName = $MemoryDump.Split('\')[-1] | ForEach-Object{($_ -replace "\..*","")}

# Output Directory
$script:OUTPUT_FOLDER = "$SCRIPT_DIR\$Timestamp-$FileName"

# Drive Letter (Mount Point)
[char[]]$Taken = (Get-PSDrive -Name [A-Z]).Name
$script:DriveLetter = ([char[]]([int][char]"D" .. [int][char]"Z")).Where({ $_ -notin $Taken }, "First")[0] + ":"
if (!$script:DriveLetter)
{
    Write-Host "[Error] No Drive Letter available." -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Create a record of your PowerShell session to a text file
Start-Transcript -Path "$SCRIPT_DIR\$Timestamp-$FileName.txt"

# Get Start Times
$script:StartTime_Processing = (Get-Date)
$script:StartTime_Analysis = (Get-Date)

# Logo
$Logo = @"
██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
"@

Write-Host ""
Write-Host "$Logo"

# Header
Write-Output ""
Write-Output "MemProcFS-Analyzer $Version - Automated Forensic Analysis of Windows Memory Dumps for DFIR"
Write-Output "(c) 2021-2025 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$AnalysisDate = $Date -replace "T", " " # YYYY-MM-DD hh:mm:ss
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

}

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Elasticsearch

Function Elasticsearch {

# Launch Elasticsearch (PowerShell.exe)
Write-Output "[Info]  Starting Elasticsearch ... "
$Elasticsearch_Process = Start-Process powershell.exe "& $Elasticsearch" -WindowStyle Minimized -PassThru
$Elasticsearch_Id = $Elasticsearch_Process.Id
$script:Elasticsearch_Termination = Get-Process | Where-Object {$_.Id -eq $Elasticsearch_Id}
$ProgressPreference = 'SilentlyContinue'
do {
  Start-Sleep 3
  $ProgressPreference = 'SilentlyContinue'
} until( Test-NetConnection 127.0.0.1 -Port 9200 -InformationLevel Quiet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)

# Launch Kibana (PowerShell.exe)
Write-Output "[Info]  Starting Kibana ... "
$Kibana_Process = Start-Process powershell.exe "& $Kibana" -WindowStyle Minimized -PassThru
$Kibana_Id = $Kibana_Process.Id
$script:Kibana_Termination = Get-Process | Where-Object {$_.Id -eq $Kibana_Id}
$ProgressPreference = 'SilentlyContinue'
do {
  Start-Sleep 3
  $ProgressPreference = 'SilentlyContinue'
} until(Test-NetConnection localhost -Port 5601 -InformationLevel Quiet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)

Start-Sleep 2

}

#endregion Elasticsearch

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region MemProcFS

Function MemProcFS {

# MemProcFS
# https://github.com/ufrisk/MemProcFS

# Remove existing MemProcFS Logfile
if (Test-Path "$($MemProcFSLogfile)")
{
    Remove-Item -Path "$MemProcFSLogfile" -Force
}

# Mount the physical memory dump file with a corresponding Pagefile and enable forensic mode
if (Test-Path "$($MemProcFS)")
{
    if (Test-Path "$($MemoryDump)")
    {
        if ($Pagefile)
        {
            if (Test-Path "$($Pagefile)")
            {
                Write-Output "[Info]  Mounting the Physical Memory Dump file with a corresponding Pagefile as $DriveLetter ..."

                $MemorySize = Get-FileSize((Get-Item "$MemoryDump").Length)
                Write-Output "[Info]  Physical Memory Dump File Size: $MemorySize"

                $PagefileSize = Get-FileSize((Get-Item -Force "$Pagefile").Length)
                Write-Output "[Info]  Pagefile Size: $PagefileSize"
                New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null
                $Mount = $DriveLetter -replace ":", ""
                $StartTime_MemProcFS = (Get-Date)

                # Check if a Custom Yara rule or Yara index file was provided
                if ($null -eq $YaraRules)
                {
                    # Offline Mode
                    if ($OfflineMode -eq "Enabled")
                    {
                        Write-Output "[Info]  MemProcFS Forensic Analysis initiated [Offline-Mode] ..."
                    }
                    else
                    {
                        Write-Output "[Info]  MemProcFS Forensic Analysis initiated ..."
                    }

                    Write-Output "[Info]  Processing $MemoryDump incl. Pagefile [approx. 10-45 min] ..."
                    Start-Process -FilePath "$MemProcFS" -ArgumentList "-mount $Mount -device `"$MemoryDump`" -pagefile0 `"$Pagefile`" -disable-python -forensic 4 -loglevel forensic:5 -v -logfile `"$MemProcFSLogfile`""
                }
                else
                {
                    if ((Test-Path "$YaraRules") -And ((Get-Item "$YaraRules").length -gt 0kb))
                    {
                        # Check if Process Skiplist is inactive
                        if ($null -eq $ForensicProcessWhitelist)
                        {
                            # Offline Mode
                            if ($OfflineMode -eq "Enabled")
                            {
                                Write-Output "[Info]  MemProcFS Forensic Analysis initiated [Offline-Mode] ..."
                            }
                            else
                            {
                                Write-Output "[Info]  MemProcFS Forensic Analysis initiated ..."
                            }

                            $Count_YaraRules = (Get-Content -Path $YaraRules | Select-String -Pattern "^include" | Measure-Object).Count
                            Write-Output "[Info]  YARA scan initialized with $Count_YaraRules rules ..."
                            Write-Output "[Info]  Processing $MemoryDump incl. Pagefile [approx. 10-45 min] ..."
                            Start-Process -FilePath "$MemProcFS" -ArgumentList "-mount $Mount -device `"$MemoryDump`" -pagefile0 `"$Pagefile`" -disable-python -disable-yara-builtin -forensic-yara-rules `"$YaraRules`" -forensic 4 -loglevel forensic:5 -v -logfile `"$MemProcFSLogfile`""
                        }
                        else
                        {
                            $Count_YaraRules = (Get-Content -Path $YaraRules | Select-String -Pattern "^include" | Measure-Object).Count
                            $Count_ProcessSkip = ($ForensicProcessWhitelist.Split(",") | Where-Object {$_.Trim() -ne "" }).Count

                            # Offline Mode
                            if ($OfflineMode -eq "Enabled")
                            {
                                Write-Output "[Info]  MemProcFS Forensic Analysis initiated [Offline-Mode] ..."
                            }
                            else
                            {
                                Write-Output "[Info]  MemProcFS Forensic Analysis initiated ..."
                            }

                            Write-Output "[Info]  YARA scan initialized with $Count_YaraRules rules ($Count_ProcessSkip Process Names will be skipped) ..."
                            Write-Output "[Info]  Processing $MemoryDump incl. Pagefile [approx. 10-45 min] ..."
                            Start-Process -FilePath "$MemProcFS" -ArgumentList "-mount $Mount -device `"$MemoryDump`" -pagefile0 `"$Pagefile`" -disable-python -disable-yara-builtin -forensic-yara-rules `"$YaraRules`" -forensic 4 -loglevel forensic:5 -forensic-process-skip `"$ForensicProcessWhitelist`""
                        }
                    }
                }

                # Check if successfully mounted
                while (!(Test-Path "$($DriveLetter)"))
                {
                    Start-Sleep -Seconds 2
                }

                # Check forensic mode processing
                while (!(Select-String -Pattern "100" -Path "$DriveLetter\forensic\progress_percent.txt" -Quiet))
                {
                    Start-Sleep -Seconds 2
                }

                $EndTime_MemProcFS = (Get-Date)
                $Time_MemProcFS = ($EndTime_MemProcFS-$StartTime_MemProcFS)
                ('MemProcFS Processing duration: {0} h {1} min {2} sec' -f $Time_MemProcFS.Hours, $Time_MemProcFS.Minutes, $Time_MemProcFS.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"
            }
        }
    }

    # Mount the physical memory dump file and enable forensic mode
    if ((Test-Path "$($MemoryDump)") -and (!("$($Pagefile)")))
    {
        Write-Output "[Info]  Mounting the Physical Memory Dump file as $DriveLetter ..."
        $MemorySize = Get-FileSize((Get-Item "$MemoryDump").Length)
        Write-Output "[Info]  Physical Memory Dump File Size: $MemorySize"
        New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null
        $Mount = $DriveLetter -replace ":", ""
        $StartTime_MemProcFS = (Get-Date)
        
        # Check if a Custom Yara rule or Yara index file was provided
        if ($null -eq $YaraRules)
        {
            # Offline Mode
            if ($OfflineMode -eq "Enabled")
            {
                Write-Output "[Info]  MemProcFS Forensic Analysis initiated [Offline-Mode] ..."
            }
            else
            {
                Write-Output "[Info]  MemProcFS Forensic Analysis initiated ..."
            }

            Write-Output "[Info]  Processing $MemoryDump [approx. 1-10 min] ..."
            Start-Process -FilePath "$MemProcFS" -ArgumentList "-mount $Mount -device `"$MemoryDump`" -disable-python -forensic 4 -loglevel forensic:5 -v -logfile `"$MemProcFSLogfile`" -forensic-process-skip `"$ForensicProcessWhitelist`""
        }
        else
        {
            if ((Test-Path "$YaraRules") -And ((Get-Item "$YaraRules").length -gt 0kb))
            {
                # Check if Process Skiplist is inactive
                if ($null -eq $ForensicProcessWhitelist)
                {
                    # Offline Mode
                    if ($OfflineMode -eq "Enabled")
                    {
                        Write-Output "[Info]  MemProcFS Forensic Analysis initiated [Offline-Mode] ..."
                    }
                    else
                    {
                        Write-Output "[Info]  MemProcFS Forensic Analysis initiated ..."
                    }

                    $Count_YaraRules = (Get-Content -Path $YaraRules | Select-String -Pattern "^include" | Measure-Object).Count
                    Write-Output "[Info]  YARA scan initialized with $Count_YaraRules rules ..."
                    Write-Output "[Info]  Processing $MemoryDump [approx. 1-10 min] ..."
                    Start-Process -FilePath "$MemProcFS" -ArgumentList "-mount $Mount -device `"$MemoryDump`" -disable-python -disable-yara-builtin -forensic-yara-rules `"$YaraRules`" -forensic 4 -loglevel forensic:5 -v -logfile `"$MemProcFSLogfile`""
                }
                else
                {
                    # Offline Mode
                    if ($OfflineMode -eq "Enabled")
                    {
                        Write-Output "[Info]  MemProcFS Forensic Analysis initiated [Offline-Mode] ..."
                    }
                    else
                    {
                        Write-Output "[Info]  MemProcFS Forensic Analysis initiated ..."
                    }

                    $Count_YaraRules = (Get-Content -Path $YaraRules | Select-String -Pattern "^include" | Measure-Object).Count
                    $Count_ProcessSkip = ($ForensicProcessWhitelist.Split(",") | Where-Object {$_.Trim() -ne "" }).Count
                    Write-Output "[Info]  YARA scan initialized with $Count_YaraRules rules ($Count_ProcessSkip Process Names will be skipped) ..."
                    Write-Output "[Info]  Processing $MemoryDump [approx. 1-10 min] ..."
                    Start-Process -FilePath "$MemProcFS" -ArgumentList "-mount $Mount -device `"$MemoryDump`" -disable-python -disable-yara-builtin -forensic-yara-rules `"$YaraRules`" -forensic 4 -loglevel forensic:5 -v -logfile `"$MemProcFSLogfile`" -forensic-process-skip `"$ForensicProcessWhitelist`""
                }
            }
        }

        # Check if successfully mounted
        while (!(Test-Path "$($DriveLetter)"))
        {
            Start-Sleep -Seconds 2
        }

        # Check forensic mode processing
        while (!(Select-String -Pattern "100" -Path "$DriveLetter\forensic\progress_percent.txt" -Quiet))
        {
            Start-Sleep -Seconds 2
        }

        $EndTime_MemProcFS = (Get-Date)
        $Time_MemProcFS = ($EndTime_MemProcFS-$StartTime_MemProcFS)
        ('MemProcFS Processing duration: {0} h {1} min {2} sec' -f $Time_MemProcFS.Hours, $Time_MemProcFS.Minutes, $Time_MemProcFS.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"
    }

    # Check if Mount Point exists
    if (Test-Path "$DriveLetter\forensic\*")
    {
        # CurrentControlSet
        $RegistryValue = "$DriveLetter\registry\HKLM\SYSTEM\Select\Current.txt"

        if (Test-Path "$($RegistryValue)")
        {
            $CurrentControlSet = Get-Content "$RegistryValue" | Select-Object -Skip 2 | ForEach-Object {$_ -replace "^0+", ""}
        }

        # ComputerName
        $RegistryValue = "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\ComputerName\ComputerName\ComputerName.txt"

        if (Test-Path "$($RegistryValue)")
        {
            $ComputerName = Get-Content "$RegistryValue" | Select-Object -Skip 2
            Write-Output "[Info]  Host Name: $ComputerName"
        }

        # ProductName
        if (Test-Path "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName.txt")
        {
            $ProductName = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName.txt" | Select-Object -Skip 2
        }

        # OSArchitecture
        if (Test-Path "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\Session Manager\Environment\PROCESSOR_ARCHITECTURE.txt")
        {
            $PROCESSOR_ARCHITECTURE = Get-Content "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\Session Manager\Environment\PROCESSOR_ARCHITECTURE.txt" | Select-Object -Skip 2

            # AMD64 (x64)
            if ($PROCESSOR_ARCHITECTURE -match "AMD64")
            {
                $OSArchitecture = "x64"
            }

            # x86
            if ($PROCESSOR_ARCHITECTURE -match "x86")
            {
                $OSArchitecture = "x86"
            }

            # ARM64
            if ($PROCESSOR_ARCHITECTURE -match "ARM64")
            {
                $OSArchitecture = "ARM64"
            }
        }
        else
        {
            Write-Output "[Info]  Processor Architecture: UNKNOWN"
        }

        # CSDVersion
        if (Test-Path "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CSDVersion.txt")
        {
            $OSVersion = (Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CSDVersion.txt" | Select-Object -Skip 2) -creplace '(?s)^.*Service Pack ', ''
        }

        # Windows 10
        if ($ProductName -like "*Windows 10*")
        {
            # Major
            $CurrentMajorVersionNumber = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentMajorVersionNumber.txt" | Select-Object -Skip 2
            $Major = [Convert]::ToInt64("$CurrentMajorVersionNumber",16)

            # Minor
            $CurrentMinorVersionNumber = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentMinorVersionNumber.txt" | Select-Object -Skip 2
            $Minor = [Convert]::ToInt64("$CurrentMinorVersionNumber",16)
        }
        else 
        {
            # CurrentVersion
            if (Test-Path "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentVersion.txt")
            {
                $CurrentVersion = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentVersion.txt" | Select-Object -Skip 2

                # Major
                $Major = $CurrentVersion.split('.')[0]

                # Minor
                $Minor = $CurrentVersion.split('.')[1]
            }
            else
            {
                Write-Host "[Error] $DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentVersion.txt does NOT exist." -ForegroundColor Red
            }
        }

        # Windows 10, Windows 11, Windows Server 2016, Windows Server 2019, and Windows Server 2022
        if (($ProductName -like "*Windows 10*") -Or ($ProductName -like "*Windows Server 2016*") -Or ($ProductName -like "*Windows Server 2019*") -Or ($ProductName -like "*Windows Server 2022*"))
        {
            # DisplayVersion
            if (Test-Path "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DisplayVersion.txt")
            {
                $DisplayVersion = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DisplayVersion.txt" | Select-Object -Skip 2
            }

            # ReleaseID
            $ReleaseID = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ReleaseId.txt" | Select-Object -Skip 2
    
            # CurrentBuildNumber
            if (Test-Path "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuildNumber.txt")
            {
                [int]$CurrentBuildNumber = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuildNumber.txt" | Select-Object -Skip 2
            }
            else
            {
                Write-Host "[Error] $DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuildNumber.txt does NOT exist." -ForegroundColor Red
            }

            # UBR
            if (Test-Path "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UBR.txt")
            {
                $Hex = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UBR.txt" | Select-Object -Skip 2
                $UBR = [uint32]"0x$Hex"
            }

            # Windows 11 (CurrentBuildNumber + Update Build Revision)
            # Windows 11 Build 21996 --> First Developer Preview
            # Windows 11 Build 22000 --> First Public Preview
            if ($CurrentBuildNumber -ge "21996")
            {
                $ProductName = $ProductName | ForEach-Object{($_ -replace "10","11")}
                $Hex = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UBR.txt" | Select-Object -Skip 2
                $UBR = [uint32]"0x$Hex"
                Write-Output "[Info]  OS: $ProductName ($OSArchitecture), Version: $DisplayVersion ($Major.$Minor.$CurrentBuildNumber.$UBR)"
            }
            else
            {
                if ($DisplayVersion)
                {
                    Write-Output "[Info]  OS: $ProductName ($OSArchitecture), Version: $ReleaseID / $DisplayVersion ($Major.$Minor.$CurrentBuildNumber.$UBR)"
                }
                else
                {
                    Write-Output "[Info]  OS: $ProductName ($OSArchitecture), Version: $ReleaseID ($Major.$Minor.$CurrentBuildNumber.$UBR)"
                }
            }
        }
        else
        {
            # CurrentBuildNumber
            $CurrentBuildNumber = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuildNumber.txt" | Select-Object -Skip 2

            # Revision Number
            if (Test-Path "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\BuildLabEx.txt")
            {
                # BuildLabEx
                $BuildLabEx = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\BuildLabEx.txt" | Select-Object -Skip 2
                $RevisionNumber = $BuildLabEx.split('.')[1]
            }
            else
            {
                if (Test-Path "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\BuildLab.txt")
                {
                    # BuildLab
                    $BuildLab = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\BuildLab.txt" | Select-Object -Skip 2
                    $RevisionNumber = $BuildLab.split('-')[1]
                }
            }

            if (Test-Path "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CSDVersion.txt")
            {
                Write-Output "[Info]  OS: $ProductName ($OSArchitecture), Service Pack $OSVersion ($Major.$Minor.$CurrentBuildNumber.$RevisionNumber)"
            }
            else
            {
                Write-Output "[Info]  OS: $ProductName ($OSArchitecture), Version: $Major.$Minor (Build: $CurrentBuildNumber.$RevisionNumber)"
            }
        }

        # InstallDate (ISO 8601)
        $RegistryValue = "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallDate.txt"

        if (Test-Path "$($RegistryValue)")
        {
            $HexadecimalBigEndian = Get-Content "$RegistryValue" | Select-Object -Skip 2
            $UnixSeconds = [Convert]::ToInt64("$HexadecimalBigEndian",16)
            $InstallDate = ((Get-Date 01.01.1970).AddSeconds($UnixSeconds)).ToString("yyyy-MM-dd HH:mm:ss")
            Write-Output "[Info]  InstallDate: $InstallDate UTC"
        }

        # RegisteredOrganization
        $RegisteredOrganization = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOrganization.txt" -ErrorAction SilentlyContinue | Select-Object -Skip 2
        if ($null -ne $RegisteredOrganization)
        {
            Write-Output "[Info]  RegisteredOrganization: $RegisteredOrganization"
        } 
        else 
        {
            Write-Output "[Info]  RegisteredOrganization: --"
        }

        # RegisteredOwner
        if (Test-Path "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOwner.txt")
        {
            $RegisteredOwner = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOwner.txt" | Select-Object -Skip 2
            if ($null -ne $RegisteredOwner)
            {
                Write-Output "[Info]  RegisteredOwner: $RegisteredOwner"
            }
            else
            {
                Write-Output "[Info]  RegisteredOwner: --"
            }
        }
        else
        {
            Write-Host "[Error] $DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOwner.txt does NOT exist." -ForegroundColor Red
        }

        # Check if it's a Domain Controller (Active Directory)
        # HKLM\System\ControlSet00$CurrentControlSet\Services\ADWS (Active Directory Domain Services)
        # HKLM\System\ControlSet00$CurrentControlSet\Services\NTDS (Windows NT Directory Services)
        if  (Test-Path "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\services")
        {
            if ((Get-ChildItem -Path "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\services" | Select-Object -ExpandProperty FullName | Select-String -Pattern "\\ADWS" -Quiet) -And (Get-ChildItem -Path "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\services" | Select-Object -ExpandProperty FullName | Select-String -Pattern "\\NTDS" -Quiet))
            {
                # ProductType
                # WinNT - Windows Client / Windows NT Workstation
                # LanmanNT – Domain Controller
                # ServerNT – Member Server / ServerNT - Windows NT Server Standalone
                if (Get-Content -Path "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\ProductOptions\ProductType.txt" | Select-Object -Skip 2 | Select-String -Pattern "LanmanNT" -Quiet)
                {
                    $ProductType = Get-Content -Path "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\ProductOptions\ProductType.txt" | Select-Object -Skip 2
                    Write-Output "[Info]  Product Type: Domain Controller ($ProductType)"
                }

                # ProductSuite
                $ProductSuite = Get-Content -Path "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\ProductOptions\ProductSuite.txt" | Select-Object -Skip 2
                if ($ProductSuite)
                {
                    Write-Output "[Info]  Product Suite: $ProductSuite"
                }
            }
        }

        # Check if it's a Microsoft Exchange Server
        if (Get-ChildItem -Path "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | Select-Object FullName | Select-String -Pattern "Microsoft Exchange*" -Quiet)
        {
            $SubDirectory = (Get-ChildItem -Path "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | Select-Object FullName).FullName | Select-String -Pattern "Microsoft Exchange*" | ForEach-Object{($_ -split "\\")[-1]}
            $DisplayName = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$SubDirectory\DisplayName.txt" | Select-Object -Skip 2
            $DisplayVersion = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$SubDirectory\DisplayVersion.txt" | Select-Object -Skip 2
            $InstallLocation = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$SubDirectory\InstallLocation.txt" | Select-Object -Skip 2
            Write-Output "[Info]  $DisplayName ($DisplayVersion)"
            Write-Output "[Info]  Install Location: $InstallLocation"
        }

        # Timezone Information
        if (Test-Path "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\TimeZoneInformation")
        {
            if (Test-Path "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\TimeZoneInformation\TimeZoneKeyName.txt")
            {
                $TimeZoneKeyName = Get-Content "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\TimeZoneInformation\TimeZoneKeyName.txt" | Select-Object -Skip 2 | ForEach-Object{($_ -replace "\.\..*$","")}
            }
            else
            {
                if (Test-Path "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\TimeZoneInformation\StandardName.txt")
                {
                    $TimeZoneKeyName = Get-Content "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\TimeZoneInformation\StandardName.txt" | Select-Object -Skip 2 | ForEach-Object{($_ -replace "\.\..*$","")}
                }
            }

            $LastWriteTime = Get-Content "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\TimeZoneInformation\(_Key_).txt" | Select-Object -Skip 3
            $ActiveTimeBias = Get-Content "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\TimeZoneInformation\ActiveTimeBias.txt" | Select-Object -Skip 2
            $UTC = '{0:d2}' -f -([int]"0x$ActiveTimeBias" / 60)

            if ($UTC -like "*-*" )
            {
                Write-Output "[Info]  Timezone Information: $TimeZoneKeyName (UTC$UTC`:00)"
                Write-Output "[Info]  Last Written Time: $LastWriteTime"
            }
            else
            {
                Write-Output "[Info]  Timezone Information: $TimeZoneKeyName (UTC+$UTC`:00)"
                Write-Output "[Info]  Last Written Time: $LastWriteTime"
            }
        }
        else
        {
            Write-Host "[Error] TimeZoneInformation Registry Subkey does NOT exist." -ForegroundColor Red
        }

        # LastLoggedOnUser
        $RegistryValue = "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\LastLoggedOnUser.txt"

        if (Test-Path "$($RegistryValue)")
        {
            $LastLoggedOnUser = (Get-Content "$RegistryValue" | Select-Object -Skip 2) -creplace '(?s)^.*\\', ''
            Write-Output "[Info]  Last Logged On User: $LastLoggedOnUser"
        }

        # Last Boot Up Time (ISO 8601)
        if (Test-Path "$DriveLetter\sys\time-boot.txt")
        {
            $LastBoot = Get-Content -Path "$DriveLetter\sys\time-boot.txt"
            Write-Output "[Info]  Last Boot: $LastBoot"
        }

        # Memory Acquisition Time (ISO 8601)
        if (Test-Path "$DriveLetter\sys\time-current.txt")
        {
            $Current = Get-Content -Path "$DriveLetter\sys\time-current.txt"
            Write-Output "[Info]  Memory Acquisition Time: $Current"
        }

        # Collecting Evidence Files
        Write-Output "[Info]  Collecting Evidence Files ..."

        # FS_Sys_Sysinfo
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Sys_Sysinfo
        if (Test-Path "$DriveLetter\sys\sysinfo\sysinfo.txt")
        {
            New-Item "$OUTPUT_FOLDER\sys\sysinfo" -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$DriveLetter\sys\sysinfo\sysinfo.txt" -Destination "$OUTPUT_FOLDER\sys\sysinfo\sysinfo.txt"
        }

        # FS_FindEvil
        # https://github.com/ufrisk/MemProcFS/wiki/FS_FindEvil
        #
        # Indicators of Evil
        # AV_DETECT      AV_DETECT reports malware detected by the anti-virus residing on the analyzed system.
        # PE_INJECT      PE_INJECT locates malware by scanning for valid .DLLs and .EXEs with executable pages in their page tables located in a private (non-image) virtual address descriptor.
        # PEB_MASQ       PEB_MASQ will flag PEB Masquerading attempts. If PEB_MASQ is detected please investigate further in /sys/proc/proc-v.txt
        # PEB_BAD_LDR    BAD_PEB_LDR will flag if no in-process modules are enumerated from the PEB/LDR_DATA structures.
        # PROC_BAD_DTB   PROC_BAD_DTB will flag active processes with an invalid DirectoryTableBase (DTB) in the kernel _EPROCESS object.
        # PROC_NOLINK    PROC_NOLINK will flag if the process does not exist in the kernel _EPROCESS linked list.
        # PROC_PARENT    PROC_PARENT will flag if a well known process has a bad parent process.
        # PROC_USER      PROC_USER may trigger if well known processes are executing as a strange user. Example cmd.exe as SYSTEM.
        # PROC_DEBUG     PROC_DEBUG flag non-SYSTEM processes with the SeDebugPrivilege.
        # THREAD         THREAD flag various thread related issues.
        # PE_NOLINK      PE_NOLINK locates malware in image virtual address descriptors which is not linked from the in-process PEB/Ldr lists.
        # PE_PATCHED     PE_PATCHED locates malware in image virtual address descriptors which executable pages (in the page tables) differs from kernel prototype memory.
        # DRIVER_PATH    DRIVER_PATH flag kernel drivers that are loaded from a non-standard path. DRIVER_PATH also flag if no corresponding module could be located.
        # PRIVATE_RWX    PRIVATE_RWX locates malware with read/write/execute (RWX) pages in the page table which belongs to a private memory virtual address descriptor.
        # NOIMAGE_RWX    NOIMAGE_RWX locates malware with read/write/execute (RWX) pages in the page table which does not belong to image (module) virtual address descriptors.
        # PRIVATE_RX     PRIVATE_RX locates malware with read/execute (RX) pages in the page table which belongs to a private memory virtual address descriptor.
        # NOIMAGE_RX     NOIMAGE_RX locates malware with read/execute (RX) pages in the page table which does not belong to image (module) virtual address descriptors.

        # FS_FindEvil
        if (Test-Path "$DriveLetter\forensic\findevil\findevil.txt")
        {
            New-Item "$OUTPUT_FOLDER\forensic\findevil" -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$DriveLetter\forensic\findevil\findevil.txt" -Destination "$OUTPUT_FOLDER\forensic\findevil\findevil.txt"

            # CSV
            if (Test-Path "$DriveLetter\forensic\json\general.json")
            {
                $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "evil" }

                $Data | Foreach-Object {

                $proc = $_ | Select-Object -ExpandProperty proc -ErrorAction SilentlyContinue
                $procid = $_ | Select-Object -ExpandProperty pid -ErrorAction SilentlyContinue

                # Microsoft Defender AntiVirus Alerts

                $addr = $_ | Select-Object -ExpandProperty addr -ErrorAction SilentlyContinue
                if ($addr)
                {
                    $Address = $addr.PadLeft(16,"0")
                }
                else
                {
                    $Address = "0000000000000000"
                }

                $desc = $_ | Select-Object -ExpandProperty desc
                $desc2 = $_ | Select-Object -ExpandProperty desc2

                New-Object -TypeName PSObject -Property @{
                    "Process Name" = $proc
	                "PID" = $procid
	                "Address" = $Address
	                "Type" = $desc
                    "Description" = $desc2
                    }
                } | Select-Object "Process Name","PID","Type","Address","Description" | Export-Csv -Path "$OUTPUT_FOLDER\forensic\findevil\findevil.csv" -Delimiter "`t" -NoTypeInformation
            }

            # XLSX
            if (Get-Module -ListAvailable -Name ImportExcel)
            {
                if (Test-Path "$OUTPUT_FOLDER\forensic\findevil\findevil.csv")
                {
                    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\forensic\findevil\findevil.csv") -gt 0)
                    {
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\findevil\findevil.csv" -Delimiter "`t"
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\findevil\findevil.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "FindEvil" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns B-D
                        $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }
        }

        # Find Evil
        if (Test-Path "$OUTPUT_FOLDER\forensic\findevil\findevil.csv")
        {
            # AV_DETECT (Microsoft Defender AntiVirus)
            $Data = Import-Csv "$OUTPUT_FOLDER\forensic\findevil\findevil.csv" -Delimiter "`t" | Where-Object { $_.Type -like "*AV_DETECT*" }
            $Count = ($Data | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] AV_DETECT found ($Count)" -ForegroundColor Red
            }
            
            # PE_INJECT (Injected Modules)
            $Data = Import-Csv "$OUTPUT_FOLDER\forensic\findevil\findevil.csv" -Delimiter "`t" | Where-Object { $_.Type -like "*PE_INJECT*" }
            $Count = ($Data | Measure-Object).Count
            if ($Count -gt 0)
            {
                New-Item "$OUTPUT_FOLDER\forensic\findevil\PE_INJECT" -ItemType Directory -Force | Out-Null
                ($Data | Select-Object PID,"Process Name",Type,Address,Description | Format-Table -HideTableHeaders | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\forensic\findevil\PE_INJECT\PE_INJECT.txt"
                Write-Host "[Alert] PE_INJECT found ($Count)" -ForegroundColor Red
                (Get-Content "$OUTPUT_FOLDER\forensic\findevil\PE_INJECT\PE_INJECT.txt") -replace "^", "        "  | Write-Host -ForegroundColor Red
            }

            # Collecting PE_INJECT (Injected Modules)
            if (Test-Path "$($7za)")
            {
                if (Test-Path "$OUTPUT_FOLDER\forensic\findevil\PE_INJECT\PE_INJECT.txt")
                {
                    $PE_INJECTS = Get-Content "$OUTPUT_FOLDER\forensic\findevil\PE_INJECT\PE_INJECT.txt"
                    ForEach( $PE_INJECT in $PE_INJECTS )
                    {
                        $ProcessID = $PE_INJECT | ForEach-Object{($_ -split "\s+")[0]}
                        $InjectedModuleList = (Get-ChildItem -Recurse -Force "$DriveLetter\pid\$ProcessID\files\modules\*" | Where-Object {($_.FullName -match "_INJECTED*")} | Foreach-Object FullName)

                        ForEach( $InjectedModule in $InjectedModuleList )
                        {
                            $INFECTED = "infected"
                            $ArchiveName = $InjectedModule | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "_INJECTED-")[-1]}
                            & $7za a -mx5 -mhe "-p$INFECTED" -t7z "$OUTPUT_FOLDER\forensic\findevil\PE_INJECT\$ProcessID-$ArchiveName.7z" "$InjectedModule" > $null 2>&1
                        }
                    }
                }
            }

            # PEB_MASQ (PEB Masquerading)
            $Data = Import-Csv "$OUTPUT_FOLDER\forensic\findevil\findevil.csv" -Delimiter "`t" | Where-Object { $_.Type -like "*PEB_MASQ*" }
            $Count = ($Data | Measure-Object).Count
            if ($Count -gt 0)
            {
                New-Item "$OUTPUT_FOLDER\forensic\findevil\PEB_MASQ" -ItemType Directory -Force | Out-Null
                ($Data | Select-Object PID,"Process Name",Type,Address,Description | Format-Table -HideTableHeaders | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\forensic\findevil\PEB_MASQ\PEB_MASQ.txt"
                Write-Host "[Alert] PEB_MASQ found ($Count)" -ForegroundColor Red
                (Get-Content "$OUTPUT_FOLDER\forensic\findevil\PEB_MASQ\PEB_MASQ.txt") -replace "^", "        "  | Write-Host -ForegroundColor Red
            }
        }
        else
        {
            Write-Output "[Info]  Your Operating System is NOT supported by FindEvil."
            Write-Output "        Note: FindEvil is only available on 64-bit Windows 11, 10 and 8.1."
        }

        # Check if YARA Index was succesfully initialized
        # https://github.com/VirusTotal/yara/blob/master/libyara/include/yara/error.h
        if (Test-Path "$MemProcFSLogfile")
        {
            if (Get-Content -Path "$MemProcFSLogfile" | Select-String -Pattern "yr_initialize\(\) failed with error code 3" -Quiet)
            {
                Write-Host "[Error] YARA Index was NOT successfully initialized: Error Code 3" -ForegroundColor Red
            }
        }
        
        # FS_Forensic_Yara
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic_Yara
        if (Test-Path "$DriveLetter\forensic\yara\*.txt")
        {
            New-Item "$OUTPUT_FOLDER\forensic\yara" -ItemType Directory -Force | Out-Null
            Copy-Item "$DriveLetter\forensic\yara\*.txt" -Destination "$OUTPUT_FOLDER\forensic\yara"

            # Match Count
            if (!($null -eq $YaraRules))
            {
                if (Test-Path "$DriveLetter\forensic\yara\match-count.txt")
                {
                    [int]$Total = Get-Content -Path "$DriveLetter\forensic\yara\match-count.txt"
                    if ($Total -gt 0)
                    {
                        Write-Host "[Alert] $Total YARA rule matches" -ForegroundColor Red
                
                        # Result
                        if (Test-Path "$DriveLetter\forensic\yara\result.txt")
                        {
                            (Get-Content -Path "$DriveLetter\forensic\yara\result.txt" | Select-String -Pattern "threat_name" | Sort-Object -Unique | ForEach-Object{($_ -split "threat_name:")[1]}).Trim() | Out-File "$OUTPUT_FOLDER\forensic\yara\threat_name.txt"
                            (Get-Content -Path "$DriveLetter\forensic\yara\result.txt" | Select-String -Pattern "threat_name" | ForEach-Object{($_ -split "threat_name:")[1]}).Trim() | Sort-Object | Out-File "$OUTPUT_FOLDER\forensic\yara\threat_name_all.txt"
                            
                            $Threats = Get-Content "$OUTPUT_FOLDER\forensic\yara\threat_name.txt"

                            foreach ($ThreatName in $Threats)
                            {
                                $Count = (Get-Content "$OUTPUT_FOLDER\forensic\yara\threat_name_all.txt" | Select-String -Pattern "$ThreatName" | Measure-Object).Count
                                Write-Host "        $ThreatName ($Count)" -ForegroundColor Red
                            }
                        }
                    }
                    else
                    {
                        Write-Output "[Info]  0 YARA rule matches"
                    }
                }
            }
        }

        Function Get-MPLogs {

        # Microsoft Protection Logs
        if ((Test-Path "$DriveLetter\forensic\files\ROOT\ProgramData\Microsoft\Windows Defender\Support\*MPLog-*.log") -or (Test-Path "$DriveLetter\forensic\files\ROOT\ProgramData\Microsoft\Windows Defender\Support\*MPDetection-*.log"))
        {
            # Step #1 - Collecting MPLogs (MPLogs-[8 digits]-[6 digits].log --> MPLogs-[date]-[time].log)
            Write-Output "[Info]  Collecting Microsoft Protection Logs (MPLogs) ..."
            New-Item "$OUTPUT_FOLDER\MPLogs\Dirty" -ItemType Directory -Force | Out-Null

            # MPLogs
            if (Test-Path "$DriveLetter\forensic\files\ROOT\ProgramData\Microsoft\Windows Defender\Support\*MPLog-*.log")
            {
                Copy-Item "$DriveLetter\forensic\files\ROOT\ProgramData\Microsoft\Windows Defender\Support\*MPLog-*.log" -Destination "$OUTPUT_FOLDER\MPLogs\Dirty"
                
                # Count
                $Count = (Get-ChildItem -Path "$OUTPUT_FOLDER\MPLogs\Dirty" -Filter "*MPLog-*.log" | Measure-Object).Count
                Write-Output "[Info]  $Count MPLog(s) found"
            }

            # MPDetection
            if (Test-Path "$DriveLetter\forensic\files\ROOT\ProgramData\Microsoft\Windows Defender\Support\*MPDetection-*.log")
            {
                Copy-Item "$DriveLetter\forensic\files\ROOT\ProgramData\Microsoft\Windows Defender\Support\*MPDetection-*.log" -Destination "$OUTPUT_FOLDER\MPLogs\Dirty"
            }

            # Step #2 - Removing Null Bytes

            # MPLogs
            if (Test-Path "$OUTPUT_FOLDER\MPLogs\Dirty\*MPLog-*.log")
            {
                Write-Output "[Info]  Recovery of Microsoft Protection Logs (MPLogs) initiated ..."
                New-Item "$OUTPUT_FOLDER\MPLogs\Clean" -ItemType Directory -Force | Out-Null

                $MPLogs = (Get-ChildItem "$OUTPUT_FOLDER\MPLogs\Dirty" -Filter "*MPLog-*.log" -File -Force -ErrorAction SilentlyContinue).FullName

                ForEach( $MPLog in $MPLogs )
                {
                    $FileName = $MPLog.Split('\')[-1]
                    Get-Content "$MPLog" -Encoding Byte | Where-Object {$_ -ne 0x00} | Set-Content "$OUTPUT_FOLDER\MPLogs\Clean\$FileName" -Encoding Byte
                }
            }

            # MPDetection
            if (Test-Path "$OUTPUT_FOLDER\MPLogs\Dirty\*MPDetection-*.log")
            {
                New-Item "$OUTPUT_FOLDER\MPLogs\Clean" -ItemType Directory -Force | Out-Null

                $MPDetectionLogs = (Get-ChildItem "$OUTPUT_FOLDER\MPLogs\Dirty" -Filter "*MPDetection-*.log" -File -Force -ErrorAction SilentlyContinue).FullName

                ForEach( $MPDetectionLog in $MPDetectionLogs )
                {
                    $FileName = $MPDetectionLog.Split('\')[-1]
                    Get-Content "$MPDetectionLog" -Encoding Byte | Where-Object {$_ -ne 0x00} | Set-Content "$OUTPUT_FOLDER\MPLogs\Clean\$FileName" -Encoding Byte
                }
            }

            # Step #3 - CSV
            # https://gist.github.com/Qazeer/5ad40f6e98362520290d13f3015f79ec
            if (Test-Path "$OUTPUT_FOLDER\MPLogs\Clean\*MPLog-*.log")
            {
                Write-Output "[Info]  Converting Microsoft Protection Logs (MPLogs) to CSV ..."
                New-Item "$OUTPUT_FOLDER\MPLogs\CSV" -ItemType Directory -Force | Out-Null

                $MPLogs = (Get-ChildItem "$OUTPUT_FOLDER\MPLogs\Clean" -Filter "*MPLog-*.log" -File -Force -ErrorAction SilentlyContinue).FullName

                ForEach( $MPLog in $MPLogs )
                {
                    $BaseName = ($MPLog.Split('\')[-1]).split('.')[0]
                    $LogFile = Get-Item -Path $MPLog
                    $LogData = $LogFile | Get-Content -Encoding UTF8 -Raw
                    $LogOutput = New-Object System.Collections.ArrayList
                    $LogEntries = $LogData -split "(?m)^(?=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)"

                    Foreach ($LogEntry in $LogEntries)
                    {
                        if ($null -eq $LogEntry -or "" -eq $LogEntry.Trim()) { continue }

                        $LogExtract = $LogEntry | Select-String -Pattern "^(?<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*?)\s(?<Provider>\[.*?]|\S+?:)?\s?(?<Message>(?s).*)$"

                        if ($LogExtract.Matches.Count -eq 0) {
                            continue
                        }

                        $Timestamp = $LogExtract.Matches[0].Groups['Timestamp'].Value
                        $Category  = $LogExtract.Matches[0].Groups['Category'].Value
                        $Message   = $LogExtract.Matches[0].Groups['Message'].Value.Trim()

                        $null = $Provider -match '^\[?(?<ProviderExtracted>.*?)]?:?$'
                        $Category = if ($Matches.Contains("ProviderExtracted")) { $Matches["ProviderExtracted"] }

                        $null = $LogOutput.Add([PSCustomObject] @{
                            Timestamp = $Timestamp
                            Category  = $Category
                            Message   = $Message
                        })
                    }

                    $LogOutput | Export-Csv -NoTypeInformation "$OUTPUT_FOLDER\MPLogs\CSV\$BaseName.csv"
                }
            }

            # Step #4 - XLSX
            if (Test-Path "$OUTPUT_FOLDER\MPLogs\CSV\*MPLog-*.csv")
            {
                Write-Output "[Info]  Creating Excel SpreadSheets(s) ..."
                New-Item "$OUTPUT_FOLDER\MPLogs\XLSX" -ItemType Directory -Force | Out-Null

                $MPLogs = (Get-ChildItem "$OUTPUT_FOLDER\MPLogs\CSV" -Filter "*MPLog-*.csv" -File -Force -ErrorAction SilentlyContinue).FullName
                
                ForEach( $MPLog in $MPLogs )
                {
                    if([int](& $xsv count "$MPLog") -gt 0)
                    {
                        $BaseName = ($MPLog.Split('\')[-1]).split('.')[0]
                        $Import = Import-Csv "$MPLog" -Delimiter "," | Select-Object @{Name="Timestamp";Expression={([DateTime]::Parse($_.Timestamp).ToString("yyyy-MM-dd HH:mm:ss"))}},Provider,Message | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                        $Import | Export-Excel -Path "$OUTPUT_FOLDER\MPLogs\XLSX\$BaseName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MPLogs" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns A-B
                        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }
        }

        }

        Get-MPLogs

        # FS_Process_Console
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Process_Console
        if (Test-Path "$DriveLetter\name\conhost.exe-*\console\console.txt")
        {
            $Console = Get-ChildItem -Path "$DriveLetter\name\conhost.exe-*\console\console.txt"
            $Count = ($Console | Measure-Object).Count

            Write-Output "[Info]  $Count Console Information File(s) found"
            New-Item "$OUTPUT_FOLDER\forensic\console" -ItemType Directory -Force | Out-Null

            $Files = ($Console).FullName
            ForEach($File in $Files)
            {
                $Suffix = $File | ForEach-Object{($_ -split "-")[1]} | ForEach-Object{($_ -split "\\")[0]}
                Copy-Item -Path "$File" -Destination "$OUTPUT_FOLDER\forensic\console\console-$Suffix.txt"
            }
        }

        # FS_Forensic_Files
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic_Files
        if (Test-Path "$DriveLetter\forensic\files\files.txt")
        {
            New-Item "$OUTPUT_FOLDER\forensic\files" -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$DriveLetter\forensic\files\files.txt" -Destination "$OUTPUT_FOLDER\forensic\files\files.txt"
        }

        # FS_Forensic_CSV
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic_CSV
        if (Test-Path "$DriveLetter\forensic\csv\*.csv")
        {
            New-Item "$OUTPUT_FOLDER\forensic\csv" -ItemType Directory -Force | Out-Null
            Copy-Item "$DriveLetter\forensic\csv\*.csv" -Destination "$OUTPUT_FOLDER\forensic\csv"
        }

        # FS_Forensic_XLSX
        if (Test-Path "$OUTPUT_FOLDER\forensic\csv\*.csv")
        {
            New-Item "$OUTPUT_FOLDER\forensic\xlsx" -ItemType Directory -Force | Out-Null

            # devices.csv --> Device Drivers
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\devices.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\forensic\csv\devices.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\devices.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\devices.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Device Drivers" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Left" of column A
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Left"
                    # HorizontalAlignment "Center" of columns B-E and G
                    $WorkSheet.Cells["B:E"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["G:G"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # drivers.csv --> Kernel Drivers
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\drivers.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\forensic\csv\drivers.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\drivers.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\drivers.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kernel Drivers" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Left" of column A
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Left"
                    # HorizontalAlignment "Center" of columns B-E
                    $WorkSheet.Cells["B:E"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # files.csv --> Recoverable Files
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\files.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\forensic\csv\files.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\files.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\files.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Files" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-C
                    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # findevil.csv --> Indicators of Evil
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\findevil.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\forensic\csv\findevil.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\findevil.csv" -Delimiter "," | Sort-Object PID
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\findevil.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "FindEvil" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-D
                    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # handles.csv --> Handles related to all processes
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\handles.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\forensic\csv\handles.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\handles.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\handles.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Handles" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-H
                    $WorkSheet.Cells["A:H"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # modules.csv --> Loaded Modules Information
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\modules.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\forensic\csv\modules.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\modules.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\modules.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Modules" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:X1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-J and M-W
                    $WorkSheet.Cells["A:J"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["M:W"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # net.csv --> Network Connection Information
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\net.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\forensic\csv\net.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\net.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\net.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Network" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-J
                    $WorkSheet.Cells["A:J"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # netdns.csv --> DNS Information
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\netdns.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\forensic\csv\netdns.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\netdns.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\netdns.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DNS" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-D
                    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # prefetch.csv --> Prefetch Information
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\prefetch.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\forensic\csv\prefetch.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\prefetch.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\prefetch.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Prefetch" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-C and E-M
                    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["E:M"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # process.csv --> Process Information
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\process.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\forensic\csv\process.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\process.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\process.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Processes" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-C and F-O
                    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:O"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # services.csv --> Services (user mode and kernel drivers)
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\services.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\forensic\csv\services.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\services.csv" -Delimiter "," | Sort-Object PID
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\services.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Services" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-B and E-J
                    $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["E:J"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # tasks.csv --> Scheduled Tasks
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\tasks.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\forensic\csv\tasks.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\tasks.csv" -Delimiter "," | Sort-Object { $_.TimeCreate -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\tasks.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Tasks" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A, D-E and H-K
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # threads.csv --> Information about all threads on the system
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\threads.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\forensic\csv\threads.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\threads.csv" -Delimiter "," | Sort-Object PID # or CreateTime???
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\threads.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Threads" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:V1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-V
                    $WorkSheet.Cells["A:V"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # timeline_all.csv --> \forensic\timeline\timeline-reverse.csv

            # timeline_kernelobject.csv --> Kernel Object Manager Objects
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\timeline_kernelobject.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\timeline_kernelobject.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\timeline_kernelobject.csv" -Delimiter "," | Select-Object Time, Type, Action, PID, Value32, Value64, Text | Sort-Object { $_.Time -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\timeline_kernelobject.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "timeline_kernelobject" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # timeline_net.csv --> Network Timeline
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\timeline_net.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\timeline_net.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\timeline_net.csv" -Delimiter "," | Select-Object Time, Type, Action, PID, Value32, Value64, Text | Sort-Object { $_.Time -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\timeline_net.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "timeline_net" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # timeline_ntfs.csv --> \forensic\timeline\timeline-reverse.csv

            # timeline_prefetch.csv --> Prefetch Timeline
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\timeline_prefetch.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\timeline_prefetch.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\timeline_prefetch.csv" -Delimiter "," | Select-Object Time, Type, Action, PID, Value32, Value64, Text | Sort-Object { $_.Time -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\timeline_prefetch.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "timeline_prefetch" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # timeline_process.csv --> Process Timeline
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\timeline_process.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\timeline_process.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\timeline_process.csv" -Delimiter "," | Select-Object Time, Type, Action, PID, Value32, Value64, Text | Sort-Object { $_.Time -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\timeline_process.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "timeline_process" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # timeline_registry.csv --> Registry Timeline
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\timeline_registry.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\timeline_registry.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\timeline_registry.csv" -Delimiter "," | Select-Object Time, Type, Action, PID, Value32, Value64, Text | Sort-Object { $_.Time -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\timeline_registry.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "timeline_registry" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # timeline_task.csv --> Scheduled Tasks Timeline
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\timeline_task.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\timeline_task.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\timeline_task.csv" -Delimiter "," | Select-Object Time, Type, Action, PID, Value32, Value64, Text | Sort-Object { $_.Time -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\timeline_task.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "timeline_task" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # timeline_thread.csv --> Threading Timeline
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\timeline_thread.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\timeline_thread.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\timeline_thread.csv" -Delimiter "," | Select-Object Time, Type, Action, PID, Value32, Value64, Text | Sort-Object { $_.Time -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\timeline_thread.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "timeline_thread" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # timeline_web --> Web Timeline
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\timeline_web.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\timeline_web.csv").length -gt 46)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\timeline_web.csv" -Delimiter "," | Sort-Object { $_.Time -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\timeline_web.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "timeline_web" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # unloaded_modules.csv --> Unloaded Modules Information
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\unloaded_modules.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\forensic\csv\unloaded_modules.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\unloaded_modules.csv" -Delimiter "," | Sort-Object PID
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\unloaded_modules.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "unloaded_modules" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-H
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:H"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # yara.csv --> Summary forensic yara scan results
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\yara.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\forensic\csv\yara.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\yara.csv" -Delimiter "," | Sort-Object { $_.Time -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\yara.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "YARA" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:Y1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-B, D-J, L-O, Q, S, U, W and Y
                    $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:J"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:O"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["Q:Q"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["S:S"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["U:U"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["W:W"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["Y:Y"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # FS_Forensic_JSON
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic_JSON
        if (Test-Path "$DriveLetter\forensic\json\*.json")
        {
            New-Item "$OUTPUT_FOLDER\forensic\json" -ItemType Directory -Force | Out-Null
            Copy-Item "$DriveLetter\forensic\json\*.json" -Destination "$OUTPUT_FOLDER\forensic\json"
        }

        # FS_Forensic_Ntfs
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic_Ntfs
        if (Test-Path "$DriveLetter\forensic\ntfs\ntfs_files.txt")
        {
            New-Item "$OUTPUT_FOLDER\forensic\ntfs" -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$DriveLetter\forensic\ntfs\ntfs_files.txt" -Destination "$OUTPUT_FOLDER\forensic\ntfs\ntfs_files.txt"
        }

        # FS_Forensic_Timeline
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic_Timeline
        if (Test-Path "$DriveLetter\forensic\timeline\*.txt")
        {
            New-Item "$OUTPUT_FOLDER\forensic\timeline" -ItemType Directory -Force | Out-Null
            Copy-Item "$DriveLetter\forensic\timeline\*.txt" -Destination "$OUTPUT_FOLDER\forensic\timeline"
        }

        # FS_SysInfo
        # https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo
        if (Test-Path "$DriveLetter\sys\*.txt")
        {
            New-Item "$OUTPUT_FOLDER\sys" -ItemType Directory -Force | Out-Null
            Copy-Item "$DriveLetter\sys\*.txt" -Destination "$OUTPUT_FOLDER\sys"
        }

        # FS_SysInfo_Users
        # https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo_Users
        if (Test-Path "$DriveLetter\sys\users\*.txt")
        {
            New-Item "$OUTPUT_FOLDER\sys\users" -ItemType Directory -Force | Out-Null
            Copy-Item "$DriveLetter\sys\users\*.txt" -Destination "$OUTPUT_FOLDER\sys\users"
        }

        # FS_SysInfo_Certificates
        # https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo_Certificates
        if (Test-Path "$DriveLetter\sys\certificates\certificates.txt")
        {
            New-Item "$OUTPUT_FOLDER\sys\certificates" -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$DriveLetter\sys\certificates\certificates.txt" -Destination "$OUTPUT_FOLDER\sys\certificates\certificates.txt"

            # SHA1
            Get-Content "$OUTPUT_FOLDER\sys\certificates\certificates.txt" | Select-String -Pattern "[A-Za-z0-9]{32}" -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File "$OUTPUT_FOLDER\sys\certificates\SHA1.txt"

            # Count
            $Total = (Get-Content "$OUTPUT_FOLDER\sys\certificates\certificates.txt" | Measure-Object).Count
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\certificates\SHA1.txt" | Measure-Object).Count
            Write-Output "[Info]  $Count Certificates found ($Total)"

            # CSV
            if (Test-Path "$DriveLetter\forensic\json\general.json")
            {
                $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "certificate" }

                $Data | Foreach-Object {

                $desc = $_ | Select-Object -ExpandProperty desc
                $store = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="store"; Expression={ForEach-Object{($_ -split "store:")[1]} | ForEach-Object{($_ -split "thumbprint:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $thumbprint = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="thumbprint"; Expression={ForEach-Object{($_ -split "thumbprint:")[1]} | ForEach-Object{($_ -split "issuer:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $issuer  = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="issuer"; Expression={ForEach-Object{($_ -split "issuer:")[1]} | ForEach-Object{($_ -replace "[\[\]]","")}}}

                New-Object -TypeName PSObject -Property @{
	                "Description" = $desc
	                "Store" = $store.store
	                "Thumbprint (SHA1)" = $thumbprint.thumbprint
	                "Issuer" = $issuer.issuer
                    }
                } | Select-Object "Description","Store","Thumbprint (SHA1)","Issuer" | Export-Csv -Path "$OUTPUT_FOLDER\sys\certificates\certificates.csv" -Delimiter "`t" -NoTypeInformation
            }

            # XLSX
            if (Get-Module -ListAvailable -Name ImportExcel)
            {
                if (Test-Path "$OUTPUT_FOLDER\sys\certificates\certificates.csv")
                {
                    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\certificates\certificates.csv") -gt 0)
                    {
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\certificates\certificates.csv" -Delimiter "`t"
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\certificates\certificates.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Certificates" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns B-C
                        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }
        }

        # FS_Sys_Drivers
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Sys_Drivers
        if (Test-Path "$DriveLetter\sys\drivers\*.txt")
        {
            New-Item "$OUTPUT_FOLDER\sys\drivers" -ItemType Directory -Force | Out-Null
            Copy-Item "$DriveLetter\sys\drivers\*.txt" -Destination "$OUTPUT_FOLDER\sys\drivers"

            # CSV
            if (Test-Path "$DriveLetter\forensic\json\general.json")
            {
                $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "driver" }

                $Data | Foreach-Object {

                $obj = $_ | Select-Object -ExpandProperty obj
                $desc = $_ | Select-Object -ExpandProperty desc
                $size = $_ | Select-Object -ExpandProperty size -ErrorAction SilentlyContinue
                $addr = $_ | Select-Object -ExpandProperty addr -ErrorAction SilentlyContinue
                $addr2 = $_ | Select-Object -ExpandProperty addr2 -ErrorAction SilentlyContinue
                $svc = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="svc"; Expression={ForEach-Object{($_ -split "svc:")[1]} | ForEach-Object{($_ -split "path:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $path = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="path"; Expression={ForEach-Object{($_ -split "path:")[1]} | ForEach-Object{($_ -replace "[\[\]]","")}}}

                New-Object -TypeName PSObject -Property @{
                    "Object Address" = $obj
                    "Driver" = $desc
                    "Size" = $size
                    "Start" = $addr
                    "End" = $addr2
                    "Service Key" = $svc.svc
                    "Driver Name" = $path.path
                    }
                } | Select-Object "Object Address","Driver","Size","Start","End","Service Key","Driver Name" | Export-Csv -Path "$OUTPUT_FOLDER\sys\drivers\drivers.csv" -Delimiter "`t" -NoTypeInformation
            }

            # XLSX
            if (Get-Module -ListAvailable -Name ImportExcel)
            {
                if (Test-Path "$OUTPUT_FOLDER\sys\drivers\drivers.csv")
                {
                    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\drivers\drivers.csv") -gt 0)
                    {
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\drivers\drivers.csv" -Delimiter "`t"
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\drivers\drivers.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Drivers" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns A, D-E
                        $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                        # HorizontalAlignment "Right" of column C
                        $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Right"
                        # HorizontalAlignment "Center" of header of column C
                        $WorkSheet.Cells["C1:C1"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }
        }

        # FS_SysInfo_Network
        # https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo_Network
        if (Test-Path "$DriveLetter\sys\net\*.txt")
        {
            New-Item "$OUTPUT_FOLDER\sys\net" -ItemType Directory -Force | Out-Null

            # netstat.txt
            if (Test-Path "$DriveLetter\sys\net\netstat.txt")
            { 
                Copy-Item "$DriveLetter\sys\net\netstat.txt" -Destination "$OUTPUT_FOLDER\sys\net\netstat.txt"

                # CSV
                if (Test-Path "$DriveLetter\forensic\json\general.json")
                {
                    New-Item "$OUTPUT_FOLDER\sys\net\CSV" -ItemType Directory -Force | Out-Null
                    
                    $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "net" }

                    $Data | Foreach-Object {

                    $proc = $_ | Select-Object -ExpandProperty proc -ErrorAction SilentlyContinue
                    $procid = $_ | Select-Object -ExpandProperty pid -ErrorAction SilentlyContinue
                    $obj = $_ | Select-Object -ExpandProperty obj
                    $desc = $_ | Select-Object -ExpandProperty desc
                    $time = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="time"; Expression={ForEach-Object{($_ -split "time:")[1]} | ForEach-Object{($_ -split "path:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                    $path = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="path"; Expression={ForEach-Object{($_ -split "path:")[1]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                    
                    New-Object -TypeName PSObject -Property @{
                        "Process" = $proc
                        "PID" = $procid
                        "Protocol" = $desc | ForEach-Object{($_ -split "\s+")[0]}
                        "State" = $desc | ForEach-Object{($_ -split "\s+")[1]}
                        "Source" = $desc | ForEach-Object{($_ -split "\s+")[2]}
                        "Destination" = $desc | ForEach-Object{($_ -split "\s+")[3]}
                        "Time" = $time.time
                        "Object Address" = $obj
                        "Process Path" = $path.path
                        }
                    } | Select-Object "Process","PID","Protocol","State","Source","Destination","Time","Object Address","Process Path" | Export-Csv -Path "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" -NoTypeInformation
                }

                # Custom CSV
                if (Test-Path "$DriveLetter\forensic\json\general.json")
                {
                    New-Item "$OUTPUT_FOLDER\sys\net\CSV" -ItemType Directory -Force | Out-Null
                    
                    $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "net" }

                    $Data | Foreach-Object {

                    $proc = $_ | Select-Object -ExpandProperty proc -ErrorAction SilentlyContinue
                    $procid = $_ | Select-Object -ExpandProperty pid -ErrorAction SilentlyContinue
                    $obj = $_ | Select-Object -ExpandProperty obj
                    $desc = $_ | Select-Object -ExpandProperty desc
                    $time = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="time"; Expression={ForEach-Object{($_ -split "time:")[1]} | ForEach-Object{($_ -split "path:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                    $path = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="path"; Expression={ForEach-Object{($_ -split "path:")[1]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                    
                    New-Object -TypeName PSObject -Property @{
                        "Process" = $proc
                        "PID" = $procid
                        "Protocol" = $desc | ForEach-Object{($_ -split "\s+")[0]}
                        "State" = $desc | ForEach-Object{($_ -split "\s+")[1]}
                        "Source" = ($desc | ForEach-Object{($_ -split "\s+")[2]} | Select-Object @{Name="Source"; Expression={ ForEach-Object{($_ -replace ":\d+$","")}}}).Source
                        "SrcPort" = ($desc | ForEach-Object{($_ -split "\s+")[2]} | Select-Object @{Name="SrcPort"; Expression={ ForEach-Object{($_ -split ":")[-1]} | ForEach-Object{($_ -replace "\*\*\*","")}}}).SrcPort
                        "Destination" = ($desc | ForEach-Object{($_ -split "\s+")[3]} | Select-Object @{Name="Destination"; Expression={ ForEach-Object{($_ -replace ":\d+$","")}}}).Destination
                        "DstPort" = ($desc | ForEach-Object{($_ -split "\s+")[3]} | Select-Object @{Name="DstPort"; Expression={ ForEach-Object{($_ -split ":")[-1]} | ForEach-Object{($_ -replace "\*\*\*","")}}}).DstPort
                        "Time" = $time.time
                        "Object Address" = $obj
                        "Process Path" = $path.path
                        }
                    } | Select-Object "Process","PID","Protocol","State","Source","SrcPort","Destination","DstPort","Time","Object Address","Process Path" | Export-Csv -Path "$OUTPUT_FOLDER\sys\net\CSV\net-custom.csv" -Delimiter "`t" -NoTypeInformation
                }

                # XLSX
                if (Get-Module -ListAvailable -Name ImportExcel)
                {
                    if (Test-Path "$OUTPUT_FOLDER\sys\net\CSV\net.csv")
                    {
                        if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\net\CSV\net.csv") -gt 0)
                        {
                            New-Item "$OUTPUT_FOLDER\sys\net\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t"
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\net\XLSX\net.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Network" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B-H
                            $WorkSheet.Cells["B:H"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }

                # Custom XLSX
                if (Get-Module -ListAvailable -Name ImportExcel)
                {
                    if (Test-Path "$OUTPUT_FOLDER\sys\net\CSV\net-custom.csv")
                    {
                        if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\net\CSV\net-custom.csv") -gt 0)
                        {
                            New-Item "$OUTPUT_FOLDER\sys\net\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net-custom.csv" -Delimiter "`t"
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\net\XLSX\net-custom.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Network" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B-J
                            $WorkSheet.Cells["B:J"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }

                # IPv4
                # https://ipinfo.io/bogon
                New-Item "$OUTPUT_FOLDER\sys\net\IPv4" -ItemType Directory -Force | Out-Null
                $IPv4 = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                $Private = "^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)"
                $Special = "^(0\.0\.0\.0|127\.0\.0\.1|169\.254\.|224\.0\.0)"
                Get-Content "$OUTPUT_FOLDER\sys\net\netstat.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Out-File "$OUTPUT_FOLDER\sys\net\IPv4\IPv4-All.txt"
                Get-Content "$OUTPUT_FOLDER\sys\net\netstat.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Where-Object {$_ -notmatch $Private} | Where-Object {$_ -notmatch $Special} | Out-File "$OUTPUT_FOLDER\sys\net\IPv4\IPv4.txt"

                # Count
                $Total = (Get-Content "$OUTPUT_FOLDER\sys\net\IPv4\IPv4-All.txt" | Measure-Object).Count
                $Count = (Get-Content "$OUTPUT_FOLDER\sys\net\IPv4\IPv4.txt" | Measure-Object).Count
                Write-Output "[Info]  $Count IPv4 addresses found ($Total)"

                # IPv6
                # https://ipinfo.io/bogon
                New-Item "$OUTPUT_FOLDER\sys\net\IPv6" -ItemType Directory -Force | Out-Null
                $IPv6 = ":(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))"
                $Bogon = "^(::1|::ffff:0:0|100::|2001:10::|2001:db8::|fc00::|fe80::|fec0::|ff00::)"
                Get-Content "$OUTPUT_FOLDER\sys\net\netstat.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File "$OUTPUT_FOLDER\sys\net\IPv6\IPv6-All.txt"
                Get-Content "$OUTPUT_FOLDER\sys\net\netstat.txt" | ForEach-Object{($_ -split "\s+")[5]} | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Where-Object {$_ -notmatch $Bogon} | Out-File "$OUTPUT_FOLDER\sys\net\IPv6\IPv6.txt"

                # Count
                $Total = (Get-Content "$OUTPUT_FOLDER\sys\net\IPv6\IPv6-All.txt" | Measure-Object).Count
                $Count = (Get-Content "$OUTPUT_FOLDER\sys\net\IPv6\IPv6.txt" | Measure-Object).Count
                Write-Output "[Info]  $Count IPv6 addresses found ($Total)"

                # IP.txt
                Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\sys\net\IP.txt" # Header

                # IPv4.txt
                if (Test-Path "$OUTPUT_FOLDER\sys\net\IPv4\IPv4.txt")
                {
                    if ((Get-Item "$OUTPUT_FOLDER\sys\net\IPv4\IPv4.txt").Length -gt 0kb)
                    {
                        Get-Content -Path "$OUTPUT_FOLDER\sys\net\IPv4\IPv4.txt" | Out-File "$OUTPUT_FOLDER\sys\net\IP.txt" -Append
                    }
                }

                # IPv6.txt
                if (Test-Path "$OUTPUT_FOLDER\sys\net\IPv6\IPv6.txt")
                {
                    if ((Get-Item "$OUTPUT_FOLDER\sys\net\IPv6\IPv6.txt").Length -gt 0kb)
                    {
                        Get-Content -Path "$OUTPUT_FOLDER\sys\net\IPv6\IPv6.txt" | Out-File "$OUTPUT_FOLDER\sys\net\IP.txt" -Append
                    }
                }

                # IPinfo CLI (50000 requests per month)
                if (Test-Path "$($IPinfo)")
                {
                    if (Test-Path "$OUTPUT_FOLDER\sys\net\IP.txt")
                    {
                        if ((Get-Item "$OUTPUT_FOLDER\sys\net\IP.txt").Length -gt 0kb)
                        {
                            # Offline Mode
                            if ($OfflineMode -eq "Enabled")
                            {
                                Write-Output "[Info]  IP Data Enrichment w/ IPinfo.io will be skipped [Offline-Mode] ..."
                            }
                            else
                            {
                                # Internet Connectivity Check (Vista+)
                                $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]‘{DCB00C01-570F-4A9B-8D69-199FDBA5723B}’)).IsConnectedToInternet

                                if (!($NetworkListManager -eq "True"))
                                {
                                    Write-Host "[Error] Your computer is NOT connected to the Internet. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
                                }
                                else
                                {
                                    # Check if IPinfo.io is reachable
                                    if (!(Test-Connection -ComputerName ipinfo.io -Count 1 -Quiet))
                                    {
                                        Write-Host "[Error] ipinfo.io is NOT reachable. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
                                    }
                                    else
                                    {
                                        # Map IPs
                                        # https://ipinfo.io/map
                                        New-Item "$OUTPUT_FOLDER\sys\net\IPinfo" -ItemType Directory -Force | Out-Null
                                        Get-Content "$OUTPUT_FOLDER\sys\net\IP.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\sys\net\IPinfo\Map.txt"

                                        # Access Token
                                        # https://ipinfo.io/signup?ref=cli
                                        if (!("$IPInfoToken" -eq "access_token"))
                                        {
                                            # Summarize IPs
                                            # https://ipinfo.io/summarize-ips

                                            # TXT --> lists VPNs
                                            Get-Content "$OUTPUT_FOLDER\sys\net\IP.txt" | & $IPinfo summarize -t $IPInfoToken | Out-File "$OUTPUT_FOLDER\sys\net\IPinfo\Summary.txt"

                                            # CSV
                                            Get-Content "$OUTPUT_FOLDER\sys\net\IP.txt" | & $IPinfo --csv -t $IPInfoToken | Out-File "$OUTPUT_FOLDER\sys\net\IPinfo\IPinfo.csv"

                                            # Custom CSV (Free)
                                            if (Test-Path "$OUTPUT_FOLDER\sys\net\IPinfo\IPinfo.csv")
                                            {
                                                if([int](& $xsv count "$OUTPUT_FOLDER\sys\net\IPinfo\IPinfo.csv") -gt 0)
                                                {
                                                    $IPinfoRecords = Import-Csv "$OUTPUT_FOLDER\sys\net\IPinfo\IPinfo.csv" -Delimiter "," -Encoding UTF8
                                
                                                    $CustomCsv = @()

                                                    ForEach($IPinfoRecord in $IPinfoRecords)
                                                    {
                                                        $Line = [PSCustomObject]@{
                                                            "IP"           = $IPinfoRecord.ip
                                                            "City"         = $IPinfoRecord.city
                                                            "Region"       = $IPinfoRecord.region
                                                            "Country"      = $IPinfoRecord.country
                                                            "Country Name" = $IPinfoRecord.country_name
                                                            "EU"           = $IPinfoRecord.isEU
                                                            "Location"     = $IPinfoRecord.loc
                                                            "ASN"          = $IPinfoRecord | Select-Object -ExpandProperty org | ForEach-Object{($_ -split "\s+")[0]}
                                                            "OrgName"      = $IPinfoRecord | Select-Object -ExpandProperty org | ForEach-Object {$_ -replace "^AS[0-9]+ "}
                                                            "Postal Code"  = $IPinfoRecord.postal
                                                            "Timezone"     = $IPinfoRecord.timezone
                                                        }

                                                        $CustomCsv += $Line
                                                    }

                                                    $CustomCsv | Sort-Object {$_.IP -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\sys\net\IPinfo\IPinfo-Custom.csv" -NoTypeInformation -Encoding UTF8
                                                }
                                            }

                                            # Custom XLSX (Free)
                                            if (Get-Module -ListAvailable -Name ImportExcel)
                                            {
                                                if (Test-Path "$OUTPUT_FOLDER\sys\net\IPinfo\IPinfo-Custom.csv")
                                                {
                                                    if([int](& $xsv count "$OUTPUT_FOLDER\sys\net\IPinfo\IPinfo-Custom.csv") -gt 0)
                                                    {
                                                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\net\IPinfo\IPinfo-Custom.csv" -Delimiter "," | Sort-Object {$_.IP -as [Version]}
                                                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\net\IPinfo\IPinfo-Custom.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -PivotRows "Country Name" -PivotData @{"IP"="Count"} -WorkSheetname "IPinfo (Free)" -CellStyleSB {
                                                        param($WorkSheet)
                                                        # BackgroundColor and FontColor for specific cells of TopRow
                                                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                        Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                                        # HorizontalAlignment "Center" of columns A-K
                                                        $WorkSheet.Cells["A:K"].Style.HorizontalAlignment="Center"
                                                        }
                                                    }
                                                }
                                            }

                                            # XLSX (Free)
                                            if (Get-Module -ListAvailable -Name ImportExcel)
                                            {
                                                if (Test-Path "$OUTPUT_FOLDER\sys\net\IPinfo\IPinfo.csv")
                                                {
                                                    if([int](& $xsv count "$OUTPUT_FOLDER\sys\net\IPinfo\IPinfo.csv") -gt 0)
                                                    {
                                                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\net\IPinfo\IPinfo.csv" -Delimiter "," -Encoding UTF8 | Select-Object ip,city,region,country,country_name,isEU,loc,org,postal,timezone | Sort-Object {$_.ip -as [Version]}
                                                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\net\IPinfo\IPinfo.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "IPinfo" -CellStyleSB {
                                                        param($WorkSheet)
                                                        # BackgroundColor and FontColor for specific cells of TopRow
                                                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                        Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                                                        # HorizontalAlignment "Center" of columns A-J
                                                        $WorkSheet.Cells["A:J"].Style.HorizontalAlignment="Center"
                                                        }
                                                    }
                                                }
                                            }

                                            # Create HashTable and import 'IPinfo-Custom.csv'
                                            $script:HashTable = @{}
                                            if (Test-Path "$OUTPUT_FOLDER\sys\net\IPinfo\IPinfo-Custom.csv")
                                            {
                                                if([int](& $xsv count "$OUTPUT_FOLDER\sys\net\IPinfo\IPinfo-Custom.csv") -gt 0)
                                                {
                                                    Import-Csv "$OUTPUT_FOLDER\sys\net\IPinfo\IPinfo-Custom.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $HashTable[$_.IP] = $_.City,$_.Region,$_.Country,$_."Country Name",$_.EU,$_.Location,$_.ASN,$_.OrgName,$_."Postal Code",$_.Timezone }

                                                    # Count Ingested Properties
                                                    $Count = $HashTable.Count
                                                    Write-Output "[Info]  Initializing 'IPinfo-Custom.csv' Lookup Table ($Count) ..."
                                                }
                                            }

                                            # IP Data Enrichment w/ IPinfo.io
                                            if (Test-Path "$OUTPUT_FOLDER\sys\net\CSV\net-custom.csv")
                                            {
                                                if([int](& $xsv count "$OUTPUT_FOLDER\sys\net\CSV\net-custom.csv") -gt 0)
                                                {
                                                    $Records = Import-Csv -Path "$OUTPUT_FOLDER\sys\net\CSV\net-custom.csv" -Delimiter "`t" -Encoding UTF8

                                                    # CSV
                                                    $Results = @()
                                                    ForEach($Record in $Records)
                                                    {
                                                        $Source = $Record.Source | & $IPinfo grepip -o
                                                        $Destination = $Record.Destination | & $IPinfo grepip -o

                                                        # Check if HashTable contains Source IP
                                                        if($HashTable.ContainsKey("$Source"))
                                                        {
                                                            $SrcCountryName = $HashTable["$Source"][3]
                                                            $SrcASN         = $HashTable["$Source"][6]
                                                            $SrcOrgName     = $HashTable["$Source"][7]
                                                        }
                                                        else
                                                        {
                                                            $SrcCountryName = ""
                                                            $SrcASN         = ""
                                                            $SrcOrgName     = ""
                                                        }

                                                        # Check if HashTable contains Destination IP
                                                        if($HashTable.ContainsKey("$Destination"))
                                                        {
                                                            $DstCountryName = $HashTable["$Destination"][3]
                                                            $DstASN         = $HashTable["$Destination"][6]
                                                            $DstOrgName     = $HashTable["$Destination"][7]
                                                        }
                                                        else
                                                        {
                                                            $DstCountryName = ""
                                                            $DstASN         = ""
                                                            $DstOrgName     = ""
                                                        }
                                                        
                                                        $Line = [PSCustomObject]@{
                                                            "Process"        = $Record.Process
                                                            "PID"            = $Record.PID
                                                            "Protocol"       = $Record.Protocol
                                                            "State"          = $Record.State
                                                            "Src IP"         = $Record.Source
                                                            "Src Port"       = $Record.SrcPort
                                                            "Src Country"    = $SrcCountryName
                                                            "Src ASN"        = $SrcASN
                                                            "Src OrgName"    = $SrcOrgName
                                                            "Dst IP"         = $Record.Destination
                                                            "Dst Port"       = $Record.DstPort
                                                            "Dst Country"    = $DstCountryName
                                                            "Dst ASN"        = $DstASN
                                                            "Dst OrgName"    = $DstOrgName
                                                            "Time"           = $Record.Time
                                                            "Object Address" = $Record."Object Address"
                                                            "Process Path"   = $Record."Process Path"
                                                        }

                                                        $Results += $Line
                                                    }

                                                    $Results | Export-Csv -Path "$OUTPUT_FOLDER\sys\net\CSV\net-enriched.csv" -NoTypeInformation -Encoding UTF8
                                                }
                                            }

                                            # XLSX
                                            if (Get-Module -ListAvailable -Name ImportExcel)
                                            {
                                                if (Test-Path "$OUTPUT_FOLDER\sys\net\CSV\net-enriched.csv")
                                                {
                                                    if([int](& $xsv count "$OUTPUT_FOLDER\sys\net\CSV\net-enriched.csv") -gt 0)
                                                    {
                                                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net-enriched.csv" -Delimiter "," | Sort-Object { $_.CreationDate -as [datetime] } -Descending
                                                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\net\XLSX\net-enriched.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -WorkSheetname "IP Data Enrichment" -CellStyleSB {
                                                        param($WorkSheet)
                                                        # BackgroundColor and FontColor for specific cells of TopRow
                                                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                        Set-Format -Address $WorkSheet.Cells["A1:Q1"] -BackgroundColor $BackgroundColor -FontColor White
                                                        # HorizontalAlignment "Center" of columns A-Q
                                                        $WorkSheet.Cells["A:Q"].Style.HorizontalAlignment="Center"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    Write-Output "[Info]  ipinfo.exe NOT found."
                }
            }

            # netstat-v.txt
            if (Test-Path "$DriveLetter\sys\net\netstat-v.txt")
            {
                Copy-Item "$DriveLetter\sys\net\netstat-v.txt" -Destination "$OUTPUT_FOLDER\sys\net\netstat-v.txt"
            }

            # State
            if ((Test-Path "$OUTPUT_FOLDER\sys\net\CSV\net.csv") -And ([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\net\CSV\net.csv") -gt 0))
            {
                $CLOSED      = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "CLOSED" }).Count
                $CLOSING     = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "CLOSING" }).Count
                $CLOSE_WAIT  = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "CLOSE_WAIT" }).Count
                $ESTABLISHED = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "ESTABLISHED" }).Count
                $FIN_WAIT_1  = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "FIN_WAIT_1" }).Count
                $FIN_WAIT_2  = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "FIN_WAIT_2" }).Count
                $LAST_ACK    = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "LAST_ACK" }).Count
                $LISTENING   = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "LISTENING" }).Count
                $SYN_RCVD    = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "SYN_RCVD" }).Count
                $SYN_SENT    = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "SYN_SENT" }).Count
                $TIME_WAIT   = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "TIME_WAIT" }).Count

                Write-Output "CLOSED      : $CLOSED" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "CLOSING     : $CLOSING" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "CLOSE_WAIT  : $CLOSE_WAIT" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "ESTABLISHED : $ESTABLISHED" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "FIN_WAIT_1  : $FIN_WAIT_1" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "FIN_WAIT_2  : $FIN_WAIT_2" | Out-File "$OUTPUT_FOLDER\sys\net\Stats.txt" -Append
                Write-Output "LAST_ACK    : $LAST_ACK" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "LISTENING   : $LISTENING" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "SYN_RCVD    : $SYN_RCVD" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "SYN_SENT    : $SYN_SENT" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "TIME_WAIT   : $TIME_WAIT" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
            }

            # Stats
            if ((Test-Path "$OUTPUT_FOLDER\sys\net\State.txt") -And ((Get-Item "$OUTPUT_FOLDER\sys\net\State.txt").length -gt 0kb))
            {
                $Stats = Get-Content "$OUTPUT_FOLDER\sys\net\State.txt" | ForEach-Object{($_ -replace ":","")} | ConvertFrom-String -PropertyNames State, Count | Sort-Object Count -Descending
                ($Stats | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\sys\net\Stats.txt"
            }

            # CLOSED        Closed. The socket is not being used.
            # CLOSING       Closed, then remote shutdown; awaiting acknowledgment.
            # CLOSE_WAIT    Remote shutdown; waiting for the socket to close.
            # ESTABLISHED   Connection has been established.
            # FIN_WAIT_1    Socket closed; shutting down connection.
            # FIN_WAIT_2    Socket closed; waiting for shutdown from remote.
            # LAST_ACK      Remote shutdown, then closed; awaiting acknowledgment.
            # LISTENING     Listening for incoming connections.
            # SYN_RCVD      Active/initiate synchronization received and the connection under way.
            # SYN_SENT      Actively trying to establish connection.
            # TIME_WAIT     Wait after close for remote shutdown retransmission.
                
            # Suspicious Port Numbers

            # Source

            # TCP on Source Port 3262 --> This rule detects events that may indicate use of encrypted traffic on TCP port 3262 (F-Response)
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Source -like "*:3262" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Output "[Info]  TCP on Source Port 3262 detected - May indicates use of encrypted traffic by F-Response ($Count)"
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Source-Port-3262.txt"
            }

            # TCP on Source Port 3389 --> This rule detects events that may indicate incoming Remote Desktop Protocol (RDP) activity on TCP port 3389 - Incoming
            # Note: proc.xlsx --> CommandLine: C:\Windows\System32\svchost.exe -k termsvc
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Source -match ":3389$" } | Where-Object { $_.Process -eq "svchost.exe" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Source Port 3389 detected - May indicates incoming Remote Desktop Protocol (RDP) activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Source-Port-3389.txt"
            }

            # TCP on Source Port 4444 --> This rule detects events that may indicate a Meterpreter session (Reverse Shell)
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.State -eq "LISTENING" } | Where-Object { $_.Source -match ":4444$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Source Port 4444 detected - May indicates use of Meterpreter Reverse Shell ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Source-Port-4444.txt"
            }

            # TCP on Source Port 4899 --> This rule detects events that may indicate incoming Radmin-Server (Remote Desktop) activity on TCP port 4899 - Incoming (rserver3.exe)
            # Note: Radmin by Famatech Corp. (e.g. Advanced IP Scanner)
            # https://www.radmin.com/
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Source -match ":4899$" }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Source Port 4899 detected - May indicates incoming Radmin-Server (Remote Desktop) activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Source-Port-4899.txt"
            }

            # Destination

            # TCP on Destination Port 20 --> This rule detects events that may indicate outgoing File Transfer Protocol (FTP) activity over port 20
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -match ":20$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 20 detected - May indicates outgoing File Transfer Protocol (FTP) activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-20.txt"
            }

            # TCP on Destination Port 21 --> This rule detects events that may indicate outgoing File Transfer Protocol (FTP) activity over port 21
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -match ":21$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 21 detected - May indicates outgoing File Transfer Protocol (FTP) activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-21.txt"
            }

            # TCP on Destination Port 3389 --> This rule detects events that may indicate outgoing Remote Desktop Protocol (RDP) activity on TCP port 3389 - Outgoing
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -match ":3389$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 3389 detected - May indicates outgoing Remote Desktop Protocol (RDP) activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-3389.txt"
            }

            # TCP on Destination Port 4899 --> This rule detects events that may indicate outgoing Radmin Viewer (Remote Desktop) activity on TCP port 4899 - Outgoing (Radmin.exe)
            # Note: Radmin by Famatech Corp. (e.g. Advanced IP Scanner)
            # https://www.radmin.com/
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -match ":4899$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 4899 detected - May indicates outgoing Radmin-Viewer (Remote Desktop) activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-4899.txt"
            }

            # TCP on Destination Port 17301 --> This rule detects events that may indicate outgoing Radmin-VPN (RvControlSvc.exe) activity on TCP port 17301 - Outgoing
            # Note: Radmin VPN by Famatech Corp. (e.g. Advanced IP Scanner)
            # https://www.radmin-vpn.com/
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -match ":17301$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 17301 detected - May indicates outgoing Radmin-VPN activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-17301.txt"
            }

            # TCP on Destination Port 8080 --> This rule detects events that may indicate Command-and-Control (C2) activity over port 8080
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -match ":8080$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 8080 detected - May indicates Command-and-Control (C2) activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-8080.txt"
            }

            # TCP on Destination Port 8081 --> This rule detects events that may indicate Command-and-Control (C2) activity over port 8081
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -match ":8081$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 8081 detected - May indicates Command-and-Control (C2) activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-8081.txt"
            }

            # TCP on Destination Port 9001 --> This rule detects events that may indicate use of Tor client on TCP port 9001
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -match ":9001$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 9001 detected - May indicates Tor activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-9001.txt"
            }

            # TCP on Destination Port 9030 --> This rule detects events that may indicate Tor activity on TCP port 9030
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -match ":9030$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 9030 detected - May indicates Tor activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-9030.txt"
            }

            # TCP on Destination Port 9150 --> This rule detects events that may indicate use of Tor client on TCP port 9150
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -eq "127.0.0.1:9150" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 9150 detected - May indicates Tor activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-9150.txt"
            }
        }

        # FS_SysInfo_Network - DNS
        # https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo_Network
        if (Test-Path "$DriveLetter\sys\net\dns\*.txt")
        {
            New-Item "$OUTPUT_FOLDER\sys\net\dns" -ItemType Directory -Force | Out-Null

            # dns.txt
            if (Test-Path "$DriveLetter\sys\net\dns\dns.txt")
            { 
                Copy-Item "$DriveLetter\sys\net\dns\dns.txt" -Destination "$OUTPUT_FOLDER\sys\net\dns\dns.txt"
            }

            # readme.txt
            if (Test-Path "$DriveLetter\sys\net\dns\readme.txt")
            { 
                Copy-Item "$DriveLetter\sys\net\dns\readme.txt" -Destination "$OUTPUT_FOLDER\sys\net\dns\readme.txt"
            }
        }

        # FS_SysInfo_Process
        # https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo_Process
        if (Test-Path "$DriveLetter\sys\proc\*.txt")
        {
            New-Item "$OUTPUT_FOLDER\sys\proc\TXT" -ItemType Directory -Force | Out-Null
            Add-Content -Path "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" -Encoding utf8 -Value (Get-Content -Path "$DriveLetter\sys\proc\proc.txt")
            Add-Content -Path "$OUTPUT_FOLDER\sys\proc\TXT\proc-v.txt" -Encoding utf8 -Value (Get-Content -Path "$DriveLetter\sys\proc\proc-v.txt")

            # Count Processes
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Measure-Object).Count -2
            Write-Output "[Info]  Processing $Count Processes ..."

            # Flags
            # 32 - Process is 32-bit on 64-bit Windows.
            # E  - Process is NOT found in EPROCESS list (memory corruption, drift or unlink)
            # T  - Process is terminated
            # U  - Process is user-account (non-system user)
            # *  - Process is outside standard paths.

            # CSV
            if (Test-Path "$DriveLetter\forensic\json\general.json")
            {
                New-Item "$OUTPUT_FOLDER\sys\proc\CSV" -ItemType Directory -Force | Out-Null

                $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "process" }

                $Data | Foreach-Object {

                $proc = $_ | Select-Object -ExpandProperty proc

                # Replace empty "Process Name" fields
                if ($proc -eq "")
                {
                    $proc = "<unknown>"        
                }

                $procid = $_ | Select-Object -ExpandProperty pid
                $obj = $_ | Select-Object -ExpandProperty obj
                $parentid = $_ | Select-Object -ExpandProperty num -ErrorAction SilentlyContinue
                $parentproc = $Data | Where-Object { $_.pid -eq "$parentid" } | Select-Object -ExpandProperty proc
                $hex = $_ | Select-Object -ExpandProperty hex -ErrorAction SilentlyContinue
                $hex2 = $_ | Select-Object -ExpandProperty hex2 -ErrorAction SilentlyContinue
                $desc = $_ | Select-Object -ExpandProperty desc
                $flags = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="flags"; Expression={ForEach-Object{($_ -split "flags:")[1]} | ForEach-Object{($_ -split "user:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $user = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="user"; Expression={ForEach-Object{($_ -split "user:")[1]} | ForEach-Object{($_ -split "upath:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $upath = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="upath"; Expression={ForEach-Object{($_ -split "upath:")[1]} | ForEach-Object{($_ -split "cmd:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $cmd = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="cmd"; Expression={ForEach-Object{($_ -split "cmd:")[1]} | ForEach-Object{($_ -split "createtime:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $createtime = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="createtime"; Expression={ForEach-Object{($_ -split "createtime:")[1]} | ForEach-Object{($_ -split "integrity:")[0]} | ForEach-Object{($_ -split "exittime:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $exittime = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="exittime"; Expression={ForEach-Object{($_ -split "exittime:")[1]} | ForEach-Object{($_ -split "integrity:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $integrity = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="integrity"; Expression={ForEach-Object{($_ -split "integrity:")[1]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $SubProcesses = ($Data | Where-Object { $_.num -eq $procid } | Measure-Object).Count

                New-Object -TypeName PSObject -Property @{
                    "Create Time" = $createtime.createtime
	                "Process Name" = $proc
	                "PID" = $procid
	                "obj " = $obj
                    "Parent Name" = $parentproc
	                "PPID" = $parentid
                    "hex" = $hex
                    "hex2" = $hex2
                    "Device Path" = $desc
                    "Flags" = $flags.flags
                    "User" = $user.user
                    "File Path" = $upath.upath
                    "CommandLine" = $cmd.cmd
                    "Integrity" = $integrity.integrity
                    "Exit Time" = $exittime.exittime
                    "Sub-Processes" = $SubProcesses
                    }
                } | Select-Object "Create Time","Process Name","PID","Parent Name","PPID","Sub-Processes","Device Path","Flags","User","File Path","CommandLine","Integrity","Exit Time" | Export-Csv -Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" -NoTypeInformation
            }

            # XLSX

            # Default
            if (Get-Module -ListAvailable -Name ImportExcel)
            {
                if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
                {
                    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv") -gt 0)
                    {
                        New-Item "$OUTPUT_FOLDER\sys\proc\XLSX" -ItemType Directory -Force | Out-Null
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Sort-Object { $_."Create Time" -as [datetime] } -Descending
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\XLSX\Processes.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Processes" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                        $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }
            
            # Process Tree (TreeView)
            if (Test-Path "$SCRIPT_DIR\Scripts\Get-ProcessTree\Get-ProcessTree.ps1")
            {
                if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
                {
                    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv") -gt 0)
                    {
                        Write-Output "[Info]  Launching Process Tree (TreeView) ... "
                        Unblock-File -Path "$SCRIPT_DIR\Scripts\Get-ProcessTree\Get-ProcessTree.ps1"
                        Start-Process -FilePath "powershell" -NoNewWindow -ArgumentList "-NoProfile", "-File", "$SCRIPT_DIR\Scripts\Get-ProcessTree\Get-ProcessTree.ps1", "-CSVPath", "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv"
                        Start-Sleep -Seconds 3
                        $Host.UI.RawUI.WindowTitle = "MemProcFS-Analyzer $Version - Automated Forensic Analysis of Windows Memory Dumps for DFIR"
                    }
                }
            }

            # Running and Exited Processes
            if (Get-Module -ListAvailable -Name ImportExcel)
            {
                if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
                {
                    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv") -gt 0)
                    {
                        New-Item "$OUTPUT_FOLDER\sys\proc\XLSX" -ItemType Directory -Force | Out-Null
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Sort-Object { $_."Create Time" -as [datetime] }
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\XLSX\RunningAndExited.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Processes" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                        $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"

                        # Exited Processes
                        $ExitedColor = [System.Drawing.Color]::FromArgb(255,0,0) # Red
                        Add-ConditionalFormatting -Address $WorkSheet.Dimension.Address -WorkSheet $WorkSheet -RuleType 'Expression' '=NOT(OR($M1="", $M1="Exit Time"))' -BackgroundColor $ExitedColor

                        # Running Processes
                        $RunningColor = [System.Drawing.Color]::FromArgb(0,176,80) # Green
                        Add-ConditionalFormatting -Address $WorkSheet.Dimension.Address -WorkSheet $WorkSheet -RuleType 'Expression' '=($M1="")' -BackgroundColor $RunningColor
                        }
                    }
                }
            }

            # Unusual Parent-Child Relationships

            # 01. Unusual Parent-Child Relationship (csrss.exe)
            $Pid_smss = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "smss.exe" | ForEach-Object{($_ -split "\s+")[2]}) -join "|"
            $Pid_svchost = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "svchost.exe" | ForEach-Object{($_ -split "\s+")[2]}) -join "|"
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "csrss.exe" | Where-Object{($_ -notmatch "$Pid_smss|$Pid_svchost")} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: csrss.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "csrss.exe" | Where-Object{($_ -notmatch "$Pid_smss|$Pid_svchost")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\csrss.exe.txt"
            }

            # 02. Unusual Parent-Child Relationship (LogonUI.exe)
            $Pid_wininit = Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "wininit.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Pid_winlogon = Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "winlogon.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "LogonUI.exe" | Where-Object{($_ -notmatch "$Pid_wininit|$Pid_winlogon")} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: LogonUI.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "LogonUI.exe" | Where-Object{($_ -notmatch "$Pid_wininit|$Pid_winlogon")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\LogonUI.exe.txt"
            }

            # 03. Unusual Parent-Child Relationship (lsass.exe)
            $Pid_wininit = Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "wininit.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "lsass.exe" | Where-Object{($_ -notmatch $Pid_wininit)} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: lsass.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "lsass.exe" | Where-Object{($_ -notmatch "$Pid_wininit")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\lsass.exe.txt"
            }

            # 04. Unusual Parent-Child Relationship (services.exe)
            $Pid_wininit = Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "wininit.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "services.exe" | Where-Object{($_ -notmatch $Pid_wininit)} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: services.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "services.exe" | Where-Object{($_ -notmatch "$Pid_wininit")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\services.exe.txt"
            }

            # 05. Unusual Parent-Child Relationship (smss.exe)
            $Pid_System = Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "System " -CaseSensitive | ForEach-Object{($_ -split "\s+")[2]}
            $Pid_smss = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "smss.exe" | ForEach-Object{($_ -split "\s+")[2]}) -join "|"
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "smss.exe" | Where-Object{($_ -notmatch "$Pid_System|$Pid_smss")} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: smss.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "smss.exe" | Where-Object{($_ -notmatch "$Pid_System|$Pid_smss")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\smss.exe.txt"
            }

            # 06. Unusual Parent-Child Relationship (spoolsv.exe)
            $Pid_services = Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "services.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "spoolsv.exe" | Where-Object{($_ -notmatch $Pid_services)} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: spoolsv.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "spoolsv.exe" | Where-Object{($_ -notmatch "$Pid_services")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\spoolsv.exe.txt"
            }

            # 07. Unusual Parent-Child Relationship (svchost.exe)
            $Pid_services = Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "services.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Pid_MsMpEng = Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "MsMpEng.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "svchost.exe" | Where-Object{($_ -notmatch "$Pid_services|$Pid_MsMpEng")} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: svchost.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "svchost.exe" | Where-Object{($_ -notmatch "$Pid_services|$Pid_MsMpEng")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\svchost.exe.txt"
            }

            # 08. Unusual Parent-Child Relationship (taskhost.exe)
            $Pid_services = Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "services.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Pid_svchost = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "svchost.exe" | ForEach-Object{($_ -split "\s+")[2]}) -join "|"
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "taskhost.exe" | Where-Object{($_ -notmatch "$Pid_services|$Pid_svchost")} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: taskhost.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "taskhost.exe" | Where-Object{($_ -notmatch "$Pid_services|$Pid_svchost")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\taskhost.exe.txt"
            }

            # 09. Unusual Parent-Child Relationship (taskhostw.exe)
            $Pid_services = Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "services.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Pid_svchost = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "svchost.exe" | ForEach-Object{($_ -split "\s+")[2]}) -join "|"
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "taskhostw.exe" | Where-Object{($_ -notmatch "$Pid_services|$Pid_svchost")} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: taskhostw.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "taskhostw.exe" | Where-Object{($_ -notmatch "$Pid_services|$Pid_svchost")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\taskhostw.exe.txt"
            }

            # 10. Unusual Parent-Child Relationship (userinit.exe)
            $Pid_dwm = Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "dwm.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Pid_winlogon = Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "winlogon.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "userinit.exe" | Where-Object{($_ -notmatch "$Pid_dwm|$Pid_winlogon")} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: userinit.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "userinit.exe" | Where-Object{($_ -notmatch "$Pid_dwm|$Pid_winlogon")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\userinit.exe.txt"
            }

            # 11. Unusual Parent-Child Relationship (wininit.exe)
            $Pid_smss = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "smss.exe" | ForEach-Object{($_ -split "\s+")[2]}) -join "|"
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "wininit.exe" | Where-Object{($_ -notmatch $Pid_smss)} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: wininit.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "wininit.exe" | Where-Object{($_ -notmatch "$Pid_smss")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\wininit.exe.txt"
            }

            # 12. Unusual Parent-Child Relationship (winlogon.exe)
            $Pid_smss = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "smss.exe" | ForEach-Object{($_ -split "\s+")[2]}) -join "|"
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "winlogon.exe" | Where-Object{($_ -notmatch $Pid_smss)} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: winlogon.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\TXT\proc.txt" | Select-String -Pattern "winlogon.exe" | Where-Object{($_ -notmatch "$Pid_smss")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\winlogon.exe.txt"
            }

            # Unusual Number of Process Instances
            if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
            {
                if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv") -gt 0)
                {
                    $RunningProcs = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Exit Time" -eq "" }

                    # Unusual Number of Process Instances (lsaiso.exe)
                    $Count = ($RunningProcs | Where-Object { $_."Process Name" -eq "lsaiso.exe" } | Measure-Object).Count
                    if ($Count -ne 0 -and $Count -ne 1)
                    {
                        Write-Host "[Alert] Unusual Number of Process Instances found: lsaiso.exe ($Count)" -ForegroundColor Red
                        New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances" -ItemType Directory -Force | Out-Null
                        $RunningProcs | Where-Object { $_."Process Name" -eq "lsaiso.exe" } | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances\lsaiso.exe.txt"
                    }

                    # Unusual Number of Process Instances (lsass.exe)
                    $Count = ($RunningProcs | Where-Object { $_."Process Name" -eq "lsass.exe" } | Measure-Object).Count
                    if ($Count -ne 1)
                    {
                        Write-Host "[Alert] Unusual Number of Process Instances found: lsass.exe ($Count)" -ForegroundColor Red
                        New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances" -ItemType Directory -Force | Out-Null
                        $RunningProcs | Where-Object { $_."Process Name" -eq "lsass.exe" } | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances\lsass.exe.txt"
                    }

                    # Unusual Number Process of Instances (lsm.exe)
                    $Count = ($RunningProcs | Where-Object { $_."Process Name" -eq "lsm.exe" } | Measure-Object).Count
                    if ($Count -ne 0 -and $Count -ne 1)
                    {
                        Write-Host "[Alert] Unusual Number of Process Instances found: lsm.exe ($Count)" -ForegroundColor Red
                        New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances" -ItemType Directory -Force | Out-Null
                        $RunningProcs | Where-Object { $_."Process Name" -eq "lsm.exe" } | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances\lsm.exe.txt"
                    }

                    # Unusual Number Process of Instances (Memory Compression)
                    $Count = ($RunningProcs | Where-Object { $_."Process Name" -eq "MemCompression" } | Measure-Object).Count
                    if ($Count -ne 0 -and $Count -ne 1)
                    {
                        Write-Host "[Alert] Unusual Number of Process Instances found: MemCompression ($Count)" -ForegroundColor Red
                        New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances" -ItemType Directory -Force | Out-Null
                        $RunningProcs | Where-Object { $_."Process Name" -eq "MemCompression" } | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances\MemCompression.txt"
                    }

                    # Unusual Number Process of Instances (Registry)
                    $Count = ($RunningProcs | Where-Object { $_."Process Name" -eq "Registry" } | Measure-Object).Count
                    if ($Count -ne 0 -and $Count -ne 1)
                    {
                        Write-Host "[Alert] Unusual Number of Process Instances found: Registry ($Count)" -ForegroundColor Red
                        New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances" -ItemType Directory -Force | Out-Null
                        $RunningProcs | Where-Object { $_."Process Name" -eq "Registry" } | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances\Registry.txt"
                    }

                    # Unusual Number of Process Instances (services.exe)
                    $Count = ($RunningProcs | Where-Object { $_."Process Name" -eq "services.exe" } | Measure-Object).Count
                    if ($Count -ne 1)
                    {
                        Write-Host "[Alert] Unusual Number of Process Instances found: services.exe ($Count)" -ForegroundColor Red
                        New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances" -ItemType Directory -Force | Out-Null
                        $RunningProcs | Where-Object { $_."Process Name" -eq "services.exe" } | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances\services.exe.txt"
                    }

                    # Unusual Number of Process Instances (System)
                    $Count = ($RunningProcs | Where-Object { $_."Process Name" -eq "System" } | Measure-Object).Count
                    if ($Count -ne 1)
                    {
                        Write-Host "[Alert] Unusual Number of Process Instances found: System ($Count)" -ForegroundColor Red
                        New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances" -ItemType Directory -Force | Out-Null
                        $RunningProcs | Where-Object { $_."Process Name" -eq "System" } | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances\System.txt"
                    }

                    # Unusual Number of Process Instances (wininit.exe)
                    $Count = ($RunningProcs | Where-Object { $_."Process Name" -eq "wininit.exe" } | Measure-Object).Count
                    if ($Count -ne 1)
                    {
                        Write-Host "[Alert] Unusual Number of Process Instances found: wininit.exe ($Count)" -ForegroundColor Red
                        New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances" -ItemType Directory -Force | Out-Null
                        $RunningProcs | Where-Object { $_."Process Name" -eq "wininit.exe" } | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances\wininit.exe.txt"
                    }
                }
            }
        }

        # Process Masquerading
        # https://attack.mitre.org/techniques/T1036/
        # https://car.mitre.org/analytics/CAR-2021-04-001/
        if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
        {
            if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv") -gt 0)
            {
                # Process Path Masquerading - Looks for mismatches between process names and their image paths
                # https://attack.mitre.org/techniques/T1036/005/
                Write-Output "[Info]  Checking for Process Path Masquerading ..."

                # Masquerading Client/Server Runtime Subsystem (csrss.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "csrss.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\csrss\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Client/Server Runtime Subsystem (csrss.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\csrss.exe.txt"
                }

                # Masquerading Windows Explorer (explorer.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "explorer.exe" -and $_."Device Path" -notmatch "\\Windows\\explorer\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Windows Explorer (explorer.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\explorer.exe.txt"
                }

                # Masquerading Local Security Authority Server Service (lsass.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "lsass.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\lsass\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Local Security Authority Server Service (lsass.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\lsass.exe.txt"
                }

                # Masquerading Local Session Manager Service (lsm.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "lsm.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\lsm\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Local Session Manager Service (lsm.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\lsm.exe.txt"
                }

                # Masquerading Windows Services Control Manager (services.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "services.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\services\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Windows Services Control Manager (services.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\services.exe.txt"
                }

                # Masquerading Windows Session Manager Subsystem (smss.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "smss.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\smss\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Windows Session Manager Subsystem (smss.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\smss.exe.txt"
                }

                # Masquerading Windows Service Host (svchost.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "svchost.exe" -and ($_."Device Path" -notmatch "\\Windows\\System32\\svchost\.exe" -and $_."Device Path" -notmatch "\\Windows\\SysWOW64\\svchost\.exe") }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Windows Service Host (svchost.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\svchost.exe.txt"
                }

                # Masquerading Host Process for Windows Tasks (taskhost.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "taskhost.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\taskhost\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Host Process for Windows Tasks (taskhost.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\taskhost.exe.txt"
                }

                # Masquerading Host Process for Windows Tasks (taskhostw.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "taskhostw.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\taskhostw\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Host Process for Windows Tasks (taskhostw.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\taskhostw.exe.txt"
                }

                # Masquerading Windows Start-Up Application (wininit.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "wininit.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\wininit\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Windows Start-Up Application (wininit.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\wininit.exe.txt"
                }

                # Masquerading Windows Logon (winlogon.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "winlogon.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\winlogon\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Windows Logon (winlogon.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\winlogon.exe.txt"
                }

                # Process Name Masquerading - Measures the edit distance between used Process Name and Original Windows Process Name (Damerau–Levenshtein Distance)
                # https://en.wikipedia.org/wiki/Damerau-Levenshtein_distance
                Write-Output "[Info]  Checking Damerau–Levenshtein Distance of common System Processes ..."
                
                if (Test-Path "$SCRIPT_DIR\Scripts\Measure-DamerauLevenshteinDistance\Measure-DamerauLevenshteinDistance.cs")
                {
                    Add-Type -Path "$SCRIPT_DIR\Scripts\Measure-DamerauLevenshteinDistance\Measure-DamerauLevenshteinDistance.cs" | Out-Null

                    $ProcessList = (Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -ne "" } | Select-Object PID | Sort-Object @{Expression={$_.PID -as [int]}}).PID

                    ForEach( $ProcessID in $ProcessList )
                    {
                        $ProcessName = (Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."PID" -eq "$ProcessID" } | Select-Object "Process Name")."Process Name"

                        # Masquerading Client/Server Runtime Subsystem (csrss.exe)
                        [int]$Distance = [LevenshteinDistance]::Measure("csrss.exe", "$ProcessName")

                        if ($Distance -eq "1")
                        {
                            Write-Host "[Alert] Process Name Masquerading detected: csrss.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                        }

                        # Masquerading COM Surrogate (dllhost.exe) --> Microsoft Component Object Model (COM)
                        [int]$Distance = [LevenshteinDistance]::Measure("dllhost.exe", "$ProcessName")

                        if ($Distance -eq "1")
                        {
                            Write-Host "[Alert] Process Name Masquerading detected: dllhost.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                        }

                        # Masquerading Windows Explorer (explorer.exe)
                        [int]$Distance = [LevenshteinDistance]::Measure("explorer.exe", "$ProcessName")

                        if ($Distance -eq "1")
                        {
                            Write-Host "[Alert] Process Name Masquerading detected: explorer.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                        }

                        # Masquerading Internet Explorer (iexplore.exe)
                        [int]$Distance = [LevenshteinDistance]::Measure("iexplore.exe", "$ProcessName")

                        if ($Distance -eq "1")
                        {
                            Write-Host "[Alert] Process Name Masquerading detected: iexplore.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                        }

                        # Masquerading Local Security Authority Server Service (lsass.exe)
                        [int]$Distance = [LevenshteinDistance]::Measure("lsass.exe", "$ProcessName")

                        if ($Distance -eq "1")
                        {
                            Write-Host "[Alert] Process Name Masquerading detected: lsass.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                        }

                        # Masquerading Shell Infrastructure Host (sihost.exe)
                        [int]$Distance = [LevenshteinDistance]::Measure("sihost.exe", "$ProcessName")

                        if ($Distance -eq "1")
                        {
                            Write-Host "[Alert] Process Name Masquerading detected: sihost.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                        }

                        # Masquerading Windows Session Manager Subsystem (smss.exe)
                        [int]$Distance = [LevenshteinDistance]::Measure("smss.exe", "$ProcessName")

                        if ($Distance -eq "1")
                        {
                            Write-Host "[Alert] Process Name Masquerading detected: smss.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                        }

                        # Masquerading Windows Service Host (svchost.exe)
                        [int]$Distance = [LevenshteinDistance]::Measure("svchost.exe", "$ProcessName")

                        if ($Distance -eq "1")
                        {
                            Write-Host "[Alert] Process Name Masquerading detected: svchost.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                        }

                        # Masquerading Windows Logon (winlogon.exe)
                        [int]$Distance = [LevenshteinDistance]::Measure("winlogon.exe", "$ProcessName")

                        if ($Distance -eq "1")
                        {
                            Write-Host "[Alert] Process Name Masquerading detected: winlogon.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                        }
                    }
                }
                else
                {
                    Write-Host "[Error] Measure-DamerauLevenshteinDistance.cs NOT found." -ForegroundColor Red
                }
            }
        }

#############################################################################################################################################################################################
        
        Function Get-ProcessesWithUnusualUserContext {

        # Processes w/ Unusual User Context
        if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
        {
            if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv") -gt 0)
            {
                Write-Output "[Info]  Checking for Processes w/ Unusual User Context ..."

                # Windows Service Host (svchost.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "svchost.exe" } | Where-Object { $_.User -notmatch "SYSTEM|LOCAL SERVICE|NETWORK SERVICE" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious Windows Service Host (svchost.exe) detected: Running under unusual user context (Count: $Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_User-Context" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_User-Context\svchost.exe.txt"
                }

                # svchost.exe is supposed to run in Session 0 under one of 3 users: SYSTEM, LOCAL SERVICE or NETWORK SERVICE.
                # If svchost.exe is ran by SYSTEM, NETWORK SERVICE or LOCAL SERVICE, then it should be legitmate, but if it is ran under an user account, 
                # then you need to investigate if the svchost.exe file is from another location than "C:\Windows\System32".
            }
        }

        }

        Get-ProcessesWithUnusualUserContext

#############################################################################################################################################################################################
        
        Function Get-ProcessesFromSuspiciousFolders {

        # Checking for processes spawned from suspicious folder locations
        if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
        {
            if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv") -gt 0)
            {
                Write-Output "[Info]  Checking for Processes Spawned From Suspicious Folder Locations ..."

                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Device Path" -ne "" } | Sort-Object @{Expression={$_.PID -as [int]}}

                # Desktop (incl. subdirectories) - The onscreen work area provided by Microsoft Windows that represents the kinds of objects one might find on top of a physical desk
                $Data = $Import | Where-Object { $_."Device Path" -match "\\Users\\.*\\Desktop\\" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process spawned from a suspicious folder location: C:\Users\*\Desktop\* ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations\Desktop.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Desktop" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["G2:G$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # Downloads (incl. subdirectories) - Default location to save all downloaded content
                $Data = $Import | Where-Object { $_."Device Path" -match "\\Users\\.*\\Downloads\\" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process spawned from a suspicious folder location: C:\Users\*\Downloads\* ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations\Downloads.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Downloads" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["G2:G$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # Documents (incl. subdirectories) - Default location for all user created documents
                $Data = $Import | Where-Object { $_."Device Path" -match "\\Users\\.*\\Documents\\" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process spawned from a suspicious folder location: C:\Users\*\Documents\* ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations\Documents.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Documents" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["G2:G$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # PUBLIC (incl. subdirectories) - The Public folder is located in "%SystemDrive%\Users\Public", in all Windows versions. All user accounts registered in Windows have access to it. That's why it is named Public. Any file and folder found in "C:\Users\Public" is completely accessible to all users.
                $Data = $Import | Where-Object { $_."Device Path" -match "\\Users\\Public\\" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process spawned from a suspicious folder location: C:\Users\Public\* ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations\PUBLIC.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "PUBLIC" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["G2:G$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # Temp (incl. subdirectories) - Temporary Files created by the User (when running any software)
                $Data = $Import | Where-Object { $_."Device Path" -match "\\Users\\.*\\AppData\\Local\\Temp\\" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process spawned from a suspicious folder location: C:\Users\*\AppData\Local\Temp\* ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations\TEMP.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "TEMP" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["G2:G$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # Temp - Root Directory (incl. subdirectories)
                $Data = $Import | Where-Object { $_."Device Path" -match "\\Device\\HarddiskVolume[0-9]\\Temp\\" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process spawned from a suspicious folder location: C:\Temp\* ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations\Temp-Root.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Temp" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["G2:G$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # ALLUSERSPROFILE (incl. subdirectories)
                $Data = $Import | Where-Object { $_."Device Path" -match "\\Device\\HarddiskVolume[0-9]\\ProgramData\\" } | Where-Object { $_."Device Path" -notmatch "\\Microsoft\\Windows Defender\\Platform\\.*\\[MsMpEng.exe|MpCopyAccelerator.exe]" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process spawned from a suspicious folder location: C:\ProgramData\* ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations\ALLUSERSPROFILE.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ALLUSERSPROFILE" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["G2:G$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # SystemDrive (Root Directory) --> [A-Za-z0-9_]*
                $Data = $Import | Where-Object { $_."Device Path" -match "\\Device\\HarddiskVolume[0-9]\\\w+$" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process spawned from a suspicious folder location: C:\* ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations\SystemDrive.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SystemDrive" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["G2:G$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # LOCALAPPDATA (incl. subdirectories) - Default location of temporary files of applications (Vista+)
                $Data = $Import | Where-Object { $_."Device Path" -match "\\Device\\HarddiskVolume[0-9]\\Users\\*\\AppData\\Local\\" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process spawned from a suspicious folder location: C:\Users\*\AppData\Local\* ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations\LOCALAPPDATA.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "LOCALAPPDATA" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["G2:G$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # LocalLow (incl. subdirectories) - like LOCALAPPDATA, but with a lower integrity level
                $Data = $Import | Where-Object { $_."Device Path" -match "\\Device\\HarddiskVolume[0-9]\\Users\\*\\AppData\\LocalLow\\" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process spawned from a suspicious folder location: C:\Users\*\AppData\LocalLow\* ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations\LocalLow.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "LocalLow" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["G2:G$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # APPDATA (incl. subdirectories) - Default location for user application data and binaries
                $Data = $Import | Where-Object { $_."Device Path" -match "\\Device\\HarddiskVolume[0-9]\\Users\\*\\AppData\\Roaming\\" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process spawned from a suspicious folder location: C:\Users\*\AppData\Roaming\* ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Folder-Locations\APPDATA.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "APPDATA" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["G2:G$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }
            }
        }

        }

        Get-ProcessesFromSuspiciousFolders

#############################################################################################################################################################################################
        
        # Checking for suspicious process lineage
        # https://d3fend.mitre.org/technique/d3f:ProcessLineageAnalysis/

        if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
        {
            if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv") -gt 0)
            {
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Sort-Object @{Expression={$_.PID -as [int]}}

                Write-Output "[Info]  Checking for Suspicious Process Lineage ..."

                # Checking for suspicious parent processes

                # System Binary Proxy Execution: rundll32.exe
                # https://attack.mitre.org/techniques/T1218/011/

                # rundll32.exe spawns conhost.exe
                # Note: With the introduction of Windows Terminal in May 2020, conhost.exe can act as an execution proxy. Attackers may abuse this feature to execute malicious files and evade detection.
                $Data = $Import | Where-Object { $_."Process Name" -eq "conhost.exe" } | Where-Object { $_."Parent Name" -eq "rundll32.exe" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Windows Console Host (conhost.exe) spawned by suspicious parent process: rundll32.exe ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Parent-Processes" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Parent-Processes\rundll32.exe_spawns_conhost.exe.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "conhost.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["D2:D$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # svchost.exe spawns cmd.exe
                $Data = $Import | Where-Object { $_."Process Name" -eq "cmd.exe" } | Where-Object { $_."Parent Name" -eq "svchost.exe" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)
  
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Windows Command Shell (cmd.exe) spawned by suspicious parent process: svchost.exe ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Parent-Processes" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Parent-Processes\svchost.exe_spawns_cmd.exe.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "cmd.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["D2:D$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # Checking for suspicious child processes

                # WINWORD.EXE spawns cmd.exe
                $Data = $Import | Where-Object { $_."Process Name" -eq "cmd.exe" } | Where-Object { $_."Parent Name" -eq "WINWORD.EXE" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious Child Process of Microsoft Word detected: cmd.exe ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Child-Processes" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Child-Processes\winword.exe_spawns_cmd.exe.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "cmd.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["D2:D$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # WINWORD.EXE spawns powershell.exe
                $Data = $Import | Where-Object { $_."Process Name" -eq "powershell.exe" } | Where-Object { $_."Parent Name" -eq "WINWORD.EXE" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious Child Process of Microsoft Word detected: powershell.exe ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Child-Processes" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Child-Processes\winword.exe_spawns_powershell.exe.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "powershell.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["D2:D$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # WINWORD.EXE spawns mshta.exe
                $Data = $Import | Where-Object { $_."Process Name" -eq "mshta.exe" } | Where-Object { $_."Parent Name" -eq "WINWORD.EXE" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious Child Process of Microsoft Word detected: mshta.exe ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Child-Processes" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Child-Processes\winword.exe_spawns_mshta.exe.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "mshta.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["D2:D$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # WINWORD.EXE spawns regsvr32.exe
                $Data = $Import | Where-Object { $_."Process Name" -eq "regsvr32.exe" } | Where-Object { $_."Parent Name" -eq "WINWORD.EXE" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious Child Process of Microsoft Word detected: regsvr32.exe ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Child-Processes" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Child-Processes\winword.exe_spawns_regsvr32.exe.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "regsvr32.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["D2:D$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }
            }
        }

#############################################################################################################################################################################################

        Function Get-ProcessesWithSuspiciousCommandLineArguments {

        # Checking for processes with suspicious command-line arguments
        if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
        {
            if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv") -gt 0)
            {
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Sort-Object @{Expression={$_.PID -as [int]}}

                Write-Output "[Info]  Checking for Processes with Suspicious Command Line Arguments ..."

                # powershell.exe
                $powershell = $Import | Where-Object { $_."Process Name" -eq "powershell.exe" } 

                # Encoded Command (indicates the following chunk of text is a base64 encoded command)
                # https://attack.mitre.org/techniques/T1027/
                $EncodedCommand = $powershell | Where-Object {($_.CommandLine -match "-EncodedCommand") -or ($_.CommandLine -match "-Enc") -or ($_.CommandLine -match "-en ") -or ($_.CommandLine -match "-e ")} | Sort-Object { $_."Create Time" -as [datetime] } -Descending
                $Count = [string]::Format('{0:N0}',($EncodedCommand | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious PowerShell Parameter detected: Encoded Command ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe" -ItemType Directory -Force | Out-Null
                    $EncodedCommand | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe\Encoded-Command.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Encoded Command" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["K2:K$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # Base64 Encoding
                # https://attack.mitre.org/techniques/T1027/
                $Base64Encoding = $powershell | Where-Object {($_.CommandLine -match "base64")} | Sort-Object { $_."Create Time" -as [datetime] } -Descending
                $Count = [string]::Format('{0:N0}',($Base64Encoding | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious PowerShell Parameter detected: Base64 Encoding ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe" -ItemType Directory -Force | Out-Null
                    $Base64Encoding | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe\Base64-Encoding.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Base64 Encoding" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["K2:K$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # WindowStyle Hidden (indicates that the PowerShell session window should be started in a hidden manner)
                # https://attack.mitre.org/techniques/T1564/003/
                $WindowStyleHidden = $powershell | Where-Object {($_.CommandLine -match "-WindowStyle Hidden") -or ($_.CommandLine -match "-W Hidden")} | Sort-Object { $_."Create Time" -as [datetime] } -Descending
                $Count = [string]::Format('{0:N0}',($WindowStyleHidden | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious PowerShell Parameter detected: WindowStyle Hidden ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe" -ItemType Directory -Force | Out-Null
                    $WindowStyleHidden | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe\WindowStyle-Hidden.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "WindowStyle Hidden" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["K2:K$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # Execution Policy Bypass (disables the execution policy for the current PowerShell session)
                # https://attack.mitre.org/techniques/T1059/001/
                $ExecutionPolicyBypass = $powershell | Where-Object {($_.CommandLine -match "-ExecutionPolicy Bypass") -or ($_.CommandLine -match "-Exec Bypass") -or ($_.CommandLine -match "-EP ByPass")} | Sort-Object { $_."Create Time" -as [datetime] } -Descending
                $Count = [string]::Format('{0:N0}',($ExecutionPolicyBypass | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious PowerShell Parameter detected: Execution Policy Bypass ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe" -ItemType Directory -Force | Out-Null
                    $ExecutionPolicyBypass | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe\Execution-Policy-Bypass.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Execution Policy Bypass" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["K2:K$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # Profile Bypass (indicates that the current user’s profile setup script should not be executed when the PowerShell engine starts)
                $ProfileBypass = $powershell | Where-Object {($_.CommandLine -match "-NoProfile") -or ($_.CommandLine -match "-nop ")} | Sort-Object { $_."Create Time" -as [datetime] } -Descending
                $Count = [string]::Format('{0:N0}',($ProfileBypass | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious PowerShell Parameter detected: Profile Bypass ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe" -ItemType Directory -Force | Out-Null
                    $ProfileBypass | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe\Profile-Bypass.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Profile Bypass" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["K2:K$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # NonInteractive Mode (meaning an interactive prompt to the user will not be presented)
                $NonInteractive = $powershell | Where-Object {($_.CommandLine -match "-NonInteractive") -or ($_.CommandLine -match "-NonI")} | Sort-Object { $_."Create Time" -as [datetime] } -Descending
                $Count = [string]::Format('{0:N0}',($NonInteractive | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious PowerShell Parameter detected: NonInteractive Mode ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe" -ItemType Directory -Force | Out-Null
                    $NonInteractive | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe\NonInteractive-Mode.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "NonInteractive" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["K2:K$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # Download (remotely download and execute arbitrary code and binaries)
                # https://attack.mitre.org/techniques/T1059/001/
                $Download = $powershell | Where-Object {($_.CommandLine -match "invoke-webrequest") -or ($_.CommandLine -match "iwr") -or ($_.CommandLine -match "http") -or ($_.CommandLine -match "DownloadString") -or ($_.CommandLine -match "WebClient") -or ($_.CommandLine -match "downloadfile") -or ($_.CommandLine -match "wget") -or ($_.CommandLine -match "cURL")} | Sort-Object { $_."Create Time" -as [datetime] } -Descending
                $Count = [string]::Format('{0:N0}',($Download | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious PowerShell Parameter detected: Remote Download ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe" -ItemType Directory -Force | Out-Null
                    $Download | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe\Download-and-Execution.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Download" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["K2:K$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # Invoke-Expression (executes the command provided on the local machine)
                # https://attack.mitre.org/techniques/T1059/001/
                $Invoke = $powershell | Where-Object {($_.CommandLine -match "Invoke-Expression") -or ($_.CommandLine -match "IEX")} | Sort-Object { $_."Create Time" -as [datetime] } -Descending
                $Count = [string]::Format('{0:N0}',($Invoke | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious PowerShell Parameter detected: Invoke-Expression ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe" -ItemType Directory -Force | Out-Null
                    $Invoke | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe\Invoke-Expression.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Invoke-Expression" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["K2:K$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # Start-Process
                # https://attack.mitre.org/techniques/T1059/001/
                $Execute = $powershell | Where-Object {($_.CommandLine -match "Start-Process")} | Sort-Object { $_."Create Time" -as [datetime] } -Descending
                $Count = [string]::Format('{0:N0}',($Execute | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious PowerShell Parameter detected: Start-Process ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe" -ItemType Directory -Force | Out-Null
                    $Execute | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\powershell.exe\Start-Process.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Start-Process" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["K2:K$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # cmd.exe
                $cmd = $Import | Where-Object { $_."Process Name" -eq "cmd.exe" } 

                # CommandLine Flags
                # https://attack.mitre.org/techniques/T1059/003/
                $CommandLineFlags = $cmd | Where-Object {($_.CommandLine -match "/c") -or ($_.CommandLine -match "/q") -or ($_.CommandLine -match "/k")} | Sort-Object { $_."Create Time" -as [datetime] } -Descending
                $Count = [string]::Format('{0:N0}',($CommandLineFlags | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious Windows Command Shell Parameter detected: CommandLine Flags ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\cmd.exe" -ItemType Directory -Force | Out-Null
                    $CommandLineFlags | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\cmd.exe\CommandLine-Flags.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "CommandLine Flags" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,255,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(0,0,0)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["K2:K$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # /c = The /c parameter is used to terminate the shell after command completion.
                # /q = The /q parameter is used to turn echo off.
                # /k = The /k parameter is used to run a command and then remain open (e.g. whoami).

                # Windows Command Shell + Execution of Batch Script
                # https://attack.mitre.org/techniques/T1059/003/
                $CommandShellBatchScript = $cmd | Where-Object {(($_.CommandLine -match "/c") -or ($_.CommandLine -match "/q") -or ($_.CommandLine -match "/k")) -and (($_.CommandLine -match "\.bat") -or ($_.CommandLine -match "\.cmd"))} | Sort-Object { $_."Create Time" -as [datetime] } -Descending
                $Count = [string]::Format('{0:N0}',($CommandShellBatchScript | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious Windows Command Shell Parameter detected: Execution of Batch Script ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\cmd.exe" -ItemType Directory -Force | Out-Null
                    $CommandShellBatchScript | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\cmd.exe\Execution-of-Batch-Script.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Batch Script" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["K2:K$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # mshta.exe
                $mshta = $Import | Where-Object { $_."Process Name" -eq "mshta.exe" }
                
                # Suspicious Execution
                # https://attack.mitre.org/techniques/T1059/007/
                # https://attack.mitre.org/techniques/T1218/005/
                $MshtaExecution = $mshta | Where-Object {(($_.CommandLine -match "\.hta") -or ($_.CommandLine -match "\.htm") -or ($_.CommandLine -match "http") -or ($_.CommandLine -match "javascript") -or ($_.CommandLine -match "vbscript"))} | Sort-Object { $_."Create Time" -as [datetime] } -Descending
                $Count = [string]::Format('{0:N0}',($MshtaExecution | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious Microsoft HTML Application Host Parameter detected: Execution of HTA File (and Javascript or VBScript) ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\mshta.exe" -ItemType Directory -Force | Out-Null
                    $MshtaExecution | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Processes-With-Suspicious-CommandLine-Arguments\mshta.exe\Suspicious-Execution.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Suspicious Execution" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["K2:K$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }  
            }
        }

        }

        Get-ProcessesWithSuspiciousCommandLineArguments

#############################################################################################################################################################################################
        
        Function Get-SuspiciousProcessesWithoutCommandLineArguments {

        # Checking for suspicious processes without any command-line arguments
        if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
        {
            if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv") -gt 0)
            {
                Write-Output "[Info]  Checking for Suspicious Processes without any Command Line Arguments ..."

                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Sort-Object @{Expression={$_.PID -as [int]}}

                # Process Injection
                # https://attack.mitre.org/techniques/T1055/

                # svchost.exe
                $Data = $Import | Where-Object { $_."Process Name" -eq "svchost.exe" } | Where-Object { $_."CommandLine" -eq " " }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious Windows Service Host (svchost.exe) detected: No CommandLine value available ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Processes-Without-CommandLine-Arguments" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Processes-Without-CommandLine-Arguments\T1055_svchost.exe.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "svchost.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["K2:K$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # System Binary Proxy Execution
                # https://attack.mitre.org/techniques/T1218/011/

                # rundll32.exe
                $Data = $Import | Where-Object { $_."Process Name" -eq "rundll32.exe" } | Where-Object { $_."CommandLine" -eq " " }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Suspicious System Binary Proxy Execution (rundll32.exe) detected: No CommandLine value available ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Processes-Without-CommandLine-Arguments" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Processes-Without-CommandLine-Arguments\T1218.011_rundll32.exe.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "rundll32.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["K2:K$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }
            }
        }

        }

        Get-SuspiciousProcessesWithoutCommandLineArguments

#############################################################################################################################################################################################

        Function Get-DoubleFileExtensions {

        # Double File Extension (Masquerading)
        # https://attack.mitre.org/techniques/T1036/007/
        # Note: This simple search looks for processes launched from files that have double extensions in the file name.
        if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
        {
            if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv") -gt 0)
            {
                Write-Output "[Info]  Checking for Processes with Suspicious Double File Extension ..."

                # Whitelist
                $Whitelist = "(Microsoft.Photos.exe|WinStore.App.exe)"

                $Processes = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object {$_."Process Name" -notmatch "$Whitelist"}

                foreach ($Process in $Processes)
                {
                    $ProcessName = $Process | Select-Object -ExpandProperty "Process Name"

                    $DotCount = ($ProcessName.ToCharArray() | Where-Object {$_ -eq "."} | Measure-Object).Count
                    if($DotCount -gt 1)
                    {
                        Write-Host "[Alert] Suspicious Double File Extension detected: $ProcessName [T1036.007]" -ForegroundColor Red
                        New-Item "$OUTPUT_FOLDER\sys\proc\Suspicious-Double-File-Extension" -ItemType Directory -Force | Out-Null
                        $Process | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Suspicious-Double-File-Extension\Double-File-Extension_$ProcessName.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Double File Extension" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns A-F, H-I and L-M
                        $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                        # BackgroundColor and FontColor for specific cells
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                        $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                        $LastRow = $WorkSheet.Dimension.End.Row
                        Set-Format -Address $WorkSheet.Cells["B2:B$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                        }
                    }
                }
            }
        }

        }

        Get-DoubleFileExtensions

#############################################################################################################################################################################################

        Function Get-CommandAndScriptingInterpreters {

        # Command and Scripting Interpreters
        # https://attack.mitre.org/techniques/T1059/
        # Note: This simple search looks for process names of Command and Scripting Interpreters. Adversaries abuse command and script interpreters to execute commands, scripts or binaries.
        if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
        {
            if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv") -gt 0)
            {
                Write-Output "[Info]  Checking for Command and Scripting Interpreters ..."

                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Sort-Object @{Expression={$_.PID -as [int]}}

                # cmd.exe
                $Data = $Import | Where-Object { $_."Process Name" -eq "cmd.exe" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Command and Scripting Interpreter detected: cmd.exe ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Command-and-Scripting-Interpreter" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Command-and-Scripting-Interpreter\cmd.exe.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "cmd.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["B2:B$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # cscript.exe
                $Data = $Import | Where-Object { $_."Process Name" -eq "cscript.exe" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Command and Scripting Interpreter detected: cscript.exe ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Command-and-Scripting-Interpreter" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Command-and-Scripting-Interpreter\cscript.exe.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "cscript.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["B2:B$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # mshta.exe
                $Data = $Import | Where-Object { $_."Process Name" -eq "mshta.exe" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Command and Scripting Interpreter detected: mshta.exe ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Command-and-Scripting-Interpreter" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Command-and-Scripting-Interpreter\mshta.exe.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "mshta.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["B2:B$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # powershell.exe
                $Data = $Import | Where-Object { $_."Process Name" -eq "powershell.exe" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Command and Scripting Interpreter detected: powershell.exe ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Command-and-Scripting-Interpreter" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Command-and-Scripting-Interpreter\powershell.exe.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "powershell.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["B2:B$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # pwsh.exe
                $Data = $Import | Where-Object { $_."Process Name" -eq "pwsh.exe" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Command and Scripting Interpreter detected: pwsh.exe ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Command-and-Scripting-Interpreter" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Command-and-Scripting-Interpreter\pwsh.exe.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "pwsh.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["B2:B$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # python.exe
                $Data = $Import | Where-Object { $_."Process Name" -eq "python.exe" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Command and Scripting Interpreter detected: python.exe ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Command-and-Scripting-Interpreter" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Command-and-Scripting-Interpreter\python.exe.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "python.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["B2:B$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }

                # wscript.exe
                $Data = $Import | Where-Object { $_."Process Name" -eq "wscript.exe" }
                $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Command and Scripting Interpreter detected: wscript.exe ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Command-and-Scripting-Interpreter" -ItemType Directory -Force | Out-Null
                    $Data | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\Command-and-Scripting-Interpreter\wscript.exe.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "wscript.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:M"].Style.HorizontalAlignment="Center"
                    # BackgroundColor and FontColor for specific cells
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
                    $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
                    $LastRow = $WorkSheet.Dimension.End.Row
                    Set-Format -Address $WorkSheet.Cells["B2:B$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
                    }
                }
            }
        }
        
        }

        Get-CommandAndScriptingInterpreters

#############################################################################################################################################################################################

        Function Get-MiniDumps {
        
        # MiniDumps
        if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
        {
            if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv") -gt 0)
            {
                New-Item "$OUTPUT_FOLDER\sys\proc\MiniDumps" -ItemType Directory -Force | Out-Null
                $ProcessList = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -ne "" } | Select-Object "Process Name", PID | Sort-Object @{Expression={$_.PID -as [int]}}

                # TXT
                ForEach( $Process in $ProcessList )
                {
                    $ProcessID = ($Process | Select-Object PID).PID
                    $FilePath  = "$DriveLetter\pid\$ProcessID\minidump\minidump.dmp"
                    $FilePath | Out-File "$OUTPUT_FOLDER\sys\proc\MiniDumps\MiniDumps.txt" -Append
                }

                # CSV
                $ProcessList | Foreach-Object {
                    
                    $ProcessName = $_ | Select-Object -ExpandProperty "Process Name"
                    $ProcessID   = $_ | Select-Object -ExpandProperty PID
                    $FilePath    = "$DriveLetter\pid\$ProcessID\minidump\minidump.dmp"
                    $FileInfo    = Get-Item "$FilePath" -Force -ErrorAction SilentlyContinue
                    $Length      = $FileInfo.Length

                    if ($Length -eq "0")
                    {
                        $FileSize = "0"
                    }
                    else
                    {
                        $FileSize = Get-FileSize($Length)
                    }

                    New-Object -TypeName PSObject -Property @{
                        "ProcessName" = $ProcessName
                        "PID"         = $ProcessID
                        "FilePath"    = $FilePath
                        "Bytes"       = $Length
                        "FileSize"    = $FileSize
                        }
                } | Select-Object "ProcessName","PID","FilePath","Bytes","FileSize" | Export-Csv -Path "$OUTPUT_FOLDER\sys\proc\MiniDumps\MiniDumps.csv" -Delimiter "," -NoTypeInformation

                # XLSX
                if (Get-Module -ListAvailable -Name ImportExcel)
                {
                    if (Test-Path "$OUTPUT_FOLDER\sys\proc\MiniDumps\MiniDumps.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\sys\proc\MiniDumps\MiniDumps.csv") -gt 0)
                        {
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\proc\MiniDumps\MiniDumps.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\MiniDumps\MiniDumps.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MiniDumps" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of column B
                            $WorkSheet.Cells["B:B"].Style.HorizontalAlignment="Center"
                            # HorizontalAlignment "Right" of columns D-E
                            $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Right"
                            # HorizontalAlignment "Center" of header of columns D-E
                            $WorkSheet.Cells["D1:E1"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
            }
        }
        
        }

        Get-MiniDumps

#############################################################################################################################################################################################

        # FS_SysInfo_Services
        # https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo_Services
        if (Test-Path "$DriveLetter\sys\services\services.txt")
        {
            New-Item "$OUTPUT_FOLDER\sys\services" -ItemType Directory -Force | Out-Null

            # All Services
            Add-Content -Path "$OUTPUT_FOLDER\sys\services\services.txt" -Encoding utf8 -Value (Get-Content -Path "$DriveLetter\sys\services\services.txt")

            # Running Services
            Write-Output "   #    PID Start Type   State      Type Type    Obj Address  Name / Display Name                                              User                         Image Path                                          Object Name / Command Line   " | Out-File "$OUTPUT_FOLDER\sys\services\services-running.txt"
            Write-Output "----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" | Out-File "$OUTPUT_FOLDER\sys\services\services-running.txt" -Append
            Get-Content "$OUTPUT_FOLDER\sys\services\services.txt" | Select-String -Pattern "RUNNING" -CaseSensitive | Add-Content "$OUTPUT_FOLDER\sys\services\services-running.txt" -Encoding utf8

            # Stopped Services
            Write-Output "   #    PID Start Type   State      Type Type    Obj Address  Name / Display Name                                              User                         Image Path                                          Object Name / Command Line   " | Out-File "$OUTPUT_FOLDER\sys\services\services-stopped.txt"
            Write-Output "----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" | Out-File "$OUTPUT_FOLDER\sys\services\services-stopped.txt" -Append
            Get-Content "$OUTPUT_FOLDER\sys\services\services.txt" | Select-String -Pattern "STOPPED" -CaseSensitive | Add-Content "$OUTPUT_FOLDER\sys\services\services-stopped.txt" -Encoding utf8

            # Count Services
            $Total = (Get-Content "$OUTPUT_FOLDER\sys\services\services.txt" | Measure-Object).Count -2
            $Running = (Get-Content "$OUTPUT_FOLDER\sys\services\services-running.txt" | Measure-Object).Count
            Write-Output "[Info]  Processing $Total Services (Running Services: $Running) ..."

            # CSV
            if (Test-Path "$DriveLetter\forensic\json\general.json")
            {
                $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "service" }

                $Data | Foreach-Object {

                $procid = $_ | Select-Object -ExpandProperty pid -ErrorAction SilentlyContinue
                $obj = $_ | Select-Object -ExpandProperty obj
                $desc = $_ | Select-Object -ExpandProperty desc
                $start = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="start"; Expression={ForEach-Object{($_ -split "start:")[1]} | ForEach-Object{($_ -split "state:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $state = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="state"; Expression={ForEach-Object{($_ -split "state:")[1]} | ForEach-Object{($_ -split "type:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $type = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="type"; Expression={ForEach-Object{($_ -split "type:")[1]} | ForEach-Object{($_ -split "user:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $user = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="user"; Expression={ForEach-Object{($_ -split "user:")[1]} | ForEach-Object{($_ -split "image:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $image = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="image"; Expression={ForEach-Object{($_ -split "image:")[1]} | ForEach-Object{($_ -split "path:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $path = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="path"; Expression={ForEach-Object{($_ -split "path:")[1]} | ForEach-Object{($_ -replace "[\[\]]","")}}}

                New-Object -TypeName PSObject -Property @{
                    "PID" = $procid
                    "Start Type" = $start.start
                    "State" = $state.state
                    "Type" = $type.type
	                "Object Address" = $obj
	                "Name / Display Name" = $desc
                    "User" = $user.user
                    "Image Path" = $image.image
                    "Object Name / Command Line" = $path.path
                    }
                } | Select-Object "PID","Start Type","State","Type","Object Address","Name / Display Name","User","Image Path","Object Name / Command Line" | Export-Csv -Path "$OUTPUT_FOLDER\sys\services\services.csv" -Delimiter "`t" -NoTypeInformation
            }

            # XLSX
            if (Get-Module -ListAvailable -Name ImportExcel)
            {
                if (Test-Path "$OUTPUT_FOLDER\sys\services\services.csv")
                {
                    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\services\services.csv") -gt 0)
                    {
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\services\services.csv" -Delimiter "`t"
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\services\services.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Services" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns A-E and G
                        $WorkSheet.Cells["A:E"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["G:G"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }
            
            # Service running from a suspicious folder location: C:\Users\*\AppData\Local\Temp\*
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\services\services.txt" | Select-String -Pattern "[A-Z]{1}:\\Users\\.*\\AppData\\Local\\Temp\\" | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Service running from a suspicious folder location: C:\Users\*\AppData\Local\Temp\* ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\services\Suspicious-Services" -ItemType Directory -Force | Out-Null
                (Get-Content "$OUTPUT_FOLDER\sys\services\services.txt" | Select-String -Pattern "[A-Z]{1}:\\Users\\.*\\AppData\\Local\\Temp\\" | Out-String).Trim() | Set-Content "$OUTPUT_FOLDER\sys\services\Suspicious-Services\AppData-Local-Temp.txt" -Encoding utf8
            }
        }

#############################################################################################################################################################################################

        # FS_SysInfo_ScheduledTasks
        # https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo_ScheduledTasks
        # Note: A scheduled task can be used by an adversary to establish persistence, move laterally, and/or escalate privileges.
        if (Test-Path "$DriveLetter\sys\tasks\tasks.txt")
        {
            # tasks.txt
            New-Item "$OUTPUT_FOLDER\sys\tasks" -ItemType Directory -Force | Out-Null
            Add-Content -Path "$OUTPUT_FOLDER\sys\tasks\tasks.txt" -Encoding UTF8 -Value (Get-Content -Path "$DriveLetter\sys\tasks\tasks.txt")
            
            # by-guid
            Copy-Item -Path "$DriveLetter\sys\tasks\by-guid" -Destination "$OUTPUT_FOLDER\sys\tasks" -Recurse

            # by-name
            Copy-Item -Path "$DriveLetter\sys\tasks\by-name" -Destination "$OUTPUT_FOLDER\sys\tasks" -Recurse

            # Count Scheduled Tasks
            if (Test-Path "$DriveLetter\forensic\csv\tasks.csv")
            {
                [int]$Count = & $xsv count "$DriveLetter\forensic\csv\tasks.csv"
                Write-Output "[Info]  Processing $Count ScheduledTasks ..."
            }

            # Threat Hunting: Scheduled Tasks
            # https://attack.mitre.org/techniques/T1053/

            if (Test-Path "$DriveLetter\forensic\csv\tasks.csv")
            {
                $Tasks = Import-Csv -Path "$DriveLetter\forensic\csv\tasks.csv" -Delimiter "," -Encoding UTF8

                # a) Task Scheduler running from a suspicious folder location (False Positives: MEDIUM)

                # Task Scheduler running from a suspicious folder location: C:\Users\*
                $Import = $Tasks | Where-Object { $_.CommandLine -match "[A-Z]{1}:\\Users\\*" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running from a suspicious folder location: C:\Users\* ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV\Users.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV\Users.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV\Users.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV\Users.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\XLSX\Users.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Users" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("\Users\",$F1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running from a suspicious folder location: C:\ProgramData\*
                $Import = $Tasks | Where-Object { $_.CommandLine -match "[A-Z]{1}:\\ProgramData\\*" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running from a suspicious folder location: C:\ProgramData\* ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV\ProgramData.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV\ProgramData.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV\ProgramData.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV\ProgramData.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\XLSX\ProgramData.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ProgramData" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("\ProgramData\",$F1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running from a suspicious folder location: C:\Windows\Temp\*
                $Import = $Tasks | Where-Object { $_.CommandLine -match "[A-Z]{1}:\\Windows\\Temp\\" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running from a suspicious folder location: C:\Windows\Temp\* ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV\Temp.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV\Temp.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV\Temp.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV\Temp.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\XLSX\Temp.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Temp" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("\Windows\Temp\",$F1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running from a suspicious folder location: C:\TMP\*
                $Import = $Tasks | Where-Object { $_.CommandLine -match "[A-Z]{1}:\\TMP\\" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running from a suspicious folder location: C:\TMP\* ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV\TMP.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV\TMP.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV\TMP.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV\TMP.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\XLSX\TMP.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "TMP" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("\TMP\",$F1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # b) Task Scheduler running using suspicious Scripting Utilities (False Positives: MEDIUM)

                # CommandLine

                # Task Scheduler running using suspicious Scripting Utility: certutil.exe
                $Import = $Tasks | Where-Object { $_.CommandLine -match "certutil.exe" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: certutil.exe ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\certutil.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\certutil.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\certutil.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\certutil.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX\certutil.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "certutil.exe" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("certutil",$F1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running using suspicious Scripting Utility: cmd.exe
                $Import = $Tasks | Where-Object { $_.CommandLine -notmatch "dsregcmd.exe" } | Where-Object { $_.CommandLine -match "cmd.exe" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: cmd.exe ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\cmd.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\cmd.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\cmd.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\cmd.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX\cmd.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "cmd.exe" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("cmd.exe",$F1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running using suspicious Scripting Utility: csript.exe
                $Import = $Tasks | Where-Object { $_.CommandLine -match "csript.exe" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: csript.exe ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\csript.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\csript.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\csript.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\csript.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX\csript.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "csript.exe" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("csript.exe",$F1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running using suspicious Scripting Utility: mshta.exe
                $Import = $Tasks | Where-Object { $_.CommandLine -match "mshta.exe" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: mshta.exe ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\mshta.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\mshta.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\mshta.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\mshta.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX\mshta.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "mshta.exe" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("mshta.exe",$F1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running using suspicious Scripting Utility: msiexec.exe
                $Import = $Tasks | Where-Object { $_.CommandLine -match "msiexec.exe" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: msiexec.exe ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\msiexec.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\msiexec.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\msiexec.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\msiexec.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX\msiexec.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "msiexec.exe" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("msiexec",$F1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running using suspicious Scripting Utility: powershell.exe
                $Import = $Tasks | Where-Object { $_.CommandLine -match "powershell.exe" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: powershell.exe ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\powershell.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\powershell.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\powershell.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\powershell.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX\powershell.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "powershell.exe" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("powershell.exe",$F1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running using suspicious Scripting Utility: regsvr32.exe
                $Import = $Tasks | Where-Object { $_.CommandLine -match "regsvr32.exe" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: regsvr32.exe ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\regsvr32.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\regsvr32.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\regsvr32.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\regsvr32.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX\regsvr32.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "regsvr32.exe" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("regsvr32.exe",$F1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running using suspicious Scripting Utility: rundll32.exe
                $Import = $Tasks | Where-Object { $_.CommandLine -match "rundll32.exe" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: rundll32.exe ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\rundll32.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\rundll32.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\rundll32.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\rundll32.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX\rundll32.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "rundll32.exe" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("rundll32.exe",$F1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running using suspicious Scripting Utility: wmic.exe
                $Import = $Tasks | Where-Object { $_.CommandLine -match "wmic.exe" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: wmic.exe ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\wmic.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\wmic.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\wmic.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\wmic.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX\wmic.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "wmic.exe" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("wmic.exe",$F1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running using suspicious Scripting Utility: wscript.exe
                $Import = $Tasks | Where-Object { $_.CommandLine -match "wscript.exe" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: wscript.exe ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\wscript.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\wscript.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\wscript.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\CSV\wscript.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\XLSX\wscript.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "wscript.exe" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("wscript.exe",$F1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Parameters

                # Task Scheduler running malicious command line argument: bitsadmin
                $Import = $Tasks | Where-Object { $_.Parameters -match "bitsadmin" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running malicious command line argument: bitsadmin ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\bitsadmin.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\bitsadmin.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\bitsadmin.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\bitsadmin.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX\bitsadmin.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "bitsadmin" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("bitsadmin",$G1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running malicious command line argument: sekurlsa::LogonPasswords --> OS Credential Dumping: LSASS Memory [T1003.001] --> Mimikatz
                $Import = $Tasks | Where-Object { $_.Parameters -match "sekurlsa::LogonPasswords" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running malicious command line argument: sekurlsa::LogonPasswords ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\sekurlsa_LogonPasswords.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\sekurlsa_LogonPasswords.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\sekurlsa_LogonPasswords.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\sekurlsa_LogonPasswords.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX\sekurlsa_LogonPasswords.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Mimikatz" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("sekurlsa::LogonPasswords",$G1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running suspicious command line argument: -WindowStyle Hidden
                $Import = $Tasks | Where-Object { $_.Parameters -match "-WindowStyle Hidden" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running suspicious command line argument: -WindowStyle Hidden ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\WindowStyle_Hidden.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\WindowStyle_Hidden.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\WindowStyle_Hidden.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\WindowStyle_Hidden.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX\WindowStyle_Hidden.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "-WindowStyle Hidden" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("-WindowStyle Hidden",$G1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running suspicious command line argument: -nop
                $Import = $Tasks | Where-Object { $_.Parameters -match "-nop" }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running suspicious command line argument: -nop ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\nop.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\nop.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\nop.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\nop.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX\nop.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "-nop" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("-nop",$G1)))' -BackgroundColor Red
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running suspicious command line argument: /s --> Remote Scheduled Task
                $Import = $Tasks | Where-Object { $_.Parameters -match " /s " }
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running suspicious command line argument which indicates a Remote Scheduled Task: /s ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\Remote-Scheduled-Task.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\Remote-Scheduled-Task.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\Remote-Scheduled-Task.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\Remote-Scheduled-Task.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX\Remote-Scheduled-Task.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Remote Scheduled Task" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("/s",$G1)))' -BackgroundColor Red
                                }
                            }
                        }
                    }
                }

                # c) Scheduled tasks with suspicious network connections (False Positives: MEDIUM)

                # Task Scheduler running suspicious command line argument: IPv4 address
                $IPv4_Pattern = ".*((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).*"
                $Import = $Tasks | Where-Object {($_.Parameters -match "$IPv4_Pattern")}
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running suspicious command line argument: IPv4 address ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\IPv4.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\IPv4.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\IPv4.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\IPv4.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX\IPv4.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "IPv4" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND(".",$G1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running suspicious command line argument: IPv6 address
                $IPv6_Pattern = ".*:(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:)).*"
                $Import = $Tasks | Where-Object { $_.Parameters -notmatch "sekurlsa::LogonPasswords" } | Where-Object {($_.Parameters -match "$IPv6_Pattern")}
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running suspicious command line argument: IPv6 address ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\IPv6.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\IPv6.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\IPv6.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\IPv6.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX\IPv6.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "IPv6" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND(".",$G1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running suspicious command line argument: http://
                $Import = $Tasks | Where-Object {($_.Parameters -match "http://")}
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running suspicious command line argument: http:// ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\http.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\http.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\http.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\http.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX\http.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "http" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("http://",$G1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # Task Scheduler running suspicious command line argument: https://
                $Import = $Tasks | Where-Object {($_.Parameters -match "https://")}
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running suspicious command line argument: https:// ($Count)" -ForegroundColor Yellow
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\https.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\https.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\https.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\https.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX\https.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "https" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("https://",$G1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }

                # d) Custom (False Positives: LOW)

                # Task Scheduler running from a suspicious folder location and executes an EXE: 'C:\Users\*\AppData\Roaming\*' + EXE
                $Import = $Tasks | Where-Object {($_.CommandLine -match "[A-Z]{1}:\\Users\\.*\\AppData\\Roaming\\")} | Where-Object {($_.CommandLine -match "\.exe")}
                $Count = ($Import | Measure-Object).Count
                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Task Scheduler running from a suspicious folder location and executes an EXE: 'C:\Users\*\AppData\Roaming\*' + EXE ($Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV" -ItemType Directory -Force | Out-Null
                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\CSV\APPDATA-EXE.csv" -NoTypeInformation -Encoding UTF8

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\APPDATA-EXE.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\APPDATA-EXE.csv") -gt 0)
                            {
                                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX" -ItemType Directory -Force | Out-Null
                                $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\CSV\APPDATA-EXE.csv" -Delimiter ","
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\XLSX\APPDATA-EXE.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "APPDATA-EXE" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, D-E and H-K
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND(".exe",$G1)))' -BackgroundColor Yellow
                                }
                            }
                        }
                    }
                }
            }
        }

#############################################################################################################################################################################################

        # FS_Process_Handles
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Process_Handles
        New-Item "$OUTPUT_FOLDER\sys\handles" -ItemType Directory -Force | Out-Null
        
        # CSV
        if (Test-Path "$DriveLetter\forensic\json\general.json")
        {
            $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "handle" }

            $Data | Foreach-Object {

                $proc = $_ | Select-Object -ExpandProperty proc
                $procid = $_ | Select-Object -ExpandProperty pid
                $handle = $_ | Select-Object -ExpandProperty hex
                $obj = $_ | Select-Object -ExpandProperty obj
                $access = $_ | Select-Object -ExpandProperty hex2 -ErrorAction SilentlyContinue
                $type = $_ | Select-Object -ExpandProperty desc
                $desc = $_ | Select-Object -ExpandProperty desc2
            
                New-Object -TypeName PSObject -Property @{
                "Process" = $proc
                "PID" = $procid
                "Handle" = $handle
                "Object Address" = $obj
                "Access" = $access
                "Type" = $type
                "Details" = $desc
                }

            } | Select-Object "Process","PID","Handle","Object Address","Access","Type","Details" | Export-Csv -Path "$OUTPUT_FOLDER\sys\handles\handles.csv" -Delimiter "`t" -NoTypeInformation
        }

        # XLSX
        if (Get-Module -ListAvailable -Name ImportExcel)
        {
            if (Test-Path "$OUTPUT_FOLDER\sys\handles\handles.csv")
            {
                if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\sys\handles\handles.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\handles\handles.csv" -Delimiter "`t"
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\handles\handles.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Handles" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-F
                    $WorkSheet.Cells["B:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

#############################################################################################################################################################################################

        # FS_Web (Web Browser History: Google Chrome, Microsoft Edge and Firefox)
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Web
        if (Test-Path "$DriveLetter\forensic\web\web.txt")
        {
            New-Item "$OUTPUT_FOLDER\forensic\web" -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$DriveLetter\forensic\web\web.txt" -Destination "$OUTPUT_FOLDER\forensic\web\web-draft.txt"
            Add-Content -Path "$OUTPUT_FOLDER\forensic\web\web.txt" -Encoding UTF8 -Value (Get-Content -Path "$OUTPUT_FOLDER\forensic\web\web-draft.txt")
            Remove-Item -Path "$OUTPUT_FOLDER\forensic\web\web-draft.txt" -Force

            # Count URL (w/ thousands separators)
            $Count = (Get-Content "$OUTPUT_FOLDER\forensic\web\web.txt" | Measure-Object).Count -2
            $URL = '{0:N0}' -f $Count
            Write-Output "[Info]  Processing Web History Information (Records: $URL) ..."

            if ($Count -gt 0)
            {
                # CSV
                if (Test-Path "$DriveLetter\forensic\json\general.json")
                {
                    $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "web" }

                    $Data | Foreach-Object {

                        $index     = $_ | Select-Object -ExpandProperty i
                        $proc      = $_ | Select-Object -ExpandProperty proc
                        $procid    = $_ | Select-Object -ExpandProperty pid
                        $url       = $_ | Select-Object -ExpandProperty desc
                        $type      = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="type"; Expression={ForEach-Object{($_ -split "type:")[1]} | ForEach-Object{($_ -split "time:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                        $time      = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="time"; Expression={ForEach-Object{($_ -split "time:")[1]} | ForEach-Object{($_ -split "info:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                        $info      = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="info"; Expression={ForEach-Object{($_ -split "info:")[1]} | ForEach-Object{($_ -split "info:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}

                        New-Object -TypeName PSObject -Property @{
                        "Index"        = $index
                        "Process Name" = $proc
                        "PID"          = $procid
                        "URL"          = $url
                        "Type"         = $type.type
                        "Timestamp"    = $time.time
                        "Info"         = $info.info
                        }

                    } | Select-Object "Index","Timestamp","Process Name","PID","Type","URL","Info" | Export-Csv -Path "$OUTPUT_FOLDER\forensic\web\web.csv" -Delimiter "," -NoTypeInformation -Encoding UTF8
                }

                # XLSX
                if (Get-Module -ListAvailable -Name ImportExcel)
                {
                    if (Test-Path "$OUTPUT_FOLDER\forensic\web\web.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\forensic\web\web.csv") -gt 0)
                        {
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\web\web.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\web\web.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Web History" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A-E
                            $WorkSheet.Cells["A:E"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
            }
        }

#############################################################################################################################################################################################

        # FS_BitLocker
        # https://github.com/ufrisk/MemProcFS/wiki/FS_BitLocker
        if (Test-Path "$DriveLetter\misc\bitlocker\*.fvek")
        {
            # Collection
            New-Item "$OUTPUT_FOLDER\misc\bitlocker" -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$DriveLetter\misc\bitlocker\*" -Destination "$OUTPUT_FOLDER\misc\bitlocker"

            # Count BitLocker Full Volume Encryption Key(s)
            $Count = (Get-ChildItem -Path "$OUTPUT_FOLDER\misc\bitlocker" -Filter "*.fvek" | Measure-Object).Count
            Write-Output "[Info]  $Count BitLocker Full Volume Encryption Key(s) found"
        }

#############################################################################################################################################################################################
        
        # Forensic Timeline
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic_Timeline

        Function Get-ForensicTimelineCSV {

        if (Test-Path "$OUTPUT_FOLDER\forensic\json\timeline.json")
        {
            Write-Output "[Info]  Creating Forensic Timeline [time-consuming task] ... "

            # Get Start Time
            $script:StartTime_CSVCreation = (Get-Date)

            # CSV --> Timeline Explorer (TLE)
            New-Item "$OUTPUT_FOLDER\forensic\timeline\CSV" -ItemType Directory -Force | Out-Null
            Get-Content "$DriveLetter\forensic\json\timeline.json" | ConvertFrom-Json | Export-Csv -Path "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv" -Delimiter "," -NoTypeInformation -Encoding UTF8

            # File Size (CSV)
            if (Test-Path "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv")
            {
                $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv").Length)
                Write-Output "[Info]  File Size (CSV): $Size"
            }

            # Count rows of CSV (w/ thousands separators)
            [int]$Count = & $xsv count "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv"
            $Rows = '{0:N0}' -f $Count
            Write-Output "[Info]  Total Lines (CSV): $Rows"

            # Get End Time
            $EndTime_CSVCreation = (Get-Date)

            # Duration CSV Creation
            $Time_CSVCreation = ($EndTime_CSVCreation-$StartTime_CSVCreation)
            ('Duration CSV Creation:         {0} h {1} min {2} sec' -f $Time_CSVCreation.Hours, $Time_CSVCreation.Minutes, $Time_CSVCreation.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"
        }

        }

        # Checkbox
        if ($ForensicTimelineCSV -eq "Enabled")
        {
            Get-ForensicTimelineCSV
        }

        Function Get-ForensicTimelineXLSX {

        # CSV
        if (!(Test-Path "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv"))
        {
            if (Test-Path "$OUTPUT_FOLDER\forensic\json\timeline.json")
            {
                Write-Output "[Info]  Creating Forensic Timeline [time-consuming task] ... "

                # Get Start Time
                $script:StartTime_CSVCreation = (Get-Date)

                # CSV --> Timeline Explorer (TLE)
                New-Item "$OUTPUT_FOLDER\forensic\timeline\CSV" -ItemType Directory -Force | Out-Null
                Get-Content "$DriveLetter\forensic\json\timeline.json" | ConvertFrom-Json | Export-Csv -Path "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv" -Delimiter "," -NoTypeInformation -Encoding UTF8

                # File Size (CSV)
                if (Test-Path "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv")
                {
                    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv").Length)
                    Write-Output "[Info]  File Size (CSV): $Size"
                }

                # Count rows of CSV (w/ thousands separators)
                [int]$Count = & $xsv count "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv"
                $Rows = '{0:N0}' -f $Count
                Write-Output "[Info]  Total Lines (CSV): $Rows"

                # Get End Time
                $EndTime_CSVCreation = (Get-Date)

                # Duration CSV Creation
                $Time_CSVCreation = ($EndTime_CSVCreation-$StartTime_CSVCreation)
                ('Duration CSV Creation:         {0} h {1} min {2} sec' -f $Time_CSVCreation.Hours, $Time_CSVCreation.Minutes, $Time_CSVCreation.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"
            }
        }

        # XLSX
        if (Get-Module -ListAvailable -Name ImportExcel) 
        {
            if (Test-Path "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv") -gt 0)
                {
                    New-Item "$OUTPUT_FOLDER\forensic\timeline\XLSX" -ItemType Directory -Force | Out-Null

                    [int]$Count = & $xsv count "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv"

                    # Get Start Time
                    $script:StartTime_XLSXCreation = (Get-Date)

                    if ($Count -gt "1048576")
                    {
                        Write-Output "[Info]  ImportExcel: timeline.csv will be splitted [time-consuming task] ..."
                        & $xsv sort -R -s "date" "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv" --delimiter "," -o "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline-reverse.csv"
                        & $xsv split -s 1000000 "$OUTPUT_FOLDER\forensic\timeline\CSV" --filename "timeline-{}.csv" --delimiter "," "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline-reverse.csv"

                        [array]$Files = (Get-ChildItem -Path "$OUTPUT_FOLDER\forensic\timeline\CSV" | Where-Object {$_.Name -match "timeline-[0-9].*\.csv"}).FullName

                        ForEach( $File in $Files )
                        {
                            $FileName = $File | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "\.")[0]}
                            $IMPORT = Import-Csv "$File" -Delimiter "," | Select-Object @{Name='Timestamp [UTC]';Expression={([datetime]$_.date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='Type';Expression={$_.type}},@{Name='Action';Expression={$_.action}},@{Name='PID';Expression={$_.pid}},@{Name='Number';Expression={$_.num}},@{Name='Description';Expression={$_.desc}} | Sort-Object { $_."Timestamp [UTC]" -as [datetime] } -Descending
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\timeline\XLSX\$FileName.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Timeline" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A-E
                            $WorkSheet.Cells["A:E"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                    else
                    {
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv" -Delimiter "," | Select-Object @{Name='Timestamp [UTC]';Expression={([datetime]$_.date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='Type';Expression={$_.type}},@{Name='Action';Expression={$_.action}},@{Name='PID';Expression={$_.pid}},@{Name='Number';Expression={$_.num}},@{Name='Description';Expression={$_.desc}} | Sort-Object { $_."Timestamp [UTC]" -as [datetime] } -Descending
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\timeline\XLSX\timeline.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Timeline" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns A-E
                        $WorkSheet.Cells["A:E"].Style.HorizontalAlignment="Center"
                        }
                    }

                    # Get End Time
                    $EndTime_XLSXCreation = (Get-Date)

                    # Duration XLSX Creation
                    $Time_XLSXCreation = ($EndTime_XLSXCreation-$StartTime_XLSXCreation)
                    ('Duration XLSX Creation:        {0} h {1} min {2} sec' -f $Time_XLSXCreation.Hours, $Time_XLSXCreation.Minutes, $Time_XLSXCreation.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"
                }
            }
        }

        }

        # Checkbox
        if ($ForensicTimelineXLSX -eq "Enabled")
        {
            Get-ForensicTimelineXLSX
        }

#############################################################################################################################################################################################
        
        Function Get-Prefetch {

        # FS_Forensic_Prefetch
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic_Prefetch
        if (Test-Path "$DriveLetter\forensic\prefetch\*.pf")
        {
            # Collection
            New-Item "$OUTPUT_FOLDER\forensic\prefetch" -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$DriveLetter\forensic\prefetch\*" -Destination "$OUTPUT_FOLDER\forensic\prefetch"

            # Count recovered Prefetch File(s)
            if (Test-Path "$OUTPUT_FOLDER\forensic\prefetch\00-prefetch-summary.txt")
            {
                [int]$Count = (Get-Content -Path "$OUTPUT_FOLDER\forensic\prefetch\00-prefetch-summary.txt" | Select-String -Pattern "\.pf" | Measure-Object).Count -2
                $Files = '{0:N0}' -f $Count
                Write-Output "[Info]  $Files Prefetch File(s) recovered"
            }
        }

        # Prefetch Files
        if (Test-Path "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv") 
        {
            Write-Output "[Info]  Extracting Prefetch File Information from Forensic Timeline ..."
            New-Item "$OUTPUT_FOLDER\Prefetch" -ItemType Directory -Force | Out-Null

            # CSV
            Import-Csv "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv" -Delimiter "," | Where-Object { $_.desc -match "\.pf$" } | Export-Csv "$OUTPUT_FOLDER\Prefetch\Prefetch.csv" -NoTypeInformation -Encoding UTF8

            # File Size (CSV)
            if (Test-Path "$OUTPUT_FOLDER\Prefetch\Prefetch.csv")
            {
                $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\Prefetch\Prefetch.csv").Length)
                Write-Output "[Info]  File Size (CSV): $Size"
            }

            # Count rows of CSV (w/ thousands separators)
            [int]$Count = & $xsv count "$OUTPUT_FOLDER\Prefetch\Prefetch.csv"
            $Rows = '{0:N0}' -f $Count
            Write-Output "[Info]  Total Lines (CSV): $Rows"

            # MOD - Last Write Time
            # CRE - Creation Time
            # RD  - Last Access Time

            # XLSX
            if (Get-Module -ListAvailable -Name ImportExcel) 
            {
                if (Test-Path "$OUTPUT_FOLDER\Prefetch\Prefetch.csv")
                {
                    if([int](& $xsv count "$OUTPUT_FOLDER\Prefetch\Prefetch.csv") -gt 0)
                    {
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Prefetch\Prefetch.csv" -Delimiter "," | Select-Object @{Name='Timestamp [UTC]';Expression={([datetime]$_.date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='Name';Expression={$_.desc | ForEach-Object{($_ -split "\\")[-1]} }},@{Name='Type';Expression={$_.type}},@{Name='Action';Expression={$_.action}},@{Name='File Path';Expression={$_.desc}} | Sort-Object { $_."Timestamp [UTC]" -as [datetime] } -Descending
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Prefetch\Prefetch.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Prefetch" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns A and C-D
                        $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }
        }

        }

        Get-Prefetch

#############################################################################################################################################################################################

        Function Get-RecentFiles {
        
        # Recent Folder Artifacts
        if (Test-Path "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv")
        {
            Write-Output "[Info]  Extracting Recent Folder Artifacts from Forensic Timeline ..."
            New-Item "$OUTPUT_FOLDER\RecentFiles" -ItemType Directory -Force | Out-Null

            # TXT (FS_Forensic_Ntfs)
            if (Test-Path "$DriveLetter\forensic\ntfs\_\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*.lnk")
            {
                Get-ChildItem -Path "$DriveLetter\forensic\ntfs\_\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*.lnk" | Select-Object -ExpandProperty FullName | Out-File "$OUTPUT_FOLDER\RecentFiles\RecentFiles.txt"
            }

            # CSV
            Import-Csv "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv" -Delimiter "," | Where-Object { $_.desc -match "\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\.*\.lnk" } | Export-Csv "$OUTPUT_FOLDER\RecentFiles\RecentFiles.csv" -NoTypeInformation -Encoding UTF8

            # File Size (CSV)
            if (Test-Path "$OUTPUT_FOLDER\RecentFiles\RecentFiles.csv")
            {
                $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\RecentFiles\RecentFiles.csv").Length)
                Write-Output "[Info]  File Size (CSV): $Size"
            }

            # Count rows of CSV (w/ thousands separators)
            [int]$Count = & $xsv count "$OUTPUT_FOLDER\RecentFiles\RecentFiles.csv"
            $Rows = '{0:N0}' -f $Count
            Write-Output "[Info]  Total Lines (CSV): $Rows"

            # MOD - Last Write Time
            # CRE - Creation Time
            # RD  - Last Access Time

            # XLSX
            if (Get-Module -ListAvailable -Name ImportExcel) 
            {
                if (Test-Path "$OUTPUT_FOLDER\RecentFiles\RecentFiles.csv")
                {
                    if([int](& $xsv count "$OUTPUT_FOLDER\RecentFiles\RecentFiles.csv") -gt 0)
                    {
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\RecentFiles\RecentFiles.csv" -Delimiter "," -Encoding UTF8 | Select-Object @{Name='Timestamp [UTC]';Expression={([datetime]$_.date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='Name';Expression={$_.desc | ForEach-Object{($_ -split "\\")[-1]}}},@{Name='Type';Expression={$_.type}},@{Name='Action';Expression={$_.action}},@{Name='File Path';Expression={$_.desc}},@{Name='Bytes';Expression={$_.num}} | Sort-Object { $_."Timestamp [UTC]" -as [datetime] } -Descending
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\RecentFiles\RecentFiles.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RecentFiles" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns A, C-D and F
                        $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["F:F"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }

            # JumpList Artifacts
            New-Item "$OUTPUT_FOLDER\JumpLists" -ItemType Directory -Force | Out-Null

            # TXT (FS_Forensic_Ntfs)
            if (Test-Path "$DriveLetter\forensic\ntfs\_\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*.lnk")
            {
                Get-ChildItem -Path "$DriveLetter\forensic\ntfs\_\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*Destinations\*" -File | Select-Object -ExpandProperty FullName | Where-Object { $_ -notmatch "`$_INFO" } | Out-File "$OUTPUT_FOLDER\JumpLists\JumpLists.txt"
            }

            # CSV
            Import-Csv "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv" -Delimiter "," | Where-Object { $_.desc -match "\\Microsoft\\Windows\\Recent\\(AutomaticDestinations|CustomDestinations)\\" } | Export-Csv "$OUTPUT_FOLDER\JumpLists\JumpLists.csv" -NoTypeInformation -Encoding UTF8

            # XLSX
            if (Get-Module -ListAvailable -Name ImportExcel) 
            {
                if (Test-Path "$OUTPUT_FOLDER\JumpLists\JumpLists.csv")
                {
                    if([int](& $xsv count "$OUTPUT_FOLDER\JumpLists\JumpLists.csv") -gt 0)
                    {
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\JumpLists\JumpLists.csv" -Delimiter "," | Select-Object @{Name='Timestamp [UTC]';Expression={([datetime]$_.date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='Name';Expression={$_.desc | ForEach-Object{($_ -split "\\")[-1]} }},@{Name='Type';Expression={$_.type}},@{Name='Action';Expression={$_.action}},@{Name='File Path';Expression={$_.desc}},@{Name='Bytes';Expression={$_.num}} | Sort-Object { $_."Timestamp [UTC]" -as [datetime] } -Descending
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\JumpLists\JumpLists.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "JumpLists" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns A, C-D and F
                        $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["F:F"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }
        }

        }

        Get-RecentFiles

#############################################################################################################################################################################################
        
        Function Get-EventLogs {

        # Windows XML Event Log (EVTX)
        if (Test-Path "$DriveLetter\name\svchost.exe-*\files\handles\*.evtx") 
        {
            Write-Output "[Info]  Collecting Windows Event Logs (EVTX) ... "
            New-Item "$OUTPUT_FOLDER\EventLogs\EventLogs" -ItemType Directory -Force | Out-Null
            Get-ChildItem -Recurse -Force "$DriveLetter\name\svchost.exe-*\files\handles\*.evtx" | Foreach-Object FullName | Out-File "$OUTPUT_FOLDER\EventLogs\EventLog-List.txt"
            Copy-Item -Recurse -Force "$DriveLetter\name\svchost.exe-*\files\handles\*.evtx" "$OUTPUT_FOLDER\EventLogs\EventLogs" 2>&1 | Out-Null

            # Rename Event Logs
            (Get-ChildItem "$OUTPUT_FOLDER\EventLogs\EventLogs") | Rename-Item -NewName { $_.Name.Substring(17) }

            # Count EVTX Files
            $Count = (Get-ChildItem -Path "$OUTPUT_FOLDER\EventLogs\EventLogs" -Filter "*.evtx" | Measure-Object).Count
            $InputSize = Get-FileSize((Get-ChildItem -Path "$OUTPUT_FOLDER\EventLogs\EventLogs" -Filter "*.evtx" | Measure-Object Length -Sum).Sum)
            Write-Output "[Info]  Processing $Count EVTX Files ($InputSize) ..."
        }

        }

        Get-EventLogs

#############################################################################################################################################################################################

        # EvtxECmd

        Function Update-EvtxECmd {

        # Internet Connectivity Check (Vista+)
        $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]‘{DCB00C01-570F-4A9B-8D69-199FDBA5723B}’)).IsConnectedToInternet

        if (!($NetworkListManager -eq "True"))
        {
            Write-Host "[Error] Your computer is NOT connected to the Internet. Event Log Maps cannot be updated." -ForegroundColor Red
        }
        else
        {
            # Check if GitHub is reachable
            if (!(Test-NetConnection -ComputerName github.com -Port 443).TcpTestSucceeded)
            {
                Write-Host "[Error] github.com is NOT reachable. Event Log Maps cannot be updated." -ForegroundColor Red
            }
            else
            {
                Write-Output "[Info]  Updating Event Log Maps ... "

                # Flush
                if (Test-Path "$SCRIPT_DIR\Tools\EvtxECmd\Maps")
                {
                    Get-ChildItem -Path "$SCRIPT_DIR\Tools\EvtxECmd\Maps" -Recurse | Remove-Item -Force -Recurse
                }

                # Sync for EvtxECmd Maps with GitHub
                if (Test-Path "$($EvtxECmd)")
                {
                    & $EvtxECmd --sync > "$SCRIPT_DIR\Tools\EvtxECmd\Maps.log" 2> $null
                }
                else
                {
                    Write-Host "[Error] EvtxECmd.exe NOT found." -ForegroundColor Red
                }
            }
        }

        }

        # Offline Mode
        if ($OfflineMode -eq "Enabled")
        {
            Write-Output "[Info]  Updating Event Log Maps will be skipped [Offline-Mode] ..."
        }
        else
        {
            Update-EvtxECmd
        }

        Function Invoke-EvtxECmd {

        # EvtxECmd --> Timeline Explorer
        if (Test-Path "$($EvtxECmd)")
        {
            $Count = (Get-ChildItem "$SCRIPT_DIR\Tools\EvtxECmd\Maps\*" -Include *.map | Measure-Object).Count
            Write-Output "[Info]  $Count Event Log Maps will be initiated by EvtxECmd ..."

            if (Test-Path "$OUTPUT_FOLDER\EventLogs\EventLogs\*.evtx") 
            {
                New-Item "$OUTPUT_FOLDER\EventLogs\EvtxECmd" -ItemType Directory -Force | Out-Null
                & $EvtxECmd -d "$OUTPUT_FOLDER\EventLogs\EventLogs" --csv "$OUTPUT_FOLDER\EventLogs\EvtxECmd" --csvf "EventLogs.csv" > "$OUTPUT_FOLDER\EventLogs\EvtxECmd\EvtxECmd.log" 2> $null

                # File Size (CSV)
                if (Test-Path "$OUTPUT_FOLDER\EventLogs\EvtxECmd\EventLogs.csv")
                {
                    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\EventLogs\EvtxECmd\EventLogs.csv").Length)
                    Write-Output "[Info]  File Size (CSV): $Size"
                }

                # Windows Title (Default)
                $Host.UI.RawUI.WindowTitle = "MemProcFS-Analyzer $Version - Automated Forensic Analysis of Windows Memory Dumps for DFIR"
            }
        }
        else
        {
            Write-Host "[Error] EvtxECmd.exe NOT found." -ForegroundColor Red
        }

        }

        Invoke-EvtxECmd

#############################################################################################################################################################################################

        Function Update-ZircoliteRules {

        # Zircolite
        if (Test-Path "$($Zircolite)")
        {
            # Offline Mode
            if ($OfflineMode -eq "Enabled")
            {
                Write-Output "[Info]  Updating SIGMA Rulesets will be skipped [Offline-Mode] ..."
            }
            else
            {
                # Update
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
        }

        }

        Update-ZircoliteRules

#############################################################################################################################################################################################

        Function Invoke-Zircolite {

        # Zircolite
        if (Test-Path "$($Zircolite)")
        {
            if (Test-Path "$OUTPUT_FOLDER\EventLogs\EventLogs\*.evtx") 
            {
                Write-Output "[Info]  Processing Windows Event Logs w/ Zircolite ... "
                New-Item "$OUTPUT_FOLDER\EventLogs\Zircolite" -ItemType Directory -Force | Out-Null

                $StartTime_Zircolite = (Get-Date)

                # Check if InputSize is greater than 500 MB
                $Bytes = ((Get-ChildItem -Path "$OUTPUT_FOLDER\EventLogs\EventLogs" -Filter "*.evtx" | Measure-Object Length -Sum).Sum)

                if ($Bytes -gt 524288000)
                {
                    # JSON
                    New-Item "$OUTPUT_FOLDER\EventLogs" -ItemType Directory -Force | Out-Null
                    $ScanPath = "$OUTPUT_FOLDER\EventLogs\EventLogs"
                    $Ruleset = "rules\rules_windows_generic_full.json"
                    $TempDir = "$OUTPUT_FOLDER\EventLogs\JSONL"
                    $MyLocation = $pwd
                    Set-Location "$SCRIPT_DIR\Tools\Zircolite"
                    & $Zircolite --evtx $ScanPath --ruleset $Ruleset --noexternal --tmpdir $TempDir --keeptmp 2>&1 | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite-draft.txt"
                    Set-Location "$MyLocation"
                }
                else
                {
                    $MyLocation = $pwd
                    Set-Location "$SCRIPT_DIR\Tools\Zircolite"

                    # JSON + Mini-GUI
                    Write-Output "[Info]  Creating JSON output and ZircoGui package ..."
                    New-Item "$OUTPUT_FOLDER\EventLogs" -ItemType Directory -Force | Out-Null
                    $ScanPath = "$OUTPUT_FOLDER\EventLogs\EventLogs"
                    $Ruleset = "rules\rules_windows_generic_full.json"
                    $TempDir = "$OUTPUT_FOLDER\EventLogs\JSONL"
                    & $Zircolite --evtx $ScanPath --ruleset $Ruleset --noexternal --package --tmpdir $TempDir --keeptmp 2>&1 | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite-draft.txt"

                    # Remove ANSI Control Characters
                    if (Test-Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite-draft.txt")
                    {
                        Get-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite-draft.txt" | ForEach-Object { $_ -replace "\x1b\[[0-9;]*m" } | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt"
                        Remove-Item "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite-draft.txt"
                    }

                    # Remove empty lines and add line breaks where needed
                    if (Test-Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt")
                    {
                        $Clean = Get-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt" | Where-Object {$_.Trim()} | ForEach-Object {($_ -replace "Finished in", "`nFinished in")} | ForEach-Object {($_ -replace "Sysmon Linux =-", "Sysmon Linux =-`n")}
                        @("") + ($Clean) | Set-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt"
                    }

                    # Cleaning up
                    if (Test-Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt")
                    {
                        $Filter = @("^zircolite_win10\.exe","MemProcFS-Analyzer-v.*\.ps1","^\+","\+ CategoryInfo          : NotSpecified:","\+ FullyQualifiedErrorId : NativeCommandError","%\|","^tmp-rules-")
                        $Clean = Get-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt" | Select-String -Pattern $Filter -NotMatch 
                        $Clean | Set-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt"
                    }

                    # Executed Ruleset
                    Start-Sleep 3
                    if (Test-Path "$pwd\zircolite.log")
                    {
                        [int]$Count = Get-Content "$pwd\zircolite.log" | Select-String -Pattern "Executing ruleset" | Select-Object -First 1 | ForEach-Object{($_ -split "\s+")[-2]}
                        $Rules = '{0:N0}' -f $Count
                        Write-Output "[Info]  Executed ruleset - $Rules rules"
                    }

                    # zircolite.log
                    if (Test-Path "$pwd\zircolite.log")
                    {
                        Remove-Item -Path "$pwd\zircolite.log" -Force
                    }

                    # JSON
                    if (Test-Path "$pwd\detected_events.json")
                    {
                        New-Item "$OUTPUT_FOLDER\EventLogs\Zircolite\JSON" -ItemType Directory -Force | Out-Null
                        Move-Item -Path "$pwd\detected_events.json" -Destination "$OUTPUT_FOLDER\EventLogs\Zircolite\JSON\detected_events.json"
                    }

                    # File Size (JSON)
                    if (Test-Path "$OUTPUT_FOLDER\EventLogs\Zircolite\JSON\detected_events.json")
                    {
                        $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\EventLogs\Zircolite\JSON\detected_events.json").Length)
                        Write-Output "[Info]  File Size (JSON): $Size"
                    }

                    # ZircoGui
                    if (Test-Path "$pwd\zircogui-output-*.zip")
                    {
                        New-Item "$OUTPUT_FOLDER\EventLogs\Zircolite\Package" -ItemType Directory -Force | Out-Null
                        New-Item "$OUTPUT_FOLDER\EventLogs\Zircolite\Mini-GUI" -ItemType Directory -Force | Out-Null
                        Move-Item -Path "$pwd\zircogui-output-*.zip" -Destination "$OUTPUT_FOLDER\EventLogs\Zircolite\Package"

                        # Unzip ZircoGui Package
                        if (Test-Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Package\zircogui-output-*.zip")
                        {
                            Expand-Archive "$OUTPUT_FOLDER\EventLogs\Zircolite\Package\zircogui-output-*.zip" -DestinationPath "$OUTPUT_FOLDER\EventLogs\Zircolite\Mini-GUI"
                        }

                        # Open ZircoGui
                        if (Test-Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Mini-GUI\index.html")
                        {
                            # Check if Google Chrome is installed
                            if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe")
                            {
                                # Open ZircoGui w/ Google Chrome
                                $Chrome = ((Get-Item (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe")."(Default)").VersionInfo).FileName
                                Start-Process -FilePath $Chrome -ArgumentList "--start-fullscreen $OUTPUT_FOLDER\EventLogs\Zircolite\Mini-GUI\index.html"
                            }
                            else
                            {
                                # Open ZircoGui in your Default Browser
                                Start-Process "$OUTPUT_FOLDER\EventLogs\Zircolite\Mini-GUI\index.html"
                            }
                        }
                    }

                    Set-Location "$MyLocation"

                    # Stats
                    if (Test-Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt")
                    {
                        if (Get-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt" | Select-String -Pattern "    - " -Quiet)
                        {
                            # Count triggered Sigma Rules
                            $Rules = (Get-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt" | Select-String -Pattern "    - " | Measure-Object).Count

                            if ($Rules -gt 0)
                            {
                                # Count Events (w/ thousands separators)
                                [int]$Count = (Get-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt" | Select-String -Pattern "    - " | ForEach-Object{($_ -split "\s+")[-2]} | Measure-Object -Sum).Sum
                                $Events = '{0:N0}' -f $Count

                                Write-Host "[Alert] $Rules Detection(s) found ($Events events)" -ForegroundColor Red

                                # Sort A-Z
                                Get-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt" | Select-String -Pattern "    - " | ForEach-Object{($_ -replace "    - ","")} | Sort-Object | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Detections.txt"

                                # SIGMA Rule Level (critical, high, medium, low)

                                # Critical
                                $Critical = Get-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt" | Select-String -Pattern "    - " | Select-String -Pattern "\[critical\]" | ForEach-Object{($_ -replace "    - ","        ")} | Sort-Object
                                $CriticalAlerts = ($Critical | Measure-Object).Count
                                if ($CriticalAlerts -gt 0)
                                { 
                                    $Critical.Trim() | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Detections-Critical.txt" 
                                }

                                # High
                                $High = Get-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt" | Select-String -Pattern "    - " | Select-String -Pattern "\[high\]" | ForEach-Object{($_ -replace "    - ","        ")} | Sort-Object
                                $HighAlerts = ($High | Measure-Object).Count
                                if ($HighAlerts -gt 0)
                                { 
                                    $High.Trim() | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Detections-High.txt"
                                }

                                # Medium
                                $Medium = Get-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt" | Select-String -Pattern "    - " | Select-String -Pattern "\[medium\]" | ForEach-Object{($_ -replace "    - ","        ")} | Sort-Object
                                $MediumAlerts = ($Medium | Measure-Object).Count
                                if ($MediumAlerts -gt 0)
                                { 
                                    $Medium.Trim() | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Detections-Medium.txt"
                                }

                                # Low
                                $Low = Get-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt" | Select-String -Pattern "    - " | Select-String -Pattern "\[low\]" | ForEach-Object{($_ -replace "    - ","        ")} | Sort-Object
                                $LowAlerts = ($Low | Measure-Object).Count
                                if ($LowAlerts -gt 0)
                                { 
                                    $Low.Trim() | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Detections-Low.txt"
                                }
                            
                                # Informational
                                $Informational = Get-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt" | Select-String -Pattern "    - " | Select-String -Pattern "\[informational\]" | ForEach-Object{($_ -replace "    - ","        ")} | Sort-Object
                                $InformationalAlerts = ($Informational | Measure-Object).Count
                                if ($InformationalAlerts -gt 0)
                                { 
                                    $Informational.Trim() | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Detections-Informational.txt"
                                }
                
                                # Unknown
                                $Unknown = Get-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Zircolite.txt" | Select-String -Pattern "    - " | Select-String -Pattern "\[unknown\]" | ForEach-Object{($_ -replace "    - ","        ")} | Sort-Object
                                $UnknownAlerts = ($Unknown | Measure-Object).Count
                                if ($UnknownAlerts -gt 0)
                                { 
                                    $Unknown.Trim() | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Detections-Unknown.txt"
                                }

                                # Stats (Alerts by Sigma Rules Level)
                                Write-Output "$Rules Alerts ($Events events)" | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Stats.txt"
                                Write-Output "" | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Stats.txt" -Append
                                Write-Output "Alerts by Sigma Rule Level" | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Stats.txt" -Append
                                Write-Output "Critical: $CriticalAlerts" | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Stats.txt" -Append
                                Write-Output "High:     $HighAlerts" | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Stats.txt" -Append
                                Write-Output "Medium:   $MediumAlerts" | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Stats.txt" -Append
                                Write-Output "Low:      $LowAlerts" | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Stats.txt" -Append
                                Write-Output "Info:     $InformationalAlerts" | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Stats.txt" -Append
                                Write-Output "Unknown:  $UnknownAlerts" | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Stats.txt" -Append
                
                                $Critical | Write-Host -ForegroundColor Red
                                $High | Write-Host -ForegroundColor Yellow
                                $Medium | Write-Host -ForegroundColor DarkCyan
                                $Low | Write-Host -ForegroundColor DarkGreen
                                $Informational | Write-Host -ForegroundColor Gray
                            }
                        }
                        else
                        {
                            Write-Host "[Info]  0 Detections found"
                        }
                    }
                }
            }
        }
        else
        {
            Write-Host "[Error] zircolite.exe NOT found." -ForegroundColor Red
        }

        # Results
        if (Test-Path "$OUTPUT_FOLDER\EventLogs\Zircolite\JSON\detected_events.json")
        {
            if((Get-Item "$OUTPUT_FOLDER\EventLogs\Zircolite\JSON\detected_events.json").length -gt 1kb)
            {
                # Import JSON Data
                $Data = Get-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\JSON\detected_events.json" | ConvertFrom-Json

                # Alerts by Sigma Rules Level
                $Events = ($Data | Select-Object count | Measure-Object Count -Sum).Sum
                $Critical = ($Data | Where-Object { $_.rule_level -eq "critical" } | Select-Object count | Measure-Object Count -Sum).Sum
                $High = ($Data | Where-Object { $_.rule_level -eq "high" } | Select-Object count | Measure-Object Count -Sum).Sum
                $Medium = ($Data | Where-Object { $_.rule_level -eq "medium" } | Select-Object count | Measure-Object Count -Sum).Sum
                $Low = ($Data | Where-Object { $_.rule_level -eq "low" } | Select-Object count | Measure-Object Count -Sum).Sum
                $Informational = ($Data | Where-Object { $_.rule_level -eq "informational" } | Select-Object count | Measure-Object Count -Sum).Sum
                $Unknown = ($Data | Where-Object { $_.rule_level -eq "unknown" } | Select-Object count | Measure-Object Count -Sum).Sum

                # Array
                $Array = @()

                # Critical
                if ($Critical)
                {
                    $Array += @{Level = "Critical"; Description = "Highly relevant event that indicates an incident. Critical events should be reviewed immediately."; Count = "$Critical"}
                }
                else
                {
                    $Array += @{Level = "Critical"; Description = "Highly relevant event that indicates an incident. Critical events should be reviewed immediately."; Count = "0"}
                }

                # High
                if ($High)
                {
                    $Array += @{Level = "High"; Description = "Relevant event that should trigger an internal alert and requires a prompt review."; Count = "$High"}
                }
                else
                {
                    $Array += @{Level = "High"; Description = "Relevant event that should trigger an internal alert and requires a prompt review."; Count = "0"}
                }

                # Medium
                if ($Medium)
                {
                    $Array += @{Level = "Medium"; Description = "Relevant event that should be reviewed manually on a more frequent basis."; Count = "$Medium"}
                }
                else
                {
                    $Array += @{Level = "Medium"; Description = "Relevant event that should be reviewed manually on a more frequent basis."; Count = "0"}
                }

                # Low
                if ($Low)
                {
                    $Array += @{Level = "Low"; Description = "Notable event but rarely an incident. Low rated events can be relevant in high numbers or combination with others. Immediate reaction shouldn't be necessary, but a regular review is recommended."; Count = "$Low"}
                }
                else
                {
                    $Array += @{Level = "Low"; Description = "Notable event but rarely an incident. Low rated events can be relevant in high numbers or combination with others. Immediate reaction shouldn't be necessary, but a regular review is recommended."; Count = "0"}
                }

                # Informational
                if ($Informational)
                {
                    $Array += @{Level = "Informational"; Description = "Rule is intended for enrichment of events, e.g. by tagging them. No case or alerting should be triggered by such rules because it is expected that a huge amount of events will match these rules."; Count = "$Informational"}
                }
                else
                {
                    $Array += @{Level = "Informational"; Description = "Rule is intended for enrichment of events, e.g. by tagging them. No case or alerting should be triggered by such rules because it is expected that a huge amount of events will match these rules."; Count = "0"}
                }

                # Unknown
                if ($Unknown)
                {
                    $Array += @{Level = "Unknown"; Description = "Unknown"; Count = "$Unknown"}
                }
                else
                {
                    $Array += @{Level = "Unknown"; Description = "Unknown"; Count = "0"}
                }

                # CSV
                $Array | ForEach-Object { New-Object PSObject -Property $_ } |  Export-Csv "$OUTPUT_FOLDER\EventLogs\Zircolite\Alerts-by-Sigma-Rule-Level.csv" -NoTypeInformation

                # XLSX
                if (Get-Module -ListAvailable -Name ImportExcel)
                {
                    if (Test-Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Alerts-by-Sigma-Rule-Level.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\EventLogs\Zircolite\Alerts-by-Sigma-Rule-Level.csv") -gt 0)
                        {
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EventLogs\Zircolite\Alerts-by-Sigma-Rule-Level.csv" -Delimiter "," | Sort-Object { $_.FileKeyLastWriteTimestamp -as [datetime] } -Descending
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Alerts-by-Sigma-Rule-Level.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SIGMA Rule Level" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A and C
                            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }

                # Alerts by MITRE ATT&CK Tactics
                # https://attack.mitre.org/tactics/enterprise/

                # Array
                $Array = @()

                # Reconnaissance - The adversary is trying to gather information they can use to plan future operations [TA0043]
                $Reconnaissance = ($Data | Where-Object { $_.tags -like "attack.reconnaissance" } | Select-Object count | Measure-Object Count -Sum).Sum
                if ($Reconnaissance)
                {
                    $Array += @{ID = "TA0043"; Name = "Reconnaissance"; Description = "The adversary is trying to gather information they can use to plan future operations."; Count = "$Reconnaissance"}
                }
                else
                {
                    $Array += @{ID = "TA0043"; Name = "Reconnaissance"; Description = "The adversary is trying to gather information they can use to plan future operations."; Count = "0"}
                }

                # Resource Development - The adversary is trying to establish resources they can use to support operations [TA0042]
                $ResourceDevelopment = ($Data | Where-Object { $_.tags -like "attack.resource_development" } | Select-Object count | Measure-Object Count -Sum).Sum
                if ($ResourceDevelopment)
                {
                    $Array += @{ID = "TA0042"; Name = "Resource Development"; Description = "The adversary is trying to establish resources they can use to support operations."; Count = "$ResourceDevelopment"}
                }
                else
                {
                    $Array += @{ID = "TA0042"; Name = "Resource Development"; Description = "The adversary is trying to establish resources they can use to support operations."; Count = "0"}
                }

                # Initial Access - The adversary is trying to get into your network [TA0001]
                $InitialAccess = ($Data | Where-Object { $_.tags -like "attack.initial_access" } | Select-Object count | Measure-Object Count -Sum).Sum
                if ($InitialAccess)
                {
                    $Array += @{ID = "TA0001"; Name = "Initial Access"; Description = "The adversary is trying to get into your network."; Count = "$InitialAccess"}
                }
                else
                {
                    $Array += @{ID = "TA0001"; Name = "Initial Access"; Description = "The adversary is trying to get into your network."; Count = "0"}
                }

                # Execution - The adversary is trying to run malicious code [TA0002]
                $Execution = ($Data | Where-Object { $_.tags -like "attack.execution" } | Select-Object count | Measure-Object Count -Sum).Sum
                if ($Execution)
                {
                    $Array += @{ID = "TA0002"; Name = "Execution"; Description = "The adversary is trying to run malicious code."; Count = "$Execution"}
                }
                else
                {
                    $Array += @{ID = "TA0002"; Name = "Execution"; Description = "The adversary is trying to run malicious code."; Count = "0"}
                }

                # Persistence - The adversary is trying to maintain their foothold [TA0003]
                $Persistence = ($Data | Where-Object { $_.tags -like "attack.persistence" } | Select-Object count | Measure-Object Count -Sum).Sum
                if ($Persistence)
                {
                    $Array += @{ID = "TA0003"; Name = "Persistence"; Description = "The adversary is trying to maintain their foothold."; Count = "$Persistence"}
                }
                else
                {
                    $Array += @{ID = "TA0003"; Name = "Persistence"; Description = "The adversary is trying to maintain their foothold."; Count = "0"}
                }

                # Privilege Escalation - The adversary is trying to gain higher-level permissions [TA0004]
                $PrivilegeEscalation = ($Data | Where-Object { $_.tags -like "attack.privilege_escalation" } | Select-Object count | Measure-Object Count -Sum).Sum
                if ($PrivilegeEscalation)
                {
                    $Array += @{ID = "TA0004"; Name = "Privilege Escalation"; Description = "The adversary is trying to gain higher-level permissions."; Count = "$PrivilegeEscalation"}
                }
                else
                {
                    $Array += @{ID = "TA0004"; Name = "Privilege Escalation"; Description = "The adversary is trying to gain higher-level permissions."; Count = "0"}
                }

                # Defense Evasion - The adversary is trying to avoid being detected [TA0005]
                $DefenseEvasion = ($Data | Where-Object { $_.tags -like "attack.defense_evasion" } | Select-Object count | Measure-Object Count -Sum).Sum
                if ($DefenseEvasion)
                {
                    $Array += @{ID = "TA0005"; Name = "Defense Evasion"; Description = "The adversary is trying to avoid being detected."; Count = "$DefenseEvasion"}
                }
                else
                {
                    $Array += @{ID = "TA0005"; Name = "Defense Evasion"; Description = "The adversary is trying to avoid being detected."; Count = "0"}
                }

                # Credential Access - The adversary is trying to steal account names and passwords [TA0006]
                $CredentialAccess = ($Data | Where-Object { $_.tags -like "attack.credential_access" } | Select-Object count | Measure-Object Count -Sum).Sum
                if ($CredentialAccess)
                {
                    $Array += @{ID = "TA0006"; Name = "Credential Access"; Description = "The adversary is trying to steal account names and passwords."; Count = "$CredentialAccess"}
                }
                else
                {
                    $Array += @{ID = "TA0006"; Name = "Credential Access"; Description = "The adversary is trying to steal account names and passwords."; Count = "0"}
                }

                # Discovery - The adversary is trying to figure out your environment [TA0007]
                $Discovery = ($Data | Where-Object { $_.tags -like "attack.discovery" } | Select-Object count | Measure-Object Count -Sum).Sum
                if ($Discovery)
                {
                    $Array += @{ID = "TA0007"; Name = "Discovery"; Description = "The adversary is trying to figure out your environment."; Count = "$Discovery"}
                }
                else
                {
                    $Array += @{ID = "TA0007"; Name = "Discovery"; Description = "The adversary is trying to figure out your environment."; Count = "0"}
                }

                # Lateral Movement - The adversary is trying to move through your environment [TA0008]
                $LateralMovement = ($Data | Where-Object { $_.tags -like "attack.lateral_movement" } | Select-Object count | Measure-Object Count -Sum).Sum
                if ($LateralMovement)
                {
                    $Array += @{ID = "TA0008"; Name = "Lateral Movement"; Description = "The adversary is trying to move through your environment."; Count = "$LateralMovement"}
                }
                else
                {
                    $Array += @{ID = "TA0008"; Name = "Lateral Movement"; Description = "The adversary is trying to move through your environment."; Count = "0"}
                }

                # Collection - The adversary is trying to gather data of interest to their goal [TA0009]
                $Collection = ($Data | Where-Object { $_.tags -like "attack.collection" } | Select-Object count | Measure-Object Count -Sum).Sum
                if ($Collection)
                {
                    $Array += @{ID = "TA0009"; Name = "Collection"; Description = "The adversary is trying to gather data of interest to their goal."; Count = "$Collection"}
                }
                else
                {
                    $Array += @{ID = "TA0009"; Name = "Collection"; Description = "The adversary is trying to gather data of interest to their goal."; Count = "0"}
                }

                # Command and Control - The adversary is trying to communicate with compromised systems to control them [TA0011]
                $CommandAndControl = ($Data | Where-Object { $_.tags -like "attack.commandandcontrol" } | Select-Object count | Measure-Object Count -Sum).Sum
                if ($CommandAndControl)
                {
                    $Array += @{ID = "TA0011"; Name = "Command and Control"; Description = "The adversary is trying to communicate with compromised systems to control them."; Count = "$CommandAndControl"}
                }
                else
                {
                    $Array += @{ID = "TA0011"; Name = "Command and Control"; Description = "The adversary is trying to communicate with compromised systems to control them."; Count = "0"}
                }

                # Exfiltration - The adversary is trying to steal data [TA0010]
                $Exfiltration = ($Data | Where-Object { $_.tags -like "attack.exfiltration" } | Select-Object count | Measure-Object Count -Sum).Sum
                if ($Exfiltration)
                {
                    $Array += @{ID = "TA0010"; Name = "Exfiltration"; Description = "The adversary is trying to steal data."; Count = "$Exfiltration"}
                }
                else
                {
                    $Array += @{ID = "TA0010"; Name = "Exfiltration"; Description = "The adversary is trying to steal data."; Count = "0"}
                }

                # Impact - The adversary is trying to manipulate, interrupt, or destroy your systems and data [TA0040]
                $Impact = ($Data | Where-Object { $_.tags -like "attack.impact" } | Select-Object count | Measure-Object Count -Sum).Sum
                if ($Impact)
                {
                    $Array += @{ID = "TA0040"; Name = "Impact"; Description = "The adversary is trying to manipulate, interrupt, or destroy your systems and data."; Count = "$Impact"}
                }
                else
                {
                    $Array += @{ID = "TA0040"; Name = "Impact"; Description = "The adversary is trying to manipulate, interrupt, or destroy your systems and data."; Count = "0"}
                }

                # Uncategorized
                $Uncategorized = ($Data | Where-Object { $_.tags -like "attack.uncategorized" } | Select-Object count | Measure-Object Count -Sum).Sum
                if ($Uncategorized)
                {
                    $Array += @{ID = "Uncategorized"; Name = "Uncategorized"; Description = "Uncategorized"; Count = "$Uncategorized"}
                }
                else
                {
                    $Array += @{ID = "Uncategorized"; Name = "Uncategorized"; Description = "Uncategorized"; Count = "0"}
                }

                # CSV
                $Array | ForEach-Object { New-Object PSObject -Property $_ } |  Export-Csv "$OUTPUT_FOLDER\EventLogs\Zircolite\Alerts-by-Tactics.csv" -NoTypeInformation

                # XLSX
                if (Get-Module -ListAvailable -Name ImportExcel)
                {
                    if (Test-Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Alerts-by-Tactics.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\EventLogs\Zircolite\Alerts-by-Tactics.csv") -gt 0)
                        {
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EventLogs\Zircolite\Alerts-by-Tactics.csv" -Delimiter "," | Sort-Object { $_.FileKeyLastWriteTimestamp -as [datetime] } -Descending
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Alerts-by-Tactics.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MITRE ATT&CK Tactics" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of column D
                            $WorkSheet.Cells["D:D"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }

                # Alerts by Channel

                # CSV
                ($Data | Select-Object matches).matches | Group-Object Channel | Select-Object Name, Count | Sort-Object Name | Export-Csv "$OUTPUT_FOLDER\EventLogs\Zircolite\Alerts-by-Channel.csv" -NoTypeInformation

                # XLSX
                if (Get-Module -ListAvailable -Name ImportExcel)
                {
                    if (Test-Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Alerts-by-Channel.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\EventLogs\Zircolite\Alerts-by-Channel.csv") -gt 0)
                        {
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EventLogs\Zircolite\Alerts-by-Channel.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Alerts-by-Channel.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Alerts by Channel" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of column B
                            $WorkSheet.Cells["B:B"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
            }

        $EndTime_Zircolite = (Get-Date)
        $Time_Zircolite = ($EndTime_Zircolite-$StartTime_Zircolite)
        ('Zircolite Processing duration: {0} h {1} min {2} sec' -f $Time_Zircolite.Hours, $Time_Zircolite.Minutes, $Time_Zircolite.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

        }

        }

        Invoke-Zircolite

#############################################################################################################################################################################################

        Function Get-EventLogOverview {

        # Event Log Overview
        if (Test-Path "$OUTPUT_FOLDER\EventLogs\JSONL\*.json")
        {
            Write-Output "[Info]  Parsing Event Record Information from JSON Files ..."
            $EventLogs = (Get-ChildItem -Path "$OUTPUT_FOLDER\EventLogs\JSONL" -Filter "*.json").FullName

            $StartTime_EventLogOverview = (Get-Date)

            $EventArray = @()
            ForEach($EventLog in $EventLogs)
            {
                $LogName = $EventLog | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "\.evtx-")[0]}
                [int64]$LogSize = (Get-Item -Path $EventLog).Length
                $Row = New-Object PSObject
                $Row | Add-Member -Name Name -MemberType NoteProperty -Value ("$LogName" + ".evtx")
                $Row | Add-Member -Name RecordCount -MemberType NoteProperty -Value ((& $jq -c '.Event.System.EventID' $EventLog | Measure-Object).Count)
                if ($LogSize -ne "0")
                {
                    $Row | Add-Member -Name "Oldest [UTC]" -MemberType NoteProperty -Value (& $jq -r '.Event.System.TimeCreated | .[]?.SystemTime' $EventLog | Sort-Object | Select-Object -First 1 | ForEach-Object{($_ -replace "T"," ")} | ForEach-Object{($_ -split "\.")[0]})
                    $Row | Add-Member -Name "Newest [UTC]" -MemberType NoteProperty -Value (& $jq -r '.Event.System.TimeCreated | .[]?.SystemTime' $EventLog | Sort-Object | Select-Object -Last 1 | ForEach-Object{($_ -replace "T"," ")} | ForEach-Object{($_ -split "\.")[0]})
                    $Row | Add-Member -Name Bytes -MemberType NoteProperty -Value ((Get-Item -Path $EventLog).Length)
                    $Row | Add-Member -Name FileSize -MemberType NoteProperty -Value (Get-FileSize (Get-Item -Path $EventLog).Length)
                }
                else
                {
                    $Row | Add-Member -Name Bytes -MemberType NoteProperty -Value ("0")
                    $Row | Add-Member -Name FileSize -MemberType NoteProperty -Value ("0")
                }
                $Row | Add-Member -Name FilePath -MemberType NoteProperty -Value ($EventLog)
                $EventArray  += $Row
            }

            # EventLogOverview.csv
            $EventArray | Export-Csv "$OUTPUT_FOLDER\EventLogs\EventLogOverview.csv" -NoTypeInformation

            # EventLogOverview.xlsx
            if (Get-Module -ListAvailable -Name ImportExcel) 
            {
                if (Test-Path "$OUTPUT_FOLDER\EventLogs\EventLogOverview.csv")
                {
                    if([int](& $xsv count "$OUTPUT_FOLDER\EventLogs\EventLogOverview.csv") -gt 0)
                    {
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\EventLogs\EventLogOverview.csv" -Delimiter ","
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EventLogs\EventLogOverview.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "EventLogOverview" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns B-D
                        $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                        # HorizontalAlignment "Right" of columns E-F
                        $WorkSheet.Cells["E:F"].Style.HorizontalAlignment="Right"
                        # HorizontalAlignment "Center" of header of columns E-F
                        $WorkSheet.Cells["E1:F1"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }

        $EndTime_EventLogOverview = (Get-Date)
        $Time_EventLogOverview = ($EndTime_EventLogOverview-$StartTime_EventLogOverview)
        ('EventLogOverview duration:     {0} h {1} min {2} sec' -f $Time_EventLogOverview.Hours, $Time_EventLogOverview.Minutes, $Time_EventLogOverview.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

        }

        }

        Get-EventLogOverview

#############################################################################################################################################################################################

        Function Get-Timesketch {

        # Timesketch
        if (Test-Path "$($Zircolite)")
        {
            Write-Output "[Info]  Creating Timesketch output ..."
            New-Item "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch" -ItemType Directory -Force | Out-Null

            $script:MyLocation = $pwd
            Set-Location "$SCRIPT_DIR\Tools\Zircolite"

            $StartTime_Timesketch = (Get-Date)

            # Zircolite
            $Ruleset = "rules\rules_windows_generic_full.json"
            $Template = "templates\exportForTimesketch.tmpl"
            $TemplateOutput = "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\Timesketch_MemProcFS-Analyzer.csv"
            $OutFile = "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\detected_events.json"
            $LogFile = "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\zircolite.log"

            # Check if JSONL Files already exist
            if (Test-Path "$OUTPUT_FOLDER\EventLogs\JSONL\*.json")
            {
                # JSONL
                $ScanPath = "$OUTPUT_FOLDER\EventLogs\JSONL"
                & $Zircolite --evtx $ScanPath --ruleset $Ruleset --jsononly --template $Template --templateOutput $TemplateOutput --outfile $OutFile --logfile $LogFile 2>&1 | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\Zircolite-draft.txt"
            }
            else
            {
                # EVTX
                $ScanPath = "$OUTPUT_FOLDER\EventLogs\EventLogs"
                & $Zircolite --evtx $ScanPath --ruleset $Ruleset --noexternal --template $Template --templateOutput $TemplateOutput --outfile $OutFile --logfile $LogFile 2>&1 | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\Zircolite-draft.txt"
            }
            
            Set-Location "$MyLocation"

            # zircolite.log
            if (Test-Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\zircolite.log")
            {
                Remove-Item -Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\zircolite.log" -Force
            }

            # Remove ANSI Control Characters
            if (Test-Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\Zircolite-draft.txt")
            {
                Get-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\Zircolite-draft.txt" | ForEach-Object { $_ -replace "\x1b\[[0-9;]*m" } | Out-File "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\Zircolite.txt"
                Remove-Item "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\Zircolite-draft.txt"
            }

            # Cleaning up
            if (Test-Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\Zircolite.txt")
            {
                $Filter = @("^zircolite_win10\.exe","MemProcFS-Analyzer-v0.*\.ps1","^\+","\+ CategoryInfo          : NotSpecified:","\+ FullyQualifiedErrorId : NativeCommandError","%\|")
                $Clean = Get-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\Zircolite.txt" | Select-String -Pattern $Filter -NotMatch 
                $Clean | Set-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\Zircolite.txt"
            }

            # Remove empty lines and add line breaks where needed
            if (Test-Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\Zircolite.txt")
            {
                $Clean = Get-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\Zircolite.txt" | Where-Object {$_.Trim()} | ForEach-Object {($_ -replace "Finished in", "`nFinished in")} | ForEach-Object {($_ -replace "Sysmon Linux =-", "Sysmon Linux =-`n")}
                @("") + ($Clean) | Set-Content "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\Zircolite.txt"
            }

            # File Size (CSV)
            if (Test-Path "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\Timesketch_MemProcFS-Analyzer.csv")
            {
                $FileSize = Get-FileSize((Get-Item "$OUTPUT_FOLDER\EventLogs\Zircolite\Timesketch\Timesketch_MemProcFS-Analyzer.csv").Length)
                Write-Output "[Info]  File Size (CSV): $FileSize"
            }

            $EndTime_Timesketch = (Get-Date)
            $Time_Timesketch = ($EndTime_Timesketch-$StartTime_Timesketch)
            ('Timesketch Output duration:    {0} h {1} min {2} sec' -f $Time_Timesketch.Hours, $Time_Timesketch.Minutes, $Time_Timesketch.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"
        }
        else
        {
            Write-Host "[Error] zircolite_win10.exe NOT found." -ForegroundColor Red
        }

        }

        #Get-Timesketch

#############################################################################################################################################################################################
        
        Function Get-RegistryHives {

        # Registry Hives
        if (Test-Path "$DriveLetter\registry\hive_files\*.reghive") 
        {
            Write-Output "[Info]  Collecting Registry Hives ... "
            New-Item "$OUTPUT_FOLDER\Registry\Registry" -ItemType Directory -Force 2>&1 | Out-Null
            Get-ChildItem "$DriveLetter\registry\hive_files\*.reghive" -Exclude "*ActivationStoredat*","*settingsdat*" | Foreach-Object FullName | Out-File "$OUTPUT_FOLDER\Registry\Hives.txt"
            Copy-Item "$DriveLetter\registry\hive_files\*.reghive" -Exclude "*ActivationStoredat*","*settingsdat*" "$OUTPUT_FOLDER\Registry\Registry" 2>&1 | Out-Null
        }

        # Count Registry Hives
        $Count = (Get-ChildItem -Path "$OUTPUT_FOLDER\Registry\Registry" | Measure-Object).Count
        $InputSize = Get-FileSize((Get-ChildItem -Path "$OUTPUT_FOLDER\Registry\Registry" | Measure-Object Length -Sum).Sum)
        Write-Output "[Info]  $Count Registry Hives ($InputSize) found"

        }

        Get-RegistryHives

#############################################################################################################################################################################################
        
        Function Get-Amcache {

        # AmcacheParser
        if (Test-Path "$OUTPUT_FOLDER\Registry\Registry\*Amcache*.reghive") 
        {
            if (Test-Path "$($AmcacheParser)")
            {
                Write-Output "[Info]  Analyzing Amcache Hive ... "

                # Collecting Amcache.hve
                New-Item "$OUTPUT_FOLDER\Amcache\Amcache" -ItemType Directory -Force 2>&1 | Out-Null
                Copy-Item "$DriveLetter\registry\hive_files\0x*Amcachehve-*.reghive" "$OUTPUT_FOLDER\Amcache\Amcache\Amcache.hve"
                
                # CSV
                New-Item "$OUTPUT_FOLDER\Amcache\CSV" -ItemType Directory -Force | Out-Null
                $AmcacheHive = "$OUTPUT_FOLDER\Amcache\Amcache\Amcache.hve"
                & $AmcacheParser -f "$AmcacheHive" -i --csv "$OUTPUT_FOLDER\Amcache\CSV" --csvf AmcacheParser.csv > "$OUTPUT_FOLDER\Amcache\AmcacheParser.log" 2> $null

                # Stats
                if (Test-Path "$OUTPUT_FOLDER\Amcache\AmcacheParser.log")
                {
                    $Total = Get-Content "$OUTPUT_FOLDER\Amcache\AmcacheParser.log" | Select-String -Pattern "unassociated file entries"
                    if ($Total) 
                    { 
                        Write-Output "[Info]  $Total"
                    }
                    else
                    {
                        Write-Output "[Info]  Amcache Hive seems to be partially corrupt."
                    }
                }

                # XLSX
                # Note: The output of Windows 10 and Win 7 looks different --> optimized for Windows 10 only
                if (Get-Module -ListAvailable -Name ImportExcel)
                {
                    # AssociatedFileEntries
                    if (Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_AssociatedFileEntries.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_AssociatedFileEntries.csv") -gt 0)
                        {
                            New-Item "$OUTPUT_FOLDER\Amcache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_AssociatedFileEntries.csv" -Delimiter "," | Sort-Object { $_.FileKeyLastWriteTimestamp -as [datetime] } -Descending
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\XLSX\AmcacheParser_AssociatedFileEntries.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AssociatedFileEntries" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:U1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A-E and G-U
                            $WorkSheet.Cells["A:E"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["G:U"].Style.HorizontalAlignment="Center"
                            # HorizontalAlignment "Center" of header of column F
                            $WorkSheet.Cells["F1:F1"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # DeviceContainers
                    if (Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DeviceContainers.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DeviceContainers.csv") -gt 0)
                        {
                            New-Item "$OUTPUT_FOLDER\Amcache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DeviceContainers.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\XLSX\AmcacheParser_DeviceContainers.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DeviceContainers" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:Q1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B-Q
                            $WorkSheet.Cells["B:Q"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # DevicePnps
                    if (Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DevicePnps.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DevicePnps.csv") -gt 0)
                        {
                            New-Item "$OUTPUT_FOLDER\Amcache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DevicePnps.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\XLSX\AmcacheParser_DevicePnps.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DevicePnps" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:Y1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B-E and G-Y
                            $WorkSheet.Cells["B:E"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["G:Y"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # DriveBinaries
                    if (Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DriveBinaries.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DriveBinaries.csv") -gt 0)
                        {
                            New-Item "$OUTPUT_FOLDER\Amcache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DriveBinaries.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\XLSX\AmcacheParser_DriveBinaries.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DriveBinaries" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:T1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B-T
                            $WorkSheet.Cells["B:T"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # DriverPackages
                    if (Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DriverPackages.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DriverPackages.csv") -gt 0)
                        {
                            New-Item "$OUTPUT_FOLDER\Amcache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DriverPackages.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\XLSX\AmcacheParser_DriverPackages.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DriverPackages" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B-D and -L
                            $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["F:L"].Style.HorizontalAlignment="Center"
                            # HorizontalAlignment "Center" of header of column E
                            $WorkSheet.Cells["E1:E1"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # ProgramEntries
                    if (Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_ProgramEntries.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_ProgramEntries.csv") -gt 0)
                        {
                            New-Item "$OUTPUT_FOLDER\Amcache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_ProgramEntries.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\XLSX\AmcacheParser_ProgramEntries.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ProgramEntries" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:Z1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A-J, L-N, P-S, V-X and Z
                            $WorkSheet.Cells["A:J"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["L:N"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["P:S"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["V:X"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["Z:Z"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # ShortCuts
                    if (Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_ShortCuts.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_ShortCuts.csv") -gt 0)
                        {
                            New-Item "$OUTPUT_FOLDER\Amcache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_ShortCuts.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\XLSX\AmcacheParser_ShortCuts.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ShortCuts" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A and C
                            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # UnassociatedFileEntries
                    if (Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_UnassociatedFileEntries.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_UnassociatedFileEntries.csv") -gt 0)
                        {
                            New-Item "$OUTPUT_FOLDER\Amcache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_UnassociatedFileEntries.csv" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.FileKeyLastWriteTimestamp -as [datetime] } -Descending
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\XLSX\AmcacheParser_UnassociatedFileEntries.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UnassociatedFileEntries" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:U1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A-E and G-T
                            $WorkSheet.Cells["A:E"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["G:T"].Style.HorizontalAlignment="Center"
                            # HorizontalAlignment "Center" of header of column F
                            $WorkSheet.Cells["F1:F1"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
                else
                {
                    Write-Output "[Info]  PowerShell module 'ImportExcel' NOT found."
                }

                # Amcache Scan --> Check SHA1 File Hashes on VirusTotal
                if ((Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_UnassociatedFileEntries.csv") -And ([int](& $xsv count "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_UnassociatedFileEntries.csv") -gt 0))
                {
                    New-Item "$OUTPUT_FOLDER\Amcache\SHA1" -ItemType Directory -Force | Out-Null
                    Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_UnassociatedFileEntries.csv" -Delimiter "," | Select-Object -Property Name, ProductName, ApplicationName, FullPath, SHA1 | Sort-Object -Property SHA1 -Unique | Export-Csv "$OUTPUT_FOLDER\Amcache\SHA1\SHA1-draft.csv" -Delimiter "," -NoTypeInformation
                    Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_AssociatedFileEntries.csv" -Delimiter "," | Select-Object -Property Name, ProductName, ApplicationName, FullPath, SHA1 | Sort-Object -Property SHA1 -Unique | Export-Csv "$OUTPUT_FOLDER\Amcache\SHA1\SHA1-draft.csv" -Delimiter "," -NoTypeInformation -Append
                    Import-Csv "$OUTPUT_FOLDER\Amcache\SHA1\SHA1-draft.csv" -Delimiter "," | Where-Object {$_.SHA1 -ne ""} | Sort-Object -Property SHA1 -Unique | Export-Csv "$OUTPUT_FOLDER\Amcache\SHA1\SHA1.csv" -Delimiter "," -NoTypeInformation
                    (Import-Csv "$OUTPUT_FOLDER\Amcache\SHA1\SHA1-draft.csv" -Delimiter "," | Where-Object {$_.SHA1 -ne ""} | Sort-Object -Property SHA1 -Unique).SHA1 | Out-File "$OUTPUT_FOLDER\Amcache\SHA1\SHA1.txt" -Encoding ascii
                    Remove-Item "$OUTPUT_FOLDER\Amcache\SHA1\SHA1-draft.csv"

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\Amcache\SHA1\SHA1.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\Amcache\SHA1\SHA1.csv") -gt 0)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\SHA1\SHA1.csv" -Delimiter ","
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\SHA1\SHA1.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SHA1" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of column E
                                $WorkSheet.Cells["E:E"].Style.HorizontalAlignment="Center"
                                }
                            }
                        }
                    }
                
                    # Count SHA1 File Hashes
                    $Count = [string]::Format('{0:N0}',(Get-Content "$OUTPUT_FOLDER\Amcache\SHA1\SHA1.txt" | Measure-Object).Count)
                    Write-Output "[Info]  $Count SHA1 hash value(s) of executables found"
                }
            }
        }

        }

        Get-Amcache

#############################################################################################################################################################################################
        
        Function Get-ShimCache {

        # AppCompatCacheParser (ShimCache)
        if (Test-Path "$OUTPUT_FOLDER\Registry\Registry\*SYSTEM*.reghive") 
        {
            if (Test-Path "$($AppCompatCacheParser)")
            {
                Write-Output "[Info]  Analyzing Application Compatibility Cache aka ShimCache ... "

                # CSV
                New-Item "$OUTPUT_FOLDER\Registry\ShimCache\CSV" -ItemType Directory -Force | Out-Null
                $SYSTEM = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Foreach-Object FullName | Select-String -Pattern "SYSTEM" -CaseSensitive | Out-String).Trim()
                & $AppCompatCacheParser -f "$SYSTEM" --csv "$OUTPUT_FOLDER\Registry\ShimCache\CSV" --csvf AppCompatCacheParser.csv -t > "$OUTPUT_FOLDER\Registry\ShimCache\AppCompatCacheParser.log" 2> $null

                # Stats
                if (Test-Path "$OUTPUT_FOLDER\Registry\ShimCache\AppCompatCacheParser.log")
                {
                    $Total = Get-Content "$OUTPUT_FOLDER\Registry\ShimCache\AppCompatCacheParser.log" | Select-String -Pattern "cache entries"
                    if ($Total)
                    {
                        Write-Output "[Info]  $Total"
                    }
                    else
                    {
                        Write-Output "[Info]  SYSTEM Hive seems to be partially corrupt."
                    }
                }

                # XLSX
                if (Get-Module -ListAvailable -Name ImportExcel)
                {
                    if (Test-Path "$OUTPUT_FOLDER\Registry\ShimCache\CSV\AppCompatCacheParser.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\Registry\ShimCache\CSV\AppCompatCacheParser.csv") -gt 0)
                        {
                            New-Item "$OUTPUT_FOLDER\Registry\ShimCache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\ShimCache\CSV\AppCompatCacheParser.csv" -Delimiter "," | Sort-Object { $_.LastModifiedTimeUTC -as [datetime] } -Descending
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\ShimCache\XLSX\AppCompatCacheParser.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ShimCache" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A-B and D-F
                            $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["D:F"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
            }
            else
            {
                Write-Host "[Error] AppCompatCacheParser.exe NOT found." -ForegroundColor Red
            }
        }

        }

        Get-ShimCache

#############################################################################################################################################################################################

        # Syscache

        Function Get-Syscache {

        # Check if Syscache hive exists
        if (Test-Path "$OUTPUT_FOLDER\Registry\Registry\*Syscachehve*.reghive") 
        {
            # Check if RECmd.exe exists
            if (Test-Path "$($RECmd)")
            {
                Write-Output "[Info]  Analyzing Syscache Hive ... "

                # CSV
                New-Item "$OUTPUT_FOLDER\Syscache\CSV" -ItemType Directory -Force | Out-Null
                $Syscachehve = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "Syscachehve")} | Foreach-Object FullName)
                & $RECmd -f "$Syscachehve" --bn "$SCRIPT_DIR\Tools\RECmd_BatchFiles\SysCache.reb" --csv "$OUTPUT_FOLDER\Syscache\CSV" --csvf "Syscache.csv" > "$OUTPUT_FOLDER\Syscache\Syscache.log" 2> $null

                # Stats
                if (Test-Path "$OUTPUT_FOLDER\Syscache\Syscache.log")
                {
                    $Total = Get-Content "$OUTPUT_FOLDER\Syscache\Syscache.log" | Select-String -Pattern "key/value pairs"
                    Write-Output "[Info]  $Total"
                }

                # SHA1 --> Check SHA1 hashes on VirusTotal
                if ((Test-Path "$OUTPUT_FOLDER\Syscache\CSV\Syscache.csv") -And ([int](& $xsv count "$OUTPUT_FOLDER\Syscache\CSV\Syscache.csv") -gt 0))
                {
                    (Import-Csv "$OUTPUT_FOLDER\Syscache\CSV\Syscache.csv" | Select-Object -Property "ValueData2" | Sort-Object -Property "ValueData2" -Unique).ValueData2 | ForEach-Object{($_ -split "SHA-1: ")[1]} | Select-Object -Skip 1 | Out-File "$OUTPUT_FOLDER\Syscache\SHA1.txt" -Encoding ascii

                    # Count SHA1 hashes
                    $Count = [string]::Format('{0:N0}',(Get-Content "$OUTPUT_FOLDER\Syscache\SHA1.txt" | Measure-Object).Count)
                    Write-Output "[Info]  $Count SHA1 hash value(s) of executables found"
                }

                # XLSX

                # Syscache.csv
                if (Test-Path "$OUTPUT_FOLDER\Syscache\CSV\Syscache.csv")
                {
                    if([int](& $xsv count "$OUTPUT_FOLDER\Syscache\CSV\Syscache.csv") -gt 0)
                    {
                        New-Item "$OUTPUT_FOLDER\Syscache\XLSX" -ItemType Directory -Force | Out-Null
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Syscache\CSV\Syscache.csv" -Delimiter "," | Sort-Object { $_.LastWriteTimestamp -as [datetime] } -Descending
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Syscache\XLSX\Syscache.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SysCache" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns B-N
                        $WorkSheet.Cells["B:N"].Style.HorizontalAlignment="Center"
                        }
                    }
                }

                # Syscache_SyscacheObjectTable.csv
                if (Test-Path "$OUTPUT_FOLDER\Syscache\CSV\*\Syscache_SyscacheObjectTable.csv")
                {
                    $FilePath = Get-ChildItem -Path "$OUTPUT_FOLDER\Syscache\CSV\*\Syscache_SyscacheObjectTable.csv" | ForEach-Object FullName
                    if([int](& $xsv count "$FilePath") -gt 0)
                    {
                        New-Item "$OUTPUT_FOLDER\Syscache\XLSX" -ItemType Directory -Force | Out-Null
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Syscache\CSV\*\Syscache_SyscacheObjectTable.csv" -Delimiter "," | Sort-Object { $_.LastWriteTime -as [datetime] } -Descending
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Syscache\XLSX\Syscache_SyscacheObjectTable.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SysCache (Plugin)" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns B-L
                        $WorkSheet.Cells["B:L"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["D:L"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }
            else
            {
                Write-Host "[Error] RECmd.exe NOT found." -ForegroundColor Red
            }
        }
        else
        {
            Write-Host "[Info]  Syscache.hve not found."
        }

        }

        Get-Syscache

#############################################################################################################################################################################################

        # UserAssist

        Function Get-UserAssist {

        # Check if RECmd.exe exists
        if (Test-Path "$($RECmd)")
        {
            # Check if batch processing file exists
            if (Test-Path "$SCRIPT_DIR\Tools\RECmd_BatchFiles\UserAssist.reb")
            {
                # Check if Registry Plugin exists
                if (Test-Path "$SCRIPT_DIR\Tools\RECmd\Plugins\RegistryPlugin.UserAssist.dll")
                {
                    # Analyzing UserAssist Artifacts
                    Write-Output "[Info]  Analyzing UserAssist Artifacts ..."
                    New-Item "$OUTPUT_FOLDER\Registry\UserAssist\CSV" -ItemType Directory -Force | Out-Null
                    New-Item "$OUTPUT_FOLDER\Registry\UserAssist\XLSX" -ItemType Directory -Force | Out-Null

                    $FilePathList = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuserdat")} | Foreach-Object FullName)

                    ForEach( $FilePath in $FilePathList )
                    {
                        $FileName = $FilePath | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "\.")[0]}
                        $SID = $FileName | ForEach-Object{($_ -split "_")[1]}

                        # Check if UserAssist key exists
                        if (Test-Path "$DriveLetter\registry\by-hive\$FileName\ROOT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
                        {
                            # CSV
                            & $RECmd -f "$FilePath" --bn "$SCRIPT_DIR\Tools\RECmd_BatchFiles\UserAssist.reb" --csv "$OUTPUT_FOLDER\Registry\UserAssist\CSV" --csvf "$SID-UserAssist.csv" > "$OUTPUT_FOLDER\Registry\UserAssist\$SID-UserAssist.log" 2> $null

                            if (Test-Path "$OUTPUT_FOLDER\Registry\UserAssist\CSV\*\$SID-UserAssist_UserAssist.csv")
                            {
                                Move-Item -Path "$OUTPUT_FOLDER\Registry\UserAssist\CSV\*\$SID-UserAssist_UserAssist.csv" -Destination "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist_PluginDetailFile.csv"
                                Get-ChildItem -Path "$OUTPUT_FOLDER\Registry\UserAssist\CSV\*" -Directory | ForEach-Object FullName | Remove-Item -Force -Recurse
                            }

                            # Stats
                            if (Test-Path "$OUTPUT_FOLDER\Registry\UserAssist\$SID-UserAssist.log")
                            {
                                # Check for parsing error
                                if (!(Get-Content -Path "$OUTPUT_FOLDER\Registry\UserAssist\$SID-UserAssist.log" | Select-String -Pattern "parse error" -Quiet))
                                {
                                    # Check if key/value pairs were found
                                    if (!(Get-Content -Path "$OUTPUT_FOLDER\Registry\UserAssist\$SID-UserAssist.log" | Select-String -Pattern "Found 0 key/value pairs across 1 file" -Quiet))
                                    {
                                        # Count
                                        $Total = Get-Content "$OUTPUT_FOLDER\Registry\UserAssist\$SID-UserAssist.log" | Select-String -Pattern "key/value pairs"
                                        Write-Output "[Info]  $Total ($SID)"

                                        # Array
                                        $Array = @()

                                        # Total Entries
                                        $TotalEntries = (Import-Csv "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist.csv" -Delimiter "," | Measure-Object).Count
                                        $Array += @{"UserAssist Entries Description" = "Total Entries"; Count = "$TotalEntries"}

                                        # Toral Entries w/ Run Count
                                        $TotalRunCount = (Import-Csv "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist.csv" -Delimiter "," | Where-Object { $_.ValueData3 -match "Run count:" } | Measure-Object).Count
                                        $Array += @{"UserAssist Entries Description" = "Total Entries with Run Count"; Count = "$TotalRunCount"}

                                        # Entries with "Run count: 0"
                                        $RunCount0 = (Import-Csv "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist.csv" -Delimiter "," | Where-Object { $_.ValueData3 -match "Run count: 0" } | Measure-Object).Count
                                        $Array += @{"UserAssist Entries Description" = "Entries with Run Count 0"; Count = "$RunCount0"}

                                        # Entries with "Last executed" field populated
                                        $LastExecutedPopulated = (Import-Csv "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist.csv" -Delimiter "," | Where-Object { $_.ValueData2 -match "Last executed: 2" } | Measure-Object).Count
                                        $Array += @{"UserAssist Entries Description" = "Entries with 'Last executed' field populated"; Count = "$LastExecutedPopulated"}

                                        # Entries with "Last executed" field not populated
                                        $LastExecutedEmpty = (Import-Csv "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist.csv" -Delimiter "," | Where-Object { $_.ValueData2 -match "Last executed: $" } | Measure-Object).Count
                                        $Array += @{"UserAssist Entries Description" = "Entries with 'Last executed' field not populated"; Count = "$LastExecutedEmpty"}

                                        # Executable File Execution (GUID)
                                        $ExecutableFileExecution = (Import-Csv "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist.csv" -Delimiter "," | Where-Object { $_.KeyPath -match "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count" } | Measure-Object).Count
                                        $Array += @{"UserAssist Entries Description" = "Executable File Execution"; Count = "$ExecutableFileExecution"}

                                        # Shortcut File Execution (GUID)
                                        $ShortcutFileExecution = (Import-Csv "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist.csv" -Delimiter "," | Where-Object { $_.KeyPath -match "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\\Count" } | Measure-Object).Count
                                        $Array += @{"UserAssist Entries Description" = "Shortcut File Execution"; Count = "$ShortcutFileExecution"}
                                        
                                        # CSV
                                        $Array | ForEach-Object { New-Object PSObject -Property $_ } |  Export-Csv "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist-Stats.csv" -NoTypeInformation
                                    }
                                    else
                                    {
                                        Write-Host "[Info]  Found 0 key/value pairs across 1 file ($SID)"
                                    }
                                }
                            }

                            # XLSX
                            if (Test-Path "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist.csv" -Delimiter "," | Sort-Object { $_.LastWriteTimestamp -as [datetime] } -Descending
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\UserAssist\XLSX\$SID-UserAssist.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAssist" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns B-D, G and J-N
                                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                                    $WorkSheet.Cells["G:G"].Style.HorizontalAlignment="Center"
                                    $WorkSheet.Cells["J:N"].Style.HorizontalAlignment="Center"
                                    }
                                }
                            }

                            # XLSX (PluginDetailFile)
                            if (Test-Path "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist_PluginDetailFile.csv")
                            {
                                if((Get-Item "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist_PluginDetailFile.csv").length -gt 0kb)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist_PluginDetailFile.csv" -Delimiter "," | Sort-Object { $_.LastExecuted -as [datetime] } -Descending
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\UserAssist\XLSX\$SID-UserAssist_PluginDetailFile.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAssist (Plugin)" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns D-G
                                    $WorkSheet.Cells["D:G"].Style.HorizontalAlignment="Center"
                                    }
                                }
                            }

                            # XLSX (Stats)
                            if (Test-Path "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist-Stats.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist-Stats.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\UserAssist\CSV\$SID-UserAssist-Stats.csv" -Delimiter ","
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\UserAssist\XLSX\$SID-UserAssist-Stats.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAssist (Stats)" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of column B
                                    $WorkSheet.Cells["B:B"].Style.HorizontalAlignment="Center"
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    Write-Host "[Error] RegistryPlugin.UserAssist.dll NOT found." -ForegroundColor Red
                }
            }
            else
            {
                Write-Host "[Error] UserAssist.reb NOT found." -ForegroundColor Red
            }
        }
        else
        {
            Write-Host "[Error] RECmd.exe NOT found." -ForegroundColor Red
        }

        }

        Get-UserAssist

#############################################################################################################################################################################################

        # Windows Background Activity Moderator (BAM)
        
        Function Get-BAM {

        # Check if RECmd.exe exists
        if (Test-Path "$($RECmd)")
        {
            # Check if batch processing file exists
            if (Test-Path "$SCRIPT_DIR\Tools\RECmd_BatchFiles\BAM.reb")
            {
                # Check if Background Activity Moderator Driver exists
                if (Test-Path "$DriveLetter\sys\services\services.txt")
                {
                    if (Get-Content "$DriveLetter\sys\services\services.txt" | Select-String -Pattern "Background Activity Moderator Driver" -Quiet)
                    {
                        # Analyzing Windows Background Activity Moderator (BAM) Artifacts
                        Write-Output "[Info]  Analyzing Windows Background Activity Moderator (BAM) Artifacts ... "
                        New-Item "$OUTPUT_FOLDER\Registry\BAM\CSV" -ItemType Directory -Force | Out-Null
                        New-Item "$OUTPUT_FOLDER\Registry\BAM\XLSX" -ItemType Directory -Force | Out-Null

                        # CSV
                        $SYSTEM = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | ForEach-Object Name | Select-String -Pattern "SYSTEM" -CaseSensitive | Out-String).Trim()
                        & $RECmd -f "$OUTPUT_FOLDER\Registry\Registry\$SYSTEM" --bn "$SCRIPT_DIR\Tools\RECmd_BatchFiles\BAM.reb" --csv "$OUTPUT_FOLDER\Registry\BAM\CSV" --csvf "BAM.csv" 2>&1 | Out-File "$OUTPUT_FOLDER\Registry\BAM\BAM.log"

                        if (Test-Path "$OUTPUT_FOLDER\Registry\BAM\CSV\*\BAM_BamDam.csv")
                        {
                            Move-Item -Path "$OUTPUT_FOLDER\Registry\BAM\CSV\*\BAM_BamDam.csv" -Destination "$OUTPUT_FOLDER\Registry\BAM\CSV\BAM_PluginDetailFile.csv"
                            Get-ChildItem -Path "$OUTPUT_FOLDER\Registry\BAM\CSV\*" -Directory | ForEach-Object FullName | Remove-Item -Force -Recurse
                        }

                        # Stats
                        if (Test-Path "$OUTPUT_FOLDER\Registry\BAM\BAM.log")
                        {
                            # Check if key/value pairs were found
                            if (!(Get-Content -Path "$OUTPUT_FOLDER\Registry\BAM\BAM.log" | Select-String -Pattern "Found 0 key/value pairs across 1 file" -Quiet))
                            {
                                # Count
                                $Count = Get-Content "$OUTPUT_FOLDER\Registry\BAM\BAM.log" | Select-String -Pattern "key/value pairs"
                                Write-Output "[Info]  $Count"
                            }
                            else
                            {
                                Write-Output "[Info]  Found 0 key/value pairs across 1 file"
                            }
                        }

                        # XLSX
                        if (Test-Path "$OUTPUT_FOLDER\Registry\BAM\CSV\BAM.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\Registry\BAM\CSV\BAM.csv") -gt 0)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\BAM\CSV\BAM.csv" -Delimiter ","
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\BAM\XLSX\BAM.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "BAM" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns B-D, G and I-N
                                $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["G:G"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["I:N"].Style.HorizontalAlignment="Center"
                                }
                            }
                        }

                        # XLSX (PluginDetailFile)
                        if (Test-Path "$OUTPUT_FOLDER\Registry\BAM\CSV\BAM_PluginDetailFile.csv")
                        {
                            if((Get-Item "$OUTPUT_FOLDER\Registry\BAM\CSV\BAM_PluginDetailFile.csv").length -gt 0kb)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\BAM\CSV\BAM_PluginDetailFile.csv" -Delimiter "," | Sort-Object { $_.ExecutionTime -as [datetime] } -Descending
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\BAM\XLSX\BAM_PluginDetailFile.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "BAM (Plugin)" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of column C
                                $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Center"
                                }
                            }
                        }
                    }
                }
            }
        }

        }

        Get-BAM

#############################################################################################################################################################################################

        # MUICache (Multi-Lingual User Interface)

        Function Get-MUICache {

        # Check if RECmd.exe exists
        if (Test-Path "$($RECmd)")
        {
            # Check if batch processing file exists
            if (Test-Path "$SCRIPT_DIR\Tools\RECmd_BatchFiles\MUICache.reb")
            {
                # Analyzing MUICache Artifacts
                Write-Output "[Info]  Analyzing MUICache Artifacts ... "
                New-Item "$OUTPUT_FOLDER\Registry\MUICache\CSV" -ItemType Directory -Force | Out-Null
                New-Item "$OUTPUT_FOLDER\Registry\MUICache\XLSX" -ItemType Directory -Force | Out-Null

                $FilePathList = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "UsrClassdat")} | Foreach-Object FullName)

                ForEach( $FilePath in $FilePathList )
                {
                    $FileName = $FilePath | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "\.")[0]}
                    $SID = $FileName | ForEach-Object{($_ -split "_")[1]}

                    # Check if MUICache key exists (Vista+)
                    if (Test-Path "$DriveLetter\registry\by-hive\$FileName\ROOT\Local Settings\Software\Microsoft\Windows\Shell\MuiCache")
                    {
                        # CSV
                        & $RECmd -f "$FilePath" --bn "$SCRIPT_DIR\Tools\RECmd_BatchFiles\MUICache.reb" --csv "$OUTPUT_FOLDER\Registry\MUICache\CSV" --csvf "$SID-MUICache.csv" > "$OUTPUT_FOLDER\Registry\MUICache\$SID-MUICache.log" 2> $null

                        # Stats
                        if (Test-Path "$OUTPUT_FOLDER\Registry\MUICache\$SID-MUICache.log")
                        {
                            # Check if key/value pairs were found
                            if (!(Get-Content -Path "$OUTPUT_FOLDER\Registry\MUICache\$SID-MUICache.log" | Select-String -Pattern "Found 0 key/value pairs across 1 file" -Quiet))
                            {
                                # Count
                                $Total = Get-Content "$OUTPUT_FOLDER\Registry\MUICache\$SID-MUICache.log" | Select-String -Pattern "key/value pairs"
                                Write-Output "[Info]  $Total ($SID)"
                            }
                        }

                        # XLSX
                        if (Test-Path "$OUTPUT_FOLDER\Registry\MUICache\CSV\$SID-MUICache.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\Registry\MUICache\CSV\$SID-MUICache.csv") -gt 0)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\MUICache\CSV\$SID-MUICache.csv" -Delimiter ","
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\MUICache\XLSX\$SID-MUICache.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MUICache" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns B-D, G and I-O
                                $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["G:G"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["I:O"].Style.HorizontalAlignment="Center"
                                }
                            }
                        }

                        # Custom CSV
                        if (Test-Path "$OUTPUT_FOLDER\Registry\MUICache\CSV\$SID-MUICache.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\Registry\MUICache\CSV\$SID-MUICache.csv") -gt 0)
                            {
                                $Import = Import-Csv "$OUTPUT_FOLDER\Registry\MUICache\CSV\$SID-MUICache.csv" -Delimiter "," | Where-Object { $_.ValueType -eq "RegSz" }

                                $Counter=0

                                $Import | Foreach-Object {

                                    $Counter++

                                    if ($_.ValueName -like "*ApplicationCompany*")
                                    {
                                        $FileName = $_ | Select-Object -ExpandProperty ValueName | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object { $_ -replace "\.ApplicationCompany$" }
                                        $FilePath = $_ | Select-Object -ExpandProperty ValueName | Split-Path 
                                        $ApplicationCompany = $_ | Select-Object -ExpandProperty ValueData
                                        $HivePath = $_ | Select-Object -ExpandProperty HivePath
                                        $LastWriteTimestamp = $_ | Select-Object -ExpandProperty LastWriteTimestamp
                                    }

                                    if ($_.ValueName -like "*FriendlyAppName*")
                                    {
                                        $FriendlyAppName = $_ | Select-Object -ExpandProperty ValueData
                                    }

                                    if($Counter -eq 2)
                                    {  
                                        New-Object -TypeName PSObject -Property @{

                                            "FileName"          = $FileName
                                            "FilePath"          = $FilePath
                                            "ApplicationCompany" = $ApplicationCompany # Company Name
                                            "FriendlyAppName"    = $FriendlyAppName # File Description
                                            "HivePath"          = $HivePath
                                            "LastWriteTimestamp" = $LastWriteTimestamp
                                            "SID"                = $SID
                                            "UserName"           = Get-Content "$OUTPUT_FOLDER\sys\users\users.txt" | Select-String -Pattern "$SID" | ForEach-Object{($_ -split "\s+")[1]}
                                            }

                                        $Counter=0
                                    }

                                } | Select-Object "FileName","FilePath","ApplicationCompany","FriendlyAppName","UserName","SID","HivePath","LastWriteTimestamp" | Export-Csv -Path "$OUTPUT_FOLDER\Registry\MUICache\CSV\$SID-MUICache_Custom.csv" -Delimiter "," -NoTypeInformation -Encoding UTF8   
                            }
                        }

                        # Stats
                        if (Test-Path "$OUTPUT_FOLDER\Registry\MUICache\CSV\$SID-MUICache_Custom.csv")
                        {
                            # Count
                            $Unique = (Import-Csv -Path "$OUTPUT_FOLDER\Registry\MUICache\CSV\$SID-MUICache_Custom.csv" | Select-Object "File Name" | Sort-Object { [string]$_."File Name" } -Unique | Measure-Object).Count
                            $Total = & $xsv count "$OUTPUT_FOLDER\Registry\MUICache\CSV\$SID-MUICache_Custom.csv"
                            Write-Output "[Info]  $Unique GUI-based executable(s) found ($Total)"
                        }

                        # XLSX
                        if (Test-Path "$OUTPUT_FOLDER\Registry\MUICache\CSV\$SID-MUICache_Custom.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\Registry\MUICache\CSV\$SID-MUICache_Custom.csv") -gt 0)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\MUICache\CSV\$SID-MUICache_Custom.csv" -Delimiter "," -Encoding UTF8
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\MUICache\XLSX\$SID-MUICache_Custom.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MUICache" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns C, E-F and H
                                $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["E:F"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["H:H"].Style.HorizontalAlignment="Center"
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                Write-Host "[Error] MUICache.reb NOT found." -ForegroundColor Red
            }
        }
        else
        {
            Write-Host "[Error] RECmd.exe NOT found." -ForegroundColor Red
        }

        }

        Get-MUICache

#############################################################################################################################################################################################

        # MRU Opened-Saved Files (OpenSavePidlMRU)

        # Files that are accessed by a Windows (Vista+) application using the common Open File or Save File dialog found at:
        # NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU

        Function Get-OpenSaveMRU {
        
        # Check if RECmd.exe exists
        if (Test-Path "$($RECmd)")
        {
            # Check if batch processing file exists
            if (Test-Path "$SCRIPT_DIR\Tools\RECmd_BatchFiles\OpenSavePidlMRU.reb")
            {
                # Analyzing OpenSaveMRU Artifacts (OpenSavePidlMRU)
                Write-Output "[Info]  Analyzing OpenSaveMRU Artifacts ... "
                New-Item "$OUTPUT_FOLDER\Registry\OpenSaveMRU\CSV" -ItemType Directory -Force | Out-Null
                New-Item "$OUTPUT_FOLDER\Registry\OpenSaveMRU\XLSX" -ItemType Directory -Force | Out-Null

                $FilePathList = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuserdat")} | Foreach-Object FullName)

                ForEach( $FilePath in $FilePathList )
                {
                    $FileName = $FilePath | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "\.")[0]}
                    $SID = $FileName | ForEach-Object{($_ -split "_")[1]}

                    # Check if OpenSavePidlMRU key exists
                    if (Test-Path "$DriveLetter\registry\by-hive\$FileName\ROOT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU")
                    {
                        # CSV
                        & $RECmd -f "$FilePath" --bn "$SCRIPT_DIR\Tools\RECmd_BatchFiles\OpenSavePidlMRU.reb" --csv "$OUTPUT_FOLDER\Registry\OpenSaveMRU\CSV" --csvf "$SID-OpenSavePidlMRU.csv" > "$OUTPUT_FOLDER\Registry\OpenSaveMRU\$SID-OpenSavePidlMRU.log" 2> $null

                        # RegistryPlugin.OpenSavePidlMRU.dll
                        if (Test-Path "$OUTPUT_FOLDER\Registry\OpenSaveMRU\CSV\*\$SID-OpenSavePidlMRU_OpenSavePidlMRU.csv")
                        {
                            Move-Item -Path "$OUTPUT_FOLDER\Registry\OpenSaveMRU\CSV\*\$SID-OpenSavePidlMRU_OpenSavePidlMRU.csv" -Destination "$OUTPUT_FOLDER\Registry\OpenSaveMRU\CSV\$SID-OpenSavePidlMRU_PluginDetailFile.csv"
                            Get-ChildItem -Path "$OUTPUT_FOLDER\Registry\OpenSaveMRU\CSV\*" -Directory | ForEach-Object FullName | Remove-Item -Force -Recurse
                        }

                        # Stats
                        if (Test-Path "$OUTPUT_FOLDER\Registry\OpenSaveMRU\$SID-OpenSavePidlMRU.log")
                        {
                            # Check if key/value pairs were found
                            if (!(Get-Content -Path "$OUTPUT_FOLDER\Registry\OpenSaveMRU\$SID-OpenSavePidlMRU.log" | Select-String -Pattern "Found 0 key/value pairs across 1 file" -Quiet))
                            {
                                # Count
                                $Total = Get-Content "$OUTPUT_FOLDER\Registry\OpenSaveMRU\$SID-OpenSavePidlMRU.log" | Select-String -Pattern "key/value pairs"
                                Write-Output "[Info]  $Total ($SID)"
                            }
                        }

                        # XLSX

                        # OpenSavePidlMRU.csv
                        if (Test-Path "$OUTPUT_FOLDER\Registry\OpenSaveMRU\CSV\$SID-OpenSavePidlMRU.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\Registry\OpenSaveMRU\CSV\$SID-OpenSavePidlMRU.csv") -gt 0)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\OpenSaveMRU\CSV\$SID-OpenSavePidlMRU.csv" -Delimiter "," -Encoding UTF8
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\OpenSaveMRU\XLSX\$SID-OpenSavePidlMRU.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "OpenSavePidlMRU" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns B-F, I and K-N
                                $WorkSheet.Cells["B:F"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["I:I"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["K:N"].Style.HorizontalAlignment="Center"
                                }
                            }
                        }

                        # OpenSavePidlMRU_PluginDetailFile.csv
                        if (Test-Path "$OUTPUT_FOLDER\Registry\OpenSaveMRU\CSV\$SID-OpenSavePidlMRU_PluginDetailFile.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\Registry\OpenSaveMRU\CSV\$SID-OpenSavePidlMRU_PluginDetailFile.csv") -gt 0)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\OpenSaveMRU\CSV\$SID-OpenSavePidlMRU_PluginDetailFile.csv" -Delimiter "," -Encoding UTF8
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\OpenSaveMRU\XLSX\$SID-OpenSavePidlMRU_PluginDetailFile.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "OpenSavePidlMRU (Plugin)" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, C-E and G
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["C:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["G:G"].Style.HorizontalAlignment="Center"
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                Write-Host "[Error] OpenSavePidlMRU.reb NOT found." -ForegroundColor Red
            }
        }
        else
        {
            Write-Host "[Error] RECmd.exe NOT found." -ForegroundColor Red
        }
        
        }

        Get-OpenSaveMRU

        # LastVisitedPidlMRU

        # Tracks the specific executable used by an application to open the files documented in OpenSavePidlMRU found at:
        # NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU

        Function Get-LastVisitedMRU {
        
        # Check if RECmd.exe exists
        if (Test-Path "$($RECmd)")
        {
            # Check if batch processing file exists
            if (Test-Path "$SCRIPT_DIR\Tools\RECmd_BatchFiles\LastVisitedPidlMRU.reb")
            {
                # Analyzing LastVisitedMRU Artifacts (LastVisitedPidlMRU)
                Write-Output "[Info]  Analyzing LastVisitedMRU Artifacts ... "
                New-Item "$OUTPUT_FOLDER\Registry\LastVisitedMRU\CSV" -ItemType Directory -Force | Out-Null
                New-Item "$OUTPUT_FOLDER\Registry\LastVisitedMRU\XLSX" -ItemType Directory -Force | Out-Null

                $FilePathList = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuserdat")} | Foreach-Object FullName)

                ForEach( $FilePath in $FilePathList )
                {
                    $FileName = $FilePath | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "\.")[0]}
                    $SID = $FileName | ForEach-Object{($_ -split "_")[1]}

                    # Check if LastVisitedPidlMRU key exists
                    if (Test-Path "$DriveLetter\registry\by-hive\$FileName\ROOT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU")
                    {
                        # CSV
                        & $RECmd -f "$FilePath" --bn "$SCRIPT_DIR\Tools\RECmd_BatchFiles\LastVisitedPidlMRU.reb" --csv "$OUTPUT_FOLDER\Registry\LastVisitedMRU\CSV" --csvf "$SID-LastVisitedPidlMRU.csv" > "$OUTPUT_FOLDER\Registry\LastVisitedMRU\$SID-LastVisitedPidlMRU.log" 2> $null
                        
                        # RegistryPlugin.LastVisitedPidlMRU.dll
                        if (Test-Path "$OUTPUT_FOLDER\Registry\LastVisitedMRU\CSV\*\$SID-LastVisitedPidlMRU_LastVisitedPidlMRU.csv")
                        {
                            Move-Item -Path "$OUTPUT_FOLDER\Registry\LastVisitedMRU\CSV\*\$SID-LastVisitedPidlMRU_LastVisitedPidlMRU.csv" -Destination "$OUTPUT_FOLDER\Registry\LastVisitedMRU\CSV\$SID-LastVisitedPidlMRU_PluginDetailFile.csv"
                            Get-ChildItem -Path "$OUTPUT_FOLDER\Registry\LastVisitedMRU\CSV\*" -Directory | ForEach-Object FullName | Remove-Item -Force -Recurse
                        }

                        # Stats
                        if (Test-Path "$OUTPUT_FOLDER\Registry\LastVisitedMRU\$SID-LastVisitedPidlMRU.log")
                        {
                            # Check if key/value pairs were found
                            if (!(Get-Content -Path "$OUTPUT_FOLDER\Registry\LastVisitedMRU\$SID-LastVisitedPidlMRU.log" | Select-String -Pattern "Found 0 key/value pairs across 1 file" -Quiet))
                            {
                                # Count
                                $Total = Get-Content "$OUTPUT_FOLDER\Registry\LastVisitedMRU\$SID-LastVisitedPidlMRU.log" | Select-String -Pattern "key/value pairs"
                                Write-Output "[Info]  $Total ($SID)"
                            }
                        }

                        # XLSX

                        # LastVisitedPidlMRU.csv
                        if (Test-Path "$OUTPUT_FOLDER\Registry\LastVisitedMRU\CSV\$SID-LastVisitedPidlMRU.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\Registry\LastVisitedMRU\CSV\$SID-LastVisitedPidlMRU.csv") -gt 0)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\LastVisitedMRU\CSV\$SID-LastVisitedPidlMRU.csv" -Delimiter "," -Encoding UTF8
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\LastVisitedMRU\XLSX\$SID-LastVisitedPidlMRU.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "LastVisitedPidlMRU" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns B-G, I and K-N
                                $WorkSheet.Cells["B:G"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["I:I"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["K:N"].Style.HorizontalAlignment="Center"
                                }
                            }
                        }

                        # LastVisitedPidlMRU_PluginDetailFile.csv
                        if (Test-Path "$OUTPUT_FOLDER\Registry\LastVisitedMRU\CSV\$SID-LastVisitedPidlMRU_PluginDetailFile.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\Registry\LastVisitedMRU\CSV\$SID-LastVisitedPidlMRU_PluginDetailFile.csv") -gt 0)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\LastVisitedMRU\CSV\$SID-LastVisitedPidlMRU_PluginDetailFile.csv" -Delimiter "," -Encoding UTF8
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\LastVisitedMRU\XLSX\$SID-LastVisitedPidlMRU_PluginDetailFile.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "LastVisitedPidlMRU (Plugin)" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, C-E and G
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["C:E"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["G:G"].Style.HorizontalAlignment="Center"
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                Write-Host "[Error] LastVisitedPidlMRU.reb NOT found." -ForegroundColor Red
            }
        }
        else
        {
            Write-Host "[Error] RECmd.exe NOT found." -ForegroundColor Red
        }

        }

        Get-LastVisitedMRU

#############################################################################################################################################################################################
        
        Function Get-TerminalServerClient {
        
        # Check if RECmd.exe exists
        if (Test-Path "$($RECmd)")
        {
            # Check if batch processing file exists
            if (Test-Path "$SCRIPT_DIR\Tools\RECmd_BatchFiles\TerminalServerClient.reb")
            {
                # Analyzing Terminal Server Client (RDP)
                $FilePathList = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuserdat")} | Foreach-Object FullName)

                ForEach( $FilePath in $FilePathList )
                {
                    $FileName = $FilePath | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "\.")[0]}
                    $SID = $FileName | ForEach-Object{($_ -split "_")[1]}

                    # Check if LastVisitedPidlMRU key exists
                    if (Test-Path "$DriveLetter\registry\by-hive\$FileName\ROOT\SOFTWARE\Microsoft\Terminal Server Client")
                    {
                        # CSV
                        New-Item "$OUTPUT_FOLDER\Registry\TerminalServerClient\CSV" -ItemType Directory -Force | Out-Null
                        New-Item "$OUTPUT_FOLDER\Registry\TerminalServerClient\XLSX" -ItemType Directory -Force | Out-Null
                        & $RECmd -f "$FilePath" --bn "$SCRIPT_DIR\Tools\RECmd_BatchFiles\TerminalServerClient.reb" --csv "$OUTPUT_FOLDER\Registry\TerminalServerClient\CSV" --csvf "$SID-TerminalServerClient.csv" > "$OUTPUT_FOLDER\Registry\TerminalServerClient\$SID-TerminalServerClient.log" 2> $null
                        
                        # RegistryPlugin.TerminalServerClient.dll
                        if (Test-Path "$OUTPUT_FOLDER\Registry\TerminalServerClient\CSV\*\$SID-TerminalServerClient_TerminalServerClient.csv")
                        {
                            Move-Item -Path "$OUTPUT_FOLDER\Registry\TerminalServerClient\CSV\*\$SID-TerminalServerClient_TerminalServerClient.csv" -Destination "$OUTPUT_FOLDER\Registry\TerminalServerClient\CSV\$SID-TerminalServerClient_TerminalServerClient.csv"
                            Get-ChildItem -Path "$OUTPUT_FOLDER\Registry\TerminalServerClient\CSV\*" -Directory | ForEach-Object FullName | Remove-Item -Force -Recurse
                        }

                        # Stats
                        if (Test-Path "$OUTPUT_FOLDER\Registry\TerminalServerClient\$SID-TerminalServerClient.log")
                        {
                            # Check if key/value pairs were found
                            if (!(Get-Content -Path "$OUTPUT_FOLDER\Registry\TerminalServerClient\$SID-TerminalServerClient.log" | Select-String -Pattern "Found 0 key/value pairs across 1 file" -Quiet))
                            {
                                # Count
                                $Total = Get-Content "$OUTPUT_FOLDER\Registry\TerminalServerClient\$SID-TerminalServerClient.log" | Select-String -Pattern "key/value pair"
                                Write-Output "[Info]  $Total ($SID)"
                            }
                        }

                        # XLSX

                        # TerminalServerClient.csv
                        if (Test-Path "$OUTPUT_FOLDER\Registry\TerminalServerClient\CSV\$SID-TerminalServerClient.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\Registry\TerminalServerClient\CSV\$SID-TerminalServerClient.csv") -gt 0)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\TerminalServerClient\CSV\$SID-TerminalServerClient.csv" -Delimiter "," -Encoding UTF8
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\TerminalServerClient\XLSX\$SID-TerminalServerClient.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "TerminalServerClient" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns B-D, F-J and L-N
                                $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["L:N"].Style.HorizontalAlignment="Center"
                                }
                            }
                        }

                        # TerminalServerClient_PluginDetailFile.csv
                        if (Test-Path "$OUTPUT_FOLDER\Registry\LastVisitedMRU\CSV\$SID-TerminalServerClient_PluginDetailFile.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\Registry\LastVisitedMRU\CSV\$SID-TerminalServerClient_PluginDetailFile.csv") -gt 0)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\LastVisitedMRU\CSV\$SID-TerminalServerClient_PluginDetailFile.csv" -Delimiter "," -Encoding UTF8
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\LastVisitedMRU\XLSX\$SID-TerminalServerClient_PluginDetailFile.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "TerminalServerClient (Plugin)" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A, C-F
                                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                Write-Host "[Error] TerminalServerClient.reb NOT found." -ForegroundColor Red
            }
        }
        else
        {
            Write-Host "[Error] RECmd.exe NOT found." -ForegroundColor Red
        }

        }

        Get-TerminalServerClient

        # RegistryPlugin.TerminalServerClient.dll

        # Displays the IP addresses/hostnames of devices this system has connected to (Outbound RDP)
        # Default subkey stores previous RDP connection entries the user has connected to.
        # UsernameHint value stores the username used on remote machine during RDP session.

#############################################################################################################################################################################################

        # SBECCmd

        Function Get-ShellBags {

        # Check ShellBags Location
        if ((Test-Path "$OUTPUT_FOLDER\Registry\Registry\*ntuserdat*") -or (Test-Path "$OUTPUT_FOLDER\Registry\Registry\*UsrClassdat*"))
        {
            if (Test-Path "$($SBECmd)")
            {
                Write-Output "[Info]  Analyzing ShellBags Artifacts ... "
                New-Item "$OUTPUT_FOLDER\Registry\ShellBags\CSV" -ItemType Directory -Force | Out-Null
                New-Item "$OUTPUT_FOLDER\Registry\ShellBags\XLSX" -ItemType Directory -Force | Out-Null

                # ShellBags are stored in both NTUSER.DAT and USRCLASS.DAT
                $FilePathList = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuserdat|UsrClassdat")} | Foreach-Object FullName)

                # Rename Registry Hives temporarily...SBECCmd requires .dat file extension
                Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuserdat|UsrClassdat")} | Rename-Item -NewName {$_.Name -replace "\.reghive$",".dat"}

                # CSV
                & $SBECmd -d "$OUTPUT_FOLDER\Registry\Registry" --csv "$OUTPUT_FOLDER\Registry\ShellBags\CSV" --csvf "SBECmd.csv" > "$OUTPUT_FOLDER\Registry\ShellBags\SBECmd.log" 2> $null
                
                # Rename Registry Hives
                Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuserdat|UsrClassdat")} | Rename-Item -NewName {$_.Name -replace "\.dat$",".reghive"}

                # Stats
                if (Get-Content "$OUTPUT_FOLDER\Registry\ShellBags\SBECmd.log" | Select-String -Pattern "^Total ShellBags found:" -Quiet)
                {
                    # Error
                    if (Get-Content "$OUTPUT_FOLDER\Registry\ShellBags\SBECmd.log" | Select-String -Pattern "Error processing hbin" -Quiet)
                    {
                        Write-Output "[Info]  ShellBags Artifacts seem to be partially corrupt."
                    }

                    # Total
                    $Total = (Get-Content "$OUTPUT_FOLDER\Registry\ShellBags\SBECmd.log" | Select-String -Pattern "Total ShellBags found:" | Select-Object -Last 1 | Out-String).Trim()
                    Write-Output "[Info]  $Total"
                }

                # XLSX
                $FilePathList = (Get-ChildItem "$OUTPUT_FOLDER\Registry\ShellBags\CSV" | Where-Object {($_.Extension -eq ".csv")} | Foreach-Object FullName)

                ForEach( $FilePath in $FilePathList )
                {
                    $FileName = $FilePath | ForEach-Object{($_ -split "-USER_")[1]} | ForEach-Object{($_ -split "\.csv")[0]}

                    if (Test-Path "$($FilePath)")
                    {
                        if([int](& $xsv count "$FilePath") -gt 0)
                        {
                            New-Item "$OUTPUT_FOLDER\Registry\ShellBags\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$FilePath" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\ShellBags\XLSX\$FileName.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ShellBags" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:S1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B-D, F and H-S
                            $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["F:F"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["H:S"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
            }
            else
            {
                Write-Host "[Error] SBECCmd.exe NOT found." -ForegroundColor Red
            }
        }

        }

        Get-ShellBags

#############################################################################################################################################################################################

        # Registry ASEPs (Auto-Start Extensibility Points)
        if (Test-Path "$OUTPUT_FOLDER\Registry\Registry\*.reghive") 
        {
            if (Test-Path "$($RECmd)")
            {
                # Check if batch processing file exists
                if (Test-Path "$SCRIPT_DIR\Tools\RECmd_BatchFiles\RegistryASEPs.reb")
                {
                    Write-Output "[Info]  Extracting Auto-Start Extensibility Points (ASEPs) ... "

                    # CSV
                    New-Item "$OUTPUT_FOLDER\Registry\RegistryASEPs\CSV" -ItemType Directory -Force | Out-Null
                    Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuse")} | Rename-Item -NewName {$_.Name -replace "\.reghive$","ntuser.dat"}
                    Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "UsrClas")} | Rename-Item -NewName {$_.Name -replace "\.reghive$","UsrClass.dat"}
                    & $RECmd -d "$OUTPUT_FOLDER\Registry\Registry" --bn "$SCRIPT_DIR\Tools\RECmd_BatchFiles\RegistryASEPs.reb" --csv "$OUTPUT_FOLDER\Registry\RegistryASEPs\CSV" --csvf "RegistryASEPs.csv" > "$OUTPUT_FOLDER\Registry\RegistryASEPs\RegistryASEPs.log" 2> $null
                    Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuse")} | Rename-Item -NewName {$_.Name -replace "ntuser\.dat$",".reghive"}
                    Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "UsrClas")} | Rename-Item -NewName {$_.Name -replace "UsrClass\.dat$",".reghive"}

                    # Stats
                    if (Test-Path "$OUTPUT_FOLDER\Registry\RegistryASEPs\RegistryASEPs.log")
                    {
                        [string]$Total = (Get-Content "$OUTPUT_FOLDER\Registry\RegistryASEPs\RegistryASEPs.log" | Select-String -Pattern "key/value pairs" | Out-String).Trim()
                        Write-Output "[Info]  $Total"
                    }

                    # XSLX
                    New-Item "$OUTPUT_FOLDER\Registry\RegistryASEPs\XLSX" -ItemType Directory -Force | Out-Null
                    if (Test-Path "$OUTPUT_FOLDER\Registry\RegistryASEPs\CSV\RegistryASEPs.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\Registry\RegistryASEPs\CSV\RegistryASEPs.csv") -gt 0)
                        {
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\RegistryASEPs\CSV\RegistryASEPs.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\RegistryASEPs\XLSX\RegistryASEPs.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RegistryASEPs" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B-D, G and L-O
                            $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["G:G"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["L:O"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
                else
                {
                    Write-Host "[Error] RegistryASEPs.reb NOT found." -ForegroundColor Red
                }
            }
            else
            {
                Write-Host "[Error] RECmd.exe NOT found." -ForegroundColor Red
            }
        }

        # Startup Folders
        if (Test-Path "$DriveLetter\forensic\timeline\timeline_ntfs.txt")
        {
            New-Item "$OUTPUT_FOLDER\Persistence" -ItemType Directory -Force | Out-Null
            $StartupFolders = (Get-Content "$DriveLetter\forensic\timeline\timeline_ntfs.txt" | Select-String -Pattern "\\Start Menu\\Programs\\Startup\\" | Where-Object {$_ -notmatch "desktop.ini"} | Out-String).Trim()
            $StartupFolders | Out-File "$OUTPUT_FOLDER\Persistence\Startup-Folders.txt"
        }

        # SQLite Database
        if (Test-Path "$DriveLetter\forensic\database.txt")
        {
            # Collecting SQLite Database
            $DatabasePath = (Get-Content "$DriveLetter\forensic\database.txt" | Select-String -Pattern "vmm.sqlite3" | Out-String).Trim()
            Write-Output "[Info]  SQLite Database: $DatabasePath"
            Write-Output "[Info]  Collecting SQLite Database ..."
            New-Item "$OUTPUT_FOLDER\database" -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$DatabasePath" -Destination "$OUTPUT_FOLDER\database\vmm.sqlite3"

            # File Size (SQLite3)
            if (Test-Path "$OUTPUT_FOLDER\database\vmm.sqlite3")
            {
                $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\database\vmm.sqlite3").Length)
                Write-Output "[Info]  File Size (SQLite3): $Size"
            }
        }

        # MemProcFS Plugins
        # https://github.com/ufrisk/MemProcFS-plugins

        # pypykatz
        # https://github.com/skelsec/pypykatz
        if (Test-Path "$DriveLetter\py\secrets\*")
        {
            Write-Output "[Info]  Collecting pypykatz ... "
            New-Item "$OUTPUT_FOLDER\MemProcFS-Plugins\pypykatz" -ItemType Directory -Force | Out-Null
            Copy-Item -Recurse -Force "$DriveLetter\py\secrets\*" "$OUTPUT_FOLDER\MemProcFS-Plugins\pypykatz" 2>&1 | Out-Null
        }

        # regsecrets
        # https://github.com/skelsec/pypykatz
        if (Test-Path "$DriveLetter\py\regsecrets\*")
        {
            Write-Output "[Info]  Collecting regsecrets ... "
            New-Item "$OUTPUT_FOLDER\MemProcFS-Plugins\regsecrets" -ItemType Directory -Force | Out-Null
            Copy-Item -Recurse -Force "$DriveLetter\py\regsecrets\*" "$OUTPUT_FOLDER\MemProcFS-Plugins\regsecrets" 2>&1 | Out-Null
        }
    }
    else
    {
        Write-Host "[Error] Forensic Directory doesn't exist." -ForegroundColor Red
    }
}
else
{
    Write-Host "[Error] MemProcFS.exe NOT found." -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

}

#endregion MemProcFS

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region ELKImport

Function ELKImport {

# Elastic-Import
if (Test-Path "$DriveLetter\forensic\json\elastic_import.ps1")
{
    # Copy elastic_import.ps1 to a trusted location (to avoid security warning)
    Copy-Item -Path "$DriveLetter\forensic\json\elastic_import.ps1" -Destination "$SCRIPT_DIR\elastic_import.ps1"

    # ELK Import
    Write-Output "[Info]  Importing JSON data to Elasticsearch [approx. 1-5 min] ... "
    $Elastic_Import = "$SCRIPT_DIR\elastic_import.ps1"
    $Argument = $DriveLetter.TrimEnd(":")
    Start-Process -FilePath "powershell" -Verb RunAs -Wait -ArgumentList "-File $Elastic_Import", "$Argument"

    # Cleaning up
    if (Test-Path "$($Elastic_Import)")
    {
        Remove-Item "$Elastic_Import" -Force
    }

    try 
    {
        # Open Kibana w/ Google Chrome
        $Chrome = ((Get-Item (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe")."(Default)").VersionInfo).FileName
        Start-Process -FilePath $Chrome -ArgumentList "http://localhost:5601"
    }
    catch 
    {
        # Open Kibana in your Default Browser
        Start-Process "http://localhost:5601"
    }
}

}

#endregion ELKImport

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region MicrosoftDefender

Function MicrosoftDefender {

# Turning Microsoft Defender AntiVirus off (Real-Time Protection)
# Note: Tamper Protection must be disabled.
if ((Get-MpComputerStatus).RealTimeProtectionEnabled)
{
    # Real-Time Protection Activation Status
    $DisableRealtimeMonitoring = ((Get-MpPreference | Select-Object DisableRealtimeMonitoring).DisableRealtimeMonitoring | Out-String).Trim()
    if ($DisableRealtimeMonitoring -eq "False")
    {
        # Disable Real-Time Protection
        Write-Output "[Info]  Microsoft Defender (Real-Time Protection) will be disabled temporarily ..."
        try { Set-MpPreference -DisableRealtimeMonitoring $true }
        catch [Microsoft.Management.Infrastructure.CimException] { Write-Host $Error[0].Exception.InnerException.Message }
        catch { }
        Start-Sleep 10
    }
}

}

#endregion MicrosoftDefender

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region ClamAVUpdate

Function ClamAVUpdate {

# ClamAVUpdate

# freshclam.conf
if (!(Test-Path "C:\Program Files\ClamAV\freshclam.conf"))
{
    Write-Host "[Error] freshclam.conf is missing." -ForegroundColor Red
    Write-Host "        https://docs.clamav.net/manual/Usage/Configuration.html#windows --> First Time Set-Up" -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# clamd.conf
if (!(Test-Path "C:\Program Files\ClamAV\clamd.conf"))
{
    Write-Host "[Error] clamd.conf is missing." -ForegroundColor Red
    Write-Host "        https://docs.clamav.net/manual/Usage/Configuration.html#windows --> First Time Set-Up" -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Update
if (Test-Path "$($freshclam)")
{
    if ($null -eq $OfflineMode)
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
                New-Item "$OUTPUT_FOLDER\ClamAV" -ItemType Directory -Force | Out-Null
                & $freshclam > "$OUTPUT_FOLDER\ClamAV\Update.txt" 2> "$OUTPUT_FOLDER\ClamAV\Warning.txt"

                # Update ClamAV Engine
                if (Select-String -Pattern "WARNING: Your ClamAV installation is OUTDATED!" -Path "$OUTPUT_FOLDER\ClamAV\Warning.txt" -Quiet)
                {
                    Write-Host "[Info]  WARNING: Your ClamAV installation is OUTDATED!" -ForegroundColor Red

                    if (Select-String -Pattern "Recommended version:" -Path "$OUTPUT_FOLDER\ClamAV\Warning.txt" -Quiet)
                    {
                        $WARNING = Get-Content "$OUTPUT_FOLDER\ClamAV\Warning.txt" | Select-String -Pattern "Recommended version:"
                        Write-Host "[Info]  $WARNING" -ForegroundColor Red
                    }
                }

                # Update Signature Databases
                $Count = (Get-Content "$OUTPUT_FOLDER\ClamAV\Update.txt" | Select-String -Pattern "is up to date" | Measure-Object).Count
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
        Write-Output "[Info]  ClamAV Updates will be skipped [Offline-Mode] ..."
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
    New-Item "$OUTPUT_FOLDER\ClamAV" -ItemType Directory -Force | Out-Null
    $Version | Out-File "$OUTPUT_FOLDER\ClamAV\Version.txt"
}
else
{
    Write-Host "[Error] clamscan.exe NOT found." -ForegroundColor Red
}

}

#endregion ClamAVUpdate

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region ClamAV

Function ClamAV {

# ClamAV

# Custom Scan
# Note: By default ClamAV will not scan files larger than 100MB.
$ScanPath1 = "$DriveLetter\name"
$ScanPath2 = "$DriveLetter\forensic\files"

# Start ClamAV Daemon
if (Test-Path "$($clamd)")
{
    if (Test-Path "$($clamdscan)")
    {
        Write-Output "[Info]  Starting ClamAV Daemon ..."
        Start-Process powershell.exe -FilePath "$clamd" -WindowStyle Minimized
        $ProgressPreference = 'SilentlyContinue'
        do {
          Start-Sleep -Seconds 5
        } until (Test-NetConnection 127.0.0.1 -Port 3310 -InformationLevel Quiet -WarningAction SilentlyContinue )
        Write-Output "[Info]  ClamAV Daemon is running ... "

        # Get Start Time
        $StartTime_ClamAV = (Get-Date)

        # ClamAV Daemon Scan (Multi-Threaded)
        Write-Output "[Info]  Custom scan w/ ClamAV is running [time-consuming task] ..."
        New-Item "$OUTPUT_FOLDER\ClamAV" -ItemType Directory -Force | Out-Null
        $LogFile = "$OUTPUT_FOLDER\ClamAV\LogFile.txt"
        Start-Process -FilePath "$clamdscan" -ArgumentList "$ScanPath1 $ScanPath2 --quiet --multiscan --log=$LogFile" -WindowStyle Minimized -Wait
        Stop-Process -Name "clamdscan" -ErrorAction SilentlyContinue
        Stop-Process -Name "clamd" -ErrorAction SilentlyContinue

        # Get End Time
        $EndTime_ClamAV = (Get-Date)

        # Scan Duration
        $Time_ClamAV = ($EndTime_ClamAV-$StartTime_ClamAV)
        ('ClamAV Scan duration:          {0} h {1} min {2} sec' -f $Time_ClamAV.Hours, $Time_ClamAV.Minutes, $Time_ClamAV.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

        # ClamAV Detection(s)

        # FOUND (Infected Files)
        New-Item "$OUTPUT_FOLDER\ClamAV\Infected" -ItemType Directory -Force | Out-Null
        $InfectedFilesCount = (Get-Content $LogFile | Select-String -Pattern "FOUND" -CaseSensitive | Select-String -Pattern "Heuristics.Encrypted.* FOUND" -NotMatch | Measure-Object).Count
        $InfectedFilesMatches = Get-Content $LogFile | Select-String -Pattern "FOUND" -CaseSensitive | Select-String -Pattern "Heuristics.Encrypted.* FOUND" -NotMatch
        if ($InfectedFilesCount -eq "0")
        {
            Write-Host "[Info]  0 infected file(s) found" -ForegroundColor Green
        }
        else
        {
            ($InfectedFilesMatches | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\ClamAV\Infected\InfectedFiles.txt"

            # Whitelist
            # MsMpEng.exe   = Microsoft Defender
            # cyserver.exe  = Palo Alto Cortex XDR
            # tlaworker.exe = Palo Alto Cortex XDR
            $Whitelist = "(cyserver.exe|MsMpEng.exe|tlaworker.exe)"
            Get-Content "$OUTPUT_FOLDER\ClamAV\Infected\InfectedFiles.txt" | Where-Object {$_ -notmatch "$Whitelist"} | Out-File "$OUTPUT_FOLDER\ClamAV\Infected\InfectedFiles-filtered.txt"
            $FilteredCount = (Get-Content "$OUTPUT_FOLDER\ClamAV\Infected\InfectedFiles-filtered.txt" | Measure-Object).Count
            Write-Host "[Alert] $FilteredCount infected file(s) found ($InfectedFilesCount)" -ForegroundColor Red
        }

        # Collect Infected Files
        if (Test-Path "$OUTPUT_FOLDER\ClamAV\Infected\InfectedFiles-filtered.txt")
        {
            $InfectedFiles = Get-Content "$OUTPUT_FOLDER\ClamAV\Infected\InfectedFiles-filtered.txt" | ForEach-Object{($_ -split ": ")[0]}
            New-Item "$OUTPUT_FOLDER\ClamAV\Infected\Infected" -ItemType Directory -Force | Out-Null

            ForEach( $InfectedFile in $InfectedFiles )
            {
                $ProcessID = $InfectedFile | ForEach-Object{($_ -split "\\")[2]} | ForEach-Object{($_ -split "-")[-1]}
                $INFECTED = "infected"
                $ArchiveName = $InfectedFile | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "_INJECTED-")[-1]}
                & $7za a -mx5 -mhe "-p$INFECTED" -t7z "$OUTPUT_FOLDER\ClamAV\Infected\Infected\$ProcessID-$ArchiveName.7z" "$InfectedFile" > $null 2>&1
            }
        }

        # Stop ClamAV Daemon
        Stop-Process -Name "clamd" -ErrorAction SilentlyContinue
    }
    else
    {
        Write-Host "[Error] clamdscan.exe NOT found." -ForegroundColor Red
    }
}
else
{
    Write-Host "[Error] clamd.exe NOT found." -ForegroundColor Red
}

}

#endregion ClamAV

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Documents

Function Documents {

# RecentDocs
if (Test-Path "$OUTPUT_FOLDER\Registry\Registry\*.reghive") 
{
    if (Test-Path "$($RECmd)")
    {
        # Check if batch processing file exists
        if (Test-Path "$SCRIPT_DIR\Tools\RECmd_BatchFiles\RecentDocs.reb")
        {
            # Check if Registry Plugin exists
            if (Test-Path "$SCRIPT_DIR\Tools\RECmd\Plugins\RegistryPlugin.RecentDocs.dll")
            {
                # Analyzing RecentDocs Artifacts
                Write-Output "[Info]  Analyzing RecentDocs Artifacts ... "
                New-Item "$OUTPUT_FOLDER\Registry\RecentDocs\CSV" -ItemType Directory -Force | Out-Null
                New-Item "$OUTPUT_FOLDER\Registry\RecentDocs\XLSX" -ItemType Directory -Force | Out-Null

                # CSV
                $FilePathList = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuserdat")} | Foreach-Object FullName)

                ForEach( $FilePath in $FilePathList )
                {
                    $FileName = $FilePath | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "\.reghive$")[0]}
                    $SID = $FileName | ForEach-Object{($_ -split "_")[1]}

                    # Check if RecentDocs key exists
                    if (Test-Path "$DriveLetter\registry\by-hive\$FileName\ROOT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")
                    {
                        & $RECmd -f "$FilePath" --bn "$SCRIPT_DIR\Tools\RECmd_BatchFiles\RecentDocs.reb" --csv "$OUTPUT_FOLDER\Registry\RecentDocs\CSV" --csvf "$SID-RecentDocs.csv" > "$OUTPUT_FOLDER\Registry\RecentDocs\$SID-RecentDocs.log" 2> $null
                    }

                    # Stats
                    if (Test-Path "$OUTPUT_FOLDER\Registry\RecentDocs\$SID-RecentDocs.log")
                    {
                        # Check for parsing error
                        if (!(Get-Content -Path "$OUTPUT_FOLDER\Registry\RecentDocs\$SID-RecentDocs.log" | Select-String -Pattern "parse error" -Quiet))
                        {
                            # Check if key/value pairs were found
                            if (!(Get-Content -Path "$OUTPUT_FOLDER\Registry\RecentDocs\$SID-RecentDocs.log" | Select-String -Pattern "Found 0 key/value pairs across 1 file" -Quiet))
                            {
                                $Total = Get-Content "$OUTPUT_FOLDER\Registry\RecentDocs\$SID-RecentDocs.log" | Select-String -Pattern "key/value pairs"
                                Write-Host "[Info]  $Total ($SID)"
                            }
                            else
                            {
                                if ($SID)
                                {
                                    Write-Output "[Info]  Found 0 key/value pairs across 1 file ($SID)"
                                }
                                else
                                {
                                    Write-Output "[Info]  Found 0 key/value pairs across 1 file"
                                }
                            }
                        }
                    }
                    
                    # XLSX
                    if (Test-Path "$OUTPUT_FOLDER\Registry\RecentDocs\CSV\$SID-RecentDocs.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\Registry\RecentDocs\CSV\$SID-RecentDocs.csv") -gt 0)
                        {
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\RecentDocs\CSV\$SID-RecentDocs.csv" -Delimiter "," | Sort-Object { $_.LastWriteTimestamp -as [datetime] } -Descending
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\RecentDocs\XLSX\$SID-RecentDocs.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RecentDocs" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B, D, F-G and J-N
                            $WorkSheet.Cells["B:B"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["D:D"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["F:G"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["J:N"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # RecentDocs_RecentDocs.csv
                    if (Test-Path "$OUTPUT_FOLDER\Registry\RecentDocs\CSV\*\$SID-RecentDocs_RecentDocs.csv")
                    {
                        if((Get-Item "$OUTPUT_FOLDER\Registry\RecentDocs\CSV\*\$SID-RecentDocs_RecentDocs.csv").length -gt 0kb)
                        {
                            New-Item "$OUTPUT_FOLDER\Registry\RecentDocs\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\RecentDocs\CSV\*\$SID-RecentDocs_RecentDocs.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\RecentDocs\XLSX\$SID-RecentDocs_RecentDocs.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RecentDocs (Plugin)" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A, C-D and G-I
                            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["G:I"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
            }
            else
            {
                Write-Host "[Error] RegistryPlugin.RecentDocs.dll NOT found." -ForegroundColor Red
            }
        }
        else
        {
            Write-Host "[Error] RecentDocs.reb NOT found." -ForegroundColor Red
        }
    }
    else
    {
        Write-Host "[Error] RECmd.exe NOT found." -ForegroundColor Red
    }
}

# Office Trusted Documents
if (Test-Path "$OUTPUT_FOLDER\Registry\Registry\*.reghive") 
{
    if (Test-Path "$($RECmd)")
    {
        # Check if batch processing file exists
        if (Test-Path "$SCRIPT_DIR\Tools\RECmd_BatchFiles\TrustedDocuments.reb")
        {
            # Check if Registry Plugin exists
            if (Test-Path "$SCRIPT_DIR\Tools\RECmd\Plugins\RegistryPlugin.TrustedDocuments.dll")
            {
                # Analyzing Trusted Documents Artifacts
                Write-Output "[Info]  Analyzing Trusted Documents Artifacts ... "
                New-Item "$OUTPUT_FOLDER\Registry\TrustedDocuments\CSV" -ItemType Directory -Force | Out-Null
                New-Item "$OUTPUT_FOLDER\Registry\TrustedDocuments\XLSX" -ItemType Directory -Force | Out-Null

                # CSV
                $FilePathList = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuserdat")} | Foreach-Object FullName)

                ForEach( $FilePath in $FilePathList )
                {
                    $FileName = $FilePath | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "\.reghive$")[0]}
                    $SID = $FileName | ForEach-Object{($_ -split "_")[1]}

                    # Check if TrustedDocuments key exists
                    if (Test-Path "$DriveLetter\registry\by-hive\$FileName\ROOT\SOFTWARE\Microsoft\Office\*\*\Security\Trusted Documents\TrustRecords")
                    {
                        & $RECmd -f "$FilePath" --bn "$SCRIPT_DIR\Tools\RECmd_BatchFiles\TrustedDocuments.reb" --csv "$OUTPUT_FOLDER\Registry\TrustedDocuments\CSV" --csvf "$SID-TrustedDocuments.csv" > "$OUTPUT_FOLDER\Registry\TrustedDocuments\$SID-TrustedDocuments.log" 2> $null
                    }

                    # Stats
                    if (Test-Path "$OUTPUT_FOLDER\Registry\TrustedDocuments\$SID-TrustedDocuments.log")
                    {
                        $Total = Get-Content "$OUTPUT_FOLDER\Registry\TrustedDocuments\$SID-TrustedDocuments.log" | Select-String -Pattern "key/value pair"
                        Write-Host "[Info]  $Total ($SID)"
                    }
                    else
                    {
                        if ($SID)
                        {
                            Write-Output "[Info]  Found 0 key/value pairs across 1 file ($SID)"
                        }
                        else
                        {
                            Write-Output "[Info]  Found 0 key/value pairs across 1 file"
                        }
                    }

                    # XLSX
                    if (Test-Path "$OUTPUT_FOLDER\Registry\TrustedDocuments\CSV\$SID-TrustedDocuments.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\Registry\TrustedDocuments\CSV\$SID-TrustedDocuments.csv") -gt 0)
                        {
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\TrustedDocuments\CSV\$SID-TrustedDocuments.csv" -Delimiter "," | Sort-Object { $_.LastWriteTimestamp -as [datetime] } -Descending
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\TrustedDocuments\XLSX\$SID-TrustedDocuments.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "TrustedDocuments" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B, D, F-G and J-N
                            $WorkSheet.Cells["B:B"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["D:D"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["F:G"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["J:N"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # TrustedDocuments_TrustedDocuments.csv
                    if (Test-Path "$OUTPUT_FOLDER\Registry\TrustedDocuments\CSV\*\$SID-TrustedDocuments_TrustedDocuments.csv")
                    {
                        $FilePath = Get-ChildItem -Path "$OUTPUT_FOLDER\Registry\TrustedDocuments\CSV\*\$SID-TrustedDocuments_TrustedDocuments.csv" | Foreach-Object FullName
                        if([int](& $xsv count "$FilePath") -gt 0)
                        {
                            New-Item "$OUTPUT_FOLDER\Registry\TrustedDocuments\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\TrustedDocuments\CSV\*\$SID-TrustedDocuments_TrustedDocuments.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\TrustedDocuments\XLSX\$SID-TrustedDocuments_TrustedDocuments.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "TrustedDocuments (Plugin)" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A, C, and F
                            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["F:F"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
            }
            else
            {
                Write-Host "[Error] RegistryPlugin.TrustedDocuments.dll NOT found." -ForegroundColor Red
            }
        }
        else
        {
            Write-Host "[Error] TrustedDocuments.reb NOT found." -ForegroundColor Red
        }
    }
    else
    {
        Write-Host "[Error] RECmd.exe NOT found." -ForegroundColor Red
    }
}

}

#endregion Documents

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region DFIR_Batch

Function DFIRBatch {

# DFIR RECmd Batch File v2.11 (2025-03-31)
# https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/DFIRBatch.md
# https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/DFIRBatch.reb
# https://github.com/AndrewRathbun
if (Test-Path "$OUTPUT_FOLDER\Registry\Registry\*.reghive") 
{
    if (Test-Path "$($RECmd)")
    {
        # Check if batch processing file exists
        if (Test-Path "$SCRIPT_DIR\Tools\RECmd\BatchExamples\DFIRBatch.reb")
        {
            # Sync for RECmd Batch Files
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

            # Analyzing Registry Hives w/ RECmd (DFIR Batch)
            Write-Output "[Info]  Analyzing Registry Hives w/ RECmd (DFIR Batch) ... "
            New-Item "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV" -ItemType Directory -Force | Out-Null

            # CSV
            Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuse")} | Rename-Item -NewName {$_.Name -replace "\.reghive$","ntuser.dat"}
            Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "UsrClas")} | Rename-Item -NewName {$_.Name -replace "\.reghive$","UsrClass.dat"}
            Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Rename-Item -NewName {$_.Name -replace "\.reghive$",""}
            & $RECmd -d "$OUTPUT_FOLDER\Registry\Registry" --bn "$SCRIPT_DIR\Tools\RECmd\BatchExamples\DFIRBatch.reb" --csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV" --csvf "DFIR.csv" > "$OUTPUT_FOLDER\Registry\DFIRBatch\DFIR_Batch.log" 2> $null
            Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuse")} | Rename-Item -NewName {$_.Name -replace "ntuser\.dat$",".reghive"}
            Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "UsrClas")} | Rename-Item -NewName {$_.Name -replace "UsrClass\.dat$",".reghive"}
            Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -notmatch "\.reghive$")} | Rename-Item -NewName { $PSItem.Name + ".reghive" }

            # Rename PluginDetailFiles Directory
            $Directory = (Get-ChildItem "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV" -Directory | Select-Object FullName).FullName
            if ($Directory)
            {
                if (Test-Path "$($Directory)")
                {
                    Rename-Item -Path "$Directory" -NewName "PluginDetailFiles" -Force
                }
            }

            # Stats
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\DFIR_Batch.log")
            {
                $Total = Get-Content "$OUTPUT_FOLDER\Registry\DFIRBatch\DFIR_Batch.log" | Select-String -Pattern "key/value pair"
                Write-Host "[Info]  $Total"
            }

            # XLSX

            # DFIR.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\DFIR.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\DFIR.csv") -gt 0)
                {
                    New-Item "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX" -ItemType Directory -Force | Out-Null
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\DFIR.csv" -Delimiter "," | Sort-Object { $_.LastWriteTimestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\DFIR.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_Batch" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, G and L-N
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["G:G"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:N"].Style.HorizontalAlignment="Center"
                    # HorizontalAlignment "Left" of columns H-J
                    $WorkSheet.Cells["H:J"].Style.HorizontalAlignment="Left"
                    }
                }
            }

            # PluginDetailFiles
            New-Item "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles" -ItemType Directory -Force | Out-Null

            # DFIR_Adobe.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_Adobe.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_Adobe.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_Adobe.csv" -Delimiter "," | Sort-Object { $_.LastOpened -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_Adobe.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_Adobe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A, C-D, F and I-J
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["I:J"].Style.HorizontalAlignment="Center"
                    # HorizontalAlignment "Right" of column H
                    $WorkSheet.Cells["H:H"].Style.HorizontalAlignment="Right"
                    # HorizontalAlignment "Center" of header of column H
                    $WorkSheet.Cells["H1:H1"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_AppCompat.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_AppCompat.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_AppCompat.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_AppCompat.csv" -Delimiter "," | Sort-Object { $_.LastOpened -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_AppCompat.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_AppCompat" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and D-E
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_AppCompatFlags2.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_AppCompatFlags2.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_AppCompatFlags2.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_AppCompatFlags2.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_AppCompatFlags2.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_AppCompatFlags2" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of column C
                    $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_AppPaths.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_AppPaths.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_AppPaths.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_AppPaths.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_AppPaths.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_AppPaths" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A nd D
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:D"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_BamDam.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_BamDam.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_BamDam.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_BamDam.csv" -Delimiter "," | Sort-Object { $_.ExecutionTime -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_BamDam.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_BamDam" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of column C
                    $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_CIDSizeMRU.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_CIDSizeMRU.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_CIDSizeMRU.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_CIDSizeMRU.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_CIDSizeMRU.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_CIDSizeMRU" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns C-E
                    $WorkSheet.Cells["C:E"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_DeviceClasses.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_DeviceClasses.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_DeviceClasses.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_DeviceClasses.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_DeviceClasses.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_DeviceClasses" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-G
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:G"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_ETW.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_ETW.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_ETW.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_ETW.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_ETW.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_ETW" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A, C-D and F-G
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:G"].Style.HorizontalAlignment="Center"
                    }
                }
            }            

            # DFIR_FileExts.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_FileExts.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_FileExts.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_FileExts.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_FileExts.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_FileExts" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and D-F
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_FirewallRules.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_FirewallRules.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_FirewallRules.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_FirewallRules.csv" -Delimiter "," | Sort-Object { $_.OpenedOn -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_FirewallRules.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_FirewallRules" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-H
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:H"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_FirstFolder.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_FirstFolder.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_FirstFolder.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_FirstFolder.csv" -Delimiter "," | Sort-Object { $_.OpenedOn -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_FirstFolder.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_FirstFolder" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns C-F
                    $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_JumplistData.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_JumplistData.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_JumplistData.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_JumplistData.csv" -Delimiter "," | Sort-Object { $_.ExecutedOn -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_JumplistData.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_JumplistData" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of column C
                    $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_KnownNetworks.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_KnownNetworks.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_KnownNetworks.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_KnownNetworks.csv" -Delimiter "," | Sort-Object { $_.LastConnectedLOCAL -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_KnownNetworks.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_KnownNetworks" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-K
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:K"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_LastVisitedPidlMRU.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_LastVisitedPidlMRU.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_LastVisitedPidlMRU.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_LastVisitedPidlMRU.csv" -Delimiter "," | Sort-Object { $_.OpenedOn -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_LastVisitedPidlMRU.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_LastVisitedPidlMRU" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A, C-E and G
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:E"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["G:G"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_MountedDevices.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_MountedDevices.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_MountedDevices.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_MountedDevices.csv" -Delimiter "," | Sort-Object { $_.OpenedOn -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_MountedDevices.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_MountedDevices" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                    }
                }
            }

            # DFIR_NetworkAdapters.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_NetworkAdapters.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_NetworkAdapters.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_NetworkAdapters.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_NetworkAdapters.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_NetworkAdapters" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and D-G
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:G"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_NetworkSetup2.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_NetworkSetup2.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_NetworkSetup2.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_NetworkSetup2.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_NetworkSetup2.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_NetworkSetup2" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns C-H
                    $WorkSheet.Cells["C:H"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_OpenSavePidlMRU.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_OpenSavePidlMRU.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_OpenSavePidlMRU.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_OpenSavePidlMRU.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_OpenSavePidlMRU.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_OpenSavePidlMRU" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A, C-E and G
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:E"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["G:G"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_Products.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_Products.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_Products.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_Products.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_Products.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_Products" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and D-H 
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:H"].Style.HorizontalAlignment="Center"

                    }
                }
            }

            # DFIR_ProfileList.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_ProfileList.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_ProfileList.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_ProfileList.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_ProfileList.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_ProfileList" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and D
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:D"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_RADAR.csv
                   if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_RADAR.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_RADAR.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_RADAR.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_RADAR.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_RADAR" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-E
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:E"].Style.HorizontalAlignment="Center"
                    }
                }
            }     

            # DFIR_RecentDocs.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_RecentDocs.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_RecentDocs.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_RecentDocs.csv" -Delimiter "," | Sort-Object { $_.OpenedOn -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_RecentDocs.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_RecentDocs" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A, C-D and F-I
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:I"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_RunMRU.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_RunMRU.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_RunMRU.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_RunMRU.csv" -Delimiter "," | Sort-Object { $_.OpenedOn -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_RunMRU.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_RunMRU" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:f1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-F
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_SAMBuiltin.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_SAMBuiltin.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_SAMBuiltin.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_SAMBuiltin.csv" -Delimiter "," | Sort-Object { $_.OpenedOn -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_SAMBuiltin.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_SAMBuiltin" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and D-E
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_SCSI.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_SCSI.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_SCSI.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_SCSI.csv" -Delimiter "," | Sort-Object { $_.OpenedOn -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_SCSI.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_SCSI" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-M
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:M"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_Services.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_Services.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_Services.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_Services.csv" -Delimiter "," | Sort-Object { $_.OpenedOn -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_Services.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_Services" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B, D and F-J
                    $WorkSheet.Cells["B:B"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_Taskband.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_Taskband.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_Taskband.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_Taskband.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_Taskband.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_Taskband" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns D-E
                    $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_TaskCache.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_TaskCache.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_TaskCache.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_TaskCache.csv" -Delimiter "," | Sort-Object { $_.CreatedOn -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_TaskCache.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_TaskCache" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-D and F-J
                    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_TimeZoneInfo.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_TimeZoneInfo.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_TimeZoneInfo.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_TimeZoneInfo.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_TimeZoneInfo.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_TimeZoneInfo" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of column D
                    $WorkSheet.Cells["D:D"].Style.HorizontalAlignment="Center"
                    # HorizontalAlignment "Left" of columnc C and E
                    $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Left"
                    $WorkSheet.Cells["E:E"].Style.HorizontalAlignment="Left"
                    }
                }
            }

            # DFIR_TrustedDocuments.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_TrustedDocuments.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_TrustedDocuments.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_TrustedDocuments.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_TrustedDocuments.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_TrustedDocuments" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A, C and F
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_TypedURLs.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_TypedURLs.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_TypedURLs.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_TypedURLs.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_TypedURLs.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_TypedURLs" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and D-E
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_UnInstall.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_UnInstall.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_UnInstall.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_UnInstall.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_UnInstall.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_UnInstall" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A, D and F-H
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:H"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_USB.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_USB.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_USB.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_USB.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_USB.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_USB" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-J
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:J"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_USBSTOR.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_USBSTOR.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_USBSTOR.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_USBSTOR.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_USBSTOR.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_USBSTOR" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-M
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:M"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_UserAccounts.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_UserAccounts.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_UserAccounts.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_UserAccounts.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_UserAccounts.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_UserAccounts" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:AE1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A, C-O and Q-AE
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:O"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["Q:AE"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_UserAssist.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_UserAssist.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_UserAssist.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_UserAssist.csv" -Delimiter "," | Sort-Object { $_.LastExecuted -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_UserAssist.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_UserAssist" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns D-G
                    $WorkSheet.Cells["D:G"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_VolumeInfoCache.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_VolumeInfoCache.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_VolumeInfoCache.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_VolumeInfoCache.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_VolumeInfoCache.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_VolumeInfoCache" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-F
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_WindowsApp.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_WindowsApp.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_WindowsApp.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_WindowsApp.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_WindowsApp.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_WindowsApp" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns D-E
                    $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_WindowsPortableDevices.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_WindowsPortableDevices.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_WindowsPortableDevices.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_WindowsPortableDevices.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_WindowsPortableDevices.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_WindowsPortableDevices" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-G
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:G"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # DFIR_WordWheelQuery.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_WordWheelQuery.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_WordWheelQuery.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\DFIRBatch\CSV\PluginDetailFiles\DFIR_WordWheelQuery.csv" -Delimiter "," | Sort-Object { $_.LastWriteTimestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\DFIRBatch\XLSX\PluginDetailFiles\DFIR_WordWheelQuery.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DFIR_WordWheelQuery" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-F
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }
        else
        {
            Write-Host "[Error] DFIRBatch.reb NOT found." -ForegroundColor Red
        }
    }
    else
    {
        Write-Host "[Error] RECmd.exe NOT found." -ForegroundColor Red
    }
}

}

#endregion DFIR_Batch

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region LNK

Function LNK {

# Check if YARA exists
if (Test-Path "$($yara64)")
{
    # Get Start Time
    $StartTime_YARA = (Get-Date)

    # Simple YARA Scanner
    Write-Output "[Info]  Scanning for Windows Shortcut Files (LNK) w/ YARA [time-consuming task] ... "
    New-Item "$OUTPUT_FOLDER\LNK" -ItemType Directory -Force | Out-Null
    $LNKRule = "$SCRIPT_DIR\yara\evild3ad\LNK.yar"
    & $yara64 -p 4 -r -f -w -N "$LNKRule" "$DriveLetter\forensic\ntfs" > "$OUTPUT_FOLDER\LNK\stdout.txt" 2> $null

    # -N   do not follow symlinks when scanning
    # -p   use the specified NUMBER of threads to scan a directory
    # -r   recursive search directories (follows symlinks)
    # -f   fast matching mode
    # -w   disable warnings

    # Get End Time
    $EndTime_YARA = (Get-Date)

    # Scan Duration
    $Time_YARA = ($EndTime_YARA-$StartTime_YARA)
    '[Info]  YARA scan duration: {0:hh} h {0:mm} min {0:ss} sec' -f ($Time_YARA)
    
    ('YARA Scan duration:            {0} h {1} min {2} sec' -f $Time_YARA.Hours, $Time_YARA.Minutes, $Time_YARA.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

    # Stats
    if ((Test-Path "$OUTPUT_FOLDER\LNK\stdout.txt") -And ((Get-Item "$OUTPUT_FOLDER\LNK\stdout.txt").length -gt 0kb))
    {
        Get-Content "$OUTPUT_FOLDER\LNK\stdout.txt" | ForEach-Object{($_ -split "LNK ")[-1]} > "$OUTPUT_FOLDER\LNK\LNK-Files.txt"
        Remove-Item "$OUTPUT_FOLDER\LNK\stdout.txt" -Force
        $Count = [string]::Format('{0:N0}',(Get-Content "$OUTPUT_FOLDER\LNK\LNK-Files.txt" | Measure-Object –Line).Lines)
        Write-Host "[Info]  $Count SHLLINK artifacts found"
    }

    # lnk_parser
    if (Test-Path "$($lnk_parser)")
    {
        if (Test-Path "$($entropy)")
        {
            Write-Output "[Info]  Parsing SHLLINK artifacts (LNK) w/ lnk_parser ... "
            New-Item "$OUTPUT_FOLDER\LNK\lnk_parser\CSV" -ItemType Directory -Force | Out-Null
            $LNK_LIST = Get-Content "$OUTPUT_FOLDER\LNK\LNK-Files.txt"

            # Add CSV Header
            Write-Output '"target_full_path","target_modification_time","target_access_time","target_creation_time","target_size","target_hostname","lnk_full_path","lnk_modification_time","lnk_access_time","lnk_creation_time"' | Out-File "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser.csv"

            ForEach( $LNK_FILE in $LNK_LIST )
            {
                & $lnk_parser -p $LNK_FILE --output-format csv --no-headers | Out-File "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser.csv" -Append
            }

            # Custom CSV (for Hunting Malicious LNK Files)
            $LNK_LIST | Foreach-Object {

                $File = $_
                $MD5 = Get-FileHash "$File" -Algorithm MD5 -ErrorAction SilentlyContinue
                $SHA1 = Get-FileHash "$File" -Algorithm SHA1 -ErrorAction SilentlyContinue
                $SHA256 = Get-FileHash "$File" -Algorithm SHA256 -ErrorAction SilentlyContinue
                $FileInfo = Get-Item -Force "$File" -ErrorAction SilentlyContinue
                $LNK_PARSER_JSON = (& $lnk_parser -p $File --output-format json | ConvertFrom-Json)
                $full_path = $LNK_PARSER_JSON | Select-Object @{Name="full_path"; Expression={$_.lnk_file_metadata.full_path}}
                $lnk_modification_time = $LNK_PARSER_JSON | Select-Object @{Name="lnk_modification_time"; Expression={$_.lnk_file_metadata.mtime}}
                $lnk_access_time = $LNK_PARSER_JSON | Select-Object @{Name="lnk_access_time"; Expression={$_.lnk_file_metadata.atime}}
                $lnk_creation_time = $LNK_PARSER_JSON | Select-Object @{Name="lnk_creation_time"; Expression={$_.lnk_file_metadata.ctime}}
                $LocalBasePath = $LNK_PARSER_JSON | Select-Object @{Name="local_base_path"; Expression={$_.link_info.local_base_path}}
                $HotKey = $LNK_PARSER_JSON | Select-Object @{Name="hot_key"; Expression={$_.shell_link_header.hot_key}}
                $FileEntropy = & $entropy "$File" | ForEach-Object{($_ -split "\s+")[0]}

                New-Object -TypeName PSObject -Property @{
                    "LNK Full Path" = $full_path.full_path
                    "LNK Modification Time" = $lnk_modification_time.lnk_modification_time
                    "LNK Access Time" = $lnk_access_time.lnk_access_time
                    "LNK Creation Time" = $lnk_creation_time.lnk_creation_time
                    "Target Full Path" = $LNK_PARSER_JSON.target_full_path
                    "Working Directory" = $LNK_PARSER_JSON.working_dir
                    "Arguments" = $LNK_PARSER_JSON.command_line_arguments
                    "Relative Path" = $LNK_PARSER_JSON.relative_path
                    "Icon Location" = $LNK_PARSER_JSON.icon_location
                    "Local Base Path" = $LocalBasePath.local_base_path
                    "Shortcut Key" = $HotKey.hot_key
                    "LNK Size" = $FileInfo.Length
                    MD5 = $MD5.Hash
                    SHA1 = $SHA1.Hash
                    SHA256 = $SHA256.Hash
                    Entropy = $FileEntropy
                }
            } | Select-Object "LNK Full Path","LNK Modification Time","LNK Access Time","LNK Creation Time","Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | ConvertTo-Csv -NoTypeInformation -Delimiter "," | Out-File "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv"

            # XLSX

            # Check if PowerShell module 'ImportExcel' exists
            if (Get-Module -ListAvailable -Name ImportExcel) 
            {
                # lnk_parser.csv
                if (Test-Path "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser.csv")
                {
                    if([int](& $xsv count "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser.csv") -gt 0)
                    {
                        New-Item "$OUTPUT_FOLDER\LNK\lnk_parser\XLSX" -ItemType Directory -Force | Out-Null
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser.csv" -Delimiter "," | Select-Object "target_full_path",@{Name='target_modification_time';Expression={([datetime]$_."target_modification_time").ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='target_access_time';Expression={([datetime]$_."target_access_time").ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='target_creation_time';Expression={([datetime]$_."target_creation_time").ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}},target_size,target_hostname,lnk_full_path,@{Name='lnk_modification_time';Expression={([datetime]$_."lnk_modification_time").ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='lnk_access_time';Expression={([datetime]$_."lnk_access_time").ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='lnk_creation_time';Expression={([datetime]$_."lnk_creation_time").ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}}
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\lnk_parser\XLSX\lnk_parser.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "lnk_parser" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns B-D, F and H-J
                        $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["F:F"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["H:J"].Style.HorizontalAlignment="Center"
                        # HorizontalAlignment "Center" of header of column E
                        $WorkSheet.Cells["E1:E1"].Style.HorizontalAlignment="Center"
                        }
                    }
                }

                # lnk_parser-hunt.csv
                # https://attack.mitre.org/techniques/T1547/009/
                if (Test-Path "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv")
                {
                    if([int](& $xsv count "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv") -gt 0)
                    {
                        New-Item "$OUTPUT_FOLDER\LNK\lnk_parser\XLSX" -ItemType Directory -Force | Out-Null
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\lnk_parser\XLSX\lnk_parser-hunt.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "lnk_parser-hunt" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns B-D, K and L-P
                        $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }
        }
        else
        {
            Write-Host "[Error] entropy.exe NOT found." -ForegroundColor Red
        }
    }
    else
    {
        Write-Host "[Error] lnk_parser_x86_64.exe NOT found." -ForegroundColor Red
    }
}
else
{
    Write-Host "[Error] yara64.exe NOT found." -ForegroundColor Red
}

}

Function LNK_Hunt {

# Hunting Malicious LNK Files
# https://attack.mitre.org/techniques/T1547/009/
if (Test-Path "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv")
{
    if([int](& $xsv count "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv") -gt 0)
    {
        New-Item "$OUTPUT_FOLDER\LNK\Hunt\CSV" -ItemType Directory -Force | Out-Null
        New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX" -ItemType Directory -Force | Out-Null

        # Target Full Path (lnk_parser)

        # Target Full Path: C:\Google\AutoIt3.exe
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Target Full Path" -match "C:\\Google\\AutoIt3\.exe")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) using AutoIt3.exe detected [Target Full Path] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-AutoIt3.exe.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-AutoIt3.exe.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-AutoIt3.exe.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-AutoIt3.exe.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath\TargetFullPath-AutoIt3.exe.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AutoIt3.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }
 
        # Target Full Path: C:\Windows\System32\cmd.exe
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Target Full Path" -match "C:\\Windows\\System32\\cmd\.exe")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) using cmd.exe detected [Target Full Path] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-cmd.exe.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-cmd.exe.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-cmd.exe.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-cmd.exe.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath\TargetFullPath-cmd.exe.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "cmd.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Target FUll Path: C:\Windows\System32\mshta.exe
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Target Full Path" -match "C:\\Windows\\System32\\mshta\.exe")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) using mshta.exe detected [Target Full Path] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-mshta.exe.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-mshta.exe.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-mshta.exe.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-mshta.exe.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath\TargetFullPath-mshta.exe.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "mshta.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Target Full Path: C:\Windows\System32\msiexec.exe
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Target Full Path" -match "C:\\Windows\\System32\\msiexec\.exe")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
        
        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) using msiexec.exe detected [Target Full Path] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-msiexec.exe.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-msiexec.exe.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-msiexec.exe.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-msiexec.exe.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath\TargetFullPath-msiexec.exe.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "msiexec.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Target Full Path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Target Full Path" -match "C:\\Windows\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) using powershell.exe detected [Target Full Path] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-powershell.exe.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-powershell.exe.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-powershell.exe.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-powershell.exe.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath\TargetFullPath-powershell.exe.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "powershell.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Target Full Path: C:\Windows\System32\rundll32.exe
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Target Full Path" -match "C:\\Windows\\System32\\rundll32\.exe")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) using rundll32.exe detected [Target Full Path] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-rundll32.exe.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-rundll32.exe.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-rundll32.exe.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-rundll32.exe.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath\TargetFullPath-rundll32.exe.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "rundll32.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Target Full Path: C:\Windows\System32\schtasks.exe
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Target Full Path" -match "C:\\Windows\\System32\\schtasks\.exe")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) using schtasks.exe detected [Target Full Path] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-schtasks.exe.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-schtasks.exe.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-schtasks.exe.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-schtasks.exe.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath\TargetFullPath-schtasks.exe.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "schtasks.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Target Full Path: C:\Windows\System32\wscript.exe
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Target Full Path" -match "C:\\Windows\\System32\\wscript\.exe")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) using wscript.exe detected [Target Full Path] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-wscript.exe.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-wscript.exe.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-wscript.exe.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-wscript.exe.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath\TargetFullPath-wscript.exe.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "wscript.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Arguments

        # Long Argument (more than 50 characters)
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {(($_."Arguments").Length -gt "50")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) w/ Long Argument detected [Arguments] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Arguments" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Long-Argument.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Long-Argument.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Long-Argument.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Long-Argument.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Arguments\Arguments-Long-Argument.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Long Argument" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Long Whitespace (more than 3 characters)
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Arguments" -match "\s{3,}")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) w/ Long Whitespace detected [Arguments] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Arguments" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Long-Whitespace.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Long-Whitespace.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Long-Whitespace.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Long-Whitespace.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Arguments\Arguments-Long-Whitespace.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Long Whitespace" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Windows shortcut file (LNK) contains suspicious strings: http://
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Arguments" -match "http://")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Windows shortcut file (LNK) contains suspicious strings: http:// [Arguments] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Arguments" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Suspicious-Strings-CommandLine-http.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Suspicious-Strings-CommandLine-http.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Suspicious-Strings-CommandLine-http.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Suspicious-Strings-CommandLine-http.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Arguments\Arguments-Suspicious-Strings-CommandLine-http.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "http" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Windows shortcut file (LNK) contains suspicious strings: https://
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Arguments" -match "https://")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Windows shortcut file (LNK) contains suspicious strings: https:// [Arguments] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Arguments" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Suspicious-Strings-CommandLine-https.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Suspicious-Strings-CommandLine-https.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Suspicious-Strings-CommandLine-https.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Suspicious-Strings-CommandLine-https.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Arguments\Arguments-Suspicious-Strings-CommandLine-https.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "https" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Relative Path

        # Long Relative Path
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Relative Path" -match "\.\.\\\.\.\\\.\.\\\.\.\\\.\.\\")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) w/ Long Relative Path detected [Arguments] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\RelativePath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\RelativePath-Long-Relative-Path.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\RelativePath-Long-Relative-Path.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\LNK\Hunt\CSV\RelativePath-Long-Relative-Path.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\RelativePath-Long-Relative-Path.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\RelativePath\RelativePath-Long-Relative-Path.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Long Relative Path" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Misc

        # Suspicious LNK Size
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {([int]$_."LNK Size" -gt "1000")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File Size detected [Arguments] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Misc" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Misc-Suspicious-LNK-Size.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\Misc-Suspicious-LNK-Size.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\LNK\Hunt\CSV\Misc-Suspicious-LNK-Size.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Misc-Suspicious-LNK-Size.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Misc\Misc-Suspicious-LNK-Size.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Suspicious LNK Size" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Suspicious High Entropy (equal or higher than 6.5)
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {([int]$_."Entropy" -ge "6.5")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) w/ High Entropy detected [Arguments] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Misc" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Misc-Suspicious-High-Entropy.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\Misc-Suspicious-High-Entropy.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\LNK\Hunt\CSV\Misc-Suspicious-High-Entropy.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Misc-Suspicious-High-Entropy.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Misc\Misc-Suspicious-High-Entropy.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "High Entropy" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }
    }
}

}

#endregion LNK

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region ImageMount

# VHDMP (VHD Miniport Driver by Microsoft Corporation)

# VHD and VHDX Files
# Windows 7 and newer systems include the ability to manually mount VHD files. Starting with Windows 8, a user can mount a VHD by simply double-clicking on the file. 
# Once mounted, a VHD disk image appears to Windows as a normal hard disk that's physically connected to the system. 
# VHDX (Virtual Hard Disk v2) images are functionally equivalent to VHD images, but they include more modern features, such as support for larger sizes and disk resizing.

# Mark of the Web (MOTW)
# MOTW was introduced in Windows XP SP2 and allowed Windows to tag files on the local file system with information about the Internet Explorer security zone from which the files originated. 
# This MOTW feature has evolved to handle more and more file types and scenarios. 
# The recurring theme is that files that came from the Internet (e.g., a web page or an email) may be dangerous, and therefore should be treated with more caution.
# For example, starting with Microsoft Office 2010, documents tagged with an MOTW that indicated that they came from the Internet are opened in Microsoft Office Protected View. 
# Documents in Protected View are restricted in what they can do, thus reducing the attack surface of potentially dangerous documents. 

# Starting with Windows 10, Windows Defender SmartScreen restricts the execution of certain file types if they originated from the Internet.

# Files contained within a VHD or VHDX container do not retain the MOTW of the container file!!!

# ISO and IMG Files
# Just like VHD and VHDX files, the contents of ISO or IMG files do not carry the MOTW of the containing file. 
# And just like VHD and VHDX files, starting with Windows 8, ISO and IMG files can be opened with a double click.

# Following Microsoft's decision to block macros by default on MS Office applications, threat actors are increasingly using container files such as ISO files to distribute malware.

Function ImageMount {

# VHDMP (Event Logs for VHD's)
if (Test-Path "$OUTPUT_FOLDER\EventLogs\EventLogs\Microsoft-Windows-VHDMP-Operational.evtx")
{
    Write-Output "[Info]  Analyzing Event Logs for Image Mount Indicators ... "
    New-Item "$OUTPUT_FOLDER\EventLogs\VHDMP" -ItemType Directory -Force | Out-Null
    Copy-Item "$OUTPUT_FOLDER\EventLogs\EventLogs\Microsoft-Windows-VHDMP-Operational.evtx" "$OUTPUT_FOLDER\EventLogs\VHDMP" 2>&1 | Out-Null

    # EvtxECmd
    if (Test-Path "$($EvtxECmd)")
    {
        if (Test-Path "$OUTPUT_FOLDER\EventLogs\VHDMP\Microsoft-Windows-VHDMP-Operational.evtx")
        {
            # EvtxECmd.csv
            New-Item "$OUTPUT_FOLDER\EventLogs\VHDMP\CSV" -ItemType Directory -Force | Out-Null
            & $EvtxECmd -f "$OUTPUT_FOLDER\EventLogs\VHDMP\Microsoft-Windows-VHDMP-Operational.evtx" --csv "$OUTPUT_FOLDER\EventLogs\VHDMP\CSV" --csvf "EvtxECmd.csv" > "$OUTPUT_FOLDER\EventLogs\VHDMP\EvtxECmd.log" 2> $null

            # Windows Title (Default)
            $Host.UI.RawUI.WindowTitle = "MemProcFS-Analyzer $Version - Automated Forensic Analysis of Windows Memory Dumps for DFIR"

            # Stats
            if (Get-Content "$OUTPUT_FOLDER\EventLogs\VHDMP\EvtxECmd.log" | Select-String -Pattern "^Total event log records found:" -Quiet)
            {
                # Error
                if (Get-Content "$OUTPUT_FOLDER\EventLogs\VHDMP\EvtxECmd.log" | Select-String -Pattern "Error processing record" -Quiet)
                {
                    Write-Output "[Info]  Microsoft-Windows-VHDMP-Operational.evtx seems to be partially corrupt."
                }

                # Total
                $Total = (Get-Content "$OUTPUT_FOLDER\EventLogs\VHDMP\EvtxECmd.log" | Select-String -Pattern "Total event log records found:" | ForEach-Object{($_ -split "\s+")[-1]} | Out-String).Trim()
                Write-Output "[Info]  Total Event Log Records found: $Total"
            }

            # ImageMount Hunt
            if (Test-Path "$OUTPUT_FOLDER\EventLogs\VHDMP\CSV\EvtxECmd.csv")
            {
                if ([int](& $xsv count "$OUTPUT_FOLDER\EventLogs\VHDMP\CSV\EvtxECmd.csv") -gt 0)
                {
                    $Import = Import-Csv "$OUTPUT_FOLDER\EventLogs\VHDMP\CSV\EvtxECmd.csv" -Delimiter "," | Select-Object RecordNumber, @{Name='TimeCreated [UTC]';Expression={([datetime]$_.TimeCreated).ToString("yyyy-MM-dd HH:mm:ss")}}, EventId, Level, Channel, MapDescription, @{Name='EventData';Expression={$_.PayloadData1}},@{Name='Name';Expression={$_.PayloadData2 | ForEach-Object{($_ -split "\\")[-1]}}},@{Name='FilePath';Expression={$_.PayloadData2 | ForEach-Object{($_ -split ": ")[-1]}}}, Computer, UserId

                    # Event ID 1 - Contains entries of Image Files that has come online (surfaced)
                    $Data = $Import | Where-Object { $_."EventId" -eq "1" }
                    $EID1 = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                    if ($EID1 -gt 0)
                    {
                        Write-Host "[Alert] Image Mount Entries found: Event ID 1 - Mount ($Count)" -ForegroundColor Red
                    }

                    # Event ID 2 - Contains entries of Image Files that has been removed (unsurfaced)
                    $Data = $Import | Where-Object { $_."EventId" -eq "2" }
                    $EID2 = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

                    if ($EID2 -gt 0)
                    {
                        Write-Host "[Alert] Image Mount Entries found: Event ID 2 - Unmount ($Count)" -ForegroundColor Red
                    }

                    # ImageMount Hunt Summary

                    # CSV
                    if (($EID1 -gt 0) -or ($EID2 -gt 0))
                    { 
                        $Import | Where-Object { $_."EventId" -eq "1" -or $_."EventId" -eq "2" } | Export-Csv "$OUTPUT_FOLDER\EventLogs\VHDMP\CSV\ImageMount.csv" -NoTypeInformation
                    }

                    # XLSX
                    if (Test-Path "$OUTPUT_FOLDER\EventLogs\VHDMP\CSV\ImageMount.csv")
                    {
                        if([int](& $xsv count "$OUTPUT_FOLDER\EventLogs\VHDMP\CSV\ImageMount.csv") -gt 0)
                        {
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EventLogs\VHDMP\CSV\ImageMount.csv" -Delimiter "," | Sort-Object { $_."TimeCreated [UTC]" -as [datetime] } -Descending
                            New-Item "$OUTPUT_FOLDER\EventLogs\VHDMP\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EventLogs\VHDMP\XLSX\ImageMount.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ImageMount" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A-F and J-K
                            $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["J:K"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
            }
        }
    }
}

#############################################################################################################################################################################################

# Recent Files
if (Test-Path "$OUTPUT_FOLDER\RecentFiles\RecentFiles.csv")
{
    if ([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\RecentFiles\RecentFiles.csv") -gt 0)
    {
        Write-Output "[Info]  Analyzing Recent Folder Artifacts for Image Mount Indicators ... "

        $Import = Import-Csv "$OUTPUT_FOLDER\RecentFiles\RecentFiles.csv" -Delimiter "," | Select-Object @{Name='Timestamp [UTC]';Expression={([datetime]$_.date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='Name';Expression={$_.desc | ForEach-Object{($_ -split "\\")[-1]}}},@{Name='Type';Expression={$_.type}},@{Name='Action';Expression={$_.action}},@{Name='File Path';Expression={$_.desc}},@{Name='Bytes';Expression={$_.num}} | Sort-Object { $_."Timestamp [UTC]" -as [datetime] } -Descending

        # IMG Files
        $Data = $Import | Where-Object { $_."FilePath" -match "\\Users\\.*\.img\.lnk" }
        $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Image Mount Indicator detected: .img.lnk ($Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\RecentFiles\Image-Mount-Indicators" -ItemType Directory -Force | Out-Null
            $Data | Export-Excel -Path "$OUTPUT_FOLDER\RecentFiles\Image-Mount-Indicators\IMG.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname ".img" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A, C-D and F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["F:F"].Style.HorizontalAlignment="Center"
            # BackgroundColor and FontColor for specific cells
            $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
            $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
            $LastRow = $WorkSheet.Dimension.End.Row
            Set-Format -Address $WorkSheet.Cells["E2:E$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
            }
        }

        # ISO Files
        $Data = $Import | Where-Object { $_."File Path" -match "\\Users\\.*\.iso\.lnk" }
        $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Image Mount Indicator detected: .iso.lnk ($Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\RecentFiles\Image-Mount-Indicators" -ItemType Directory -Force | Out-Null
            $Data | Export-Excel -Path "$OUTPUT_FOLDER\RecentFiles\Image-Mount-Indicators\ISO.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname ".iso" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A, C-D and F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["F:F"].Style.HorizontalAlignment="Center"
            # BackgroundColor and FontColor for specific cells
            $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
            $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
            $LastRow = $WorkSheet.Dimension.End.Row
            Set-Format -Address $WorkSheet.Cells["E2:E$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
            }
        }

        # VHD Files
        $Data = $Import | Where-Object { $_."File Path" -match "\\Users\\.*\.vhd\.lnk" }
        $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Image Mount Indicator detected: .vhd.lnk ($Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\RecentFiles\Image-Mount-Indicators" -ItemType Directory -Force | Out-Null
            $Data | Export-Excel -Path "$OUTPUT_FOLDER\RecentFiles\Image-Mount-Indicators\VHD.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname ".vhd" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A, C-D and F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["F:F"].Style.HorizontalAlignment="Center"
            # BackgroundColor and FontColor for specific cells
            $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
            $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
            $LastRow = $WorkSheet.Dimension.End.Row
            Set-Format -Address $WorkSheet.Cells["E2:E$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
            }
        }

        # VHDX Files
        $Data = $Import | Where-Object { $_."File Path" -match "\\Users\\.*\.vhdx\.lnk" }
        $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Image Mount Indicator detected: .vhdx.lnk ($Count)" -ForegroundColor Yellow
            New-Item "$OUTPUT_FOLDER\RecentFiles\Image-Mount-Indicators" -ItemType Directory -Force | Out-Null
            $Data | Export-Excel -Path "$OUTPUT_FOLDER\RecentFiles\Image-Mount-Indicators\VHDX.xlsx" -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname ".vhdx" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A, C-D and F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["F:F"].Style.HorizontalAlignment="Center"
            # BackgroundColor and FontColor for specific cells
            $BackgroundColor = [System.Drawing.Color]::FromArgb(255,0,0)
            $FontColor = [System.Drawing.Color]::FromArgb(255,255,255)
            $LastRow = $WorkSheet.Dimension.End.Row
            Set-Format -Address $WorkSheet.Cells["E2:E$LastRow"] -BackgroundColor $BackgroundColor -FontColor $FontColor -Bold
            }
        }
    }
}

}

#endregion ImageMount

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Modules

# Status: Experimental
# The recovered files are often partial. Often the metadata isn't yet read into memory (it's read on-demand on first use from disk) or paged out. File hashes are more or less useless since you'll never recover the whole file from memory.
# But it seems that in some cases it's working better than expected and helps you to find evil.

# https://github.com/ufrisk/MemProcFS/wiki/FS_Process_Modules

Function Modules {

# Get Start Time
$StartTime_Modules = (Get-Date)

# Modules
Write-Host "[Info]  Analyzing Reconstructed Process Modules ... "
New-Item "$OUTPUT_FOLDER\sys\modules\CSV" -ItemType Directory -Force | Out-Null

if (!(Test-Path "$($entropy)"))
{
    Write-Host "[Error] entropy.exe NOT found." -ForegroundColor Red
}

$Modules = Get-ChildItem -Path "$DriveLetter\pid\*\modules\*.exe\pefile.dll" | ForEach-Object { $_.FullName }
$Modules | Out-File "$OUTPUT_FOLDER\sys\modules\Modules-List.txt"

$Modules | Foreach-Object {

    $File = $_
    $FileInfo = Get-Item -Force "$File" -ErrorAction SilentlyContinue
    $Length = $FileInfo.Length

    if ($Length -ne "0")
    {
        $MD5 = Get-FileHash "$File" -Algorithm MD5 -ErrorAction SilentlyContinue
        $SHA1 = Get-FileHash "$File" -Algorithm SHA1 -ErrorAction SilentlyContinue
        $SHA256 = Get-FileHash "$File" -Algorithm SHA256 -ErrorAction SilentlyContinue
    }
    else
    {
        $MD5 = ""
        $SHA1 = ""
        $SHA256 = ""
    }

    $ProcessId = $File | ForEach-Object{($_ -split "\\")[2]}
    $FullPath = $File.Replace("pefile.dll", "fullname.txt")
    $ImagePath = Get-Content -Path $FullPath
    $FileName = Split-Path $ImagePath -Leaf
    $InternalName = $FileInfo.VersionInfo.InternalName
    $OriginalFileName = $FileInfo.VersionInfo.OriginalFileName
    $FileDescription = $FileInfo.VersionInfo.FileDescription
    $CompanyName = $FileInfo.VersionInfo.CompanyName
    $FileVersion = $FileInfo.VersionInfo.FileVersion
    $Language = $FileInfo.VersionInfo.Language
    $ProductName = $FileInfo.VersionInfo.ProductName

    if (Test-Path "$($entropy)")
    {
        $FileEntropy = & $entropy "$File" | ForEach-Object{($_ -split "\s+")[0]}
    }
    else
    {
        $FileEntropy = ""
    }

    $LastAccessTimeUtc = $FileInfo.LastAccessTimeUtc

    # CSV
    New-Object -TypeName PSObject -Property @{
        "File Name"         = $FileName
        "PID"               = $ProcessId
        "Internal Name"     = $InternalName
        "Original FileName" = $OriginalFileName
        "File Description"  = $FileDescription
        "Image Path"        = $ImagePath
        "File Version"      = $FileVersion
        "Company Name"      = $CompanyName
        "Product Name"      = $ProductName
        "Language"          = $Language
        "Bytes"             = $Length
        "File Size"         = Get-FileSize($Length)
        "File Path"         = $File
        "MD5"               = $MD5.Hash
        "SHA1"              = $SHA1.Hash
        "SHA256"            = $SHA256.Hash
        "Entropy"           = $FileEntropy
        "Last Access Time"  = $LastAccessTimeUtc
    }
} | Select-Object "File Name","PID","Internal Name","Original FileName","File Description","Image Path","File Version","Company Name","Product Name","Language","Bytes","File Size","File Path","Entropy","Last Access Time","MD5","SHA1","SHA256" | ConvertTo-Csv -NoTypeInformation -Delimiter "," | Out-File "$OUTPUT_FOLDER\sys\modules\CSV\modules-untouched.csv" -Encoding UTF8

# Whitelist
if (Test-Path "$OUTPUT_FOLDER\sys\modules\CSV\modules-untouched.csv")
{
    if([int](& $xsv count "$OUTPUT_FOLDER\sys\modules\CSV\modules-untouched.csv") -gt 0)
    {
        # Exclude 0-Byte Files
        $Data = Get-Content "$OUTPUT_FOLDER\sys\modules\CSV\modules-untouched.csv" | ConvertFrom-Csv
        $Data | Where-Object {$_."Image Path" -notmatch  "\\SystemRoot\\system32\\ntoskrnl\.exe"} | Where-Object {$_."Bytes" -notmatch  "^0"} | Export-Csv "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv" -NoTypeInformation -Encoding UTF8

        # Count
        [int]$Total = & $xsv count "$OUTPUT_FOLDER\sys\modules\CSV\modules-untouched.csv"
        [int]$Cleaned = & $xsv count "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv"
        Write-Output "[Info]  $Cleaned Reconstructed Process Modules found ($Total)"
    }
    else
    {
        Write-Output "[Info]  No Reconstructed Process Modules found"
    }
}

# Check if PowerShell module 'ImportExcel' exists
if (Get-Module -ListAvailable -Name ImportExcel) 
{
    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv")
    {
        if((Get-Item "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv").length -gt 0kb)
        {
            New-Item "$OUTPUT_FOLDER\sys\modules\XLSX" -ItemType Directory -Force | Out-Null
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\modules\XLSX\modules.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Modules" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-B, G-J and N-R
            $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["G:J"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["N:R"].Style.HorizontalAlignment="Center"
            # HorizontalAlignment "Right" of columns K-L
            $WorkSheet.Cells["K:L"].Style.HorizontalAlignment="Right"
            # HorizontalAlignment "Center" of header of columns K-L
            $WorkSheet.Cells["K1:L1"].Style.HorizontalAlignment="Center"

            # Threat Hunting

            # Fields are missing / empty (W/ Rule Priority)

            # "Internal Name" and "Original FileName" and "File Description" and "Company Name" --> Red
            $HighColor = [System.Drawing.Color]::FromArgb(255,0,0)
            Add-ConditionalFormatting -Address $WorkSheet.Dimension.Address -WorkSheet $WorkSheet -RuleType 'Expression' '=AND($C1="",$D1="",$E1="",$H1="")' -BackgroundColor $HighColor
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv" -Delimiter "," | Where-Object {(($_."Internal Name" -eq "") -and ($_."Original FileName" -eq "") -and ($_."File Description" -eq "") -and ($_."Company Name" -eq ""))}
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Missing Internal Name, Original FileName, File Description, and Company Name detected [Modules] (Count: $Count)" -ForegroundColor Red
            }

            # "File Description" or "Company Name": Empty --> Orange
            $MediumColor = [System.Drawing.Color]::FromArgb(255,192,0)
            Add-ConditionalFormatting -Address $WorkSheet.Dimension.Address -WorkSheet $WorkSheet -RuleType 'Expression' '=OR($E1="",$H1="")' -BackgroundColor $MediumColor
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv" -Delimiter "," | Where-Object {(($_."File Description" -eq "") -or ($_."Company Name" -eq ""))}
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Missing File Description and/or Company Name detected [Modules] (Count: $Count)" -ForegroundColor Yellow
            }

            # "Internal Name" or "Original FileName": Empty --> Yellow
            $LowColor = [System.Drawing.Color]::FromArgb(255,255,0)
            Add-ConditionalFormatting -Address $WorkSheet.Dimension.Address -WorkSheet $WorkSheet -RuleType 'Expression' '=OR($C1="",$D1="")' -BackgroundColor $LowColor
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv" -Delimiter "," | Where-Object {(($_."Internal Name" -eq "") -or ($_."Original FileName" -eq ""))}
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Missing Internal Name and/or Original FileName detected [Modules] (Count: $Count)" -ForegroundColor Yellow
            }

            # Mismatch on Original FileName
            $LowColor = [System.Drawing.Color]::FromArgb(255,255,0)
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["D2:D$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$A2<>$D2' -BackgroundColor $LowColor
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv" -Delimiter "," | Where-Object {($_."File Name" -notlike $_."Original FileName")}
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Mismatch on Original FileName detected [Modules] (Count: $Count)" -ForegroundColor Yellow
            }

            }
        }
    }
}

# Get End Time
$EndTime_Modules = (Get-Date)

# Processing Duration
$Time_Modules = ($EndTime_Modules-$StartTime_Modules)
('Modules Analysis duration:     {0} h {1} min {2} sec' -f $Time_Modules.Hours, $Time_Modules.Minutes, $Time_Modules.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#endregion Modules

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region CobaltStrike

Function Invoke-1768 {

# 1768.py v.0.0.23 (2025-03-07)
# https://blog.didierstevens.com/?s=1768.py
# https://github.com/DidierStevens/DidierStevensSuite/blob/master/1768.py
if ((Test-Path "$SCRIPT_DIR\Scripts\1768\1768.py") -and (Test-Path "$SCRIPT_DIR\Scripts\1768\1768.json"))
{
    # Current version
    New-Item "$OUTPUT_FOLDER\CobaltStrike\1768" -ItemType Directory -Force | Out-Null
    python "$SCRIPT_DIR\Scripts\1768\1768.py" --version > "$OUTPUT_FOLDER\CobaltStrike\1768\Version.txt" 2> $null

    # Get Start Time
    $StartTime_1768 = (Get-Date)

    # Searching for Cobalt Strike Beacons Configuration(s) w/ 1768.py
    Write-Output "[Info]  Searching for Cobalt Strike Beacons Configuration(s) w/ 1768.py ..."
    python "$SCRIPT_DIR\Scripts\1768\1768.py" -S $MemoryDump -o "$OUTPUT_FOLDER\CobaltStrike\1768\1768.txt" 2> $null

    # Get End Time
    $EndTime_1768 = (Get-Date)

    # Scan Duration
    $Time_1768 = ($EndTime_1768-$StartTime_1768)
    ('1768 Scan duration:            {0} h {1} min {2} sec' -f $Time_1768.Hours, $Time_1768.Minutes, $Time_1768.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

    if (Test-Path "$OUTPUT_FOLDER\CobaltStrike\1768\1768.txt")
    {
        if (Get-Content -Path "$OUTPUT_FOLDER\CobaltStrike\1768\1768.txt" | Select-String -Pattern "Sanity check Cobalt Strike config: OK" -Quiet)
        {
            Write-Host "[Alert] Cobalt Strike Beacons Configuration found" -ForegroundColor Red
        }
    }
}

}

#endregion CobaltStrike

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region SecureArchive

Function SecureArchive {

# Get End Time
$EndTime_Processing = (Get-Date)

# Total Processing Duration
$Time_Processing = ($EndTime_Processing-$StartTime_Processing)
('Total Processing duration:     {0} h {1} min {2} sec' -f $Time_Processing.Hours, $Time_Processing.Minutes, $Time_Processing.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

# Creating Secure Archive
if (Test-Path "$($7za)") 
{
    if (Test-Path "$($OUTPUT_FOLDER)") 
    {
        Write-Output "[Info]  Preparing Secure Archive Container ... "
        & $7za a -mx5 -mhe "-p$PASSWORD" -t7z "$OUTPUT_FOLDER.7z" "$OUTPUT_FOLDER\*" > $null 2>&1
    }

    # Archive Size
    $Length = (Get-Item -Path "$OUTPUT_FOLDER.7z").Length
    $Size = Get-FileSize($Length)
    Write-Output "[Info]  Archive Size: $Size"

    # Cleaning up
    if (Test-Path "$($OUTPUT_FOLDER)")
    {
        Get-ChildItem -Path "$OUTPUT_FOLDER" -Recurse | Remove-Item -Force -Recurse
        Remove-Item "$OUTPUT_FOLDER" -Force
    }
}
else
{
    Write-Host "[Error] 7za.exe NOT found." -ForegroundColor Red
}

}

#endregion SecureArchive

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Footer

Function Footer {

# Shutting Down (Unmount)
if (Get-Process -Name "MemProcFS" -ErrorAction SilentlyContinue)
{
    # MessageBox UI
    $Form = New-Object System.Windows.Forms.Form
    $Form.TopMost = $true
    $MessageBody = "Happy Hunting!`n`nMemProcFS - The Memory Process File System by Ulf Frisk`nhttps://github.com/ufrisk/MemProcFS`n`nPress OK to shutdown virtual file system (Unmount)`n`nNote: Elasticsearch will also be stopped."
    $MessageTitle = "MemProcFS-Analyzer.ps1 (https://lethal-forensics.com/)"
    $ButtonType = "OK"
    $MessageIcon = "Info"
    $Result = [System.Windows.Forms.MessageBox]::Show($Form, $MessageBody, $MessageTitle, $ButtonType, $MessageIcon)

    if ($Result -eq "OK" ) 
    {
        Write-Output "[Info]  Shutting Down (Unmount) ..."
        Start-Sleep -Seconds 1

        # MemProcFS
        [void][System.Reflection.Assembly]::LoadWithPartialName("'Microsoft.VisualBasic")
        [void][System.Reflection.Assembly]::LoadWithPartialName("'System.Windows.Forms")
        $Process = Get-Process | Where-Object {$_.Name -eq "MemProcFS"}
        [Microsoft.VisualBasic.Interaction]::AppActivate($Process.Id)
        [System.Windows.Forms.SendKeys]::SendWait("^{c}")

        # Kibana
        if ($Kibana_Termination)
        {
            $Kibana_Termination.CloseMainWindow() > $null
        }

        # Elasticsearch
        if ($Elasticsearch_Termination)
        {
            $Elasticsearch_Termination.CloseMainWindow() > $null
        }

        # Wait for MemProcFS to shut down properly before exiting MemProcFS-Analyzer
        while(@(Get-Process | Where-Object {$_.Name -eq "MemProcFS"}).Count -gt 0) {
            Start-Sleep -Milliseconds 100
        }

        Start-Sleep -Seconds 1
    }
}

# Get End Time
$EndTime_Analysis = (Get-Date)

# Overall Analysis Duration
Write-Output ""
Write-Output "FINISHED!"
$Time_Analysis = ($EndTime_Analysis-$StartTime_Analysis)
$ElapsedTime_Analysis = ('Overall analysis duration: {0} h {1} min {2} sec' -f $Time_Analysis.Hours, $Time_Analysis.Minutes, $Time_Analysis.Seconds)
Write-Output "$ElapsedTime_Analysis"

# Stop logging
Write-Output ""
Stop-Transcript

# Remove Variables

# ClamAV
if (!($null -eq $ClamAV))
{
    Remove-Variable -Name "ClamAV" -Scope Script
}

# ForensicTimelineCSV
if (!($null -eq $ForensicTimelineCSV))
{
    Remove-Variable -Name "ForensicTimelineCSV" -Scope Script
}

# ForensicTimelineXLSX
if (!($null -eq $ForensicTimelineXLSX))
{
    Remove-Variable -Name "ForensicTimelineXLSX" -Scope Script
}

# OfflineMode
if (!($null -eq $OfflineMode))
{
    Remove-Variable -Name "OfflineMode" -Scope Script
}

# YaraRules
if (!($null -eq $YaraRules))
{
    Remove-Variable -Name "YaraRules" -Scope Script
}

# Reset Progress Preference
$Global:ProgressPreference = $OriginalProgressPreference

# Set Windows Title back to default
$Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"

}

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Main

# Main
Header
#Elasticsearch
MicrosoftDefender
MemProcFS
#ELKImport

if ($ClamAV -eq "Enabled")
{
    ClamAVUpdate
    ClamAV
}

Documents
DFIRBatch
#LNK
#LNK_Hunt
ImageMount
Modules
#Invoke-1768
SecureArchive
Footer

#endregion Main
