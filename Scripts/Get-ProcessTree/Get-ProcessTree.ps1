<#
.SYNOPSIS
    Shows a process history tree with data extracted from a MemProcFS-Analyzer process overview CSV
.EXAMPLE
    PS> Get-ProcessTree.ps1 -CSVPath "~\Desktop\proc.csv"
    Shows the process tree using data from the given CSV
.AUTHOR
	Dominik Schmidt @ https://github.com/DaFuqs
.VERSION
    1.5
.VERSION_HISTORY
    1.5: - Load PresentationCore if env does not load it automatically
    1.4: - Nodes to not expand / subtract on double click anymore. This action is already used for opening the properties window
    1.3: - Use a compiled version of DamerauLevenshteinDistance for increased performance
         - Orphaned processes get that listed in the "Suspicious" tag
         - New Switch Param: NoSuspiciousChecks: for when you just want a quick process tree without automatic checks for suspicious entries
         - Right click menu for the popup process properties window to copy selected/all values
    1.2: - Fixed hang when pid<=>parent PPIDs result in a ppid loop (like when PIDs have been reused). Findings will be reported
         - 4 new process masquerading checks:
             - processes with unusual parents
             - processes in unusual paths
             - processes with an unusual number of instances
             - similarly named processes to known-good ones
    1.1: - Double Clicking an Entry brings up a property view
         - Suspicious Entries get colored red and list their suspicion hits in their tooltip + properties view
    1.0: Public release
#>

[CmdletBinding()]

Param (
    # Path to the input CSV file
    [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
	[ValidateScript({try { Test-Path -Path $_ -PathType Leaf } catch { throw "No file at `"$_`"" }})] # test if there is a file at given location
    [string] $CSVPath = ".\proc.csv",
    
    # Process names of script interpreters
    # Will be matched 1:1
    [Parameter(Mandatory=$false)]
    $ScriptInterpreters = @("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "python.exe"),

    [Parameter(Mandatory=$false)]
    $LateralMovementPrograms =  @("*psexec*", "mstsc.exe", "putty.exe", "winscp.exe", "scp.exe"),

    # https://attack.mitre.org/techniques/T1218/
    [Parameter(Mandatory=$false)]
    $SuspiciousPrograms =  @("*certutil.exe", "ping.exe", "msconfig.exe", "nslookup.exe", "ipconfig.exe", "systeminfo.exe", "nltest.exe", "net.exe", "chcp.exe", "bitsadmin.exe", "WSreset.exe", "mshta.exe", 
    "regsvr32.exe", "rundll32.exe", "mavinject.exe", "sc.exe", "tasklist.exe", 
    "msbuild.exe" # https://attack.mitre.org/techniques/T1127/001/
    "adfind.exe" # https://attack.mitre.org/techniques/T1087/002/
    ),

    # 
    [Parameter(Mandatory=$false)]
    $SuspiciousParameters = @(
        [Tuple]::Create("powershell.exe", "-Enc")
        [Tuple]::Create("powershell.exe", "Webclient")
        [Tuple]::Create("powershell.exe", "Hidden")  # T1564.003
        [Tuple]::Create("powershell.exe", "Bypass")
        [Tuple]::Create("wscript.exe", "PubPrn") # https://attack.mitre.org/techniques/T1216/001/
        [Tuple]::Create("cscript.exe", "PubPrn") # https://attack.mitre.org/techniques/T1216/001
    ),

    #  [T1036.007]
    $DoubleFileExtensions,

    # Names of folders where process launch should be noted as suspicious
    # Will be matched via -like (use * as wildcard at start and end)
    [Parameter(Mandatory=$false)]
    $SuspiciousFolders =  @("*\appdata\*", "*\temp\*"),

    # Parent Process Name => File Path
    # Process names will be matched 1:1
    # File Paths will be matched via -like (use * as wildcard at start and end)
    [Parameter(Mandatory=$false)]
    $UnusualRelationships = @(
        [Tuple]::Create("Excel.exe", "*.exe")
        [Tuple]::Create("Word.exe", "*.exe")
        [Tuple]::Create("Outlook.exe", "*.exe")
        [Tuple]::Create("MSEdge.exe", "*.exe")
        [Tuple]::Create("Chrome.exe", "*.exe")
        [Tuple]::Create("Firefox.exe", "*.exe")
        [Tuple]::Create("Schtasks.exe", "powershell.exe")
        [Tuple]::Create("Schtasks.exe", "cmd.exe")
        [Tuple]::Create("Schtasks.exe", "C:\Users\*")
        [Tuple]::Create("Schtasks.exe", "C:\ProgramData\*")
        [Tuple]::Create("Schtasks.exe", "rundll32.exe")
        [Tuple]::Create("userinit.exe", "*exp*")
        [Tuple]::Create("powershell.exe", "*")
        [Tuple]::Create("WMIPrvSE.exe", "*")
        [Tuple]::Create("rundll32.exe", "C:\Users\*")
    ),

    # Known windows processes and their usual parents
    [Parameter(Mandatory=$false)]
    $ExpectedRelationships = @{
        "csrss.exe" = @("smss.exe", "svchost.exe")
        "LogonUI.exe" = @("wininit.exe", "winlogon.exe")
        "lsass.exe" = @("wininit.exe")
        "services.exe" = @("wininit.exe")
        "smss.exe" = @("System", "smss.exe")
        "spoolsv.exe" = @("services.exe")
        "svchost.exe" = @("services.exe", "MsMpEng.exe", "svchost.exe")
        "taskhost.exe" = @("services.exe", "svchost.exe")
        "taskhostw.exe" = @("services.exe", "svchost.exe")
        "userinit.exe" = @("dwm.exe", "winlogon.exe")
        "wininit.exe" = @("smss.exe")
        "winlogon.exe" = @("smss.exe")
    },

    # They will be matched using regex
    [Parameter(Mandatory=$false)]
    $ExpectedProcessPaths = @{
        "csrss.exe" = "\\Windows\\System32\\csrss\.exe"
        "explorer.exe" = "\\Windows\\explorer\.exe"
        "lsass.exe" = "\\Windows\\System32\\lsass\.exe"
        "lsm.exe" = "\\Windows\\System32\\lsm\.exe"
        "services.exe" = "\\Windows\\System32\\services\.exe"
        "smss.exe" = "\\Windows\\System32\\smss\.exe"
        "svchost.exe" = "\\Windows\\(System32)?(SysWOW64)?\\svchost\.exe"
        "taskhost.exe" = "\\Windows\\System32\\taskhost\.exe"
        "taskhostw.exe" = "\\Windows\\System32\\taskhostw\.exe"
        "wininit.exe" = "\\Windows\\System32\\wininit\.exe"
        "winlogon.exe" = "\\Windows\\System32\\winlogon\.exe"
    },

    [Parameter(Mandatory=$false)]
    $ExpectedProcessInstanceCounts = @{
        "lsaiso.exe" = 1
        "lsass.exe" = 1
        "lsm.exe" = 1
        "services.exe" = 1
        "wininit.exe" = 1
    },

    [Parameter(Mandatory=$false)]
    $ProcessesToSearchSimilarNames = @("csrss.exe", "dllhost.exe", "explorer.exe", "iexplore.exe", "lsass.exe", "sihost.exe", "smss.exe", "svchost.exe", "winlogon.exe"),

    # Directly display not only process names, but also PIDs
    [Parameter(Mandatory=$false)]
    [switch] $VisualPIDs = $true,
    
    # Skips all checks of suspicous entries, making the GUI display much faster
    [Parameter(Mandatory=$false)]
    [switch] $NoSuspiciousChecks
)

[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows")
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
[void][System.Reflection.Assembly]::LoadWithPartialName("PresentationFramework")
[void][System.Reflection.Assembly]::LoadWithPartialName("PresentationCore")


# querying the entries of the csv file
$csvEntries = @(Import-CSV -Path $CSVPath -Delimiter "`t")


####################################
#region    DOTNET-SHENANIGANS      #
####################################


try {
    [LevenshteinDistance]::new() -as [Type] | Out-Null
} catch {
    Add-Type -Path (Join-Path $PSScriptRoot -ChildPath "..\Measure-DamerauLevenshteinDistance\Measure-DamerauLevenshteinDistance.cs") | Out-Null
}


# Fuse of
# https://docs.microsoft.com/en-us/dotnet/api/system.windows.forms.treeview.treeviewnodesorter
# https://www.dotnetperls.com/alphanumeric-sorting
try {
    [TreeNodeAlphanumComparator] -as [Type] | Out-Null
} catch {
    Add-Type @"
using System;
using System.Collections;
using System.Windows.Forms;
public class TreeNodeAlphanumComparator : IComparer {
    public int Compare(object x, object y) {
        TreeNode tx = x as TreeNode;
        TreeNode ty = y as TreeNode;
        if (tx == null) {
            return 0;
        }
        if (ty == null) {
            return 0;
        }
        string s1 = tx.Text;
        if (s1 == null) {
            return 0;
        }
        string s2 = ty.Text;
        if (s2 == null) {
            return 0;
        }
        
        int len1 = s1.Length;
        int len2 = s2.Length;
        int marker1 = 0;
        int marker2 = 0;
        
        // Walk through two the strings with two markers.
        while (marker1 < len1 && marker2 < len2) {
            char ch1 = s1[marker1];
            char ch2 = s2[marker2];
            
            // Some buffers we can build up characters in for each chunk.
            char[] space1 = new char[len1];
            int loc1 = 0;
            char[] space2 = new char[len2];
            int loc2 = 0;
            
            // Walk through all following characters that are digits or
            // characters in BOTH strings starting at the appropriate marker.
            // Collect char arrays.
            do {
                space1[loc1++] = ch1;
                marker1++;
                
                if (marker1 < len1) {
                    ch1 = s1[marker1];
                } else {
                    break;
                }
            } while (char.IsDigit(ch1) == char.IsDigit(space1[0]));
            
            do {
                space2[loc2++] = ch2;
                marker2++;
                
                if (marker2 < len2) {
                    ch2 = s2[marker2];
                } else {
                    break;
                }
            } while (char.IsDigit(ch2) == char.IsDigit(space2[0]));
            
            // If we have collected numbers, compare them numerically.
            // Otherwise, if we have strings, compare them alphabetically.
            string str1 = new string(space1);
            string str2 = new string(space2);
            
            int result;
            
            if (char.IsDigit(space1[0]) && char.IsDigit(space2[0])) {
                int thisNumericChunk = int.Parse(str1);
                int thatNumericChunk = int.Parse(str2);
                result = thisNumericChunk.CompareTo(thatNumericChunk);
            } else {
                result = str1.CompareTo(str2);
            }
            
            if (result != 0) {
                return result;
            }
        }
        return len1 - len2;
    }
}
"@ -ReferencedAssemblies System.Windows.Forms | Out-Null
}

####################################
#endregion DOTNET-SHENANIGANS      #
####################################


####################################
#region    HELPER FUNCTIONS        #
####################################

# huge thanks to
# https://nasbench.medium.com/demystifying-the-svchost-exe-process-and-its-command-line-options-508e9114e747
# for the great writeup!
function Get-SVCHostData($k, $s) {
    $values = @((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\").$k)
    if($s) {
        if($values -contains($s)) {
            return "[$s]"
        } else {
            return "[???]"
        }
    }
    return "[" + ($values -join ", ") + "]"
}

function Is-Match($Text, $SearchText, $SearchMode) {
    if($searchMode -eq 0) { # plaintext
        if($text -and $Text.toLower().Contains($SearchText.toLower())) {
            return $true
        }
    } elseif($searchMode -eq 1) { # extended
        if($Text -like $SearchText) {
            return $true
        }
    } else { # regex
        if($Text -match $SearchText) {
            return $true
        }
    }
    $false
}

function Show-EntryWindow($entry) {
    # create form for displaying the folder tree
    $entryForm = New-Object System.Windows.Forms.Form
    $entryForm.Text = $entry."Process Name" + ": " + $entry.PID + " - Properties"
    $entryForm.Size = New-Object System.Drawing.Size(500, 395)
    $entryForm.Icon = $icon

    $alternateCellStyle = New-Object System.Windows.Forms.DataGridViewCellStyle
    $alternateCellStyle.BackColor = [System.Drawing.SystemColors]::ControlLight
    
    $script:dataGridView = New-Object System.Windows.Forms.DataGridView
    $dataGridView.Name = "EntryPropertiesGridView"
    $dataGridView.AllowUserToAddRows = $false
    $dataGridView.AllowUserToDeleteRows = $false
    $dataGridView.AllowUserToOrderColumns = $false
    $dataGridView.AllowUserToResizeRows = $false
    $dataGridView.ColumnHeadersHeightSizeMode = [System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::DisableResizing
    $dataGridView.RowHeadersVisible = $false
    $dataGridView.ReadOnly = $true
    $dataGridView.ColumnCount = 2
    $dataGridView.Columns[0].Name = "Property"
    $dataGridView.Columns[0].AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::AllCells
    $dataGridView.Columns[1].Name = "Value"
    $dataGridView.Columns[1].AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
    $dataGridView.AlternatingRowsDefaultCellStyle = $alternateCellStyle
    $dataGridView.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $dataGridView.Dock = [System.Windows.Forms.DockStyle]::Fill

    $contextMenuStrip = New-Object System.Windows.Forms.ContextMenuStrip
    $contextMenuStrip.Items.Add("Copy highlighted rows").add_Click({
        $sb = New-Object System.Text.StringBuilder
        foreach($row in $dataGridView.SelectedRows) {
            $sb.AppendLine($row.Cells[0].Value + " " + $row.Cells[1].Value)
        }
        [System.Windows.Forms.Clipboard]::SetText($sb.ToString())
    })
    $contextMenuStrip.Items.Add("Copy all rows").add_Click({
        $sb = New-Object System.Text.StringBuilder
        foreach($row in $dataGridView.Rows) {
            $sb.AppendLine($row.Cells[0].Value + " " + $row.Cells[1].Value)
        }
        [System.Windows.Forms.Clipboard]::SetText($sb.ToString())
    })
    $dataGridView.ContextMenuStrip = $contextMenuStrip

    foreach($property in $entry.psobject.Properties) {
        $dataGridView.Rows.Add($property.Name + ":", $property.Value)
    }

    $entryForm.BackColor = [System.Drawing.SystemColors]::ControlLight
    $entryForm.Controls.Add($dataGridView)
    $entryForm.Show()
}

function Note-Suspicious($Node, $Description) {
    if($Node.Tag.Suspicious) {
        $Node.Tag.Suspicious = $Node.Tag.Suspicious + ", " + $Description
    } else {
        $Node.Tag.Suspicious = $Description
    }
    $Node.ForeColor = [System.Drawing.Color]::Red
    $Node.ToolTipText = ($Node.Tag | Out-String).Trim() -replace " *:", ":"
}

function Set-Suspicious($Node, $ParentID, $Description, $ShortId) {
    Note-Suspicious -Node $node -Description $Description
    New-Node -ID $($Node.Tag.PID + "_" + $ShortId) -Text $process."Call Chain" -Tooltip $node.ToolTipText -Parent $ParentID -Tag $Node.Tag
}

####################################
#endregion HELPER FUNCTIONS        #
####################################


####################################
#region    GUI                     #
####################################

# create form for displaying the folder tree
$Form = New-Object System.Windows.Forms.Form
$Form.Text = "MemProcFS-Analyzer - Process Tree"
$Form.Size = New-Object System.Drawing.Size(800, 600)

# the icon (base 64 encoded png, converted and set as icon)
$base64Icon = "iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAABmJLR0QAAAAAAAD5Q7t/AAAACXBIWXMAAABgAAAAYADwa0LPAAAAxElEQVRIx+3TsWoCQRCA4Y8kNkklnCRVEB/gGh/ZB8gTCJo6zYGtiJ0vYH0pMsJiItzpRBt/WLid5f6Znd3lzq15TPY94wM7bLKLfcESLVZ4uEQ2xiykx/JNrP+i7TAOLGK+xGsXed8E45C12HeRn8M71iHfYpIpL3eyyK78KtT4xFsRG8VuphkJ5n5636CK0URsnpGgFDZH39Wpn/pcUxjiq1j7U37Jc37CoJgPIpbCWS3qw78fch2istoqYnVWm+7k8A1FT08gOQfCGwAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAyMi0wOS0wNVQxMjoyMTozMSswMDowMOTTZSwAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMjItMDktMDVUMTI6MjE6MzErMDA6MDCVjt2QAAAAAElFTkSuQmCC"
$bitmap = New-Object System.Windows.Media.Imaging.BitmapImage
$bitmap.BeginInit()
$bitmap.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($base64Icon)
$bitmap.EndInit()
$bitmap.Freeze()
$image = [System.Drawing.Bitmap][System.Drawing.Image]::FromStream($bitmap.StreamSource)
$icon = [System.Drawing.Icon]::FromHandle($image.GetHicon())
$Form.Icon = $icon

# the main tree
$TreeView = New-Object System.Windows.Forms.TreeView
$TreeView.Dock = [System.Windows.Forms.DockStyle]::Fill
$TreeView.TreeViewNodeSorter = New-Object -TypeName TreeNodeAlphanumComparator
$TreeView.ShowNodeToolTips = $true
$Form.Controls.Add($TreeView)

# top "search" strip
$MenuStrip = New-Object System.Windows.Forms.MenuStrip
$MenuStrip.ShowItemToolTips = $true
$MenuStrip.Dock = [System.Windows.Forms.DockStyle]::Top

$ExpandButton = New-Object System.Windows.Forms.ToolStripButton
$ExpandButton.Text = "+"
$ExpandButton.ToolTipText = "Expand All"
$ExpandButton.Add_Click({
    $TreeView.ExpandAll()
})

$CollapseButton = New-Object System.Windows.Forms.ToolStripButton
$CollapseButton.Text = "-"
$CollapseButton.ToolTipText = "Collapse All"
$CollapseButton.Add_Click({
    $TreeView.CollapseAll()
})
$ButtonSeparator = New-Object System.Windows.Forms.ToolStripSeparator

# Search
$SearchTextStrip = New-Object System.Windows.Forms.ToolStripStatusLabel
$SearchTextStrip.Text = "Search:"

$SearchBox = New-Object System.Windows.Forms.ToolStripTextBox
$SearchBox.Size = New-Object System.Drawing.Size(250, $SearchBox.Size.Height)
$SearchBox.Add_TextChanged({
    Search-Nodes
})

$SearchTextStrip2 = New-Object System.Windows.Forms.ToolStripStatusLabel
$SearchTextStrip2.Text = "Mode:"

$SearchModeDropDownButton = New-Object System.Windows.Forms.ToolStripDropDownButton
$SearchModeDropDown = New-Object System.Windows.Forms.ToolStripDropDown
[void] $SearchModeDropDown.Items.Add("Plaintext")
[void] $SearchModeDropDown.Items.Add("Extended")
[void] $SearchModeDropDown.Items.Add("RegEx")
$SearchModeDropDownButton.Text = $SearchModeDropDown.Items[0]
$SearchModeDropDownButton.DropDown = $SearchModeDropDown

$SearchModeDropDown.Add_ItemClicked({
    $SearchModeDropDownButton.Text = $_.ClickedItem.Text
    Search-Nodes
})

$SearchTextStrip3 = New-Object System.Windows.Forms.ToolStripStatusLabel
$SearchTextStrip3.Text = "Filter:"

$SearchLocationDropDownButton = New-Object System.Windows.Forms.ToolStripDropDownButton
$SearchLocationDropDown = New-Object System.Windows.Forms.ToolStripDropDown
[void] $SearchLocationDropDown.Items.Add("Everywhere")
[void] $SearchLocationDropDown.Items.Add("Call Chain")
$blacklistedSearchEntries = @("Sub-Processes")
foreach($property in $csvEntries[0].PSObject.Properties | Sort-Object) {
    if($property.Name -notin $blacklistedSearchEntries) {
        [void] $SearchLocationDropDown.Items.Add($property.Name)
    }
}
$SearchLocationDropDownButton.Text = $SearchLocationDropDown.Items[0]
$SearchLocationDropDownButton.DropDown = $SearchLocationDropDown

$SearchLocationDropDown.Add_ItemClicked({
    $SearchLocationDropDownButton.Text = $_.ClickedItem.Text
    Search-Nodes
})

# Dispay Mode Selection
$DisplayModeSeparator = New-Object System.Windows.Forms.ToolStripSeparator
$DisplayModeTextStrip = New-Object System.Windows.Forms.ToolStripStatusLabel
$DisplayModeTextStrip.Text = "Display Mode:"

$DisplayModeDropDown = New-Object System.Windows.Forms.ToolStripDropDown
[void] $DisplayModeDropDown.Items.Add("PID: Name")
[void] $DisplayModeDropDown.Items.Add("Name")

$DisplayModeDropDownButton = New-Object System.Windows.Forms.ToolStripDropDownButton
if($VisualPIDs) {
    $DisplayModeDropDownButton.Text = $DisplayModeDropDown.Items[0]
} else {
    $DisplayModeDropDownButton.Text = $DisplayModeDropDown.Items[1]
}
$DisplayModeDropDownButton.DropDown = $DisplayModeDropDown

$DisplayModeDropDown.Add_ItemClicked({
    $newValue = $_.ClickedItem.Text
    $currentValue = $DisplayModeDropDownButton.Text
    if($newValue -ne $currentValue) {
        $DisplayModeDropDownButton.Text = $newValue
        if($newValue -eq "PID: Name") {
            $VisualPIDs = $true
        } else {
            $VisualPIDs = $false
        }

        Fill-GUIData
    }
})

$MenuStrip.Items.AddRange($ExpandButton)
$MenuStrip.Items.AddRange($CollapseButton)
$MenuStrip.Items.AddRange($ButtonSeparator)

$MenuStrip.Items.AddRange($SearchTextStrip)
$MenuStrip.Items.AddRange($SearchBox)
$MenuStrip.Items.AddRange($SearchTextStrip2)
$MenuStrip.Items.AddRange($SearchModeDropDownButton)
$MenuStrip.Items.AddRange($SearchTextStrip3)
$MenuStrip.Items.AddRange($SearchLocationDropDownButton)

$MenuStrip.Items.AddRange($DisplayModeSeparator)
$MenuStrip.Items.AddRange($DisplayModeTextStrip)
$MenuStrip.Items.AddRange($DisplayModeDropDownButton)
$Form.Controls.Add($MenuStrip)

# bottom "statistics" strip
$StatusStrip = New-Object System.Windows.Forms.StatusStrip
$StatusStrip.Dock = [System.Windows.Forms.DockStyle]::Bottom
$StatusStrip.LayoutStyle = [System.Windows.Forms.ToolStripLayoutStyle]::HorizontalStackWithOverflow

# text block that lists the count of found elements in the bottom strip
$ElementCountLabel = New-Object System.Windows.Forms.ToolStripStatusLabel

$OSStartLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$OSStartLabel.Alignment = [System.Windows.Forms.ToolStripItemAlignment]::Right
$OSStartLabel.BorderStyle = [System.Windows.Forms.Border3DStyle]::Raised

$StatusStrip.Items.AddRange($ElementCountLabel)
$StatusStrip.Items.AddRange($OSStartLabel)
$Form.Controls.Add($StatusStrip)

####################################
#endregion GUI                     #
####################################


####################################
#region    DISPLAY                 #
####################################

$script:dataInitialised = $false

function Search-Nodes {
    $expandSet = [System.Collections.Generic.HashSet[System.Windows.Forms.TreeNode]]@()

    # iterate through all nodes in the treeview
    # and expand / collapse them according to the search
    $searchText = $SearchBox.Text
    $clear = $searchtext -eq ""
    $searchLocation = $SearchLocationDropDownButton.Text

    # Map search mode to an int (faster than string compare every time)
    # ideally use an enum here, but that's a newer PS feature
    [int] $searchMode = 0
    switch ($SearchModeDropDownButton.Text) {
        'PlainText' { $searchMode = 0}
        'Extended' { $searchMode = 1 }
        Default { # regex
            $searchMode = 2
            try {
                [regex] $searchText
            } catch {
                # current serach text is not valid regex
                return
            }
        }
    }

    $TreeView.BeginUpdate() # do not redraw the tree view everytime a property changes
   
    $queue = New-Object System.Collections.Queue
    foreach($node in $TreeView.Nodes) {
        $queue.Enqueue($node)
    }

    while($queue.Count -gt 0) {
        $node = $queue.Dequeue()
        foreach($childNode in $node.Nodes) {
            $queue.Enqueue($childNode)
        }

        $node.Collapse()
        $node.BackColor = [System.Drawing.Color]::Transparent

        if(!$clear) {
            $element = $node.Tag
            $match = $false
            if($null -eq $element) {
                # node without element. Never matches
            } if($searchLocation -eq "Everywhere") {
                foreach($property in $element.PSObject.Properties) {
                    if($property.Name -eq "Call Chain") {
                        continue
                    }
                    if(Is-Match -Text $property.Value -SearchText $searchText -SearchMode $searchMode) {
                        $match = $true
                        break
                    }
                }
            } else {
                $match = Is-Match -Text $element.$searchLocation -SearchText $searchText -SearchMode $searchMode
            }

            if($match) {
                $node.BackColor = [System.Drawing.Color]::Yellow

                # note this node and all of it's parents to expand later
                $currentNode = $node
                do {
                    $expandSet.Add($currentNode)
                    $currentNode = $currentNode.Parent
                } while ($null -ne $currentNode)
            }
        }
    }

    foreach($expandEntry in $expandSet) {
        $expandEntry.expand()
    }
    $TreeView.EndUpdate()
}

function New-Node($ID, $Text, $Tooltip, $Parent, $Tag, [switch] $AddToMap) {
    $newNode = New-Object System.Windows.Forms.TreeNode
    $newNode.Name = $ID
    $newNode.Text = if($Text) { $Text } else { "<unknown>" }
    $newNode.ToolTipText = $Tooltip
    if($AddToMap) {
        $nodesMap[$ID] = $newNode
    }
    if($Tag) {
        $newNode.Tag = $Tag
    }
    if($Parent) {
        [void] $nodesMap[$Parent].Nodes.Add($newNode)
    } else {
        [void] $TreeView.Nodes.Add($newNode)
    }
}

function Set-Nodes($Root, $Depth, $Collapsed) {
    $TreeView.BeginUpdate() # do not redraw the tree view everytime a property changes
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue([Tuple]::Create($Root, 0))

    while($queue.Count -gt 0) {
        $entry = $queue.Dequeue()
        $node = $entry.Item1
        $currentDepth = $entry.Item2

        if($currentDepth -lt $Depth) {
            foreach($childNode in $node.Nodes) {
                $queue.Enqueue([Tuple]::Create($childNode, $currentDepth + 1))
            }
        }

        if($collapsed) {
            $node.Collapse()
        } else {
            $node.Expand()
        }
   }
   $TreeView.EndUpdate()
}

<#
    In the tree view, we want nodes that are double clicked on, to show a properties view popup.
    Since by default, tree nodes have an event mapped to double click already (namely expanding / collapsing the node),
    we have to check if it's a double click in BeforeExpand() and BeforeCollapse() and cancel this default behavior
    so it does not interfere with the opening of our new properties window
    The user is still able to nagigate the tree via keyboard, or as usual, by using the +/- buttons on each node
#>
$script:CancelNodeExpanding = $false

function Fill-GUIData {
    $TreeView.BeginUpdate()
    $TreeView.Nodes.Clear()
    $TreeView.Add_KeyDown({
        # Ctrl+C override
        # If there is a better event handler please enlighten me
        # it makes the annoying "warning" sound, for whatever reason
        if($_.Control -and $_.KeyCode -eq "C") {
            $node = $TreeView.SelectedNode
            if($node -and $node.TooltipText) {
                [System.Windows.Forms.Clipboard]::SetDataObject($node.TooltipText)
            }
        }
    })
    $TreeView.Add_MouseDown({
        $script:CancelNodeExpanding = $_.Clicks -gt 1
    })
    $TreeView.Add_BeforeExpand({
        $_.Cancel = $script:CancelNodeExpanding
    })
    $TreeView.Add_BeforeCollapse({
        $_.Cancel = $script:CancelNodeExpanding
    })
    
    $TreeView.Add_NodeMouseDoubleClick({
        if($_.Node.Tag) {
            if(-not $_.Node.IsExpanded) {
                $_.Node.Expand()
            } else {
                $_.Node.Collapse();
            }

            Show-EntryWindow($_.Node.Tag)
            return $false
        }
    })
    $nodesMap = @{}
    
    $TotalProcesses = ($csvEntries).Count
    $RunningProcesses = ($csvEntries | Where-Object { $_."Exit Time" -eq "" }).Count
    $ExitedProcesses = ($csvEntries | Where-Object { $_."Exit Time" -ne "" }).Count
    $ElementCountLabel.Text = "Total Processes: $TotalProcesses | Running Processes: $RunningProcesses | Exited Processes: $ExitedProcesses"

    # a list of dedicated (root) nodes for special case handling
    $orphanID = $((New-Guid).Guid)
    New-Node -ID $orphanID -Text "Orphan Processes" -Tooltip "Processes where parent processes could not be found anymore" -AddToMap

    $notableID = $((New-Guid).Guid)
    New-Node -ID $notableID -Text "Alert Messages" -Tooltip "Common low hanging fruits" -AddToMap

    # LP_Windows Processes Suspicious Parent Directory Detected
    # Trigger Condition: Suspicious parent processes of Windows processes are detected.
    # ATT&CK Category: Defense Evasion
    # ATT&CK Tag: Masquerading
    $unusualRelationShipsID = $((New-Guid).Guid)
    New-Node -ID $unusualRelationShipsID -Text "Suspicious Parent-Child Relationships [T1036]" -Tooltip "Processes called from an unusual parent process" -Parent $notableID -AddToMap

    $scriptInterpretersID = $((New-Guid).Guid)
    New-Node -ID $scriptInterpretersID -Text "Command and Scripting Interpreters [T1059]" -Tooltip "CMD, Python, VB, Powershell, you name it" -Parent $notableID -AddToMap

    $suspiciousFoldersID = $((New-Guid).Guid)
    New-Node -ID $suspiciousFoldersID -Text "Suspicious Process File Path [T1543]" -Tooltip "Process Execution from an Unusual Directory" -Parent $notableID -AddToMap

    $lateralMovementProgramsID = $((New-Guid).Guid)
    New-Node -ID $lateralMovementProgramsID -Text "Lateral Movement Tools [TA0008]" -Tooltip "Process Execution from an Unusual Directory" -Parent $notableID -AddToMap

    $suspiciousProgramsID = $((New-Guid).Guid)
    New-Node -ID $suspiciousProgramsID -Text "Suspicious Program Execution [T1218, T1127.001, T1087.002]" -Tooltip "All kinds of suspicious Programs, usually used for Discovery, Privilege Escalation to Proxy Execution" -Parent $notableID -AddToMap

    $doubleFileExtensionsID = $((New-Guid).Guid)
    New-Node -ID $doubleFileExtensionsID -Text "Double File Extensions [T1036.007]" -Tooltip "Processes spawned from execuables using a double file extension, most often in a way to deceive users to execute malicious payloads, like 'invoice.doc.exe'" -Parent $notableID -AddToMap

    $suspiciousParametersID = $((New-Guid).Guid)
    New-Node -ID $suspiciousParametersID -Text "Suspicious Command Line Parameters" -Tooltip "Command Line Parameters that are oftentimes used my malware" -Parent $notableID -AddToMap

    $expectedRelationshipDiscrepancyID = $((New-Guid).Guid)
    New-Node -ID $expectedRelationshipDiscrepancyID -Text "Processes with different Parent than usual [T1036.005]" -Tooltip "The process loading chain of system processes is mostly fixed, like lsass.exe always getting started via wininit.exe. Are there discrepancies, chances are they got started for means of process injection, or by giving a malicious payload the same name as a known good process, but in a different path." -Parent $notableID -AddToMap
    
    $expectedProcessPathDiscrepancyID = $((New-Guid).Guid)
    New-Node -ID $expectedProcessPathDiscrepancyID -Text "Known Process Names in different Path [T1036.005]" -Tooltip "System processes have a dedicated path where their executables are stored (such as in %windir%). If a process with a well known name runs in a different folder, chances are it is malicious and the name was chosen to fly under the radar" -Parent $notableID -AddToMap
    
    $expectedProcessInstanceDiscrepancyID = $((New-Guid).Guid)
    New-Node -ID $expectedProcessInstanceDiscrepancyID -Text "Process instance count mismatch [T1036.005]" -Tooltip "Lots of system processes have a fixed number of instances runnung simultaneously - most often 1. If there are more, chances are they got started for means of process injection, or by giving a malicious payload the same name as a known good process, but in a different path." -Parent $notableID -AddToMap
    
    $ProcessNameMasqueradingID = $((New-Guid).Guid)
    New-Node -ID $ProcessNameMasqueradingID -Text "Process Name Masquerading [T1036.005]" -Tooltip "Attackers name their payloads similar to known system processes to avoid detection. Something like 'lsaas.exe' closely resembles the legitimate 'lsass.exe' on first glance." -Parent $notableID -AddToMap

    $runningInUNCNetworkPathID = $((New-Guid).Guid)
    New-Node -ID $runningInUNCNetworkPathID -Text "Processes running from UNC Network Paths" -Tooltip "Processes running in UNC paths can hint to remote execution through file shares without having to copy malicious files to the local system" -Parent $notableID -AddToMap

    # create nodes, but not attach them yet. It will make parent search possible.
    foreach ($csvEntry in $csvEntries) {
        # Add a "Suspicious" attribute
        Add-Member -InputObject $csvEntry -MemberType NoteProperty -Name "Suspicious" -Value ""

        $newNode = New-Object System.Windows.Forms.TreeNode
        if($VisualPIDs) {
            $newNode.Text = $(if($csvEntry.PID) { $csvEntry.PID } else { "???" }) + ": " + $(if($csvEntry."Process Name") { $csvEntry."Process Name" } else { "<unknown>" })
        } else {
            $newNode.Text = if($csvEntry."Process Name") { $csvEntry."Process Name" } else { "<unknown>" }
        }

        # custom handling for svchost.exe
        # add command line parameters to displayed node
        if($csvEntry."Process Name" -eq "svchost.exe") {
            $newText = $newNode.Text
            $svcHostS = $null
            $svcHostK = $null
            if($csvEntry.CommandLine -match "-s (\w+)") {
                $svcHostS = $Matches[0] -replace "-s ", ""
            }
            if($csvEntry.CommandLine -match "-k (\w+)") {
                $svcHostK = $Matches[0] -replace "-k ", ""
            }
            if($svcHostK) {
                $newNode.Text = $newText + " " + (Get-SVCHostData -K $svcHostK -S $svcHostS)
            }
        }

        $newNode.Name = $csvEntry.PID
        $newNode.Tag = $csvEntry
        $newNode.ToolTipText = ($csvEntry | Out-String).Trim() -replace " *:", ":"
        $nodesMap[$csvEntry.PID] = $newNode
    }

    # iterate all nodes and attach each node to its parent
    foreach ($entry in $nodesMap.GetEnumerator()) {
        # skip nodes without tag (root tags)
        if($null -eq $entry.Value.Tag) {
            continue
        }
    
        $currPID = $entry.Key
        $currNode = $entry.Value
        $currProcess = $entry.Value.Tag
    
        # PID 4 is the known PID of the system process
        # this is where the system started up. Note startup time in the entry
        # this entry will be used as root, therefore it does not need
        # to get attached to an other element
        if ($currProcess.PID -eq 4) {
            $OSStartLabel.Text = "Windows Start: " + $currProcess."Create Time"
            [void] $TreeView.Nodes.Add($nodesMap[$currPID])
            continue
        }

        # entries who PPID does not exist get attached to the ORPHANS node instead
        $parentNode = $nodesMap[$currProcess.PPID]
        if ($null -eq $parentNode) {
            $parentNode = $orphanNode
            $currProcess.Suspicious = "Orphaned"
        }
    
        # attach this node to the element with matching PID => PPID
        $cyclicalPIDRelationship = $false
        $cyclicalParent = $false
        $PIDTreeList = New-Object System.Collections.ArrayList

        $checkProcess = $currProcess
        $checkNode = $currNode
        $orphanNode = $nodesMap[$orphanID]
        Write-Verbose "Starting with $($checkProcess.PID)"
        while($checkProcess) {
            if($checkNode.Parent -eq $orphanNode) {
                Write-Verbose ".......PID $($checkProcess.PID) is already known having a cyclical PID relationship. Aborting."
                $cyclicalParent = $true
                break
            }
            [void] $PIDTreeList.Add($checkProcess.PID)
            $checkNode = $nodesMap[$checkProcess.PPID]
            $checkProcess = $checkNode.Tag
            Write-Verbose "...checking $($checkProcess.PID) (Tree: $($PIDTreeList))"
            if($PIDTreeList.Contains($checkProcess.PID)) {
                Write-Verbose "......cyclical pid<=>ppid relationship found: PID $($checkProcess.PID)"
                $cyclicalPIDRelationship = $true
                break
            }
        }

        if($cyclicalPIDRelationship) {
            if(-not $orphanNode.Nodes.Contains($checkNode)) {
                Note-Suspicious -Node $checkNode -Description "Cyclical PID Relationship (Process with PID $($checkProcess.PPID) is a child process of this)"
                [void] $orphanNode.Nodes.Add($checkNode)
            }
        }

        if($cyclicalParent -and $checkProcess -eq $currProcess) {
            Write-Verbose "NOT ADDING $($currProcess.PID) to node with PID $($nodesMap[$currProcess.PPID].Tag.PID) - currently already: $($nodesMap[$currProcess.PPID].Nodes.Tag.PID)"
        } else {
            Write-Verbose "Adding $($currProcess.PID) to node with PID $($nodesMap[$currProcess.PPID].Tag.PID) - currently already: $($nodesMap[$currProcess.PPID].Nodes.Tag.PID)"
            [void] $parentNode.Nodes.Add($currNode)
        }
    }

    # one last iteration: add a full path property to all nodes
    foreach ($node in @($nodesMap.Values)) {
        $process = $node.Tag
        if($null -ne $process) {        
            # Add a "Call Chain" attribute
            $processTree = $node.Text
            $currentNode = $node
            while($null -ne $currentNode.Parent -and $null -ne $currentNode.Parent.Tag) {
                $parentNode = $currentNode.Parent
                [string]$processTree = $parentNode.Tag.'Process Name' + " → " + $processTree
                $currentNode = $parentNode
            }

            if($script:dataInitialised) {
                $process."Call Chain" = $processTree
            } else {
                Add-Member -InputObject $process -MemberType NoteProperty -Name "Call Chain" -Value $processTree
            }

            $node.ToolTipText = ($process | Out-String).Trim() -replace " *:", ":"
        }

        if(-not $NoSuspiciousChecks) {
            # enumerate each process and search if they match any notable criteria
            # script interpreters
            if($null -ne $process.'Process Name') {
                # script interpreters
                if ($process.'Process Name' -in $scriptInterpreters) {
                    Set-Suspicious -Node $node -ParentID $scriptInterpretersID -Description "Script Interpreter" -ShortId "in"
                }

                # lateral movement programs
                if($process.'Process Name' -in $LateralMovementPrograms) {
                    Set-Suspicious -Node $node -ParentID $lateralMovementProgramsID -Description "Lateral Movement Program" -ShortId "lm"
                }

                # suspicious programs
                if($process.'Process Name' -in $SuspiciousPrograms) {
                    Set-Suspicious -Node $node -ParentID $suspiciousProgramsID -Description "Suspicious Program" -ShortId "sp"
                }

                # double file extensions
                if($process.'Process Name') {
                    $dotCount = ($process.'Process Name'.ToCharArray() | Where-Object {$_ -eq '.'} | Measure-Object).Count
                    if($dotCount -gt 1) {
                        Set-Suspicious -Node $node -ParentID $doubleFileExtensionsID -Description "Double File Extension" -ShortId "dfe"
                    }
                }

                # suspicious parameters
                if($process.CommandLine) {
                    foreach($suspiciousParameter in $SuspiciousParameters) {
                        if($process.'Process Name' -like $suspiciousParameter.Item1 -and $process.CommandLine -like $suspiciousParameter.Item2) {
                            Set-Suspicious -Node $node -ParentID $suspiciousParametersID -Description "Suspicious Command Line Parameters" -ShortId "sparam"
                        }
                    }
                }

                # known good processes but with unusual parent
                if($ExpectedRelationships.ContainsKey($process.'Process Name')) {
                    $acceptableParents = $ExpectedRelationships[$process.'Process Name']
                    $parentProcessNode = $nodesMap[$process.PPID]
                    if($null -ne $parentProcessNode -and $null -ne $parentProcessNode.Tag) {
                        if($parentProcessNode.Tag.'Process Name' -notin $acceptableParents) {
                            Set-Suspicious -Node $node -ParentID $expectedRelationshipDiscrepancyID -Description $("Parent process mismatch. Should match one of: " + $acceptableParents -join ", ") -ShortId "accp"
                        }
                    }
                }

                # check the number of running instances with the same process name.
                # does the found count match the expected count?
                if($ExpectedProcessInstanceCounts.ContainsKey($process.'Process Name')) {
                    $expectedInstances = $ExpectedProcessInstanceCounts[$process.'Process Name']
                    [int] $runningInstances = 0 # the upcoming loop also counts this instance, so we start at 0 instead of 1
                    foreach($mapNode in $nodesMap.Values) {
                        if($null -ne $mapNode.Tag -and $process.'Process Name' -eq $mapNode.Tag.'Process Name') {
                            $runningInstances++
                        }
                    }
                    if($expectedInstances -ne $runningInstances) {
                        Set-Suspicious -Node $node -ParentID $expectedProcessInstanceDiscrepancyID -Description $("Found " + $runningInstances + " running instances instead of the expected " + $expectedInstances) -ShortId "eicm"
                    }
                }

                # check if this process name is typed very similar than known good ones
                foreach($similarName in $ProcessesToSearchSimilarNames) {
                    [int] $distance = [LevenshteinDistance]::Measure($process.'Process Name', $similarName)
                    if($distance -eq 1) {
                        Set-Suspicious -Node $node -ParentID $ProcessNameMasqueradingID -Description $("Name " + $process.'Process Name' + " is very similar to known " + $similarName) -ShortId "pnm"
                    }
                }
            }

            if($null -ne $process.'File Path') {
                # unusual file locations
                foreach($suspiciousFolder in $suspiciousFolders) {
                    if($process.'File Path' -like $suspiciousFolder) {
                        Set-Suspicious -Node $node -ParentID $suspiciousFoldersID -Description "Running in Suspicious Folder" -ShortId "sf"
                        break
                    }
                }
        
                # unusual parent <=> child relationship
                if($node.Tag.PID -and $nodesMap.ContainsKey($node.Tag.PID)) {
                    $parentNode = $nodesMap[$node.Tag.PID]
                    if($null -ne $parentNode -and $null -ne $parentNode.Tag -and $null -ne $parentNode.Tag.'Process Name') {
                        $parentProcess = $parent.Tag
                        foreach($unusualRelationShip in $unusualRelationShips) {
                            if($parentProcess.'Process Name' -like $unusualRelationShip.Item1 -and $process.'File Path' -like $unusualRelationShip.Item2) {
                                Set-Suspicious -Node $node -ParentID $unusualRelationShipsID -Description "Unusual Parent<=>Child Relationship" -ShortId "ur"
                                break
                            }
                        }
                    }
                }

                # known good programs, but in unusual path
                if($null -ne $process.'Process Name' -and $ExpectedProcessPaths.ContainsKey($process.'Process Name')) {
                    $knownPath = $ExpectedProcessPaths[$process.'Process Name']
                    if($process.'Device Path' -notmatch $knownPath) {
                        Set-Suspicious -Node $node -ParentID $expectedProcessPathDiscrepancyID -Description $("Process Path mismatch. Should match: '" + $knownPath + "'") -ShortId "kppm"
                    }
                }

                # running in unc path
                if($process.'File Path'.StartsWith("\\")) {
                    Set-Suspicious -Node $node -ParentID $runningInUNCNetworkPathID -Description $("Running in UNC network path") -ShortId "unc"
                }

            }
        }

    }

    $TreeView.Sort()

    $systemNode = $nodesMap["4"]
    if($systemNode) {
        Set-Nodes -Root $systemNode -Depth 3 -Collapsed $false
    }

    $TreeView.EndUpdate()

    $script:dataInitialised = $true
}


####################################
#endregion DISPLAY                 #
####################################

Fill-GUIData

$Form.Add_Shown( { $Form.Activate() })
[system.windows.forms.application]::run($Form)

# SIG # Begin signature block
# MIIrywYJKoZIhvcNAQcCoIIrvDCCK7gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUUCu8zWVKXUIA1uCCB+zhICIq
# ZZOggiUEMIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
# AQwFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEh
# MB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTIxMDUyNTAwMDAw
# MFoXDTI4MTIzMTIzNTk1OVowVjELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDEtMCsGA1UEAxMkU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5n
# IFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjeeUEiIE
# JHQu/xYjApKKtq42haxH1CORKz7cfeIxoFFvrISR41KKteKW3tCHYySJiv/vEpM7
# fbu2ir29BX8nm2tl06UMabG8STma8W1uquSggyfamg0rUOlLW7O4ZDakfko9qXGr
# YbNzszwLDO/bM1flvjQ345cbXf0fEj2CA3bm+z9m0pQxafptszSswXp43JJQ8mTH
# qi0Eq8Nq6uAvp6fcbtfo/9ohq0C/ue4NnsbZnpnvxt4fqQx2sycgoda6/YDnAdLv
# 64IplXCN/7sVz/7RDzaiLk8ykHRGa0c1E3cFM09jLrgt4b9lpwRrGNhx+swI8m2J
# mRCxrds+LOSqGLDGBwF1Z95t6WNjHjZ/aYm+qkU+blpfj6Fby50whjDoA7NAxg0P
# OM1nqFOI+rgwZfpvx+cdsYN0aT6sxGg7seZnM5q2COCABUhA7vaCZEao9XOwBpXy
# bGWfv1VbHJxXGsd4RnxwqpQbghesh+m2yQ6BHEDWFhcp/FycGCvqRfXvvdVnTyhe
# Be6QTHrnxvTQ/PrNPjJGEyA2igTqt6oHRpwNkzoJZplYXCmjuQymMDg80EY2NXyc
# uu7D1fkKdvp+BRtAypI16dV60bV/AK6pkKrFfwGcELEW/MxuGNxvYv6mUKe4e7id
# FT/+IAx1yCJaE5UZkADpGtXChvHjjuxf9OUCAwEAAaOCARIwggEOMB8GA1UdIwQY
# MBaAFKARCiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQy65Ka/zWWSC8oQEJw
# IDaRXBeF5jAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUE
# DDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmlj
# YXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUAA4IBAQASv6Hvi3Sa
# mES4aUa1qyQKDKSKZ7g6gb9Fin1SB6iNH04hhTmja14tIIa/ELiueTtTzbT72ES+
# BtlcY2fUQBaHRIZyKtYyFfUSg8L54V0RQGf2QidyxSPiAjgaTCDi2wH3zUZPJqJ8
# ZsBRNraJAlTH/Fj7bADu/pimLpWhDFMpH2/YGaZPnvesCepdgsaLr4CnvYFIUoQx
# 2jLsFeSmTD1sOXPUC4U5IOCFGmjhp0g4qdE2JXfBjRkWxYhMZn0vY86Y6GnfrDyo
# XZ3JHFuu2PMvdM+4fvbXg50RlmKarkUT2n/cR/vfw1Kf5gZV6Z2M8jpiUbzsJA8p
# 1FiAhORFe1rYMIIGFDCCA/ygAwIBAgIQeiOu2lNplg+RyD5c9MfjPzANBgkqhkiG
# 9w0BAQwFADBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2
# MB4XDTIxMDMyMjAwMDAwMFoXDTM2MDMyMTIzNTk1OVowVTELMAkGA1UEBhMCR0Ix
# GDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJs
# aWMgVGltZSBTdGFtcGluZyBDQSBSMzYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAw
# ggGKAoIBgQDNmNhDQatugivs9jN+JjTkiYzT7yISgFQ+7yavjA6Bg+OiIjPm/N/t
# 3nC7wYUrUlY3mFyI32t2o6Ft3EtxJXCc5MmZQZ8AxCbh5c6WzeJDB9qkQVa46xiY
# Epc81KnBkAWgsaXnLURoYZzksHIzzCNxtIXnb9njZholGw9djnjkTdAA83abEOHQ
# 4ujOGIaBhPXG2NdV8TNgFWZ9BojlAvflxNMCOwkCnzlH4oCw5+4v1nssWeN1y4+R
# laOywwRMUi54fr2vFsU5QPrgb6tSjvEUh1EC4M29YGy/SIYM8ZpHadmVjbi3Pl8h
# JiTWw9jiCKv31pcAaeijS9fc6R7DgyyLIGflmdQMwrNRxCulVq8ZpysiSYNi79tw
# 5RHWZUEhnRfs/hsp/fwkXsynu1jcsUX+HuG8FLa2BNheUPtOcgw+vHJcJ8HnJCrc
# UWhdFczf8O+pDiyGhVYX+bDDP3GhGS7TmKmGnbZ9N+MpEhWmbiAVPbgkqykSkzyY
# Vr15OApZYK8CAwEAAaOCAVwwggFYMB8GA1UdIwQYMBaAFPZ3at0//QET/xahbIIC
# L9AKPRQlMB0GA1UdDgQWBBRfWO1MMXqiYUKNUoC6s2GXGaIymzAOBgNVHQ8BAf8E
# BAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcDCDAR
# BgNVHSAECjAIMAYGBFUdIAAwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL2NybC5z
# ZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nUm9vdFI0Ni5jcmww
# fAYIKwYBBQUHAQEEcDBuMEcGCCsGAQUFBzAChjtodHRwOi8vY3J0LnNlY3RpZ28u
# Y29tL1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdSb290UjQ2LnA3YzAjBggrBgEF
# BQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIB
# ABLXeyCtDjVYDJ6BHSVY/UwtZ3Svx2ImIfZVVGnGoUaGdltoX4hDskBMZx5NY5L6
# SCcwDMZhHOmbyMhyOVJDwm1yrKYqGDHWzpwVkFJ+996jKKAXyIIaUf5JVKjccev3
# w16mNIUlNTkpJEor7edVJZiRJVCAmWAaHcw9zP0hY3gj+fWp8MbOocI9Zn78xvm9
# XKGBp6rEs9sEiq/pwzvg2/KjXE2yWUQIkms6+yslCRqNXPjEnBnxuUB1fm6bPAV+
# Tsr/Qrd+mOCJemo06ldon4pJFbQd0TQVIMLv5koklInHvyaf6vATJP4DfPtKzSBP
# kKlOtyaFTAjD2Nu+di5hErEVVaMqSVbfPzd6kNXOhYm23EWm6N2s2ZHCHVhlUgHa
# C4ACMRCgXjYfQEDtYEK54dUwPJXV7icz0rgCzs9VI29DwsjVZFpO4ZIVR33LwXyP
# DbYFkLqYmgHjR3tKVkhh9qKV2WCmBuC27pIOx6TYvyqiYbntinmpOqh/QPAnhDge
# xKG9GX/n1PggkGi9HCapZp8fRwg8RftwS21Ln61euBG0yONM6noD2XQPrFwpm3Gc
# uqJMf0o8LLrFkSLRQNwxPDDkWXhW+gZswbaiie5fd/W2ygcto78XCSPfFWveUOSZ
# 5SqK95tBO8aTHmEa4lpJVD7HrTEn9jb1EGvxOb1cnn0CMIIGGjCCBAKgAwIBAgIQ
# Yh1tDFIBnjuQeRUgiSEcCjANBgkqhkiG9w0BAQwFADBWMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdvIFB1Ymxp
# YyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwHhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIx
# MjM1OTU5WjBUMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2MIIB
# ojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAmyudU/o1P45gBkNqwM/1f/bI
# U1MYyM7TbH78WAeVF3llMwsRHgBGRmxDeEDIArCS2VCoVk4Y/8j6stIkmYV5Gej4
# NgNjVQ4BYoDjGMwdjioXan1hlaGFt4Wk9vT0k2oWJMJjL9G//N523hAm4jF4UjrW
# 2pvv9+hdPX8tbbAfI3v0VdJiJPFy/7XwiunD7mBxNtecM6ytIdUlh08T2z7mJEXZ
# D9OWcJkZk5wDuf2q52PN43jc4T9OkoXZ0arWZVeffvMr/iiIROSCzKoDmWABDRzV
# /UiQ5vqsaeFaqQdzFf4ed8peNWh1OaZXnYvZQgWx/SXiJDRSAolRzZEZquE6cbcH
# 747FHncs/Kzcn0Ccv2jrOW+LPmnOyB+tAfiWu01TPhCr9VrkxsHC5qFNxaThTG5j
# 4/Kc+ODD2dX/fmBECELcvzUHf9shoFvrn35XGf2RPaNTO2uSZ6n9otv7jElspkfK
# 9qEATHZcodp+R4q2OIypxR//YEb3fkDn3UayWW9bAgMBAAGjggFkMIIBYDAfBgNV
# HSMEGDAWgBQy65Ka/zWWSC8oQEJwIDaRXBeF5jAdBgNVHQ4EFgQUDyrLIIcouOxv
# SK4rVKYpqhekzQwwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwGwYDVR0gBBQwEjAGBgRVHSAAMAgGBmeBDAEE
# ATBLBgNVHR8ERDBCMECgPqA8hjpodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3Rp
# Z29QdWJsaWNDb2RlU2lnbmluZ1Jvb3RSNDYuY3JsMHsGCCsGAQUFBwEBBG8wbTBG
# BggrBgEFBQcwAoY6aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGlj
# Q29kZVNpZ25pbmdSb290UjQ2LnA3YzAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Au
# c2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIBAAb/guF3YzZue6EVIJsT/wT+
# mHVEYcNWlXHRkT+FoetAQLHI1uBy/YXKZDk8+Y1LoNqHrp22AKMGxQtgCivnDHFy
# AQ9GXTmlk7MjcgQbDCx6mn7yIawsppWkvfPkKaAQsiqaT9DnMWBHVNIabGqgQSGT
# rQWo43MOfsPynhbz2Hyxf5XWKZpRvr3dMapandPfYgoZ8iDL2OR3sYztgJrbG6VZ
# 9DoTXFm1g0Rf97Aaen1l4c+w3DC+IkwFkvjFV3jS49ZSc4lShKK6BrPTJYs4NG1D
# GzmpToTnwoqZ8fAmi2XlZnuchC4NPSZaPATHvNIzt+z1PHo35D/f7j2pO1S8BCys
# QDHCbM5Mnomnq5aYcKCsdbh0czchOm8bkinLrYrKpii+Tk7pwL7TjRKLXkomm5D1
# Umds++pip8wH2cQpf93at3VDcOK4N7EwoIJB0kak6pSzEu4I64U6gZs7tS/dGNSl
# jf2OSSnRr7KWzq03zl8l75jy+hOds9TWSenLbjBQUGR96cFr6lEUfAIEHVC1L68Y
# 1GGxx4/eRI82ut83axHMViw1+sVpbPxg51Tbnio1lB93079WPFnYaOvfGAA0e0zc
# fF/M9gXr+korwQTh2Prqooq2bYNMvUoUKD85gnJ+t0smrWrb8dee2CvYZXD5laGt
# aAxOfy/VKNmwuWuAh9kcMIIGYjCCBMqgAwIBAgIRAKQpO24e3denNAiHrXpOtyQw
# DQYJKoZIhvcNAQEMBQAwVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28g
# TGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBD
# QSBSMzYwHhcNMjUwMzI3MDAwMDAwWhcNMzYwMzIxMjM1OTU5WjByMQswCQYDVQQG
# EwJHQjEXMBUGA1UECBMOV2VzdCBZb3Jrc2hpcmUxGDAWBgNVBAoTD1NlY3RpZ28g
# TGltaXRlZDEwMC4GA1UEAxMnU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBT
# aWduZXIgUjM2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA04SV9G6k
# U3jyPRBLeBIHPNyUgVNnYayfsGOyYEXrn3+SkDYTLs1crcw/ol2swE1TzB2aR/5J
# IjKNf75QBha2Ddj+4NEPKDxHEd4dEn7RTWMcTIfm492TW22I8LfH+A7Ehz0/safc
# 6BbsNBzjHTt7FngNfhfJoYOrkugSaT8F0IzUh6VUwoHdYDpiln9dh0n0m545d5A5
# tJD92iFAIbKHQWGbCQNYplqpAFasHBn77OqW37P9BhOASdmjp3IijYiFdcA0WQIe
# 60vzvrk0HG+iVcwVZjz+t5OcXGTcxqOAzk1frDNZ1aw8nFhGEvG0ktJQknnJZE3D
# 40GofV7O8WzgaAnZmoUn4PCpvH36vD4XaAF2CjiPsJWiY/j2xLsJuqx3JtuI4akH
# 0MmGzlBUylhXvdNVXcjAuIEcEQKtOBR9lU4wXQpISrbOT8ux+96GzBq8TdbhoFcm
# YaOBZKlwPP7pOp5Mzx/UMhyBA93PQhiCdPfIVOCINsUY4U23p4KJ3F1HqP3H6Slw
# 3lHACnLilGETXRg5X/Fp8G8qlG5Y+M49ZEGUp2bneRLZoyHTyynHvFISpefhBCV0
# KdRZHPcuSL5OAGWnBjAlRtHvsMBrI3AAA0Tu1oGvPa/4yeeiAyu+9y3SLC98gDVb
# ySnXnkujjhIh+oaatsk/oyf5R2vcxHahajMCAwEAAaOCAY4wggGKMB8GA1UdIwQY
# MBaAFF9Y7UwxeqJhQo1SgLqzYZcZojKbMB0GA1UdDgQWBBSIYYyhKjdkgShgoZsx
# 0Iz9LALOTzAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8E
# DDAKBggrBgEFBQcDCDBKBgNVHSAEQzBBMDUGDCsGAQQBsjEBAgEDCDAlMCMGCCsG
# AQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAIBgZngQwBBAIwSgYDVR0f
# BEMwQTA/oD2gO4Y5aHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGlj
# VGltZVN0YW1waW5nQ0FSMzYuY3JsMHoGCCsGAQUFBwEBBG4wbDBFBggrBgEFBQcw
# AoY5aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1w
# aW5nQ0FSMzYuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNv
# bTANBgkqhkiG9w0BAQwFAAOCAYEAAoE+pIZyUSH5ZakuPVKK4eWbzEsTRJOEjbIu
# 6r7vmzXXLpJx4FyGmcqnFZoa1dzx3JrUCrdG5b//LfAxOGy9Ph9JtrYChJaVHrus
# Dh9NgYwiGDOhyyJ2zRy3+kdqhwtUlLCdNjFjakTSE+hkC9F5ty1uxOoQ2ZkfI5WM
# 4WXA3ZHcNHB4V42zi7Jk3ktEnkSdViVxM6rduXW0jmmiu71ZpBFZDh7Kdens+PQX
# PgMqvzodgQJEkxaION5XRCoBxAwWwiMm2thPDuZTzWp/gUFzi7izCmEt4pE3Kf0M
# Ot3ccgwn4Kl2FIcQaV55nkjv1gODcHcD9+ZVjYZoyKTVWb4VqMQy/j8Q3aaYd/jO
# Q66Fhk3NWbg2tYl5jhQCuIsE55Vg4N0DUbEWvXJxtxQQaVR5xzhEI+BjJKzh3TQ0
# 26JxHhr2fuJ0mV68AluFr9qshgwS5SpN5FFtaSEnAwqZv3IS+mlG50rK7W3qXbWw
# i4hmpylUfygtYLEdLQukNEX1jiOKMIIGazCCBNOgAwIBAgIRAIxBnpO/K86siAYo
# O3YZvTwwDQYJKoZIhvcNAQEMBQAwVDELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1Nl
# Y3RpZ28gTGltaXRlZDErMCkGA1UEAxMiU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWdu
# aW5nIENBIFIzNjAeFw0yNDExMTQwMDAwMDBaFw0yNzExMTQyMzU5NTlaMFcxCzAJ
# BgNVBAYTAkRFMRYwFAYDVQQIDA1OaWVkZXJzYWNoc2VuMRcwFQYDVQQKDA5NYXJ0
# aW4gV2lsbGluZzEXMBUGA1UEAwwOTWFydGluIFdpbGxpbmcwggIiMA0GCSqGSIb3
# DQEBAQUAA4ICDwAwggIKAoICAQDRn27mnIzB6dsJFLMexQQNRd8aMv73DTla68G6
# Q8u+V2TY1JQ/Z4j2oCI9ATW3K3P7NAPdlE0QmtdjC0F/74jsfil/i8LwxuyT034w
# abViZKUcodmKsEFhM9am8W5kUgLuC5FIK4wNOq5TfzYdHTyJu1eR2XuSDoMp0wg4
# 5mOuFNBbYB8DVBtHxobvWq4eCs3lUxX07wR3Qr2Utb92w8eU2vKr2Ss9xIh/YvM4
# UxgBpO1I6O+W2tAB5mmynIgoCfX7mu6iD3A+AhpQ9Gv209G83y8FPrFJIWU77TTe
# hErbPjZ074xXwrlEkhnGUCk1w+KiNtZHaSn0X+vnhqJ7otBxQZQAESlhWXpDKCun
# nnVnVgwvVWtccAhxZO95eif6Vss/UhCaBZ26szlneGtFeTClI4+k3mqfWuodtXjH
# c8ohAclWp7XVywliwhCFEsAcFkpkCyivey0sqEfrwiMnRy1elH1S37XcQaav5+bt
# 4KxtIXuOVEx3vM9MHdlraW0y1on5E8i4tagdI45TH0LU080ubc2MKqq6ZXtplTu1
# wdF2Cgy3hfSSLkJscRWApvpvOO6Vtc4jTG/AO6iqN5M6Swd+g40XtsxBD/gSk9kM
# qkgJ1pD1Gp5gkHnP1veut+YgJ9xWcRDJI7vcis9qsXwtVybeOCh56rTQvC/Tf6BJ
# tiieEQIDAQABo4IBszCCAa8wHwYDVR0jBBgwFoAUDyrLIIcouOxvSK4rVKYpqhek
# zQwwHQYDVR0OBBYEFIxyZAmEHl7uAfEwbB4nzI8MCCLbMA4GA1UdDwEB/wQEAwIH
# gDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEoGA1UdIARDMEEw
# NQYMKwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5j
# b20vQ1BTMAgGBmeBDAEEATBJBgNVHR8EQjBAMD6gPKA6hjhodHRwOi8vY3JsLnNl
# Y3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ0NBUjM2LmNybDB5Bggr
# BgEFBQcBAQRtMGswRAYIKwYBBQUHMAKGOGh0dHA6Ly9jcnQuc2VjdGlnby5jb20v
# U2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYuY3J0MCMGCCsGAQUFBzABhhdo
# dHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAoBgNVHREEITAfgR1td2lsbGluZ0BsZXRo
# YWwtZm9yZW5zaWNzLmNvbTANBgkqhkiG9w0BAQwFAAOCAYEAZ0dBMMwluWGb+MD1
# rGWaPtaXrNZnlZqOZxgbdrMLBKAQr0QGcILCVIZ4SZYaevT5yMR6jFGSAjgaFtnk
# 8ZpbtGwig/ed/C/D1Ne8SZyffdtALns/5CHxMnU8ks7ut7dsR6zFD4/bmljuoUoi
# 55W6/XU/1pr+tqRaZGJvjSKJQCN9MhFAvXSpPPqRsj27ze1+KYIBF1/L0BW0HS0d
# 9ZhGSUoEwqMDLpQf2eqJFyyyzWt21VVhLF6mgZ1dE5tCLZY7ERzx6/h5N7F0w361
# oigizMbCMdST29XOc5mB8q6Cye7OmEfM2jByRWa+cd4RycsN2p2wHRukpq48iX+t
# PVKmHwNKf+upuKPDQAeV4J7gUCtevIsOtoyiC2+amimu81o424Dl+NsAyCLz0SXv
# NAhVvtU73H61gtoPa/SWouem2S+bzp7oGvGPop/9mh4CXki6LVeDH3hDM8hZsJg/
# EToIWiDozTc2yWqwV4Ozyd4x5Ix8lckXMgWuyWcxmLK1RmKpMIIGgjCCBGqgAwIB
# AgIQNsKwvXwbOuejs902y8l1aDANBgkqhkiG9w0BAQwFADCBiDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4w
# HAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVz
# dCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjEwMzIyMDAwMDAwWhcN
# MzgwMTE4MjM1OTU5WjBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJv
# b3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAiJ3YuUVnnR3d
# 6LkmgZpUVMB8SQWbzFoVD9mUEES0QUCBdxSZqdTkdizICFNeINCSJS+lV1ipnW5i
# hkQyC0cRLWXUJzodqpnMRs46npiJPHrfLBOifjfhpdXJ2aHHsPHggGsCi7uE0awq
# KggE/LkYw3sqaBia67h/3awoqNvGqiFRJ+OTWYmUCO2GAXsePHi+/JUNAax3kpqs
# tbl3vcTdOGhtKShvZIvjwulRH87rbukNyHGWX5tNK/WABKf+Gnoi4cmisS7oSimg
# HUI0Wn/4elNd40BFdSZ1EwpuddZ+Wr7+Dfo0lcHflm/FDDrOJ3rWqauUP8hsokDo
# I7D/yUVI9DAE/WK3Jl3C4LKwIpn1mNzMyptRwsXKrop06m7NUNHdlTDEMovXAIDG
# AvYynPt5lutv8lZeI5w3MOlCybAZDpK3Dy1MKo+6aEtE9vtiTMzz/o2dYfdP0KWZ
# wZIXbYsTIlg1YIetCpi5s14qiXOpRsKqFKqav9R1R5vj3NgevsAsvxsAnI8Oa5s2
# oy25qhsoBIGo/zi6GpxFj+mOdh35Xn91y72J4RGOJEoqzEIbW3q0b2iPuWLA911c
# RxgY5SJYubvjay3nSMbBPPFsyl6mY4/WYucmyS9lo3l7jk27MAe145GWxK4O3m3g
# EFEIkv7kRmefDR7Oe2T1HxAnICQvr9sCAwEAAaOCARYwggESMB8GA1UdIwQYMBaA
# FFN5v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBT2d2rdP/0BE/8WoWyCAi/Q
# Cj0UJTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAK
# BggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAwUAYDVR0fBEkwRzBFoEOgQYY/
# aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUNlcnRpZmljYXRp
# b25BdXRob3JpdHkuY3JsMDUGCCsGAQUFBwEBBCkwJzAlBggrBgEFBQcwAYYZaHR0
# cDovL29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEADr5lQe1o
# RLjlocXUEYfktzsljOt+2sgXke3Y8UPEooU5y39rAARaAdAxUeiX1ktLJ3+lgxto
# LQhn5cFb3GF2SSZRX8ptQ6IvuD3wz/LNHKpQ5nX8hjsDLRhsyeIiJsms9yAWnvdY
# OdEMq1W61KE9JlBkB20XBee6JaXx4UBErc+YuoSb1SxVf7nkNtUjPfcxuFtrQdRM
# Ri/fInV/AobE8Gw/8yBMQKKaHt5eia8ybT8Y/Ffa6HAJyz9gvEOcF1VWXG8OMeM7
# Vy7Bs6mSIkYeYtddU1ux1dQLbEGur18ut97wgGwDiGinCwKPyFO7ApcmVJOtlw9F
# VJxw/mL1TbyBns4zOgkaXFnnfzg4qbSvnrwyj1NiurMp4pmAWjR+Pb/SIduPnmFz
# bSN/G8reZCL4fvGlvPFk4Uab/JVCSmj59+/mB2Gn6G/UYOy8k60mKcmaAZsEVkhO
# Fuoj4we8CYyaR9vd9PGZKSinaZIkvVjbH/3nlLb0a7SBIkiRzfPfS9T+JesylbHa
# 1LtRV9U/7m0q7Ma2CQ/t392ioOssXW7oKLdOmMBl14suVFBmbzrt5V5cQPnwtd3U
# OTpS9oCG+ZZheiIvPgkDmA8FzPsnfXW5qHELB43ET7HHFHeRPRYrMBKjkb8/IN7P
# o0d0hQoF4TeMM+zYAJzoKQnVKOLg8pZVPT8xggYxMIIGLQIBATBpMFQxCzAJBgNV
# BAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxKzApBgNVBAMTIlNlY3Rp
# Z28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYCEQCMQZ6TvyvOrIgGKDt2Gb08
# MAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3
# DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEV
# MCMGCSqGSIb3DQEJBDEWBBST3S9uZfOSRTGoGSJ0Eip8E5X1eTANBgkqhkiG9w0B
# AQEFAASCAgB4VUwJg/VBiXJXBEY2kQfrbiivCG26nU0P2cgtobXNiMOSFMnarWtE
# JF2Kwq60yguIuGUmsTgTHQewyFDZNNoltK5pmRJpGssMMDo18t9excWsk0ZI5W9f
# pLP4zw+f1ycNEl2xMMn/E+tlb3eKdYWDe+2qGeChAZVBQ67uJZdFTWv3TjvddWU+
# Q3qNT8jRUK7cxys7gBdsKvze2oOwr7KXHDjvuHajA2vYPfqNf9HEGGYQwOj0IkOU
# ct47pfSRsqEX3h0fkqkmSYc+ctZd0kiy0NCIzexKQlVY/5BDeKEFaX7vUhy+NDYZ
# 3I4nClecTcLNPFMXDWqrcsxSHLKKzkmiIiDIn0Es88M20puRZDkdBHPG36mspZSW
# /B2gUQ1k26k8p+MaBQz2UFhEAlAkWgz2gZnMKp7f7Rup3yv74tT7BLcQS90CM4Mj
# ckFEntEd7z/rsSYNRIojnfUVPPFTmHEb+cwkNnW64qJFcyAJGzRyTVPEG7mjc5Vc
# +m6WEGTaCZtnWh76lku4lauQ4d3umqkS0mY7T/QpyBIPfVQVXkJ01O6Zx59RFapd
# jV2nYBPCnUVxcuprtUJPCQAyyUb/pHp0EcXg0Ct4T6cj1tY8r8sA42tWsgUmL8/T
# om4W08VCs7kxgHOqq4QdeD0rROgfVKepHwB7poHMTJIKLWGjDWIrmqGCAyMwggMf
# BgkqhkiG9w0BCQYxggMQMIIDDAIBATBqMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUg
# U3RhbXBpbmcgQ0EgUjM2AhEApCk7bh7d16c0CIetek63JDANBglghkgBZQMEAgIF
# AKB5MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDcyNTE2MzEyNVowPwYJKoZIhvcNAQkEMTIEMLSbd0iElA5i9dna4ivC2MAEOyYq
# JPRFqyWLfx+gugCxLAc1Q6w95w50KB36Y6J2iTANBgkqhkiG9w0BAQEFAASCAgA6
# ids57O2v/GGWcrH2Fsor1VljQZYZlyYz/tfTYKiq5MFdeIge9kAMMw13U6on+Mym
# 7uNHUgEuhDyr2bU3HQR6hIJaT26mUKbh4I7V2BYM0XxnqyTAsR0cG4pYHjLS+BMi
# hFdjk4gB6fOFiP65Vycr6AoufIf6FF4cJFcuQG8cgICM+f1021sX6gc8hj7tqFI3
# 0LhylBaO+NOJ8A9zrkI+FUj2qXnrrq4vMeIVWXy4FrEMGutSKoAkvcUwf4cRZlhs
# Th5JjHskEtUIo207158VwNKSsdT5yrS9aR6iYjXywyZQJjoTBxhEI+s8sHSXYU4J
# fMsbD5C7pZ0VyUWukvu/AmghwvD5XVGk2CmuepDCO73byqkgArF17STfFfwZAXCR
# T/D4sZG0nZIX7w+to1dhuXlkuh2TfsAyt218f4r4aTSEeL1zCZblE5+g8bkTY92O
# rWda3rWGLcHvKtFT5rcbaQgWTCP7E9KBL7gL6LwCxfr1O2/ZpVwHoZ29+REK4mHL
# ldFMqO46m20PFOZQ8ChEhiAD4lnA1+6YNuSWLqqCNEgH8PATuXVXFR2HWokzexIe
# J9YFiGiubW+978BdBYr8/I53fQdGqf4sOF98NLOSfLPxmR3m5i/lGWN5o/BRgvz/
# BbDBMf3L1rVOcsB+5ucd+xtgwqAqRpyB77tQAR7XTA==
# SIG # End signature block
