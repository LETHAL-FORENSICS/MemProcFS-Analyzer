Function Find-WmiPrvSEParentAnomaly {
<#
.SYNOPSIS
  Unusual Parent-Child Relationship (WmiPrvSE.exe) - WMI Provider Host

.DESCRIPTION
  Parses MemProcFS proc-v.txt and flags every WmiPrvSE.exe whose parent process is NOT "svchost.exe -k DcomLaunch".

  A WmiPrvSE.exe is flagged when:
    - the parent PID is not present in the process list (orphan / parent exited), or
    - the parent was created AFTER the child (PID reuse - real parent is gone), or
    - the parent image is not svchost.exe, or
    - the parent command line does not contain "-k DcomLaunch".

  Returns one object per finding (nothing if clean).

.EXAMPLE
  Find-WmiPrvSEParentAnomaly -Path "$OUTPUT_FOLDER\sys\proc\TXT\proc-v.txt"

.EXAMPLE
  Find-WmiPrvSEParentAnomaly -Path "$OUTPUT_FOLDER\sys\proc\TXT\proc-v.txt" | Export-Csv "$OUTPUT_FOLDER\WmiPrvSE.csv" -NoTypeInformation
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$Path
)

if (!(Test-Path -LiteralPath $Path)) { Write-Error "File not found: $Path"; return }

# Parse proc-v.txt
$Lines = Get-Content -LiteralPath $Path
$Header = $Lines | Where-Object { $_ -match "^\s+Process\s+Pid\s+Parent" } | Select-Object -First 1
if (!$Header) { Write-Error "Unexpected format (header not found): $Path"; return }
$UserCol = $Header.IndexOf("User")
$PathCol = $Header.IndexOf("Path")

$Processes = @{}  # Key = PID (not [ordered] - an [int] key would be treated as a positional index)
$Current   = $null

foreach ($Line in $Lines)
{
    if ($Line -match "^(-+) (.+?)\s+(\d+)\s+(\d+) ")
    {
        $Current = [PSCustomObject]@{
            Depth       = $Matches[1].Length
            Name        = $Matches[2].Trim()
            PID         = [int]$Matches[3]
            PPID        = [int]$Matches[4]
            User        = if ($Line.Length -gt $UserCol) { $Line.Substring($UserCol, [Math]::Min($PathCol, $Line.Length) - $UserCol).Trim() } else { "" }
            KernelPath  = if ($Line.Length -gt $PathCol) { $Line.Substring($PathCol).Trim() } else { "" }
            Detail      = New-Object System.Collections.Generic.List[string]
            ImagePath   = ""
            CommandLine = ""
            CreateTime  = $null
            Integrity   = ""
        }
        $Processes[$Current.PID] = $Current
        continue
    }

    # Continuation lines (Path / Command / Time / Integrity)
    if ($Current -and $Line.Trim()) { $Current.Detail.Add($Line.Trim()) }
}

foreach ($Proc in $Processes.Values)
{
    $TimeIndex = -1
    for ($i = 0; $i -lt $Proc.Detail.Count; $i++)
    {
        if ($Proc.Detail[$i] -match "^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC ->") { $TimeIndex = $i; break }
    }

    if ($TimeIndex -ge 0)
    {
        $Proc.CreateTime = [datetime]::ParseExact($Matches[1], "yyyy-MM-dd HH:mm:ss", [Globalization.CultureInfo]::InvariantCulture)
        if ($TimeIndex -ge 2) { $Proc.ImagePath = $Proc.Detail[0]; $Proc.CommandLine = $Proc.Detail[1] }
        elseif ($TimeIndex -eq 1) { $Proc.ImagePath = $Proc.Detail[0] }
        if ($Proc.Detail.Count -gt $TimeIndex + 1) { $Proc.Integrity = $Proc.Detail[$TimeIndex + 1] }
    }
}

# Detection: WmiPrvSE.exe whose parent is not "svchost.exe -k DcomLaunch"
foreach ($Proc in $Processes.Values | Where-Object { $_.Name -eq "WmiPrvSE.exe" } | Sort-Object PID)
{
    $Parent = $Processes[$Proc.PPID]
    $Reason = $null

    if (!$Parent)
    {
        $Reason = "Parent process not found (orphan)"
    }
    elseif ($Parent.CreateTime -and $Proc.CreateTime -and $Parent.CreateTime -gt $Proc.CreateTime)
    {
        $Reason = "Parent created after child (PID reuse)"
    }
    elseif ($Parent.Name -ne "svchost.exe")
    {
        $Reason = "Parent is not svchost.exe"
    }
    elseif ($Parent.CommandLine -notmatch "-k\s+DcomLaunch\b")
    {
        $Reason = "Parent svchost.exe is not -k DcomLaunch"
    }

    if ($Reason)
    {
        [PSCustomObject]@{
            "Process Name"        = $Proc.Name
            "PID"                 = $Proc.PID
            "User"                = $Proc.User
            "Integrity"           = $Proc.Integrity
            "Created (UTC)"       = if ($Proc.CreateTime) { $Proc.CreateTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
            "Command Line"        = $Proc.CommandLine
            "PPID"                = $Proc.PPID
            "Parent Name"         = if ($Parent) { $Parent.Name } else { "<not found>" }
            "Parent Command Line" = if ($Parent) { $Parent.CommandLine } else { "" }
            "Reason"              = $Reason
        }
    }
}

}

# SIG # Begin signature block
# MIInkAYJKoZIhvcNAQcCoIIngTCCJ30CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAEBoT7aojVbn7B
# Yc3hYnFdhAr8LlHTO3ZCHtQEZufslaCCIKQwggYaMIIEAqADAgECAhBiHW0MUgGe
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCB4ns3mZttL1Cq05lFCbk3yvwlhNVlu
# CfG6RyTzrD/NIDANBgkqhkiG9w0BAQEFAASCAgAxhGgqcZvmeK4e7KBqIIyANw3P
# G5uAEIIuFTVkElRjHZ+lRTyhdlUiatBm+RA8sCWlpWUMF8c0qThK4oufDiOJXCNI
# sZMrIOUMlfGSDhCCJUs/u48uKwFdkSEX+AEUzWnJkW1VkS/Oebp7QOWlta+luPLk
# UDJ/lH+fdyLXsiu+dvdB609veNWAGc1+YIN4P/pX3K+iGEm2Q9DC6+X8SBDre8mE
# hqPmBgKUkBuLSgG9KBWKVHE4s6lgWBo8pkvDP6H+f+WM5Us78pMubF6XaVB3ZlMY
# GprJ9QnDBz7sl3JG4jXc0lwMyVSi6oR0n8f88LlKhKc+QPZq5EqIKne1hGvWUbLt
# aWhB/iG9hjJ6HA4aQ2/h7GM68oo++rTO8PBio/pshoBz6vDInfsFFQPXKttPOatx
# MljaD0GBuS5xCcELz9ziHbiO0bjdoRpTTlpYpY9uu+NvVKWS5A4L19/aE7Twxk6x
# GEhR/Q4L29C74xzuWuA08tqpdUs6VQ5ACOhk7hbhzJmqIyOIzjCh6PrIPcq7S2er
# hBRjjf4c0QwYUpxWzILlm6+Veca0Hxhibkz37SjPpGOjwO+/WODaagrM82fqst5w
# urXaFRJadAUSA4XlF8axqL3hwLrCBfh5vrzkbUUD+AQT8nseawHosdojh72zuwbP
# rq4NGhTTBniRLqGGmaGCAyMwggMfBgkqhkiG9w0BCQYxggMQMIIDDAIBATBqMFUx
# CzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMT
# I1NlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcgQ0EgUjQxAhEA507yVbBQT/rb
# pt/3/IujFTANBglghkgBZQMEAgIFAKB5MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTI2MTEwOTEwMTM1OFowPwYJKoZIhvcNAQkEMTIE
# MI8AdaKzjfIn0kMLQi6kMpT0bUXxgrEpOPaSoMmHvARWL/doDDCJCpWSahrZzmkx
# tjANBgkqhkiG9w0BAQEFAASCAgAbBxiyG4Dvx3tkFpBWUW9rQFdtnOBsvuPzAtLx
# NUeFyXSYUZOcJNyK4Y2+7MOiiS6zztLIpoxtfuNfm4HBzr9aAboL4hd2wypTR5tG
# RMSrG+sdrV9HabElSjg8plBnr7y04QC5Smd7n6W7cr04RWPq+e4VIbH5eWc1i/YV
# 8Thiq/c5/fbTlXNELNe91xUnXLjFSbxUGdHG/H+jlKnvmVLTlDN/HcScURmg22ar
# TDZqkkcnqhOhKbIGzMpSFyLDIZfcBBz3ulVUQUwnAxZ6wlHPY0/TAJIQaXYVRtKU
# bjY+jcJSbuXGTb8Rkltdec48c7HLcf40MiJ9TP96ehQFJRg6k0lCix/GFKdHAKkH
# MhYbIR/DDsJCMX2aT3a5Hf9+KDbmgWTMK81JbK/Zamit8ArynqS+pDsIbBe8t7xb
# +ofeyWSWTkfwVUBmJloMSq2E/UeUJC5hGxqStRC21Y9uBKo8frX9qMrjNdb4Kmii
# ZoQuXcaXeKK4VMwQ3UO/NVOXAf8le0OUT7ygVEO+BeN7KyyOpsakGYLoTUwSpFva
# vxZblYRFTLrlY3Oq99k4YjuqgQspy0a6ySyEF2uC0O9x1DnnyFaqSErD2D1HPmTf
# DCr/oKVWLgN4LIHcFqTmYqDt8UgxoqRqeg4oMlw2nGXXf3RCDVuBDd+De52Zk3dc
# 79OvcA==
# SIG # End signature block
