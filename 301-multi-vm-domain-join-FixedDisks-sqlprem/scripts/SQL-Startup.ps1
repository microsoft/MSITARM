# Name: SqlTempdriveAndStartup
#
# Install: SQL-Startup.ps1 [tempdbpath]
#
# example:
# install: c:\SQLStartup\SQL-Startup.ps1 D:\MSSQL13.MSSQLSERVER\MSSQL\DATA
#
# Run at startup, delay 30 seconds
# Run: powershell.exe
# Args: -NoLogo -NonInteractive -ExecutionPolicy ByPass -Command "c:\\SQLStartup\\SQL-Startup.ps1 D:\MSSQL13.MSSQLSERVER\MSSQL\DATA"
# Run as: SYSTEM

$TemporaryStorageVolume = $args
$TemporaryStorageDisk = $(split-Path -path $TemporaryStorageVolume -Qualifier);

# we only run this if the temporary storage account is used.

if($TemporaryStorageDisk -eq 'D:') {

    Write-Host -ForegroundColor Yellow "Temporary storage = $TemporaryStorageDisk";


if ((Get-ScheduledTask -TaskPath '\' | Where-Object { $_.TaskName -eq 'SqlTempdriveAndStartup'; }) -eq $null)
{
    $TaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $('-NoLogo -NonInteractive -ExecutionPolicy ByPass -Command "c:\\SQLStartup\\SQL-Startup.ps1 ' +$TemporaryStorageVolume +'"');
    $TaskTrigger = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Seconds 30);
    $TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Limited ;
    $TaskSettings = New-ScheduledTaskSettingsSet -Compatibility Win8 -ExecutionTimeLimit (New-TimeSpan -Hours 1);

    # Unregister-ScheduledTask -TaskName SqlTempdriveAndStartup -Confirm
    $ScheduledTask = Register-ScheduledTask -TaskName SqlTempdriveAndStartup -TaskPath '\' -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings -Principal $TaskPrincipal
}

$InstalledInstances = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -Name InstalledInstances | Select-Object -ExpandProperty InstalledInstances;

foreach ( $InstanceName in $InstalledInstances )
{
    Write-Host -ForegroundColor Green $InstanceName;
    
    $InstanceFullName = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -Name $InstanceName | Select-Object -ExpandProperty $InstanceName;

    $InstanceTempFilePath = "{0}\{1}\MSSQL\Data" -f $TemporaryStorageDisk, $InstanceFullName;
    Write-Host -ForegroundColor Cyan $InstanceTempFilePath;

    if ( -not (Test-Path -Path $InstanceTempFilePath) )
    {
        New-Item -Path $InstanceTempFilePath -ItemType directory | Out-Null;
    }

    icacls "$InstanceTempFilePath" /inheritance:d;
    icacls "$InstanceTempFilePath" /remove "CREATOR OWNER";

    if ( $InstanceName -ne 'MSSQLSERVER' )
    {
        $SQLServiceName = 'MSSQL${0}' -f $InstanceName;
        $SQLAgentServiceName = 'SQLAgent${0}' -f $InstanceName;
        $ServerInstance = '.\{0}' -f $InstanceName;
    }
    else
    {
        $SQLServiceName = 'MSSQLSERVER';
        $SQLAgentServiceName = 'SQLSERVERAGENT';
        $ServerInstance = '.';
    }

    Write-Debug $SQLServiceName;
    Write-Debug $SQLAgentServiceName;

    $SQLService = Get-Service -Name $SQLServiceName;
    $SQLAgentService = Get-Service -Name $SQLAgentServiceName;

    if ( $SQLService.StartType -eq 'Automatic' )
    {
        $SQLService | Set-Service -StartupType Manual;
    }

    if ( $SQLAgentService.StartType -eq 'Automatic' )
    {
        $SQLAgentService | Set-Service -StartupType Manual;
    }

    $Args = @($InstanceTempFilePath, '/grant:r', """NT SERVICE\$($SQLService.ServiceName)"":`(OI`)`(CI`)`(F`)");
    # $Args;

    icacls $args;
    icacls "$InstanceTempFilePath";

    if ( $SQLService.Status -eq 'running' )
    {
        $Query = 'SELECT name, type_desc, physical_name, SizeMB = size * 8 / 1024, growth = CASE WHEN is_percent_growth = 0 THEN growth * 8 / 1024 ELSE growth END, is_percent_growth FROM tempdb.sys.database_files'
        $TempDBFiles = Invoke-Sqlcmd -ServerInstance $ServerInstance -Query $Query -QueryTimeout 10;

        $AverageFileSize = ($TempDBFiles | ? { $_.type_desc -eq 'ROWS' } | Measure-Object -Average SizeMB).Average;

        $TargetFileSize = 100 * [Math]::Ceiling($AverageFileSize / 100);
        Write-Debug "Target file size = $TargetFileSize MB";

        $TargetFileGrowth = 100 * [Math]::Ceiling($AverageFileSize / 1000);
        Write-Debug "Target file growth = $TargetFileGrowth MB";
        
        foreach ( $TempFile in $TempDBFiles)
        {
            $Query = "ALTER DATABASE tempdb MODIFY FILE (NAME='{0}', FILENAME='{1}', SIZE={2}MB, FILEGROWTH={3}MB)" -f $TempFile.name, ($TemporaryStorageDisk + $TempFile.physical_name.Remove(0,2)), $TargetFileSize, $TargetFileGrowth;
            Write-Debug $Query;
            
            Invoke-Sqlcmd -ServerInstance $ServerInstance -Query $Query -QueryTimeout 10;
        }
    }


    if ( $SQLService.Status -eq 'Stopped' )
    {
        $SQLService | Start-Service;
    }

    if ( $SQLAgentService.Status -eq 'Stopped')
    {
        $SQLAgentService | Start-Service;
    }

  }
}

# SIG # Begin signature block
# MIIkRQYJKoZIhvcNAQcCoIIkNjCCJDICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD/gHy8d3DrALE7
# KrgISzKsU7NTYf6q8o9fynOumQyLoKCCDZIwggYQMIID+KADAgECAhMzAAAAZEeE
# lIbbQRk4AAAAAABkMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTUxMDI4MjAzMTQ2WhcNMTcwMTI4MjAzMTQ2WjCBgzEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjENMAsGA1UECxMETU9Q
# UjEeMBwGA1UEAxMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAky7a2OY+mNkbD2RfTahYTRQ793qE/DwRMTrvicJK
# LUGlSF3dEp7vq2YoNNV9KlV7TE2K8sDxstNSFYu2swi4i1AL3X/7agmg3GcExPHf
# vHUYIEC+eCyZVt3u9S7dPkL5Wh8wrgEUirCCtVGg4m1l/vcYCo0wbU06p8XzNi3u
# XyygkgCxHEziy/f/JCV/14/A3ZduzrIXtsccRKckyn6B5uYxuRbZXT7RaO6+zUjQ
# hiyu3A4hwcCKw+4bk1kT9sY7gHIYiFP7q78wPqB3vVKIv3rY6LCTraEbjNR+phBQ
# EL7hyBxk+ocu+8RHZhbAhHs2r1+6hURsAg8t4LAOG6I+JQIDAQABo4IBfzCCAXsw
# HwYDVR0lBBgwFgYIKwYBBQUHAwMGCisGAQQBgjdMCAEwHQYDVR0OBBYEFFhWcQTw
# vbsz9YNozOeARvdXr9IiMFEGA1UdEQRKMEikRjBEMQ0wCwYDVQQLEwRNT1BSMTMw
# MQYDVQQFEyozMTY0Mis0OWU4YzNmMy0yMzU5LTQ3ZjYtYTNiZS02YzhjNDc1MWM0
# YjYwHwYDVR0jBBgwFoAUSG5k5VAF04KqFzc3IrVtqMp1ApUwVAYDVR0fBE0wSzBJ
# oEegRYZDaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljQ29k
# U2lnUENBMjAxMV8yMDExLTA3LTA4LmNybDBhBggrBgEFBQcBAQRVMFMwUQYIKwYB
# BQUHMAKGRWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWlj
# Q29kU2lnUENBMjAxMV8yMDExLTA3LTA4LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqG
# SIb3DQEBCwUAA4ICAQCI4gxkQx3dXK6MO4UktZ1A1r1mrFtXNdn06DrARZkQTdu0
# kOTLdlGBCfCzk0309RLkvUgnFKpvLddrg9TGp3n80yUbRsp2AogyrlBU+gP5ggHF
# i7NjGEpj5bH+FDsMw9PygLg8JelgsvBVudw1SgUt625nY7w1vrwk+cDd58TvAyJQ
# FAW1zJ+0ySgB9lu2vwg0NKetOyL7dxe3KoRLaztUcqXoYW5CkI+Mv3m8HOeqlhyf
# FTYxPB5YXyQJPKQJYh8zC9b90JXLT7raM7mQ94ygDuFmlaiZ+QSUR3XVupdEngrm
# ZgUB5jX13M+Pl2Vv7PPFU3xlo3Uhj1wtupNC81epoxGhJ0tRuLdEajD/dCZ0xIni
# esRXCKSC4HCL3BMnSwVXtIoj/QFymFYwD5+sAZuvRSgkKyD1rDA7MPcEI2i/Bh5O
# MAo9App4sR0Gp049oSkXNhvRi/au7QG6NJBTSBbNBGJG8Qp+5QThKoQUk8mj0ugr
# 4yWRsA9JTbmqVw7u9suB5OKYBMUN4hL/yI+aFVsE/KJInvnxSzXJ1YHka45ADYMK
# AMl+fLdIqm3nx6rIN0RkoDAbvTAAXGehUCsIod049A1T3IJyUJXt3OsTd3WabhIB
# XICYfxMg10naaWcyUePgW3+VwP0XLKu4O1+8ZeGyaDSi33GnzmmyYacX3BTqMDCC
# B3owggVioAMCAQICCmEOkNIAAAAAAAMwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29m
# dCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDExMB4XDTExMDcwODIwNTkw
# OVoXDTI2MDcwODIxMDkwOVowfjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEoMCYGA1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAx
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKvw+nIQHC6t2G6qghBN
# NLrytlghn0IbKmvpWlCquAY4GgRJun/DDB7dN2vGEtgL8DjCmQawyDnVARQxQtOJ
# DXlkh36UYCRsr55JnOloXtLfm1OyCizDr9mpK656Ca/XllnKYBoF6WZ26DJSJhIv
# 56sIUM+zRLdd2MQuA3WraPPLbfM6XKEW9Ea64DhkrG5kNXimoGMPLdNAk/jj3gcN
# 1Vx5pUkp5w2+oBN3vpQ97/vjK1oQH01WKKJ6cuASOrdJXtjt7UORg9l7snuGG9k+
# sYxd6IlPhBryoS9Z5JA7La4zWMW3Pv4y07MDPbGyr5I4ftKdgCz1TlaRITUlwzlu
# ZH9TupwPrRkjhMv0ugOGjfdf8NBSv4yUh7zAIXQlXxgotswnKDglmDlKNs98sZKu
# HCOnqWbsYR9q4ShJnV+I4iVd0yFLPlLEtVc/JAPw0XpbL9Uj43BdD1FGd7P4AOG8
# rAKCX9vAFbO9G9RVS+c5oQ/pI0m8GLhEfEXkwcNyeuBy5yTfv0aZxe/CHFfbg43s
# TUkwp6uO3+xbn6/83bBm4sGXgXvt1u1L50kppxMopqd9Z4DmimJ4X7IvhNdXnFy/
# dygo8e1twyiPLI9AN0/B4YVEicQJTMXUpUMvdJX3bvh4IFgsE11glZo+TzOE2rCI
# F96eTvSWsLxGoGyY0uDWiIwLAgMBAAGjggHtMIIB6TAQBgkrBgEEAYI3FQEEAwIB
# ADAdBgNVHQ4EFgQUSG5k5VAF04KqFzc3IrVtqMp1ApUwGQYJKwYBBAGCNxQCBAwe
# CgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0j
# BBgwFoAUci06AjGQQ7kUBU7h6qfHMdEjiTQwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0
# cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2Vy
# QXV0MjAxMV8yMDExXzAzXzIyLmNybDBeBggrBgEFBQcBAQRSMFAwTgYIKwYBBQUH
# MAKGQmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2Vy
# QXV0MjAxMV8yMDExXzAzXzIyLmNydDCBnwYDVR0gBIGXMIGUMIGRBgkrBgEEAYI3
# LgMwgYMwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvZG9jcy9wcmltYXJ5Y3BzLmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBh
# AGwAXwBwAG8AbABpAGMAeQBfAHMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG
# 9w0BAQsFAAOCAgEAZ/KGpZjgVHkaLtPYdGcimwuWEeFjkplCln3SeQyQwWVfLiw+
# +MNy0W2D/r4/6ArKO79HqaPzadtjvyI1pZddZYSQfYtGUFXYDJJ80hpLHPM8QotS
# 0LD9a+M+By4pm+Y9G6XUtR13lDni6WTJRD14eiPzE32mkHSDjfTLJgJGKsKKELuk
# qQUMm+1o+mgulaAqPyprWEljHwlpblqYluSD9MCP80Yr3vw70L01724lruWvJ+3Q
# 3fMOr5kol5hNDj0L8giJ1h/DMhji8MUtzluetEk5CsYKwsatruWy2dsViFFFWDgy
# cScaf7H0J/jeLDogaZiyWYlobm+nt3TDQAUGpgEqKD6CPxNNZgvAs0314Y9/HG8V
# fUWnduVAKmWjw11SYobDHWM2l4bf2vP48hahmifhzaWX0O5dY0HjWwechz4GdwbR
# BrF1HxS+YWG18NzGGwS+30HHDiju3mUv7Jf2oVyW2ADWoUa9WfOXpQlLSBCZgB/Q
# ACnFsZulP0V3HjXG0qKin3p6IvpIlR+r+0cjgPWe+L9rt0uX4ut1eBrs6jeZeRhL
# /9azI2h15q/6/IvrC4DqaTuv/DDtBEyO3991bWORPdGdVk5Pv4BXIqF4ETIheu9B
# CrE/+6jMpF3BoYibV3FWTkhFwELJm3ZbCoBIa/15n8G9bW1qyVJzEw16UM0xghYJ
# MIIWBQIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExAhMzAAAA
# ZEeElIbbQRk4AAAAAABkMA0GCWCGSAFlAwQCAQUAoIH3MBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqG
# SIb3DQEJBDEiBCD+KX8zxpjlzA3GITTNHJ/dqXl9UOc33NeXOBVaxuIbaTCBigYK
# KwYBBAGCNwIBDDF8MHqgGIAWAEEAUgBNACAAcwBjAHIAaQBwAHQAc6FegFxodHRw
# czovL2dpdGh1Yi5jb20vTWljcm9zb2Z0L01TSVRBUk0vdHJlZS9kZXZlbG9wLzMw
# MS1tdWx0aS12bS1kb21haW4tam9pbi1idWlsZC1kc2Mvc2NyaXB0czANBgkqhkiG
# 9w0BAQEFAASCAQA01PIy25ELtJ3G5crA9//fmmD4EFPhhfbqA0A4JEdPzdc1eQxq
# 3QzUvolzzTyZPxuQRrWvOn+XG5PHU8AuNQJ+zE2Q87lkK8bH4kXdipgIrpuSEiUa
# viEasNW6xA/liZd2oTEb3z67qVLVhWiv/E/edMH+JXoWsTykKWMxOSkW3YL2k2XT
# AGDPJbLH/OxY3WmaYiztWrbHcGAyx6Gk2jMTQETEWucnti8z+M95YtNCnBnVDRvs
# TlHg3wSeFy39FlbIJBll37c+WOFpbplyE4qL3S2WLxcNLxAKzx2oW5v3HF9PkM1b
# 6IzF7J/SOozcvWCcteWnllVFEEA6r9aZTHxyoYITSjCCE0YGCisGAQQBgjcDAwEx
# ghM2MIITMgYJKoZIhvcNAQcCoIITIzCCEx8CAQMxDzANBglghkgBZQMEAgEFADCC
# AT0GCyqGSIb3DQEJEAEEoIIBLASCASgwggEkAgEBBgorBgEEAYRZCgMBMDEwDQYJ
# YIZIAWUDBAIBBQAEIG9BUDjGRvP8hGPU6p6dD7cbgJfz2ky7/bWK+0Y+YARbAgZX
# vIMR4UoYEzIwMTYwODMwMDI1MDQ0LjM2OFowBwIBAYACAfSggbmkgbYwgbMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIx
# JzAlBgNVBAsTHm5DaXBoZXIgRFNFIEVTTjpDMEY0LTMwODYtREVGODElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCDs0wggZxMIIEWaADAgEC
# AgphCYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0
# aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEy
# MTQ2NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG
# 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCC
# hfvtfGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRU
# QwzXTbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FU
# sc+TTJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBX
# day9ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4
# HLDpmc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCC
# AeIwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2ha
# hW1VMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNV
# HRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYG
# A1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3Js
# L3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcB
# AQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kv
# Y2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUw
# gZIwgY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0
# HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0
# AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1
# Mb7PBeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRg
# Eop2zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X
# 9S95gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbl
# jjO7Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQ
# eKZt0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ou
# OVd2onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+9
# 8eEA3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUB
# HoD7G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ay
# p0Kiyc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXj
# ad5XwdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb
# 01+P3nSISRIwggTaMIIDwqADAgECAhMzAAAAlr/ytCHAd3UkAAAAAACWMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTE2MDQy
# NzE3MDYxN1oXDTE3MDcyNzE3MDYxN1owgbMxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBoZXIg
# RFNFIEVTTjpDMEY0LTMwODYtREVGODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ0y
# MLS8iyZFouvssJCJhu4iIx0gusRfKVF7DWXu7wgOO9477m+PTOzSXnV9566lvsLf
# vgQm7t7B383R71dVwEqcWpugW0aIj7URDPHiH/g9/aNYIDgDywTeKCkyQh2G5J/u
# fM7RQXhwraJHfzjvk2l8jBljcoiz4YlQPJ0JTvBjUfKSCcflDhtL07mVB4MUpa+9
# NuwH8C52KrTc+T0iwyMwxLoXgfZasopTXlRWj5Nbz9/rGN8cPcpEiH9FAdQBVGDU
# 3xkWdis/lcxTtrJV/Da+GVLrRC/Nly5yk7lik30WcA6Ndgei3YNaKKcPXRiQJdgj
# YMh7ALehdDfzty0tf/0CAwEAAaOCARswggEXMB0GA1UdDgQWBBSdGDcZIbm19sxj
# 3raOFolLMOX9XjAfBgNVHSMEGDAWgBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNV
# HR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9w
# cm9kdWN0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEE
# TjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMG
# A1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IBAQBQdKGemJkwFnJb
# j2WSZpoRoAj01e9ubPNIlqXP3oFUkuCQS/Hsf5ZCZkYJJlcNqOjgu4UJTzCgRNs4
# OxsUlfdwha2jLNcovgVtl9R0BntG6JXN9RMftNii2Y4lN/5+TwKLplQBN+2HCyqw
# uyeLBjekQKVEQZ57EK+SP4BUDzBb5DqwtC3E/haFY0tSAFgNubv56tiOIt7FSxiT
# ZCBaes15EKC5qB7CydMLENBFHMMcQPFB+iECYTyzbWLodGRhSSd7/bGuTSvWYr02
# PC18lPwl4wpC74QteYfIWAbvfqxgm4ODFosCsAcudB7xsCp6MnBM7VwmvAiGODAk
# q1s84WGuoYIDdjCCAl4CAQEwgeOhgbmkgbYwgbMxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBo
# ZXIgRFNFIEVTTjpDMEY0LTMwODYtREVGODElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZaIlCgEBMAkGBSsOAwIaBQADFQDkasCTMEE2e4WWCwtc
# Zcgdi8C9nqCBwjCBv6SBvDCBuTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBOVFMgRVNO
# OjU3RjYtQzFFMC01NTRDMSswKQYDVQQDEyJNaWNyb3NvZnQgVGltZSBTb3VyY2Ug
# TWFzdGVyIENsb2NrMA0GCSqGSIb3DQEBBQUAAgUA229FOTAiGA8yMDE2MDgyOTIz
# MzUyMVoYDzIwMTYwODMwMjMzNTIxWjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDb
# b0U5AgEAMAcCAQACAgpJMAcCAQACAhe+MAoCBQDbcJa5AgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwGgCjAIAgEAAgMW42ChCjAIAgEAAgMHoSAwDQYJ
# KoZIhvcNAQEFBQADggEBAF0UWzLKc/zabtd9Uo2oCvug++P6zN5Gyoaq/bPXIYf7
# H/+9Oiogt5cvDvZO1Nc+YZEn9e9TaDctVP4XazXkLUEinwCNx+7btLfrDhdvGw/0
# GWMd96HX5Zq3J3pP6SZdEM8HAODlJF+PShMxjx3d0K+74FZi2rx5aea1CAkfkKhK
# v3w7fV/u+rp/5YsJLHXt6GRAlk+MSACGSD5bvDyNLf1Ysc2K71TnKc8Fvtata61Y
# aLEDOJmhdHxfrorIdGbags70aShPsyoTE2AHC3CsAay5qQmkbgX1XW15peLMywe1
# Uy1V67uDBpmLBBFhMKPA4rg3oepSJ02JF+zdzRkjqfcxggL1MIIC8QIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAJa/8rQhwHd1JAAAAAAA
# ljANBglghkgBZQMEAgEFAKCCATIwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCAqnYxFF2oUW661CBv1haL9gDA6dkHW+sddaTFDvv9Y
# ejCB4gYLKoZIhvcNAQkQAgwxgdIwgc8wgcwwgbEEFORqwJMwQTZ7hZYLC1xlyB2L
# wL2eMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAACW
# v/K0IcB3dSQAAAAAAJYwFgQU5KCcVmW+1ST/ElYeo79Gge+2IkUwDQYJKoZIhvcN
# AQELBQAEggEAFdn9be73bCxra/q2km8jrUVOo0ok0Vn9MyBajAg0PQCPhtPMo51q
# X6vMH5jz4y+fqcMnwEHzU4sKvWzlyC3zsYkUyF/T0PcPQUDQsduClQPG/PnbMu4K
# f995nfZLBCs12eJWQ7On3J2fh6PFkZxKrmbRRCtlWGAzfYW32+ZwRYr8k2Kz9vu2
# p9iO1vjCoePpVC6+FD/FUnmubSn44yRa5SObNG9DWsZyNHbGSYd2nj51BQJixGmu
# XTWSeBtGecqZRP7Y+SygBcDjbEa7aGZzUSVN9qZjWUqD+vw+TTiZ2RYVaS06F48P
# dVR0Y6JDuo4+DgsL3T42DjNrIPjOp6lDrA==
# SIG # End signature block
