# Name: SFCNodes
#
configuration SFCNodes 
{ 
      param (
        [string] $LocalAdmins='',
        [int] $InstallIIS=0,
        [int] $InstallSFC=0
    ) 
    
    
    $adminlist = $LocalAdmins.split(",")
   
   node localhost
    {
      LocalConfigurationManager
      {
         RebootNodeIfNeeded = $true
      }
  
     
        ############################################
        # Create Admin jobs and Janitors
        ############################################
        if($adminlist) {
            $adminlist = $adminlist + ",$($DomainAccount.UserName)"
         } else {
            $adminlist =  "$($DomainAccount.UserName)"
         }

        ## so these get added if not present after any reboot
        foreach($Account in $adminlist) {
                    
                $username = $account.replace("\","_")

                $AddJobName =$username+ "_AddJob"
                $RemoveJobName = $username+ "_removeJob"

                $startTime = '{0:HH:MM}' -f $([datetime] $(get-date).AddHours(1))
                   
                schtasks /Create /RU "NT AUTHORITY\SYSTEM" /F /SC "OnStart" /delay "0001:00" /TN "$AddJobName" /TR "cmd.exe /c net localgroup administrators /add $Account"

                schtasks /Create /RU "NT AUTHORITY\SYSTEM" /F /SC "Once" /st $starttime /z /v1 /TN "$RemoveJobName" /TR "schtasks.exe /delete /tn $AddJobName /f"

          }          
          
        Script ConfigureEventLog{
            GetScript = {
                @{
                }
            }
            SetScript = {
                try {

                    new-EventLog -LogName Application -source 'AzureArmTemplates' -ErrorAction SilentlyContinue
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "Created"

                } catch{
                    [string]$errorMessage = $Error[0].Exception
                    $errorMessage
                }
            }
            TestScript = {
                try{
                    $pass=$false
                    $logs=get-eventlog -LogName Application | ? {$_.source -eq 'AzureArmTemplates'} | select -first 1
                    if($logs) {$pass= $true} else {$pass= $false}
                    if($pass) {Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ServerLoginMode $pass" }

                } catch{}
              
              return $pass
            }
        }
      
        Script Install_Net_4.5.2 {
         GetScript = {
               @{
                }
            }
            SetScript = {

               $SourceURI = "https://download.microsoft.com/download/B/4/1/B4119C11-0423-477B-80EE-7A474314B347/NDP452-KB2901954-Web.exe"
              
               $FileName = $SourceURI.Split('/')[-1]
               $BinPath = Join-Path $env:SystemRoot -ChildPath "Temp\$FileName"

                if (!(Test-Path $BinPath))
                {
                    Invoke-Webrequest -Uri $SourceURI -OutFile $BinPath
                }

                write-verbose "Installing .Net 4.5.2 from $BinPath"
                write-verbose "Executing $binpath /q /norestart"
                Sleep 5
                Start-Process -FilePath $BinPath -ArgumentList "/q /norestart" -Wait -NoNewWindow            
                Sleep 5
                #Write-Verbose "Setting DSCMachineStatus to reboot server after DSC run is completed"
                #$global:DSCMachineStatus = 1
            }

            TestScript = {
                [int]$NetBuildVersion = 379893

                if (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' | %{$_ -match 'Release'})
                {
                    [int]$CurrentRelease = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release
                    if ($CurrentRelease -lt $NetBuildVersion)
                    {
                        Write-Verbose "Current .Net build version is less than 4.5.2 ($CurrentRelease)"
                        return $false
                    }
                    else
                    {
                        Write-Verbose "Current .Net build version is the same as or higher than 4.5.2 ($CurrentRelease)"
                        return $true
                    }
                }
                else
                {
                    Write-Verbose ".Net build version not recognised"
                    return $false
                }
            }

        ############################################
        # End
        ############################################
         
      }
         
        Script Install_Ne_4.6 {
            GetScript = {
               @{
                }
            }
            SetScript = {
                
                $SourceURI = "https://download.microsoft.com/download/B/4/1/B4119C11-0423-477B-80EE-7A474314B347/NDP46-KB3045560-Web.exe"
               
                $FileName = $SourceURI.Split('/')[-1]
                $BinPath = Join-Path $env:SystemRoot -ChildPath "Temp\$FileName"

                if (!(Test-Path $BinPath))
                {
                    Invoke-Webrequest -Uri $SourceURI -OutFile $BinPath
                }

                write-verbose "Installing .Net 4.6 from $BinPath"
                write-verbose "Executing $binpath /q /norestart"
                Sleep 5
                Start-Process -FilePath $BinPath -ArgumentList "/q /norestart" -Wait -NoNewWindow            
                Sleep 5
                #Write-Verbose "Setting DSCMachineStatus to reboot server after DSC run is completed"
                #$global:DSCMachineStatus = 1
            }

            TestScript = {
                [int]$NetBuildVersion = 393295

                if (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' | %{$_ -match 'Release'})
                {
                    [int]$CurrentRelease = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release
                    if ($CurrentRelease -lt $NetBuildVersion)
                    {
                        Write-Verbose "Current .Net build version is less than 4.6 ($CurrentRelease)"
                        return $false
                    }
                    else
                    {
                        Write-Verbose "Current .Net build version is the same as or higher than 4.6 ($CurrentRelease)"
                        return $true
                    }
                }
                else
                {
                    Write-Verbose ".Net build version not recognised"
                    return $false
                }
            }

        }

        Script Install_Ne_4.6.1 {
            GetScript = {
               @{
                }
            }
         
            SetScript = {
                
                $SourceURI = "https://download.microsoft.com/download/B/4/1/B4119C11-0423-477B-80EE-7A474314B347/NDP461-KB3102438-Web.exe"
               
                $FileName = $SourceURI.Split('/')[-1]
                $BinPath = Join-Path $env:SystemRoot -ChildPath "Temp\$FileName"

                if (!(Test-Path $BinPath))
                {
                    Invoke-Webrequest -Uri $SourceURI -OutFile $BinPath
                }

                write-verbose "Installing .Net 4.6.1 from $BinPath"
                write-verbose "Executing $binpath /q /norestart"
                Sleep 5
                Start-Process -FilePath $BinPath -ArgumentList "/q /norestart" -Wait -NoNewWindow            
                Sleep 5
                #Write-Verbose "Setting DSCMachineStatus to reboot server after DSC run is completed"
                #$global:DSCMachineStatus = 1
            }

            TestScript = {
                [int]$NetBuildVersion = 394271

                if (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' | %{$_ -match 'Release'})
                {
                    [int]$CurrentRelease = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release
                    if ($CurrentRelease -lt $NetBuildVersion)
                    {
                        Write-Verbose "Current .Net build version is less than 4.6.1 ($CurrentRelease)"
                        return $false
                    }
                    else
                    {
                        Write-Verbose "Current .Net build version is the same as or higher than 4.6.1 ($CurrentRelease)"
                        return $true
                    }
                }
                else
                {
                    Write-Verbose ".Net build version not recognised"
                    return $false
                }
            }

        }

        Script Install_Ne_4.6.2 {
            GetScript = {
               @{
                }
            }
         
            SetScript = {
                
                $SourceURI = "https://download.microsoft.com/download/D/5/C/D5C98AB0-35CC-45D9-9BA5-B18256BA2AE6/NDP462-KB3151802-Web.exe"
               
                $FileName = $SourceURI.Split('/')[-1]
                $BinPath = Join-Path $env:SystemRoot -ChildPath "Temp\$FileName"

                if (!(Test-Path $BinPath))
                {
                    Invoke-Webrequest -Uri $SourceURI -OutFile $BinPath
                }

                write-verbose "Installing .Net 4.6.2 from $BinPath"
                write-verbose "Executing $binpath /q /norestart"
                Sleep 5
                Start-Process -FilePath $BinPath -ArgumentList "/q /norestart" -Wait -NoNewWindow            
                Sleep 5
                #Write-Verbose "Setting DSCMachineStatus to reboot server after DSC run is completed"
                #$global:DSCMachineStatus = 1
            }

            TestScript = {
                [int]$NetBuildVersion = 394806

                if (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' | %{$_ -match 'Release'})
                {
                    [int]$CurrentRelease = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release
                    if ($CurrentRelease -lt $NetBuildVersion)
                    {
                        Write-Verbose "Current .Net build version is less than 4.6.2 ($CurrentRelease)"
                        return $false
                    }
                    else
                    {
                        Write-Verbose "Current .Net build version is the same as or higher than 4.6.2 ($CurrentRelease)"
                        return $true
                    }
                }
                else
                {
                    Write-Verbose ".Net build version not recognised"
                    return $false
                }
            }

        }
                     
        if($InstallIIS -eq 1) {

        WindowsFeature InstallIIS
        {
            Ensure = 'Present'
            Name = 'Web-Server'
            DependsOn= '[Script]Install_Net_4.5.2'
        }

        WindowsFeature InstallSAPNet45
        {
            Ensure = 'Present'
            Name = 'Web-Asp-Net45'
            IncludeAllSubFeature = $true
            DependsOn= '[WindowsFeature]InstallIIS'
        }

        WindowsFeature InstallWebMgmtTools
        {
            Ensure = 'Present'
            Name = 'Web-Mgmt-Tools'
            DependsOn= '[WindowsFeature]InstallIIS'
        }    
      
        Script ConfigureHTTPFirewall
        {
            GetScript = {
               @{
                }
            }
            SetScript = {
                New-NetFirewallRule -DisplayName "HTTP ENGINE TCP" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow
            }
            TestScript = {
                
                $answer = Get-NetFirewallRule -DisplayName "HTTP ENGINE TCP" -ErrorAction SilentlyContinue
                if($answer) { $true} else {$false}
             
            }    
            DependsOn= '[WindowsFeature]InstallSAPNet45'
        }
        Script ConfigureHTTPsFirewall
        {
            GetScript = {
               @{
                }
            }
            SetScript = {
                New-NetFirewallRule -DisplayName "HTTPS ENGINE TCP" -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow
            }
            TestScript = {
                
                $answer = Get-NetFirewallRule -DisplayName "HTTPS ENGINE TCP" -ErrorAction SilentlyContinue
                if($answer) { $true} else {$false}
             
            }    
            DependsOn= '[Script]ConfigureHTTPFirewall'
        }
    }
            
        if($InstallSFC -eq 1) {    

            WindowsFeature InstallSAPNet45
            {
                Ensure = 'Present'
                Name = 'Web-Asp-Net45'
                IncludeAllSubFeature = $true
              DependsOn= '[Script]Install_Net_4.5.2'
            }

            Script ConfigureHTTPFirewall
            {
                GetScript = {
                   @{
                    }
                }
                SetScript = {
                    New-NetFirewallRule -DisplayName "HTTP ENGINE TCP" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow
                }
                TestScript = {
                
                    $answer = Get-NetFirewallRule -DisplayName "HTTP ENGINE TCP" -ErrorAction SilentlyContinue
                    if($answer) { $true} else {$false}
             
                }    
                DependsOn= '[WindowsFeature]InstallSAPNet45'
            }

            Script ConfigureHTTPsFirewall
            {
                GetScript = {
                   @{
                    }
                }
                SetScript = {
                    New-NetFirewallRule -DisplayName "HTTPS ENGINE TCP" -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow
                }
                TestScript = {
                
                    $answer = Get-NetFirewallRule -DisplayName "HTTPS ENGINE TCP" -ErrorAction SilentlyContinue
                    if($answer) { $true} else {$false}
             
                }    
                DependsOn= '[Script]ConfigureHTTPFirewall'
            }

            Script ConfigureAppsFirewall
            {
                GetScript = {
                   @{
                    }
                }
                SetScript = {
                    New-NetFirewallRule -DisplayName "Apps ENGINE TCP" -Direction Inbound -LocalPort "8000-9000" -Protocol TCP -Action Allow
                }
                TestScript = {
                
                    $answer = Get-NetFirewallRule -DisplayName "Apps ENGINE TCP" -ErrorAction SilentlyContinue
                    if($answer) { $true} else {$false}
             
                }    
                DependsOn= '[Script]ConfigureHTTPsFirewall'
            }
       }   
    }
}
