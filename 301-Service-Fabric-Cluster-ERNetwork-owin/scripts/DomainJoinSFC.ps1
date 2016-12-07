# Name: DomainJoin
#
configuration DomainJoin 
{ 
      param (
        [Parameter(Mandatory)]
        [string] $Domain,
        [string] $ou,
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential] $LocalAccount,
         [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential] $DomainAccount,
        [string] $LocalAdmins='',
        [string] $SQLAdmins='',
        [int] $InstallIIS=0,
        [int] $InstallSFC=0
    ) 
    
    
    $adminlist = $LocalAdmins.split(",")
    
    Import-DscResource -ModuleName cComputerManagement
    Import-DscResource -ModuleName xActiveDirectory

    Import-Module ServerManager
    Add-WindowsFeature RSAT-AD-PowerShell
    import-module activedirectory

   node localhost
    {
      LocalConfigurationManager
      {
         RebootNodeIfNeeded = $true
      }
  
        [System.Management.Automation.PSCredential ]$DomainCreds = New-Object System.Management.Automation.PSCredential ($DomainAccount.UserName, $DomainAccount.Password)

        if($domain -match 'partners') {

                     try{
                            $fw=New-object –comObject HNetCfg.FwPolicy2
                         
                            foreach($z in (1..4)) {
                            $CurrentProfiles=$z
                             $fw.EnableRuleGroup($CurrentProfiles, "File and Printer Sharing", $true)
                             $fw.EnableRuleGroup($CurrentProfiles, "File and Printer Sharing (SMB-In)", $true)
                             $fw.EnableRuleGroup($CurrentProfiles, "File and Printer Sharing (Spooler Service - RPC-EPMAP)", $true)
                             $fw.EnableRuleGroup($CurrentProfiles, "File and Printer Sharing (Spooler Service - RPC)", $true)
                             $fw.EnableRuleGroup($CurrentProfiles, "File and Printer Sharing (NB-Session-In)", $true)
                             $fw.EnableRuleGroup($CurrentProfiles, "File and Printer Sharing (NB-Name-In)", $true)
                             $fw.EnableRuleGroup($CurrentProfiles, "File and Printer Sharing (NB-Datagram-In)", $true)

                            }

                            
                    }catch{}
                }
                try {
                    $gemaltoDriver = $(ChildItem -Recurse -Force "C:\Program Files\WindowsPowerShell\Modules\" -ErrorAction SilentlyContinue | Where-Object { ($_.PSIsContainer -eq $false) -and  ( $_.Name -like "Gemalto.MiniDriver.NET.inf") } | Select-Object FullName) | select -first 1

                    if($gemaltoDriver){
                        $f = '"' + $($gemaltoDriver.FullName) + '"'
                        iex "rundll32.exe advpack.dll,LaunchINFSectionEx $f"
                    }
                }catch {}

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

        Script ConfigureDVDDrive{
            GetScript = {
                @{
                }
            }
            SetScript = {
                try {

                   # Change E: => F: to move DVD to F because E will be utilized as a data disk.
                    
                    $drive = Get-WmiObject -Class win32_volume -Filter "DriveLetter = 'E:'"
                    if($drive) {
                        Set-WmiInstance -input $drive -Arguments @{DriveLetter="F:"}
                        Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "Move E to F" 
                    }
                } catch{
                    [string]$errorMessage = $Error[0].Exception
                    if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                        Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
                    } else {$errorMessage}
                }
            }
            TestScript = {
                $pass=$false
                try{
                    $drive = Get-WmiObject -Class win32_volume -Filter "DriveLetter = 'E:'"
                    if($drive) {$pass= $False} else {$pass= $True}
                    if(!$drive) {Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureDVDDrive $pass" }
                } catch{
                    [string]$errorMessage = $Error[0].Exception
                    if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                        Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
                    } else {$errorMessage}
                }
              
              return $pass
            }
            DependsOn= '[Script]ConfigureEventLog'
        }    
      
      if((gwmi win32_computersystem).partofdomain -eq $false) {
        xComputer DomainJoin
        {
            Name = $env:computername
            DomainName = $domain
            Credential = $DomainCreds
            ouPath = $ou
            DependsOn= '[Script]ConfigureDVDDrive'
        }
       }

        WindowsFeature RSATTools
        {
            Ensure = 'Present'
            Name = 'RSAT-AD-Tools'
            IncludeAllSubFeature = $true
            DependsOn= '[xComputer]DomainJoin'
        }

        xWaitForADDomain DscForestWait 
        { 
            DomainName       = $domain
            DomainUserCredential = $DomainCreds
            RetryCount       = 100
            RetryIntervalSec = 5
            DependsOn = "[WindowsFeature]RSATTools"
        } 
      
        ############################################
        # Configure Domain account for SQL Access if SQL is installed
        ############################################
       
        Script ConfigureSQLServerDomain
        {
            GetScript = {
                $sqlInstances = gwmi win32_service -computerName $env:computername | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } | % { $_.Caption }
                $res = $sqlInstances -ne $null -and $sqlInstances -gt 0
                $vals = @{ 
                    Installed = $res; 
                    InstanceCount = $sqlInstances.count 
                }
                $vals
            }
            SetScript = {

               $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } | % { $_.Caption }
               $ret = $false

                if($sqlInstances -ne $null -and $sqlInstances -gt 0){
                    
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "Configuring SQL Server Admin Access" 

                    try{                    

                        ###############################################################
                        $NtLogin = $($using:DomainAccount.UserName) 
                        $LocalLogin = "$($env:computername)\$($using:LocalAccount.UserName)"
                        ###############################################################

                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
 
                        $NtLogin = $($using:DomainAccount.UserName) 

                        $srvConn.connect();
                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn
            
                        $login = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $Srv, $NtLogin
                        $login.LoginType = 'WindowsUser'
                        $login.PasswordExpirationEnabled = $false
                        $login.Create()

                        #  Next two lines to give the new login a server role, optional

                        $login.AddToRole('sysadmin')
                        $login.Alter()
                          
                        ########################## +SQLSvcAccounts ##################################### 
                        try{                                                                    
                        $SQLAdminsList = $($using:SQLAdmins).split(",")
                        
                        foreach($SysAdmin in $SQLAdminsList) {

                            $login = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $Srv, $SysAdmin
                            $login.LoginType = 'WindowsUser'
                            $login.PasswordExpirationEnabled = $false
                           
                            $Exists = $srv.Logins | ?{$_.name -eq $SysAdmin}
                             if(!$Exists) {
                                $login.Create()
                                
                                #  Next two lines to give the new login a server role, optional
                                $login.AddToRole('sysadmin')
                                $login.Alter()           
                            }
                         }
                        }catch{} #nice to have but dont want it to be fatal.

                        ########################## -[localadmin] #####################################
                        try{
                        $q = "if Exists(select 1 from sys.syslogins where name='" + $locallogin + "') drop login [$locallogin]"
				        Invoke-Sqlcmd -Database master -Query $q
                        }catch{} #nice to have but dont want it to be fatal.

                        ########################## -[BUILTIN\Administrators] #####################################
                        $q = "if Exists(select 1 from sys.syslogins where name='[BUILTIN\Administrators]') drop login [BUILTIN\Administrators]"
				        Invoke-Sqlcmd -Database master -Query $q
                                                
                        New-NetFirewallRule -DisplayName "MSSQL ENGINE TCP" -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Allow

                    } catch {
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
                        } else {$errorMessage}
                    }
                }
            }
            TestScript = {
                
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } | % { $_.Caption }
                $ret=$false

                if($sqlInstances -ne $null -and $sqlInstances -gt 0){
                   try{
                        
                        $null= [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null= [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null= [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
            
                        $NtLogin =$($using:DomainAccount.UserName) 
                        
                        $srvConn.connect();
                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $Exists = $srv.Logins | ?{$_.name -eq $NtLogin}
                        if($Exists) {$ret=$true} else {$ret=$false}

                         ########################## +SQLSvcAccounts ##################################### 
                     
                        if($ret)  {
                                                                                         
                            $SQLAdminsList = $($using:SQLAdmins).split(",")
                                                          
                                foreach($SysAdmin in $SQLAdminsList) {
                                                            
                                    $Exists = $srv.Logins | ?{$_.name -eq $SysAdmin}
                                    if($Exists) {$ret=$true} else {$ret=$false; break;}
                            
                                }
                            }

                    } catch{$ret=$false}   
                                             
                } else {$ret=$true}

            Return $ret
            }    
            DependsOn= '[xWaitForADDomain]DscForestWait'
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
