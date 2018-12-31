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
        [string] $scriptFolderUrl="https://raw.githubusercontent.com/Microsoft/MSITARM/develop/all-scripts/",
        $Disks
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
                   
                schtasks /Create /RU "NT AUTHORITY\SYSTEM" /F /SC "OnStart" /delay "0001:00" /TN "$AddJobName" /TR "cmd.exe /c C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe Add-LocalGroupMember -Group administrators -Member $Account"

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
                    
                    $drive = Get-WmiObject -Class win32_volume -Filter "DriveLetter = 'E:' AND DriveType = '5'"
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
                    $drive = Get-WmiObject -Class win32_volume -Filter "DriveLetter = 'E:' AND DriveType = '5'"
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
        xComputer DomainJoin
        {
            Name = $env:computername
            DomainName = $domain
            Credential = $DomainCreds
            ouPath = $ou
            DependsOn= '[Script]ConfigureDVDDrive'
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
                                                                                        
                        $SQLAdminsList = $($using:SQLAdmins).split(",")
                        
                        foreach($SysAdmin in $SQLAdminsList) {
                         try{   
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
                             }catch{
                                Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Error -message "Failed to add: $($SysAdmin) $($_.exception.message)" 
                             } #dont want it to be fatal for the rest.
                         }
                       

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
         

        ############################################
        # Configure Simple Patching
        ############################################

        File PatchPath {
            Type = 'Directory'
            DestinationPath = "C:\PowerPatch"
            Ensure = "Present"
            DependsOn = "[Script]ConfigureSQLServerDomain"
        }

        Script ConfigurePatchPatch{
            GetScript = {
                @{
                }
            }
            SetScript = {
                   
                    try { 
 
                        $Root = "C:\PowerPatch"

                        if($(test-path -path $root) -eq $true) {
                        
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"

                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule
                                                                                           
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "ReadAndExecute", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                            
                            #Setting the Change
                            Set-Acl $Root $acl
                      }                         
                       
                    } catch{
                       [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureDataPath: $errorMessage"
                       }
                    }
                }           
            TestScript = { 

                $pass = $true

                $Root = "C:\PowerPatch"

                if($(test-path -path $root) -eq $true) {
                    $ACL = Get-Acl $Root
                                   
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'CREATOR OWNER'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'NT AUTHORITY\SYSTEM'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'BUILTIN\Administrators'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'BUILTIN\Users'}}).FileSystemRights -ne 'ReadAndExecute'){
                        $pass= $false
                    }                      

                } else {
                    $pass = $false
                }

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureDataPath $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureDataPath $pass"
                }

             return $pass
            }
            DependsOn = "[File]PatchPath"
        }

        Script SetPowerPatchExe {
            GetScript = {
                @{
                }
            }
            SetScript = {
                if($(test-path -path C:\PowerPatch) -eq $true) {
               
                    $WebClient = New-Object System.Net.WebClient
                    $WebClient.DownloadFile($($Using:scriptFolderUrl) + "supdate_v4.0.exe_1","C:\PowerPatch\supdate_v4.0.exe")

                }
            }
            TestScript = { 
                $pass=$false
                if($(test-path -path "C:\PowerPatch\supdate_v4.0.exe") -eq $true) {
                    $pass=$true
                } else {
                    $pass=$false
                }

                return $Pass
            }
            DependsOn = "[Script]ConfigurePatchPatch"
        }
        
        Script SetPowerPatchPs1 {
            GetScript = {
                @{
                }
            }
            SetScript = {
                if($(test-path -path C:\PowerPatch) -eq $true) {
               
                    $WebClient = New-Object System.Net.WebClient
                    $WebClient.DownloadFile($($Using:scriptFolderUrl) + "PowerPatching.ps1","C:\PowerPatch\PowerPatching.ps1")
                                       
                }
            }
            TestScript = { 
                $pass=$false
                if($(test-path -path "C:\PowerPatch\PowerPatching.ps1") -eq $true) {
                    $pass=$true
                } else {
                    $pass=$false
                }

                return $Pass
            }
            DependsOn = "[Script]SetPowerPatchExe"
        }
        
        Script SetPowerPatchJob {
            GetScript = {
                @{
                }
            }
            SetScript = {
                if($(test-path -path C:\PowerPatch) -eq $true) {
            
                    if($(test-path -path C:\PowerPatch\PowerPatching.ps1) -eq $true) {
                        . C:\PowerPatch\PowerPatching.ps1
                    }
                }
            }
            TestScript = { 
                $pass=$false
                if($(test-path -path "C:\PowerPatch\PowerPatching.ps1") -eq $true) {

                    if ((Get-ScheduledTask -TaskPath '\' | Where-Object { $_.TaskName -eq 'E2SPowerPatching'; }) -eq $null) {
                        $pass=$false
                    }else {
                        $pass=$true
                    }

                } else {
                    $pass=$false
                }

                return $Pass
            }
            DependsOn = "[Script]SetPowerPatchPs1"
        }

        ############################################
        # End
        ############################################

        ############################################
        # Format Data Disks
        ############################################
        Script FormatVolumnes
        {
            GetScript = {
              get-disk
              Get-Partition
            }
            SetScript = {
               try {
                
                # Initialize All
                Get-Disk | ?{$_.PartitionStyle -eq "Raw"} | ?{$_.number -ne 0}| Initialize-Disk -PartitionStyle GPT

                #format the ones requested
                foreach($disk in $using:Disks.values) {

                    $partArray = Get-Partition
                    
                    #remove any non-lettered partitions
                    $(Get-Partition |? {if($_.DriveLetter -notmatch "[A-Z]" -and $_.DiskNumber -gt 1 -and $_.Type -ne "IFS" ){$_} }) | Remove-Partition -Confirm:$false

                    #Get the list of whats left
                    $UsedDiskArray = $(Get-Partition | ?{$_.DiskNumber -gt 1} | Select DiskNumber -Unique)

                    $thisExists =$partArray  | Where-Object {$_.DriveLetter -eq $($disk.DiskName)} | Select -First 1
        
                    if($thisExists -eq $null) {
                        
                       $DiskExists =   get-disk  | ? {$_.Number -notin $UsedDiskArray.DiskNumber} | ? {$($_.Size/1GB) -eq $($disk.Disksize) }  | Sort-Object DiskNumber | select -First 1
                      
                        try {
                            if($DiskExists) {      
                            
                                if($DiskExists.PartitionStyle -eq 'Raw') {
                                       Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter $($disk.DiskName) -UseMaximumSize -DiskNumber $($DiskExists.Number) | Format-Volume -NewFileSystemLabel $($disk.DiskLabel) -FileSystem NTFS -AllocationUnitSize 65536 -Confirm:$false -Force     
                                    } else {
                                       New-Partition -DriveLetter $($disk.DiskName) -UseMaximumSize -DiskNumber $($DiskExists.Number) | Format-Volume -NewFileSystemLabel $($disk.DiskLabel) -FileSystem NTFS -AllocationUnitSize 65536 -Confirm:$false -Force
                                    } 
                          
                            } else {
                                write-verbose "No Drive avail"
                            }
                        } catch {
                                write-verbose  "`t[FAIL] $VM Setting Drive $($Disk.DiskName) Failed.`n"
                        
                        }

                    } else {
                        Write-verbose "`t[PASS] $VM Drive $($Disk.DiskName) exists.`n"
                    }
                }

                #format the remaining using next available drive letter
                get-disk | ? {$_.PartitionStyle -eq 'Raw'} | %{ Initialize-Disk -PartitionStyle GPT -Number $_.number -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -Confirm:$false  }   

               } catch {}
            }
            TestScript = {
                 $diskArray = get-disk | ? {$_.PartitionStyle -eq 'RAW'}
                 $partArray = Get-Partition

                 $vols =@()
                 $disks | ? {
                    $d=$_
                    $v =  $($partArray  | Where-Object {$_.DriveLetter -eq $($d.DiskName)} | Select -First 1)
                    if(!$v){
                        $vols+=$d
                    }
                 }

            if($vols) {return $true} else {return $false}
            }    
            DependsOn = "[Script]SetPowerPatchJob"
        }
         
      }
       
    }
