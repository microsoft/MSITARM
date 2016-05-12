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
        [string] $AdditionalAdmins=''
    ) 
    
    
    $adminlist = $AdditionalAdmins.split(",")
    
    Import-DscResource -ModuleName xComputerManagement
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
              
        cd\
        md Temp
        $sw = New-Object System.IO.StreamWriter(“C:\Temp\domainJoin.log”)
        ############################################
        # Start
        ############################################
        $sw.WriteLine("$(Get-Date -Format g) Begin Domain Join")
        
        # Change E: => F: to move DVD to F.
        $sw.WriteLine("$(Get-Date -Format g) Change E: => F:...")
        $drive = Get-WmiObject -Class win32_volume -Filter "DriveLetter = 'E:'"
        Set-WmiInstance -input $drive -Arguments @{DriveLetter="F:"}


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

                     $gemaltoDriver = $(ChildItem -Recurse -Force "C:\Program Files\WindowsPowerShell\Modules\" -ErrorAction SilentlyContinue | Where-Object { ($_.PSIsContainer -eq $false) -and  ( $_.Name -like "Gemalto.MiniDriver.NET.inf") } | Select-Object FullName) | select -first 1

                     if($gemaltoDriver){
                         $f = '"' + $($gemaltoDriver.FullName) + '"'
                         iex "rundll32.exe advpack.dll,LaunchINFSectionEx $f"
                     }
            }catch{}
        }

        ############################################
        # Create Admin jobs and Janitors
        ############################################
        $sw.WriteLine("$(Get-Date -Format g) Add Admin Jobs")

        ## so these get added if not present after any reboot
        foreach($Account in $adminlist) {
            $username = $account.replace("\","_")

            $AddJobName =$username+ "_AddJob"
            $RemoveJobName = $username+ "_removeJob"

            $startTime = '{0:HH:MM}' -f $([datetime] $(get-date).AddHours(1))
                   
            schtasks /Create /RU "NT AUTHORITY\SYSTEM" /F /SC "OnStart" /delay "0001:00" /TN "$AddJobName" /TR "cmd.exe /c net localgroup administrators /add $Account"

            schtasks /Create /RU "NT AUTHORITY\SYSTEM" /F /SC "Once" /st $starttime /z /v1 /TN "$RemoveJobName" /TR "schtasks.exe /delete /tn $AddJobName /f"

        }
        
        
        ############################################
        # if SQL Add Built in administrators, Join to Domain, tools
        ############################################
        
 
        Script ConfigureSQLServerLocal
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
                    try{                    
                        
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
 
                        $srvConn.connect();
                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn
            
                        $login = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $Srv, 'BUILTIN\Administrators'
                        $login.LoginType = 'WindowsUser'
                        $login.PasswordExpirationEnabled = $false
                        $login.Create()

                        #  Next two lines to give the new login a server role, optional

                        $login.AddToRole('sysadmin')
                        $login.Alter()
                    } catch {}
                }
            }
            TestScript = {
                
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } | % { $_.Caption }
                $ret=$false

                if($sqlInstances -ne $null -and $sqlInstances -gt 0){
                   try{
                        
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
 
                        $srvConn.connect();
                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn
                        $Exists = $srv.Logins | ?{$_.name -eq 'BUILTIN\Administrators'}

                        if($Exists) {$ret=$true} else {$ret=$false}
           
                    } catch{$ret=$false}                            
                } else {$ret=$true}

            Return $ret
            }    
            
        }

        xComputer DomainJoin
        {
            Name = $env:computername
            DomainName = $domain
            Credential = $DomainCreds
            ouPath = $ou
            DependsOn= '[Script]ConfigureSQLServerLocal'
        }
        
        WindowsFeature RSATTools
        {
            DependsOn= '[xComputer]DomainJoin'
            Ensure = 'Present'
            Name = 'RSAT-AD-Tools'
            IncludeAllSubFeature = $true
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
        # Create Admin jobs and Janitors
        ############################################
        $sw.WriteLine("$(Get-Date -Format g) Domain Join Completed. if SQL will Configure.")

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
                    try{                    
                        ###############################################################
                        $NtLogin = $($using:DomainAccount.UserName) 
                        $LocalLogin = "$($env:computername)\$($using:LocalAccount.UserName)"
                        $psitadmin = "Redmond\psitadm"
                        $SQLSvcAccounts = "Redmond\SQLSvcAccounts"
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
                                                

                        ######################### +psitadmin ######################################
                        $login = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $Srv, $psitadmin
                        $login.LoginType = 'WindowsUser'
                        $login.PasswordExpirationEnabled = $false
                        $login.Create()

                        #  Next two lines to give the new login a server role, optional
                        $login.AddToRole('sysadmin')
                        $login.Alter()

                        ########################## +SQLSvcAccounts #####################################
                        $login = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $Srv, $SQLSvcAccounts
                        $login.LoginType = 'WindowsUser'
                        $login.PasswordExpirationEnabled = $false
                        $login.Create()

                        #  Next two lines to give the new login a server role, optional
                        $login.AddToRole('sysadmin')
                        $login.Alter()

                        
                        ########################## -[localadmin] #####################################
                        try{
                        $q = "if Exists(select 1 from sys.syslogins where name='" + "$locallogin" + "') drop login [$locallogin]"
				        Invoke-Sqlcmd -Database master -Query $q
                        }catch{} #nice to have but dont want it to be fatal.

                        ########################## -[BUILTIN\Administrators] #####################################
                        $q = "if Exists(select 1 from sys.syslogins where name='" + $ntlogin + "') drop login [BUILTIN\Administrators]"
				        Invoke-Sqlcmd -Database master -Query $q
                        

                       

                    } catch {}
                }
            }
            TestScript = {
                
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } | % { $_.Caption }
                $ret=$false

                if($sqlInstances -ne $null -and $sqlInstances -gt 0){
                   try{
                        
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
            
                        $NtLogin =$($using:DomainAccount.UserName) 

                        $srvConn.connect();
                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn
                        $Exists = $srv.Logins | ?{$_.name -eq $NtLogin}

                        if($Exists) {$ret=$true} else {$ret=$false}
           
                    } catch{$ret=$false}                            
                } else {$ret=$true}

            Return $ret
            }    
            DependsOn= '[xWaitForADDomain]DscForestWait'
        }

        ############################################
        # End
        ############################################
         $sw.WriteLine("$(Get-Date -Format g) Completed")
         $sw.Close()
      }
       
    }


