# Name: DeploySQLServer
#
Configuration DeploySQLServer
{
  param (  
   [Parameter(Mandatory)]
   [string] $DataPath="H:\MSSqlServer\MSSQL\DATA",
   [Parameter(Mandatory)]
   [string] $LogPath="O:\MSSqlServer\MSSQL\DATA",
   [Parameter(Mandatory)]
   [string] $BackupPath="E:\MSSqlServer\MSSQL\bak",
   [Parameter(Mandatory)]
   [string] $TempDBPath="T:\MSSqlServer\MSSQL\DATA",
   
   [parameter(Mandatory=$true)]
   [string] $SQLServerAccount,
   [parameter(Mandatory=$true)]
   [string] $SQLServerPassword,
   [parameter(Mandatory=$true)]
   [string] $SQLAgentAccount,
   [parameter(Mandatory=$true)]
   [string] $SQLAgentPassword,
   [parameter(Mandatory=$true)]
   [string] $SQLAdmin,
   [parameter(Mandatory=$true)]
   [string] $SQLAdminPwd,

   [Parameter(Mandatory)]
   [string] $baseurl="https://raw.githubusercontent.com/Microsoft/MSITARM/"
  )

  Node localhost
  {
  

    $InstanceName =Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -Name InstalledInstances | Select-Object -ExpandProperty InstalledInstances | ?{$_ -eq 'MSSQLSERVER'}
    $InstanceFullName = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -Name $InstanceName | Select-Object -ExpandProperty $InstanceName;
    $DataPath   = $DataPath.replace('MSSqlServer',$InstanceFullName)
    $LogPath    = $LogPath.replace('MSSqlServer',$InstanceFullName)
    $BackupPath = $BackupPath.replace('MSSqlServer',$InstanceFullName)
    $TempDBPath = $TempDBPath.replace('MSSqlServer',$InstanceFullName)
    $ErrorPath = $(split-path $("$dataPath") -Parent)+"\Log"

    #region "global functions"

    #endRegion

  	    Script ConfigureEventLog{
            GetScript = {
                @{
                }
            }
            SetScript = {
                try {

                    new-EventLog -LogName Application -source 'AzureArmTemplates' -ErrorAction SilentlyContinue
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "Created"

                } catch{}
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
         Script DriveCheck{
            GetScript = {
                @{
                }
            }
            SetScript = {
                try {
                    $diskArray = Get-Partition
                    $diskArray | select DriveLetter | ? {$_ -eq 'H'}

                    if($diskArray -eq $nothing) {

                        Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "H Drive not found"
                        throw "Drives not available as expected"

                        }else{Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "Drives Ready"}

                    } catch{}

            }
            TestScript = {
                 try {
                    $diskArray = Get-Partition
                    $diskArray | select DriveLetter | ? {$_ -eq 'H'}

                if($diskArray -eq $nothing) {                                    
                        $pass = $true
                    }else{
                        $pass = $false
                    }

                } catch{}
              
              return $pass
            }
            DependsOn = "[Script]ConfigureEventLog"
        }

        File StartupPath {
            Type = 'Directory'
            DestinationPath = "C:\SQLStartup"
            Ensure = "Present"
            DependsOn = "[Script]DriveCheck"
        }

        Script ConfigureStartupPath{
            GetScript = {
                @{
                }
            }
            SetScript = {
                   
                    try { 
 
                        $Root = "C:\SQLStartup"

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

                $Root = "C:\SQLStartup"

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
            DependsOn = "[File]StartupPath"
        }

        File SQLDataPath {
            Type = 'Directory'
            DestinationPath = $DataPath
            Ensure = "Present"
            DependsOn = "[Script]ConfigureStartupPath"
        }
        Script ConfigureDataPath{
            GetScript = {
                @{
                }
            }
            SetScript = {
                   
                    try { 
 
                        $Root = $($using:DataPath)

                        if($(test-path -path $root) -eq $true) {
                        
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"

                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\MSSQLSERVER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\SQLSERVERAGENT", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
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

                $Root = $($using:DataPath)

                if($(test-path -path $root) -eq $true) {
                    $ACL = Get-Acl $Root
                
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'NT SERVICE\MSSQLSERVER'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    }
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -ne 'NT SERVICE\SQLSERVERAGENT'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
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
            DependsOn = "[File]SQLDataPath"
        }
       
        File SQLLogPath {
            Type = 'Directory'
            DestinationPath = $LogPath
            Ensure = "Present"
        }
        Script ConfigureLogPath{
            GetScript = {
                @{
                }
            }
            SetScript = {
                   
                    try { 
 
                        $Root = $($using:logPath)

                        if($(test-path -path $root) -eq $true) {
                        
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"

                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\MSSQLSERVER", "FullControl", $inherit, $propagation, "Allow")   
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\SQLSERVERAGENT", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
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
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureLogPath: $errorMessage"
                       }
                    }
                }
            TestScript = { 

                $pass = $true

                $Root = $($using:LogPath)

               if($(test-path -path $root) -eq $true) {
                    $ACL = Get-Acl $Root
                
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'NT SERVICE\MSSQLSERVER'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    }
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -ne 'NT SERVICE\SQLSERVERAGENT'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
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
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureLogPath $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureLogPath $pass"
                }

             return $pass
            }
            DependsOn = "[File]SQLLogPath"
        }

        File SQLTempdbPath {
            Type = 'Directory'
            DestinationPath = $TempDBPath
            Ensure = "Present"
        }
        Script ConfigureTempdbPath{
            GetScript = {
                @{
                }
            }
            SetScript = {
                   
                    try { 
 
                        $Root = $($using:TempdbPath)

                        if($(test-path -path $root) -eq $true) {
                        
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"

                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\MSSQLSERVER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\SQLSERVERAGENT", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
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
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureTempdbPath: $errorMessage"
                       }
                    }
                }
            TestScript = { 

                $pass = $true

                $Root = $($using:TempdbPath)

               if($(test-path -path $root) -eq $true) {
                    $ACL = Get-Acl $Root
                
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'NT SERVICE\MSSQLSERVER'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    }
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -ne 'NT SERVICE\SQLSERVERAGENT'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
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
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureTempdbPath $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureTempdbPath $pass"
                }

             return $pass
            }
            DependsOn = "[File]SQLTempdbPath"
        }

        File SQLBackupPath {
            Type = 'Directory'
            DestinationPath = $BackupPath
            Ensure = "Present"
        }
        Script ConfigurebacakupPath{
            GetScript = {
                @{
                }
            }
            SetScript = {
                   
                    try { 
 
                        $Root = $($using:BackupPath)

                        if($(test-path -path $root) -eq $true) {
                        
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"

                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule


                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\MSSQLSERVER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\SQLSERVERAGENT", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
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
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigurebacakupPath: $errorMessage"
                       }
                    }
                }
            TestScript = { 

                $pass = $true

                $Root = $($using:BackupPath)

               if($(test-path -path $root) -eq $true) {
                    $ACL = Get-Acl $Root
                
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'NT SERVICE\MSSQLSERVER'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    }
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -ne 'NT SERVICE\SQLSERVERAGENT'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
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
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigurebacakupPath $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigurebacakupPath $pass"
                }

             return $pass
            }
            DependsOn = "[File]SQLBackupPath"
        }

        File SQLErrorPath {
            Type = 'Directory'
            DestinationPath = $ErrorPath
            Ensure = "Present"
        }
        Script ConfigureErrorPath{
            GetScript = {
                @{
                }
            }
            SetScript = {
                   
                    try { 
 
                        $Root = $($using:ErrorPath)

                        if($(test-path -path $root) -eq $true) {
                        
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"

                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\MSSQLSERVER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\SQLSERVERAGENT", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
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
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureErrorPath: $errorMessage"
                       }
                    }
            }           
            TestScript = { 

                $pass = $true

                $Root = $($using:ErrorPath)

               if($(test-path -path $root) -eq $true) {
                    $ACL = Get-Acl $Root
                
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'NT SERVICE\MSSQLSERVER'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    }
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -ne 'NT SERVICE\SQLSERVERAGENT'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
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
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureErrorPath $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureErrorPath $pass"
                }

             return $pass
            }
            DependsOn = "[File]SQLErrorPath"
        }
                      
        Script ConfigureServerLoginMode{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
   
                if($sqlInstances -ne $null){

                    try {  

                        ############################################                     
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
 
                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn
                        $srv.Settings.LoginMode = [Microsoft.SqlServer.Management.SMO.ServerLoginMode]::Integrated
                        $srv.Alter()
                       
                    } catch {
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureServerLoginMode: $errorMessage"
                        }
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $pass = $false

                if($sqlInstances -ne $null){

                    try {
                        ############################################
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
 
                        $srvConn.connect();
                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn
            
                        if($srv.Settings.LoginMode -eq "Integrated") {$pass =  $true} else {$pass =  $false}
                
                    }catch {$pass = $false}
                }else{$pass=$true}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureServerLoginMode $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureServerLoginMode $pass"
                }
                
              
              return $pass
            }
            DependsOn = "[Script]ConfigureErrorPath"

        }

        Script ConfigureMaxDop{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                    try {

                        ############################################         
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                        
                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn
                             
                        ############################################
                        # Set Max D.O.P.:  n=num of procs
                        ############################################
                       
                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $coreCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
                  
                        if($($coreCount) -eq 1) { $maxDop=1 }
                        if($($coreCount) -ge 2 -and $($coreCount) -le 7) { $maxDop=2 }
                        if($($coreCount) -ge 8 -and $($coreCount) -le 16) { $maxDop=4 }
                        if($($coreCount) -gt 16) { $maxDop=8 }
                                          
                        $srv.configuration.MaxDegreeOfParallelism.ConfigValue =$maxDop
                        $srv.configuration.Alter();
                                               
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMaxDop: $errorMessage"
                        } 
                    }
                }
            }
            TestScript = { 

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){

                    try {

                        ############################################
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        ############################################
                        # Test Max D.O.P.:  n=num of procs
                        ############################################
                        $pass=$false

                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $coreCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
                   
                        if($($coreCount) -eq 1) { $maxDop=1 }
                        if($($coreCount) -ge 2 -and $($coreCount) -le 7) { $maxDop=2 }
                        if($($coreCount) -ge 8 -and $($coreCount) -le 16) { $maxDop=4 }
                        if($($coreCount) -gt 16) { $maxDop=8 }
                
                        if($srv.configuration.MaxDegreeOfParallelism.ConfigValue -eq $maxDop) { $pass= $true} else { $pass= $false}
                        
                    } catch{ $pass= $false}

                } else { $pass= $false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureMaxDop $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureMaxDop $pass"
                }
             return $pass
            }
            DependsOn = "[Script]ConfigureServerLoginMode"
        }

        Script ConfigureDefaultLocations{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
    
                if($sqlInstances -ne $null){
                   
                    try {
                        ############################################      
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        ###########################################
                        #  Set the backup location to $disks.SQLServer.backupPath
                        ############################################
                        $BackupDir = $($using:backupPath)
                       
                        $srv.BackupDirectory = $BackupDir
                        $srv.Alter()

                        ###########################################
                        #  Set the backup compression to true
                        ###########################################
                        $srv.Configuration.DefaultBackupCompression.ConfigValue = $true
                        $srv.Configuration.Alter()

                        ###########################################
                        #  Set the data location to $disks.SQLServer.backupPath
                        ############################################
                        $DefaultFileDir = $($using:DataPath)
                        
                        $srv.defaultfile = $DefaultFileDir
                        $srv.Alter()

                        ###########################################
                        #  Set the backup location to $disks.SQLServer.backupPath
                        ############################################
                        $DefaultLog = $($using:LogPath)
                        
                        $srv.DefaultLog = $DefaultLog
                        $srv.Alter()                 
                                               
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureDefaultLocations: $errorMessage"
                        }
                    }
                }
            }
            TestScript = { 

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                    
                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $pass=$true

                    ###########################################
                    #  Set the backup location to $disks.SQLServer.backupPath
                    ############################################
                    $BackupDir = $($using:backupPath)
               
                    if($srv.BackupDirectory -ne $BackupDir) {
                        $pass = $false
                    }

                    ###########################################
                    #  Set the data location to $disks.SQLServer.DataPath
                    ############################################
                    $DefaultFileDir = $($using:DataPath+"\")
                
                    if($srv.defaultfile -ne $DefaultFileDir){
                        $pass = $false
                    }

                    ###########################################
                    #  Set the backup location to $disks.SQLServer.LogPath
                    ############################################
                    $DefaultLog = $($using:LogPath+"\")
               
                    if($srv.DefaultLog -ne $DefaultLog) {
                        $pass = $false
                    }

                } else {$pass=$false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureDefaultLocations $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureDefaultLocations $pass"
                }

             return $pass
            }
            DependsOn = "[Script]ConfigureMaxDop"
        }

        Script ConfigureMaxMemory{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try { 
                        ############################################ 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                        
                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        ############################################
                        # Set Max Server MemorySQL
                        ############################################

                        $PhysicalRAM = (Get-WMIObject -class Win32_PhysicalMemory -ComputerName:$env:COMPUTERNAME |Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB),2)})
                      
                       if($PhysicalRAM -eq 7) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 4096 
                        }
                        if($PhysicalRAM -eq 8) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 4096
                        }
                         if($PhysicalRAM -eq 14) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 10240 
                        }
                        if($PhysicalRAM -eq 16) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 12288 
                        }
                        if($PhysicalRAM -eq 24) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 19456   
                        }
                         if($PhysicalRAM -eq 28) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 22528 
                        }
                        if($PhysicalRAM -eq 32) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 25600
                        }
                        if($PhysicalRAM -eq 48) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 38912
                        }
                        if($PhysicalRAM -eq 56) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 45056
                        }

                        if($PhysicalRAM -eq 64) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 52224
                        }
                        if($PhysicalRAM -eq 72) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 38912
                        }
                        if($PhysicalRAM -eq 96) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 77824
                        }
                         if($PhysicalRAM -eq 112) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 91136 
                        }
                        if($PhysicalRAM -eq 128) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 104448
                        }
                         if($PhysicalRAM -eq 140) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 114688 
                        }
                         if($PhysicalRAM -eq 224) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 196608 
                        }
                        if($PhysicalRAM -eq 256) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 229376
                        }
                         if($PhysicalRAM -eq 448) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 425984 
                        }
                        if($PhysicalRAM -eq 512) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 491520
                        }
                        if($PhysicalRAM -eq 768) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 753664
                        }
                        if($PhysicalRAM -eq 1024) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 1015808
                        }
                        $srv.configuration.Alter(); 
                                                
                       
                    } catch{
                       [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMaxMemory: $errorMessage"
                       }
                    }
                }
            }
            TestScript = { 

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
   
                if($sqlInstances -ne $null){

                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                
                    $srvConn.connect();

                    $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $PhysicalRAM = (Get-WMIObject -class Win32_PhysicalMemory -ComputerName:$env:COMPUTERNAME |Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB),2)})
                           
                       if($PhysicalRAM -eq 7) 
                        {
                            $srvRAM = 4096
                        }
                        if($PhysicalRAM -eq 8) 
                        {
                            $srvRAM = 10240
                        }
                        if($PhysicalRAM -eq 14) 
                        {
                            $srvRAM = 4096
                        }
                        if($PhysicalRAM -eq 16) 
                        {
                            $srvRAM = 12288 
                        }
                        if($PhysicalRAM -eq 24) 
                        {
                            $srvRAM = 19456   
                        }
                        if($PhysicalRAM -eq 28) 
                        {
                            $srvRAM = 22528
                        }
                        if($PhysicalRAM -eq 32) 
                        {
                            $srvRAM = 25600
                        }
                        if($PhysicalRAM -eq 48) 
                        {
                            $srvRAM = 38912
                        }
                        if($PhysicalRAM -eq 56) 
                        {
                            $srvRAM = 45056
                        }
                        if($PhysicalRAM -eq 64) 
                        {
                            $srvRAM = 52224
                        }
                        if($PhysicalRAM -eq 72) 
                        {
                            $srvRAM = 38912
                        }
                        if($PhysicalRAM -eq 96) 
                        {
                            $srvRAM = 77824
                        }
                        if($PhysicalRAM -eq 112) 
                        {
                            $srvRAM = 91136
                        }
                        if($PhysicalRAM -eq 128) 
                        {
                            $srvRAM = 104448
                        }
                        if($PhysicalRAM -eq 140) 
                        {
                            $srvRAM = 114688
                        }
                        if($PhysicalRAM -eq 224) 
                        {
                            $srvRAM = 196608
                        }
                        if($PhysicalRAM -eq 256) 
                        {
                            $srvRAM = 229376
                        }
                        if($PhysicalRAM -eq 448) 
                        {
                            $srvRAM = 425984
                        }
                        if($PhysicalRAM -eq 512) 
                        {
                            $srvRAM = 491520
                        }
                        if($PhysicalRAM -eq 768) 
                        {
                            $srvRAM = 753664
                        }
                        if($PhysicalRAM -eq 1024) 
                        {
                            $srvRAM = 1015808
                        }
                       
                        if($srv.configuration.MaxServerMemory.ConfigValue -eq $srvRAM -or $PhysicalRAM -le 8 ) {
                            $pass=$true
                        }else {
                            $pass=$false
                        }
                }else {$pass=$false}

               if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureMaxMemory $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureMaxMemory $pass"
                }

             return $pass
            }
            DependsOn = "[Script]ConfigureDefaultLocations"
        }

        Script ConfigureSQLAgent{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
   
                if($sqlInstances -ne $null){
                   
                    try {   
                      
                        ############################################
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                        
                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn 
                                              
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "SQLServerAgent*" -and $_.PathName -match "SQLAGENT.exe" } 
                            if($sqlInstances.State -eq 'Stopped'){
                                net start SQLSERVERAGENT
                            }

                            $db = New-Object Microsoft.SqlServer.Management.Smo.Database
                            $db = $srv.Databases.Item("msdb")
                            # Select SQLAgent 
                            $SQLAgent = $db.parent.JobServer ;
                     
                            # Show settings
                            $CurrentSettings = $SQLAgent | select @{n="SQLInstance";e={$db.parent.Name}},MaximumHistoryRows, MaximumJobHistoryRows ;
                            #$CurrentSettings | ft -AutoSize ;
                            $TargetMaximumHistoryRows = 100000;
                            $TargetMaximumJobHistoryRows = 1000 ;

                            $SQLAgent.MaximumHistoryRows = $TargetMaximumHistoryRows ;
                            $SQLAgent.MaximumJobHistoryRows = $TargetMaximumJobHistoryRows ; 
                            $db.Parent.JobServer.SqlServerRestart=1
                            $db.Parent.JobServer.SqlAgentRestart=1
                            $SQLAgent.Alter();
                     
                            # ensuring we have the latest information
                            $SQLAgent.Refresh();
                            #$SQLAgent | select @{n="SQLInstance";e={$db.parent.Name}},MaximumHistoryRows, MaximumJobHistoryRows ;
                            $db.Parent.ConnectionContext.Disconnect();

                            CD HKLM:\
                            $Registry_Key ="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SQLSERVERAGENT\"
                            Set-ItemProperty -Path $Registry_Key -Name Start  -Value 2 
                            CD C:\

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureSQLAgent: $errorMessage"
                        }
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
   
                if($sqlInstances -ne $null){

                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                               
                    $srvConn.connect();

                    $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                     $db = New-Object Microsoft.SqlServer.Management.Smo.Database
                     $db = $srv.Databases.Item("msdb")
                     $SQLAgent = $db.parent.JobServer ;

                     $pass=$true

                      if($SQLAgent.MaximumHistoryRows -ne $TargetMaximumHistoryRows){$pass=$false}
                      if($SQLAgent.MaximumJobHistoryRows -ne $TargetMaximumJobHistoryRows){$pass=$false}
                      if($db.Parent.JobServer.SqlServerRestart -ne 1) {$pass=$false} 
                      if($db.Parent.JobServer.SqlAgentRestart -ne 1) {$pass=$false}

                      $db.Parent.ConnectionContext.Disconnect();
                
                }else {$pass=$false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureSQLAgent $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureSQLAgent $pass"
                }

             return $pass
            }
            DependsOn = "[Script]ConfigureMaxMemory"
        }  
       
        Script MoveMasterFiles{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 

                        ################################################################
	                    # Data.
                        ################################################################                     
                        $DataPath = $($using:dataPath)
                        $logPath = $($using:logPath)
                        $ErrorPath = $($using:ErrorPath)
                	    $flagsToAdd = "-T1118"

                        if($(Test-Path -Path $dataPath -ErrorAction SilentlyContinue) -eq $true) {
                        ################################################################
	                    # Alter DB...
                        ################################################################
        
                           $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                        if($sqlInstances -ne $null -and $sqlInstances.State -eq 'Running'){
	                        $q = "ALTER DATABASE [master] MODIFY FILE (NAME = master, FILENAME = '$($DataPath)\master.mdf')"
		                    Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            $q = "ALTER DATABASE [master] MODIFY FILE (NAME = mastlog, FILENAME = '$($logPath)\mastlog.ldf')"
	                        Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue
                        }

                        ################################################################

                        ################################################################
                        #Change the startup parameters 
                        ################################################################
                        $hklmRootNode = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server" 
                            $props = Get-ItemProperty "$hklmRootNode\Instance Names\SQL" 
                            $instances = $props.psobject.properties | ?{$_.Value -like 'MSSQL*'} | select Value 

                            $instances | %{ $inst = $_.Value;}

                            $regKey = "$hklmRootNode\$inst\MSSQLServer\Parameters" 
                            $props = Get-ItemProperty $regKey 
                            $params = $props.psobject.properties | ?{$_.Name -like 'SQLArg*'} | select Name, Value 
                            $flagset=$false

                            $c=0
                            foreach ($param in $params) { 
                                if($param.Value -match '-d') {
                                    $param.value = "-d$datapath\master.mdf"
                                } elseif($param.Value -match '-l') {
                                    $param.value = "-l$logpath\mastlog.ldf"
                                } elseif($param.Value -match '-e') {
                                     $param.value = "-e$errorpath\ERRORLOG"
                                } elseif($param.Value -match '-T') {
                                     $flagset=$true
                                } 
                                Set-ItemProperty -Path $regKey -Name $param.Name -Value $param.value 

                                $c+=1
                             }
                             if(!$flagset) {
                                $newRegProp = "SQLArg"+($c) 
                                Set-ItemProperty -Path $regKey -Name $newRegProp -Value $flagsToAdd 
                             }
                               
                             $q = "EXEC msdb.dbo.sp_set_sqlagent_properties @errorlog_file=N'" +$ErrorPath + "\SQLAGENT.OUT'"
                             Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue
                             
                            ################################################################

                            ################################################################
                            # Stop SQL, move the files, start SQL 
                            ################################################################
                            #Stop
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Running') {
                            "$(Get-Date -Format g) Stopping SQL Server."
                                Stop-Service -displayname "SQL Server (MSSQLSERVER)" -Force
                            }
                            
                             $readylog = $(test-path -Path $("$($logPath)\mastlog.ldf"))
                             $readyData = $(test-path -Path $("$($DataPath)\master.mdf"))

                                  #Move
                              if(!$readyData) {
                                 Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'master.mdf'} | %{Move-Item -Path $_.FullName -Destination $datapath -force }
                              }
                              if(!$readyLog) {
                                 Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'mastlog.ldf'} | %{Move-Item -Path $_.FullName -Destination $logPath -force }
                              }
                               
                            #Start
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Stopped') {                            
                            "$(Get-Date -Format g) Starting SQL Server."
                                Start-Service -displayname "SQL Server (MSSQLSERVER)" 
                            }
                       }                                                     
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "MoveMasterFiles: $errorMessage"
                        } else {$errorMessage}
                    }
                }
               
                
            }
            TestScript = { 
            
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){

                    $DataPath = $($using:dataPath)
                    $logPath = $($using:logPath)
                    $ErrorPath = $($using:ErrorPath)

                    $readylog = $(test-path -Path $("$($logPath)\mastlog.ldf"))
                    $readyData = $(test-path -Path $("$($DataPath)\master.mdf"))
                    
                     $hklmRootNode = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server" 
                        $props = Get-ItemProperty "$hklmRootNode\Instance Names\SQL" 
                        $instances = $props.psobject.properties | ?{$_.Value -like 'MSSQL*'} | select Value 

                        $instances | %{ $inst = $_.Value;}

                        $regKey = "$hklmRootNode\$inst\MSSQLServer\Parameters" 
                        $props = Get-ItemProperty $regKey 
                        $params = $props.psobject.properties | ?{$_.Name -like 'SQLArg*'} | select Name, Value 

                        $c=0
                        foreach ($param in $params) { 
                            if($param.Value -eq "-d$datapath\master.mdf") {
                                $ReadyMastermdf = $true
                            } elseif($param.Value -eq "-l$logpath\mastlog.ldf") {
                                $ReadyMasterldf = $true 
                            } elseif($param.Value -eq "-e$errorpath\ERRORLOG") {
                                    $ReadyErrorLog = $true 
                            } 
                        }
                    if($readyLog -and $readyData -and $readyMastermdf -and $readymasterldf -and $readyErrorlog){return $true} else {return $false}
                
                }

                if($pass) {
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "MoveMasterFiles $pass"
                }else {
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "MoveMasterFiles $pass"
                }
             return $pass
            }
            DependsOn = "[Script]ConfigureSQLAgent"
        }

        Script MoveModelFiles{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 
                     
                        $DataPath = $($using:dataPath)
                        $logPath = $($using:logPath)

                        if($(Test-Path -Path $dataPath -ErrorAction SilentlyContinue) -eq $true) {
                            ################################################################
	                        # Move tempdb.mdf...
                            ################################################################
	                        $q = "ALTER DATABASE [model] MODIFY FILE (NAME = modeldev, FILENAME = '$($DataPath)\model.mdf')"
				            Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            $q = "ALTER DATABASE [model] MODIFY FILE (NAME = modellog, FILENAME = '$($logPath)\modellog.ldf')"
	                        Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            #Stop
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Running') {
                            "$(Get-Date -Format g) Stopping SQL Server."
                                Stop-Service -displayname "SQL Server (MSSQLSERVER)" -Force
                            }
                               
                                $readylog = $(test-path -Path $("$($logPath)\modellog.ldf"))
                                $readyData = $(test-path -Path $("$($DataPath)\model.mdf"))

                                #Move
                                if(!$readyData) {
                                    Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'model.mdf'} | %{Move-Item -Path $_.FullName -Destination $datapath -force}
                                }
                                if(!$readylog) {
                                    Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'modellog.ldf'} | %{Move-Item -Path $_.FullName -Destination $logPath -force}
                                }
                                    
                            #Start
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Stopped') {                            
                            "$(Get-Date -Format g) Starting SQL Server."
                                Start-Service -displayname "SQL Server (MSSQLSERVER)" 
                            }
                          }
                                                                             
                        } catch{
                            [string]$errorMessage = $Error[0].Exception
                            if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                                Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "MoveModelFiles: $errorMessage"
                            } else {$errorMessage}
                        }
                }
                
            }
            TestScript = { 
            
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){

                    $DataPath = $($using:dataPath)
                    $logPath = $($using:logPath)

                    $readylog = $(test-path -Path $("$($logPath)\modellog.ldf"))
                    $readyData = $(test-path -Path $("$($DataPath)\model.mdf"))
                    
                    if($readyLog -and $readyData){return $true} else {return $false}
                }

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "MoveModelFiles $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "MoveModelFiles $pass"
                }

             return $pass
            }
            DependsOn = "[Script]MoveMasterFiles"
        }

        Script MoveMSDBFiles{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 
                     
                        $DataPath = $($using:dataPath)
                        $logPath = $($using:logPath)

                        if($(Test-Path -Path $dataPath -ErrorAction SilentlyContinue) -eq $true) {
                            ################################################################
	                        # Move tempdb.mdf...
                            ################################################################
	                        $q = "ALTER DATABASE [MSDB] MODIFY FILE (NAME = MSDBData, FILENAME = '$($DataPath)\MSDBData.mdf')"
				            Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            $q = "ALTER DATABASE [MSDB] MODIFY FILE (NAME = MSDBlog, FILENAME = '$($logPath)\MSDBlog.ldf')"
	                        Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue


                            #Stop
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Running') {
                            "$(Get-Date -Format g) Stopping SQL Server."
                                Stop-Service -displayname "SQL Server (MSSQLSERVER)" -Force
                            }
                                
                               $readylog = $(test-path -Path $("$($logPath)\MSDBlog.ldf"))
                               $readyData = $(test-path -Path $("$($DataPath)\MSDBData.mdf"))
                                                               
                                #Move
                                if(!$readyData) {
                                    Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'MSDBData.mdf'} | %{Move-Item -Path $_.FullName -Destination $datapath -force}
                                 }
                                if(!$readylog) {
                                    Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'MSDBlog.ldf'} | %{Move-Item -Path $_.FullName -Destination $logPath -force}
                                }
                                                           
                                    
                            #Start
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Stopped') {                            
                            "$(Get-Date -Format g) Starting SQL Server."
                                Start-Service -displayname "SQL Server (MSSQLSERVER)" 
                            }
                          }
                                             
                        } catch{
                            [string]$errorMessage = $Error[0].Exception
                            if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                                Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "MoveMSDBFiles: $errorMessage"
                            } else {$errorMessage}
                        }
                }
                
            }
            TestScript = { 
            
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){

                    $DataPath = $($using:dataPath)
                    $logPath = $($using:logPath)

                    $readylog = $(test-path -Path $("$($logPath)\MSDBlog.ldf"))
                    $readyData = $(test-path -Path $("$($DataPath)\MSDBData.mdf"))
                    
                    if($readyLog -and $readyData){return $true} else {return $false}
                }

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "MoveMSDBFiles $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "MoveMSDBFiles $pass"
                }

             return $pass
            }
            DependsOn = "[Script]MoveModelFiles"
        }
                
        Script ConfigureModelDataFile{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 
                        ############################################ 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="Model"

                        $MyDatabase = $srv.Databases[$DatabaseName]
                        $MyDatabase.RecoveryModel = "Simple"                                            
                        $MyDatabase.Alter()

                        $DBFG = $MyDatabase.FileGroups;
                        foreach ($DBF in $DBFG.Files) {
                           if((50*1024) -ne $dbf.Size -or (5*1024) -ne $dbf.Growth) {
                               $DBF.MaxSize = -1
                               $dbf.Growth = (5*1024)
                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = (50*1024)
                               $dbf.Alter()

                           } else {"$($DBF.Name) Size to 50MB, Filegrowth to 5MB"}
                                                      

                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureModelDataFile: $errorMessage"
                        }
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                           
                if($sqlInstances -ne $null){

                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                
                     $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $DatabaseName="Model"

                    $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                    $DBFG = $MyDatabase.FileGroups;
                    $pass=$true
                    foreach ($DBF in $DBFG.Files) {
                        if((20*1024) -ne $dbf.Size) {
                            $pass= $false
                        } 
                        if((5*1024) -ne $dbf.Growth) {
                            $pass= $false
                        } 
                    }
                } else {$pass=$false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureModelDataFile $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureModelDataFile $pass"
                }

               return $pass
            }
            DependsOn = "[Script]MoveMSDBFiles"
        }

        Script ConfigureModelLogFile{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try { 
                        
                        ############################################
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="Model"

                        $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                        foreach ($DBF in $MyDatabase.LogFiles) {
                            

                                $DBF.MaxSize = -1
                                $dbf.Growth = (5*1024)
                                $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                                $dbf.Size = (20*1024)
                                $dbf.Alter()

                          
                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureModelLogFile: $errorMessage"
                        }
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                           
                if($sqlInstances -ne $null){

                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                
                     $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $DatabaseName="Model"

                    $MyDatabase = $srv.Databases[$DatabaseName]
                    $pass=$true

                    foreach ($DBF in $MyDatabase.LogFiles) {
                        if((50*1024) -ne $dbf.Size) {
                            $pass= $false
                        } 
                        if((5*1024) -ne $dbf.Growth) {
                            $pass= $false
                        } 
                    }
                } else {$pass=$false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureModelLogFile $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureModelLogFile $pass"
                }

               return $pass
            }
            DependsOn = "[Script]ConfigureModelDataFile"
        }
         
        Script ConfigureMSDBDataFile{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try {
                     
                        ############################################     
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="MSDB"

                        $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                        $DBFG = $MyDatabase.FileGroups;
                        foreach ($DBF in $DBFG.Files) {
                           if((50*1024) -ne $dbf.Size) {
                                $DBF.MaxSize = -1
                                 $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                                $dbf.Size = (50*1024)
                                $dbf.Growth = (5*1024)
                                $dbf.Alter()

                           } else {"$($DBF.Name) Size to 50MB,Filegrowth to 5MB, unlimited growth"}
                          
                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMSDBDataFile: $errorMessage"
                        } else {$errorMessage}
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){

                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                
                     $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $DatabaseName="MSDB"

                    $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                    $DBFG = $MyDatabase.FileGroups;
                    $pass=$true

                    foreach ($DBF in $DBFG.Files) {
                        if((50*1024) -ne $dbf.Size) {
                            $pass= $false
                        } 
                        if((5*1024) -ne $dbf.Growth) {
                            $pass= $false
                        } 
                    }
                    } else {$pass=$false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureMSDBDataFile $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureMSDBDataFile $pass"
                }

               return $pass
            }
            DependsOn = "[Script]ConfigureModelLogFile"
        }

        Script ConfigureMSDBLogFile{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try {

                        ############################################      
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="MSDB"

                        $MyDatabase = $srv.Databases[$DatabaseName]
       
                        foreach ($DBF in $MyDatabase.LogFiles) {
                                                       
                                $DBF.MaxSize = -1
                                $dbf.Growth = (5*1024)
                                $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                                $dbf.Size = (20*1024)
                                $dbf.Alter()
                                                         
                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMSDBLogFile: $errorMessage"
                        } else {$errorMessage}
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){

                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                
                    $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $DatabaseName="MSDB"

                    $MyDatabase = $srv.Databases[$DatabaseName]
                    $pass=$true

                    foreach ($DBF in $MyDatabase.LogFiles) {
                        if((20*1024) -ne $dbf.Size) {
                            $pass= $false
                        } 
                        if((5*1024) -ne $dbf.Growth) {
                            $pass= $false
                        } 
                        if(-1 -ne $dbf.maxsize) {
                            $pass= $false
                        } 
                    }

                 }else {$pass=$false}
                 
                 Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureMSDBLogFile $pass"

               return $pass
            }
            DependsOn = "[Script]ConfigureMSDBDataFile"
        }
        
        Script ConfigureAuditing{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                    try{
                        INVOKE-sqlcmd  -Database master -Query "Exec [master].[sys].[xp_instance_regwrite] N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs', REG_DWORD, 30"
                    }catch{
                       [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureAuditing: $errorMessage"
                        } else {$errorMessage}
                    }
                }
            }
            TestScript = { 

               $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
               $pass = $false

                if($sqlInstances -ne $null){
                    try{
                        $retval=INVOKE-sqlcmd  -Database master -Query "Exec [master].[sys].[xp_instance_regread] N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs'"
                        if($retval.Data -eq 30) {$pass=$true} else {$pass=$false}
                    }catch{
                    [string]$errorMessage = $Error[0].Exception
		            
                    }

                }
            
                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureAuditing $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureAuditing $pass"
                }

             return $pass 
            }
            DependsOn = "[Script]ConfigureMSDBLogFile"
        }

        Script ConfigureBuiltInAdmins{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                    try {                            
                        $q = "if Exists(select 1 from sys.syslogins where name='[BUILTIN\Administrators]') drop login [BUILTIN\Administrators]"
				        Invoke-Sqlcmd -Database master -Query $q
                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureBuiltInAdmins: $errorMessage"
                        } else {$errorMessage}
                    }
                }
            }
            TestScript = { 
                try{
                    $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                    if($sqlInstances -ne $null){

                        $pass=$false
                        $q = "select count(*) as Instances from sys.syslogins where name='[BUILTIN\Administrators]'"
				        Invoke-Sqlcmd -Database master -Query $q            
                        if(($q.Instances) -eq 0) {$pass=$true}else{$pass=$false} 
                     
                     }else{$pass=$false}
                  
                }catch{$pass=$false}
            
                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureBuiltInAdmins $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureBuiltInAdmins $pass"
                }

             return $pass
            }
            DependsOn = "[Script]ConfigureAuditing"
        }
        
        Script MoveTempdbFiles{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 
                     
                        $TempDrive=$($using:TempDbPath).split("\")[0] 
                        $TempPath = $($using:TempDbPath)

                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $TempDBSpaceAvailGB = $FreeSpaceGB - 50
	                    $TempDBSpaceAvailMB = $TempDBSpaceAvailGB * 1024

                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $fileCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
                        if($fileCount -gt 8)
                        {
                            $fileCount = 8
                        } 

                        $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                        $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)
	                    $fileSize     = '1000'
                        $fileGrowthMB = '50' 

                            ################################################################
	                        # Move tempdb.mdf...
                            ################################################################
	                        $q = "ALTER DATABASE [tempdb] MODIFY FILE (NAME = tempdev, FILENAME = '$($TempPath)\tempdb.mdf')"
				            Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            $q = "ALTER DATABASE [tempdb] MODIFY FILE (NAME = templog, FILENAME = '$($TempPath)\templog.ldf')"
	                        Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            "$(Get-Date -Format g) Restarting SQL Server."
                                    $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "SQLServerAgent*" -and $_.PathName -match "SQLAGENT.exe" } 
                                    if($sqlInstances.State -eq 'Running'){
                                    net stop sqlserveragent
                                    }
                                    $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                                    if($sqlInstances.state -eq 'Running'){
                                    net stop mssqlserver
                                    }
                                    start-sleep 30
                                    $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "SQLServerAgent*" -and $_.PathName -match "SQLAGENT.exe" } 
                                    if($sqlInstances.State -eq 'Stopped'){
                                    net start sqlserveragent
                                    }
                                    $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                                    if($sqlInstances.state -eq 'Stopped'){
                                    net start mssqlserver
                                    }
                                Start-Sleep 30
                                               
                            } catch{
                                [string]$errorMessage = $Error[0].Exception
                                if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "MoveTempdbFiles: $errorMessage"
                                } else {$errorMessage}
                            }
                    }
                
            }
            TestScript = { 
            
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                    
                    $TempDrive=$($using:TempDbPath).split("\")[0] 
                    $TempPath = $($using:TempDbPath)
                    
                    $readylog = $(test-path -Path $("$($TempPath)\templog.ldf"))
                    $readyData = $(test-path -Path $("$($TempPath)\tempdb.mdf"))
                    
                    if($readyLog -and $readyData){return $true} else {return $false}
                }

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "MoveTempdbFiles $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "MoveTempdbFiles $pass"
                }

             return $pass
            }
            DependsOn = "[Script]ConfigureBuiltInAdmins"
        }

        Script AddTempdbFiles{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 
                     
                        $TempDrive=$($using:TempDbPath).split("\")[0] 
                        $TempPath = $($using:TempDbPath)

                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $TempDBSpaceAvailGB = $FreeSpaceGB - 50
	                    $TempDBSpaceAvailMB = $TempDBSpaceAvailGB * 1024

                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $fileCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
            
                        #maximum of 8 to start, the additional ones to be added by the server Owners
                        if($fileCount -gt 8){ $fileCount = 8 }

                        $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                        $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)
	                    $fileSize     = '1000'
                        $fileGrowthMB = '50' 

                            ################################################################
	                        # Move tempdb.mdf...
                            ################################################################                       
	                        "$(Get-Date -Format g) Creating remaining data files..."

                            for ($i = 2; $i -le $fileCount; $i++) {

                                $msg="Create tempdev$($i)"
                                           
                                try{
                                    
                                        $q = "IF NOT EXISTS(SELECT 1 FROM tempdb.dbo.sysfiles WHERE name = 'tempdev$($i)') Begin ALTER DATABASE [tempdb] ADD FILE ( NAME = tempdev$($i), SIZE = $($fileSize)MB, MAXSIZE = 'unlimited', FILEGROWTH = $($fileGrowthMB)MB, FILENAME = '$($TempPath)\tempdb$($i).mdf') END "; 
		                                Invoke-Sqlcmd -Database master -Query $q -QueryTimeout 10000 -ErrorAction SilentlyContinue
                                    
                                    }catch{
                                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
                                        }else {$errorMessage}
                                    }
                                                                                               
                            Restart-Service -displayname "SQL Server (MSSQLSERVER)" -Force

		                        	                        
                        }

                          

                                               
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "AddTempdbFiles: $errorMessage"
                        } else {$errorMessage}
                   }
                }
            }
            TestScript = { 
            
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                    
                    $TempDrive=$($using:TempDbPath).split("\")[0] 
                    $TempPath = $($using:TempDbPath)
                    
                    $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                    $fileCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
                        if($fileCount -gt 8)
                        {
                            $fileCount = 8
                        }

                    $pass=$true
                    for ($i = 2; $i -le $fileCount; $i++) {

                        $readylog = $(test-path -Path $("$($TempPath)\tempdb$($i).mdf"))
                        if(!$readylog) {$pass=$false}            

                    }
                }

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "AddTempdbFiles $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "AddTempdbFiles $pass"
                }

             return $pass
            }
            DependsOn = "[Script]MoveTempdbFiles"
        }

        Script ConfigureTempDataFile{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try {
                     
                        ############################################     
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="tempdb"
                        $tempDrive = $(split-path $($using:tempdbpath) -Qualifier)  
                        $TempPath = $($using:TempDbPath)

                        $MyDatabase = $srv.Databases[$DatabaseName]
                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $TempDBSpaceAvailGB = $FreeSpaceGB - 50
	                    $TempDBSpaceAvailMB = $TempDBSpaceAvailGB * 1024
                       
                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $fileCount =($cpu.NumberOfCores | Measure-Object -Sum).Sum

                        if($fileCount -gt 8){ $fileCount = 8 }
                       
                        $fileSize     = $(1024*1000)
                        $fileGrowthMB = $(1024*50)
                        if($FreeSpaceGB -ge  10 -and $FreeSpaceGB -lt 50 ){
                            $fileSize     = $(1024*500)
                            $fileGrowthMB = $(1024*50)
                        }elseif($FreeSpaceGB -ge  50  ){
                            $fileSize     = $(1024*1000)
                            $fileGrowthMB = $(1024*100)
                        }

                        $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                        $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)
                                                                           
                        $DBFG = $MyDatabase.FileGroups;
                        foreach ($DBF in $DBFG.Files) {
                          
                               $DBF.MaxSize = -1
                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = $($fileSize)
                               $dbf.Growth = "$fileGrowthMB"
                               $dbf.Alter()                        
                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureTempDataFile: $errorMessage"
                        }else {$errorMessage}
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){

                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                
                    $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $DatabaseName="tempdb"
                   
                    $tempDrive = $(split-path $($using:tempdbpath) -Qualifier)  
                    $TempPath = $($using:TempDbPath)

                    $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                    $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                    $fileCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
                     if($fileCount -gt 8)
                        {
                            $fileCount = 8
                        }

                    $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                    $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)

                    if($fileCount -gt 8){ $fileCount = 8 }
                       
                    if($FreeSpaceGB -ge  10 -and $FreeSpaceGB -lt 50 ){
                        $fileSize     = $(1024*500)
                        $fileGrowthMB = $(1024*50)
                    }elseif($FreeSpaceGB -ge  50  ){
                        $fileSize     = $(1024*1000)
                        $fileGrowthMB = $(1024*100)
                    }

                    $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                    $DBFG = $MyDatabase.FileGroups;
                    $pass=$true

                    foreach ($DBF in $DBFG.Files) {
                        if(($fileSize) -ne $dbf.Size) {
                            $pass= $false
                        } 
                        if(($fileGrowthMB) -ne $dbf.Growth) {
                            $pass= $false
                        } 
                         if(($maxFileGrowthSizeMB) -ne $dbf.Maxsize) {
                            $pass= $false
                        } 
                    }
                    } else {$pass=$false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureTempDataFile $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureTempDataFile $pass"
                }

               return $pass
            }
            DependsOn = "[Script]AddTempdbFiles"
        }

        Script ConfigureTempLogFile{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try {

                        ############################################      
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="tempdb"
                        $tempDrive = $(split-path $($using:tempdbpath) -Qualifier)  
                        $TempPath = $($using:TempDbPath)
                    
                        
                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $TempDBSpaceAvailGB = $FreeSpaceGB - 50
	                    $TempDBSpaceAvailMB = $TempDBSpaceAvailGB * 1024
                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $fileCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
                        if($fileCount -gt 8)
                        {
                            $fileCount = 8
                        } 

                        $DatafileSize     = $(1024*1000)
                        $fileGrowthMB = $(1024*50)
                        if($FreeSpaceGB -ge  10 -and $FreeSpaceGB -lt 50 ){
                            $DatafileSize = $(1024*500)
                            $fileGrowthMB = $(1024*50)
                        }elseif($FreeSpaceGB -ge  50  ){
                            $DatafileSize = $(1024*1000)
                            $fileGrowthMB = $(1024*100)
                        }

                        if($fileCount -gt 8){ $fileCount = 8 }
                        $LogfileSize     = $(.25 * $($fileCount * $DatafileSize))

                        $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                        $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)

                        $MyDatabase = $srv.Databases[$DatabaseName]
          
                        foreach ($DBF in $MyDatabase.LogFiles) {
                          
                               $DBF.MaxSize = -1
                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = ($LogfileSize)
                               $dbf.Growth = $fileGrowthMB
                               $dbf.Alter()

                               "$($DBF.Name) Size is $($dbf.Size) MB,Growth is $($dbf.Growth) MB, MaxSize is $($dbf.MaxSize) MB"

                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureTempLogFile: $errorMessage"
                        } else {$errorMessage}
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){

                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                    
                    $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $DatabaseName="tempdb"
                    $TempDrive = $(split-path $($using:tempdbpath) -Qualifier)    

                        $fileSize     = $(1024*1000)
                        $fileGrowthMB = $(1024*50)
                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $TempDBSpaceAvailGB = $FreeSpaceGB - 50
	                    $TempDBSpaceAvailMB = $TempDBSpaceAvailGB * 1024
                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $fileCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
                        if($fileCount -gt 8)
                        {
                            $fileCount = 8
                        } 

                        if($fileCount -gt 8){ $fileCount = 8 }
                       
                        if($FreeSpaceGB -ge  10 -and $FreeSpaceGB -lt 50 ){
                            $fileSize     = $(1024*500)
                            $fileGrowthMB = $(1024*50)
                        }elseif($FreeSpaceGB -ge  50  ){
                            $fileSize     = $(1024*1000)
                            $fileGrowthMB = $(1024*100)
                        }

                        $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                        $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)

                    $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                    $DBFG = $MyDatabase.Logs;
                    $pass=$true

                    foreach ($DBF in $MyDatabase.LogFiles) {
                        if(($fileSize) -ne $dbf.Size) {
                            $pass= $false
                        } 
                        if(($fileGrowthMB) -ne $dbf.Growth) {
                            $pass= $false
                        } 
                         if((-1) -ne $dbf.Maxsize) {
                            $pass= $false
                        }  
                    }

                 }else {$pass=$false}
                 
                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureTempLogFile $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureTempLogFile $pass"
                }

               return $pass
            }
            DependsOn = "[Script]ConfigureTempDataFile"
        }
          
        Script ConfigureMasterDataFile{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try {  
                        ############################################
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="Master"

                        $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                        $DBFG = $MyDatabase.FileGroups;
                        foreach ($DBF in $DBFG.Files) {
                           if((50*1024) -ne $dbf.Size) {

                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = (50*1024)
                               $dbf.Alter()

                           } else {"$($DBF.Name) Size to 50MB"}
                           
                           if((5*1024) -ne $dbf.Growth) {

                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Growth = (5*1024)
                               $dbf.Alter()

                           } else {"$($DBF.Name) Filegrowth to 5MB"}

                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMasterDataFile: $errorMessage"
                        }
                    }
                }
            }
            TestScript = { 
            
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                     
                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                     ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                
                     $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $DatabaseName="Master"

                    $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                    $DBFG = $MyDatabase.FileGroups;
                    $pass=$true
                    foreach ($DBF in $DBFG.Files) {
                        if((50*1024) -ne $dbf.Size) {
                            $pass= $false
                        } 
                        if((5*1024) -ne $dbf.Growth) {
                            $pass= $false
                        } 
                    }

                }else {$pass=$false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureMasterDataFile $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureMasterDataFile $pass"
                }

               return $pass
            }
            DependsOn = "[Script]ConfigureSQLAgent"
        }

        Script ConfigureMasterLogFile{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                
                if($sqlInstances -ne $null){
                   
                    try {    
                      
                        ############################################
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="Master"

                        $MyDatabase = $srv.Databases[$DatabaseName]
                      
                        foreach ($DBF in $MyDatabase.LogFiles) {
                           if((50*1024) -ne $dbf.Size) {
                                $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = (20*1024)
                               $dbf.Alter()

                           } else {"$($DBF.Name) Size to 50MB"}
                           
                           if((5*1024) -ne $dbf.Growth) {
                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Growth = (5*1024)
                               $dbf.Alter()

                           } else {"$($DBF.Name) Filegrowth to 5MB"}

                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMasterLogFile: $errorMessage"
                        }
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                           
                if($sqlInstances -ne $null){
                     
                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                
                     $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $DatabaseName="Master"

                    $MyDatabase = $srv.Databases[$DatabaseName]
                    $pass=$true

                    foreach ($DBF in $MyDatabase.LogFiles) {
                        if((20*1024) -ne $dbf.Size) {
                            $pass= $false
                        } 
                        if((5*1024) -ne $dbf.Growth) {
                            $pass= $false
                        } 
                    }
                } else {$pass=$false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureMasterLogFile $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureMasterLogFile $pass"
                }

               return $pass
            }
            DependsOn = "[Script]ConfigureMasterDataFile"
        }

        Script ConfigureStartupJob {
            GetScript = {
                @{
                }
            }
            SetScript = {
                if($(test-path -path C:\SQLStartup) -eq $true) {
               
                    $WebClient = New-Object System.Net.WebClient
                    $WebClient.DownloadFile($($Using:baseURL) + "scripts/SQL-Startup.ps1","C:\SQLStartup\SQL-Startup.ps1")

                    if($(test-path -path C:\SQLStartup\SQL-Startup.ps1) -eq $true) {
                        C:\SQLStartup\SQL-Startup.ps1 $($using:TempDBPath)
                    }
                }
            }
            TestScript = { 
                $pass=$false
                if($(test-path -path "C:\SQLStartup\SQL-Startup.ps1") -eq $true) {

                    if ((Get-ScheduledTask -TaskPath '\' | Where-Object { $_.TaskName -eq 'SqlTempdriveAndStartup'; }) -eq $null) {
                        $pass=$false
                    }else {
                        $pass=$true
                    }

                } else {
                    $pass=$false
                }

                return $Pass
            }
            DependsOn = "[Script]ConfigureMasterLogFile"
        }

        Script ConfigureExtendedSprocs {
            GetScript = {
                @{
                }
            }
            SetScript = {
                if($(test-path -path C:\SQLStartup) -eq $true) {
               
                    $WebClient = New-Object System.Net.WebClient
                    $WebClient.DownloadFile($($Using:baseURL) + "scripts/PostConfiguration.sql","C:\SQLStartup\PostConfiguration.sql")

                    if($(test-path -path C:\SQLStartup\PostConfiguration.sql) -eq $true) {
                         $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
   
                    if($sqlInstances -ne $null){

                        ############################################
                        try {
               
                             write-verbose "Extended Sprocs on $server"
                                                    
                            Invoke-SQLCmd -ServerInstance $($env:computername) -Database 'master' -ConnectionTimeout 300 -QueryTimeout 600 -inputfile "C:\SQLStartup\PostConfiguration.sql"                       

                        } catch{
                            [string]$errorMessage = $_.Exception.Message
                            if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                                Write-EventLog -LogName Application -source AzureArmTemplates -eventID 5001 -entrytype Error -message "PostConfiguration.SQL: $errorMessage"
                            }else {$error}
                            throw $errorMessage
                        }
                     }
                 }
              }
            }
            TestScript = { 
                $pass=$false
                if($(test-path -path "C:\SQLStartup\PostConfiguration.sql") -eq $true) {
                         $pass=$true           
                } else {
                    $pass=$false
                }

                return $Pass
            }
            DependsOn = "[Script]ConfigureStartupJob"
        }

          Script ConfigureSQLAccount{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                    try {                            
                        
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
 
                        $NtLogin = $($using:SQLServerAccount.UserName) 

                        $srvConn.connect();
                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn
            
                        $login = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $Srv, $NtLogin
                        $login.LoginType = 'WindowsUser'
                        $login.PasswordExpirationEnabled = $false
                        $login.Create()

                        #  Next two lines to give the new login a server role, optional

                        $login.AddToRole('sysadmin')
                        $login.Alter()

                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureBuiltInAdmins: $errorMessage"
                        } else {$errorMessage}
                    }
                }
            }
            TestScript = { 
                try{
                    $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                    if($sqlInstances -ne $null){

                        $pass=$false
                        $NtLogin = $($using:SQLServerAccount.UserName) 
                        $q = "select count(*) as Instances from sys.syslogins where name='$ntLogin'"
				        Invoke-Sqlcmd -Database master -Query $q            
                        if(($q.Instances) -eq 1) {$pass=$true}else{$pass=$false} 
                     
                     }else{$pass=$false}
                  
                }catch{$pass=$false}
            
                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureSQLAccount $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureSQLAccount $pass"
                }

             return $pass
            }
            DependsOn = "[Script]ConfigureExtendedSprocs"
        }

        Script ConfigureSQLServerService{
            GetScript = {
                @{
                }
            }
            SetScript = {
            
                if($using:SQLServerAccount -and $using:SQLServerPassword) {
                                
                    ############################################             
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement")
                    ############################################

                    try {

                                                
                        $wmi = new-object ("Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer") $env:computername
                           
                        #disabling these until the user decides                     
                        $SQLsvc = get-service| where {$_.DisplayName -match 'SQL' -and ($_.name -ne 'MSSQLSERVER' -and $_.Name -ne 'SQLSERVERAGENT' -and $_.Name -ne 'SQLWriter')}
                        $SQLsvc  | %{Set-Service $_.Name -StartupType disabled -Status Stopped}
                        
                        #set sql Service
                      
                        $svc = $wmi.services | where {$_.Type -eq 'SqlServer'} 
                        $svc.SetServiceAccount($using:SQLServerAccount,$using:SQLServerPassword)
                        
                        $svc = $wmi.services | where {$_.DisplayName -match 'SQL'}

                        $svc | ft  name,displayname,serviceaccount,startmode,serviceState  -AutoSize
                        
                    } catch {}
                }

            }
            TestScript = { 
                $pass=$false
                
                if($using:SQLServerAccount -and $using:SQLServerPassword) {
                                        
                    ############################################             
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement")
                    ############################################

                    $wmi = new-object ("Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer") $env:computername
                    $svc = $wmi.services | where {$_.Type -eq 'SqlServer'} 
                    
                        try {
                            $pass = $($svc.ServiceAccount -eq $using:SQLServerAccount)
                        } catch {
                            $pass = $false
                        }
                    }

            return $pass
            }
            DependsOn = "[Script]ConfigureSQLAccount"
        }

        Script ConfigureSQLAgentService{
            GetScript = {
                @{
                }
            }
            SetScript = {
            
                    ############################################             
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement")
                    ############################################

                if($using:SQLAgentAccount -and $using:SQLAgentPassword) {
                    try {
                        $wmi = new-object ("Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer") $env:computername
                        $svc = $wmi.services | where {$_.Type -eq 'SqlAgent'} 
                        $svc.Start()
                        $svc.SetServiceAccount($using:SQLAgentAccount,$using:SQLAgentPassword)

                    } catch {}
                }

            }
            TestScript = { 
                $pass=$false

                if($using:SQLAgentAccount -and $using:SQLAgentPassword) {
                    
                        ############################################             
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement")
                        ############################################

                        
                        $wmi = new-object ("Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer") $env:computername
                        $svc = $wmi.services | where {$_.Type -eq 'SqlAgent'} 
                        $svc.Start()

                        try {
                            $pass = $($svc.ServiceAccount -eq $using:SQLAgentAccount)
                        } catch {
                            $pass = $false
                        }
                    }
            return $pass
            }
            DependsOn = "[Script]ConfigureSQLServerService"
        }

        Script ConfigureLocalPolicy{
            GetScript = {
                @{
                }
            }
            SetScript = {
  
            #################Policy Changes####################################

            $ret1=  Add-LoginToLocalPrivilege "NT Service\Mssqlserver" "SeLockMemoryPrivilege"

            $ret2=  Add-LoginToLocalPrivilege "NT Service\Mssqlserver" "SeManageVolumePrivilege"

            }
            TestScript = { 
                  
               ###############################################################          
  
                    function Add-LoginToLocalPrivilege {

                        #Specify the default parameterset
                        [CmdletBinding(DefaultParametersetName="JointNames", SupportsShouldProcess=$true, ConfirmImpact='High')]
                        param
                            (
                        [parameter(
                        Mandatory=$true, 
                        Position=0,
                        ValueFromPipeline= $true
                                    )]
                        [string] $DomainAccount,

                        [parameter(Mandatory=$true, Position=2)]
                        [ValidateSet("SeManageVolumePrivilege", "SeLockMemoryPrivilege")]
                        [string] $Privilege,

                        [parameter(Mandatory=$false, Position=3)]
                        [string] $TemporaryFolderPath = $env:USERPROFILE
        
                        )

                            #Determine which parameter set was used
                            switch ($PsCmdlet.ParameterSetName)
                            {
                            "SplitNames"
                                                    { 
                        #If SplitNames was used, combine the names into a single string
                                    Write-Verbose "Domain and Account provided - combining for rest of script."
                                    $DomainAccount = "$Domain`\$Account"
                                }
                            "JointNames"
                                                {
                        Write-Verbose "Domain\Account combination provided."
                                    #Need to do nothing more, the parameter passed is sufficient.
                                }
                            }

                        Write-Verbose "Adding $DomainAccount to $Privilege"

                            Write-Verbose "Verifying that export file does not exist."
                            #Clean Up any files that may be hanging around.
                            Remove-TempFiles
    
                        Write-Verbose "Executing secedit and sending to $TemporaryFolderPath"
                            #Use secedit (built in command in windows) to export current User Rights Assignment
                            $SeceditResults = secedit /export /areas USER_RIGHTS /cfg $TemporaryFolderPath\UserRightsAsTheyExist.inf

                        #Make certain export was successful
                        if($SeceditResults[$SeceditResults.Count-2] -eq "The task has completed successfully.")
                        {

                        Write-Verbose "Secedit export was successful, proceeding to re-import"
                                #Save out the header of the file to be imported
        
                        Write-Verbose "Save out header for $TemporaryFolderPath`\ApplyUserRights.inf"
        
                        "[Unicode]
                        Unicode=yes
                        [Version]
                        signature=`"`$CHICAGO`$`"
                        Revision=1
                        [Privilege Rights]" | Out-File $TemporaryFolderPath\ApplyUserRights.inf -Force -WhatIf:$false
                                    
                        #Bring the exported config file in as an array
                        Write-Verbose "Importing the exported secedit file."
                        $SecurityPolicyExport = Get-Content $TemporaryFolderPath\UserRightsAsTheyExist.inf

                        #enumerate over each of these files, looking for the Perform Volume Maintenance Tasks privilege
                       [Boolean]$isFound = $false
       
                        foreach($line in $SecurityPolicyExport) {

                         if($line -like "$Privilege`*")  {

                                Write-Verbose "Line with the $Privilege found in export, appending $DomainAccount to it"
                                #Add the current domain\user to the list
                                $line = $line + ",$DomainAccount"
                                #output line, with all old + new accounts to re-import
                                $line | Out-File $TemporaryFolderPath\ApplyUserRights.inf -Append -WhatIf:$false

                                Write-verbose "Added $DomainAccount to $Privilege"                            
                                $isFound = $true
                            }
                        }

                        if($isFound -eq $false) {
                            #If the particular command we are looking for can't be found, create it to be imported.
                            Write-Verbose "No line found for $Privilege - Adding new line for $DomainAccount"
                            "$Privilege`=$DomainAccount" | Out-File $TemporaryFolderPath\ApplyUserRights.inf -Append -WhatIf:$false
                        }

                            #Import the new .inf into the local security policy.
        
                            Write-Verbose "Importing $TemporaryfolderPath\ApplyUserRighs.inf"
                            $SeceditApplyResults = SECEDIT /configure /db secedit.sdb /cfg $TemporaryFolderPath\ApplyUserRights.inf 

                            #Verify that update was successful (string reading, blegh.)
                            if($SeceditApplyResults[$SeceditApplyResults.Count-2] -eq "The task has completed successfully.")
                            {
                                #Success, return true
                                Write-Verbose "Import was successful."
                                Write-Output $true
                            }
                            else
                            {
                                #Import failed for some reason
                                Write-Verbose "Import from $TemporaryFolderPath\ApplyUserRights.inf failed."
                                Write-Output $false
                                throw -Message "The import from$TemporaryFolderPath\ApplyUserRights using secedit failed. Full Text Below:
                                $SeceditApplyResults)"
                            }

                        }
                        else
                            {
                                #Export failed for some reason.
                                Write-Verbose "Export to $TemporaryFolderPath\UserRightsAsTheyExist.inf failed."
                                Write-Output $false
                                throw -Message "The export to $TemporaryFolderPath\UserRightsAsTheyExist.inf from secedit failed. Full Text Below: $SeceditResults)"
        
                        }

                        Write-Verbose "Cleaning up temporary files that were created."
                            #Delete the two temp files we created.
                            Remove-TempFiles
    
                        }

                    function Remove-TempFiles {

                        #Evaluate whether the ApplyUserRights.inf file exists
                        if(Test-Path $TemporaryFolderPath\ApplyUserRights.inf)
                        {
                            #Remove it if it does.
                            Write-Verbose "Removing $TemporaryFolderPath`\ApplyUserRights.inf"
                            Remove-Item $TemporaryFolderPath\ApplyUserRights.inf -Force -WhatIf:$false
                        }

                        #Evaluate whether the UserRightsAsTheyExists.inf file exists
                        if(Test-Path $TemporaryFolderPath\UserRightsAsTheyExist.inf)
                        {
                            #Remove it if it does.
                            Write-Verbose "Removing $TemporaryFolderPath\UserRightsAsTheyExist.inf"
                            Remove-Item $TemporaryFolderPath\UserRightsAsTheyExist.inf -Force -WhatIf:$false
                        }
                    }
  
               ###############################################################
             
            #################Policy Changes####################################

            $ret1=  Add-LoginToLocalPrivilege "NT Service\Mssqlserver" "SeLockMemoryPrivilege"

            $ret2=  Add-LoginToLocalPrivilege "NT Service\Mssqlserver" "SeManageVolumePrivilege"
            
            return $($ret1 -and $ret2)
            }
             DependsOn = "[Script]ConfigureSQLAgentService"
       }
    }

}
