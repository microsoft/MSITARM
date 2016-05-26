
Configuration DeploySQLServer
{
  param (  
   [Parameter(Mandatory)]
   [string] $DataPath="H:\MSSqlServer\MSSQL\DATA",
   [Parameter(Mandatory)]
   [string] $LogPath="O:\MSSqlServer\MSSQL\DATA",
   [Parameter(Mandatory)]
   [string] $BackupPath="E:\MSSqlServer\MSSQL\DATA",
   [Parameter(Mandatory)]
   [string] $TempDBPath="T:\MSSqlServer\MSSQL\DATA"
  )

  Node localhost
  {

  	    Script ConfigureEventLog{
            GetScript = {
                @{
                }
            }
            SetScript = {
                try {

                    new-EventLog -LogName Application -source 'CloudMSArmTemplates' -ErrorAction SilentlyContinue
                    Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "Created"

                } catch{}
            }
            TestScript = {
                try{
                    $pass=$false
                    $logs=get-eventlog -LogName Application | ? {$_.source -eq 'CloudMSArmTemplates'} | select -first 1
                    if($logs) {$pass= $true} else {$pass= $false}
                    if($pass) {Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "ServerLoginMode $pass" }

                } catch{}
              
              return $pass
            }

        }

        File SQLDataPath {
            Type = 'Directory'
            DestinationPath = $DataPath
            Ensure = "Present"
        }
        
        File SQLLogPath {
            Type = 'Directory'
            DestinationPath = $LogPath
            Ensure = "Present"
        }
  
        File SQLTempdbPath {
            Type = 'Directory'
            DestinationPath = $TempDBPath
            Ensure = "Present"
        }
      
        File SQLBackupPath {
            Type = 'Directory'
            DestinationPath = $BackupPath
            Ensure = "Present"
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
                            Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
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
                
                        Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "ServerLoginMode $pass" 

                    }catch {$pass = $false}
                }
              
              return $pass
            }
            DependsOn = "[Script]ConfigureEventLog"

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
                        $NumberOfProcessors = Get-WmiObject -Class Win32_ComputerSystem 
                        if($($NumberOfProcessors.NumberOfProcessors) -eq 1) { $maxDop=1 }
                        if($($NumberOfProcessors.NumberOfProcessors) -ge 2 -and $($NumberOfProcessors.NumberOfProcessors) -le 7) { $maxDop=2 }
                        if($($NumberOfProcessors.NumberOfProcessors) -ge 8 -and $($NumberOfProcessors.NumberOfProcessors) -le 16) { $maxDop=4 }
                        if($($NumberOfProcessors.NumberOfProcessors) -gt 16) { $maxDop=8 }
                                          
                        $srv.configuration.MaxDegreeOfParallelism.ConfigValue =$maxDop
                        $srv.configuration.Alter();
                                               
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
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

                        $NumberOfProcessors = Get-WmiObject -Class Win32_ComputerSystem 
                        if($($NumberOfProcessors.NumberOfProcessors) -eq 1) { $maxDop=1 }
                        if($($NumberOfProcessors.NumberOfProcessors) -ge 2 -and $($NumberOfProcessors.NumberOfProcessors) -le 7) { $maxDop=2 }
                        if($($NumberOfProcessors.NumberOfProcessors) -ge 8 -and $($NumberOfProcessors.NumberOfProcessors) -le 16) { $maxDop=4 }
                        if($($NumberOfProcessors.NumberOfProcessors) -gt 16) { $maxDop=8 }

                        $maxdop

                        $srv.configuration.MaxDegreeOfParallelism.ConfigValue;
                
                        if($srv.configuration.MaxDegreeOfParallelism.ConfigValue -eq $maxDop) { $pass= $true} else { $pass= $false}
                        
                        Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "ServerLoginMode $pass"

                    } catch{ $pass= $false}

                } else { $pass= $false}

             return $pass
            }
            DependsOn = "[Script]ConfigureEventLog"
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
                            Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
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

                Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "DefaultLocations $pass"

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
                      
                        if($PhysicalRAM -eq 8) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 4096
                        }
                        if($PhysicalRAM -eq 16) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 12288 
                        }
                        if($PhysicalRAM -eq 24) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 19456   
                        }
                        if($PhysicalRAM -eq 32) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 25600
                        }
                        if($PhysicalRAM -eq 48) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 38912
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
                        if($PhysicalRAM -eq 128) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 104448
                        }
                        if($PhysicalRAM -eq 256) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 229376
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
                            Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
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
                           
                      
                        if($PhysicalRAM -eq 8) 
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
                        if($PhysicalRAM -eq 32) 
                        {
                            $srvRAM = 25600
                        }
                        if($PhysicalRAM -eq 48) 
                        {
                            $srvRAM = 38912
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
                        if($PhysicalRAM -eq 128) 
                        {
                            $srvRAM = 104448
                        }
                        if($PhysicalRAM -eq 256) 
                        {
                            $srvRAM = 229376
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

                Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "MaxMemory $pass"

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
                            Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
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

                Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "SQLAgentConfiguration $pass"

             return $pass
            }
            DependsOn = "[Script]ConfigureMaxMemory"
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
                            Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
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

                Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "MasterDataFile $pass"

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
                            Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
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

                Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "MasterLogFile $pass"

               return $pass
            }
            DependsOn = "[Script]ConfigureMasterDataFile"
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
                            Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
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

                Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "ModelDataFile $pass"

               return $pass
            }
            DependsOn = "[Script]ConfigureMasterLogFile"
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
                            if((20*1024) -ne $dbf.Size -or (5*1024) -ne $dbf.Growth) {

                                $DBF.MaxSize = -1
                                $dbf.Growth = (5*1024)
                                $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                                $dbf.Size = (20*1024)
                                $dbf.Alter()

                           } else {"$($DBF.Name) Size to 20MB, Filegrowth to 5MB, unlimited growth"}
                          
                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
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

                Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "ModelLogFile $pass"

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
                                $dbf.Size = (50*1024)
                                $dbf.Growth = (5*1024)
                                $dbf.Alter()

                           } else {"$($DBF.Name) Size to 50MB,Filegrowth to 5MB, unlimited growth"}
                          
                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
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

                    Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "MSDBDataFile $pass"

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
       
                        foreach ($DBF in $DBFG.LogFiles) {
                           if((50*1024) -ne $dbf.Size -or (5*1024) -ne $dbf.Growth) {

                               $DBF.MaxSize = -1
                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = (20*1024)
                               $dbf.Alter()

                           } else {"$($DBF.Name) Size to 20MB,Filegrowth to 5MB"}
                          

                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
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
                    }

                 }else {$pass=$false}
                 
                 Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "MSDBLogFile $pass"

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
                            Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
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
            
                Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "ModelDataFile $pass"

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
                            Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
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
            
                Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "BuiltInAdmins $pass"

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
                        $fileCount = $cpu.NumberOfCores

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
                                    Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
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

                Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "MoveTempdb $pass"

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
                        $fileCount = $cpu.NumberOfCores

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
                                            Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
                                        }else {$errorMessage}
                                    }
                                                                                               
                            Restart-Service -displayname "SQL Server (MSSQLSERVER)" -Force

		                        	                        
                        }

                          

                                               
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
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
                    $fileCount = $cpu.NumberOfCores

                    $pass=$true
                    for ($i = 2; $i -le $fileCount; $i++) {

                        $readylog = $(test-path -Path $("$($TempPath)\tempdb$($i).mdf"))
                        if(!$readylog) {$pass=$false}            

                    }
                }

                Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "AddTempdbFiles $pass"

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

                        $MyDatabase = $srv.Databases[$DatabaseName]
                         
                        $fileSize     = $(1024*1000)
                        $fileGrowthMB = $(1024*50)
                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $fileCount = $cpu.NumberOfCores

                        if($fileCount -gt 8){ $fileCount = 8 }
                       
                        if($FreeSpaceGB -ge  10 -and $FreeSpaceGB -lt 50 ){
                            $fileSize     = $(1024*500)
                            $fileGrowthMB = $(1024*50)
                        }elseif($FreeSpaceGB -ge  50  ){
                            $fileSize     = $(1024*100)
                            $fileGrowthMB = $(1024*100)
                        }

                        $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                        $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)
                                                                           
                        $DBFG = $MyDatabase.FileGroups;
                        foreach ($DBF in $DBFG.Files) {
                           if(($FileSize) -ne $dbf.Size) {
                               $DBF.MaxSize = -1
                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = $($fileSize)
                               $dbf.Growth = "$fileGrowthMB"
                               $dbf.Alter()

                           } else {"$($DBF.Name) Size to $($dbf.Size), growth=$($dbf.Growth)"}
                         

                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
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
                   
                    $TempDrive=$($using:TempDbPath).split("\")[0] 
                    $TempPath = $($using:TempDbPath)

                    $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                    $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                    $fileCount = $cpu.NumberOfCores

                    $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                    $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)

                    if($fileCount -gt 8){ $fileCount = 8 }
                       
                    if($FreeSpaceGB -ge  10 -and $FreeSpaceGB -lt 50 ){
                        $fileSize     = $(1024*500)
                        $fileGrowthMB = $(1024*50)
                    }elseif($FreeSpaceGB -ge  50  ){
                        $fileSize     = $(1024*100)
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

                    Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "ConfigureTempDataFile $pass"

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
                        
                        $fileSize     = $(1024*1000)
                        $fileGrowthMB = $(1024*50)
                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $TempDBSpaceAvailGB = $FreeSpaceGB - 50
	                    $TempDBSpaceAvailMB = $TempDBSpaceAvailGB * 1024
                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $fileCount = $cpu.NumberOfCores


                        if($fileCount -gt 8){ $fileCount = 8 }
                       
                        if($FreeSpaceGB -ge  10 -and $FreeSpaceGB -lt 50 ){
                            $fileSize     = $(1024*500)
                            $fileGrowthMB = $(1024*50)
                        }elseif($FreeSpaceGB -ge  50  ){
                            $fileSize     = $(1024*100)
                            $fileGrowthMB = $(1024*100)
                        }

                        $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                        $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)

                        $MyDatabase = $srv.Databases[$DatabaseName]
          
                        foreach ($DBF in $MyDatabase.LogFiles) {
                           if(($fileSize) -ne $dbf.Size -or ($fileGrowthMB) -ne $dbf.Growth -or ($maxFileGrowthSizeMB) -ne $dbf.MaxSize) {
                               $DBF.MaxSize = -1
                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = ($fileSize)
                               $dbf.Growth = $fileGrowthMB
                               $dbf.Alter()

                               "$($DBF.Name) Size is $($dbf.Size) MB,Growth is $($dbf.Growth) MB, MaxSize is $($dbf.MaxSize) MB"

                           } else {"$($DBF.Name) Size is $fileSize MB,Growth is $fileGrowthMB MB, MaxSize is $maxFileGrowthSizeMB MB"}

                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
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
                    
                        $fileSize     = $(1024*1000)
                        $fileGrowthMB = $(1024*50)
                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $TempDBSpaceAvailGB = $FreeSpaceGB - 50
	                    $TempDBSpaceAvailMB = $TempDBSpaceAvailGB * 1024
                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $fileCount = $cpu.NumberOfCores

                        if($fileCount -gt 8){ $fileCount = 8 }
                       
                        if($FreeSpaceGB -ge  10 -and $FreeSpaceGB -lt 50 ){
                            $fileSize     = $(1024*500)
                            $fileGrowthMB = $(1024*50)
                        }elseif($FreeSpaceGB -ge  50  ){
                            $fileSize     = $(1024*100)
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
                 
                 Write-EventLog -LogName Application -source CloudMSArmTemplates -eventID 1000 -entrytype Information -message "ConfigureTempLogFile $pass"

               return $pass
            }
            DependsOn = "[Script]ConfigureTempDataFile"
        }
    }

}