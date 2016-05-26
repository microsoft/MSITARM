
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
  	    
        if($(test-path "t:") -eq $true) {
        $drive = "T:"
        }else{
        $drive = "D:"
        }
        File SQLDataPath {
            Type = 'Directory'
            DestinationPath = "H:\MSSqlServer\MSSQL\DATA"
            Ensure = "Present"
        }
        
        File SQLLogPath {
            Type = 'Directory'
            DestinationPath = "O:\MSSqlServer\MSSQL\DATA"
            Ensure = "Present"
        }
  
        File SQLTempdbPath {
            Type = 'Directory'
            DestinationPath = $($drive + "\MSSqlServer\MSSQL\DATA")
            Ensure = "Present"
        }
      
        File SQLBackupPath {
            Type = 'Directory'
            DestinationPath = "E:\MSSqlServer\MSSQL\DATA"
            Ensure = "Present"
        }
          
          Script ConfigureSQLServerLocal{
            GetScript = {
                @{
                }
            }

            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){

                    #
                    # Start SQL if its not running so we can chat with it.
                    #
                     if($sqlInstances.state -eq 'Stopped'){
                        net start mssqlserver
                        Start-Sleep 15
                     }   
                      
                    cd\
                    if($(test-path -path c:\temp) -eq $false){
                            md Temp
                    }
                  
                    ## wait here til the tempdb drive is online.
                    $sw = New-Object System.IO.StreamWriter(“C:\Temp\sqlinstall.log”)
                    $sw.WriteLine("$(Get-Date -Format g) Starting.") 
                   
                        $ready=$false
                        $Time = [System.Diagnostics.Stopwatch]::StartNew()
                        do {

                            $disk = $(test-path -Path $($using:TempdbPath))

                            if($disk) {$ready = $true} else {
                                $sw.WriteLine("$(Get-Date -Format g) $pid Waiting for $($using:TempdbPath)") 
                                sleep 30}
                            
                                $CurrentTime = $Time.Elapsed
                                if($CurrentTime.minutes -gt 10) {$ready = $true}

                        }until ($ready) 

                    try{  
  
                        #$ErrorActionPreference = "SilentlyContinue"
                      
                        ###############################################
                        #
                        # SQL COnfiguration
                        #
                        ###############################################

                        ###########################################
                        #  New SQL SMO connection
                        ############################################

                        $sw.WriteLine("$(Get-Date -Format g) Configuring SQL...")
                                                  
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
 
                        $srvConn.connect();
                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn


                        $db = $srv.Databases["master"] 
                        $NumberOfProcessors = Get-WmiObject -Class Win32_ComputerSystem 
                        $sw.WriteLine("$(Get-Date -Format g) NumberOfProcessors= $($NumberOfProcessors)") 
                       

                        ###########################################
                        #  Set Auth Mode to Windows Integrated
                        ############################################
                        $sw.WriteLine("$(Get-Date -Format g) Setting Auth Mode to Windows Integrated") 
                        $srv.Settings.LoginMode = [Microsoft.SqlServer.Management.SMO.ServerLoginMode]::Integrated
                        $srv.Alter()

                        ###########################################
                        #  Set the backup location to $disks.SQLServer.backupPath
                        ############################################
                        $BackupDir = $($using:backupPath)
                        $sw.WriteLine("$(Get-Date -Format g) Set Backup location to $($BackupDir)")

                        $sw.WriteLine("$(Get-Date -Format g) Updating SQL...")
                        $srv.BackupDirectory = $BackupDir
                        $srv.Alter()

                        ###########################################
                        #  Set the data location to $disks.SQLServer.backupPath
                        ############################################
                        $DefaultFileDir = $($using:DataPath)
                        $sw.WriteLine("$(Get-Date -Format g) Set Backup location to $($DefaultFileDir)")

                        $sw.WriteLine("$(Get-Date -Format g) Updating SQL...")
                        $srv.defaultfile = $DefaultFileDir
                        $srv.Alter()

                        ###########################################
                        #  Set the backup location to $disks.SQLServer.backupPath
                        ############################################
                        $DefaultLog = $($using:LogPath)
                        $sw.WriteLine("$(Get-Date -Format g) Set Backup location to $($DefaultLog)")
                        
                        $sw.WriteLine("$(Get-Date -Format g) Updating SQL...")
                        $srv.DefaultLog = $DefaultLog
                        $srv.Alter()


                        ############################################
                        # Set Max D.O.P.:  n=num of procs
                        ############################################
                        $sw.WriteLine("$(Get-Date -Format g) Set Max D.O.P.:  n=num of procs,m=maxDop")
                        $sw.WriteLine("$(Get-Date -Format g)                  n=1 then m=1")
                        $sw.WriteLine("$(Get-Date -Format g)                  n=2-7 then m=2")
                        $sw.WriteLine("$(Get-Date -Format g)                  n=8-16 then m=4")
                        $sw.WriteLine("$(Get-Date -Format g)                  n>16 then m=8")
                        if($($NumberOfProcessors.NumberOfProcessors) -eq 1) { $maxDop=1 }
                        if($($NumberOfProcessors.NumberOfProcessors) -ge 2 -and $($NumberOfProcessors.NumberOfProcessors) -le 7) { $maxDop=2 }
                        if($($NumberOfProcessors.NumberOfProcessors) -ge 8 -and $($NumberOfProcessors.NumberOfProcessors) -le 16) { $maxDop=4 }
                        if($($NumberOfProcessors.NumberOfProcessors) -gt 16) { $maxDop=8 }

                        $sw.WriteLine("$(Get-Date -Format g) Before: altering MaxDegreeOfParallelism" + $srv.configuration.MaxDegreeOfParallelism.ConfigValue)

                        $srv.configuration.MaxDegreeOfParallelism.ConfigValue;
                        $srv.configuration.MaxDegreeOfParallelism.ConfigValue =$maxDop
                        $srv.configuration.Alter();

                        $sw.WriteLine("$(Get-Date -Format g) After: altering MaxDegreeOfParallelism" + $srv.configuration.MaxDegreeOfParallelism.ConfigValue)

                        ############################################
                        # Set Max Server Memory
                        ############################################
                        $sw.WriteLine("$(Get-Date -Format g) Set Max Server Memory")
                        $sw.WriteLine("$(Get-Date -Format g) Before altering MaxServerMemory: " + $srv.configuration.MaxServerMemory.ConfigValue)
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
                        
                        $sw.WriteLine("$(Get-Date -Format g) After altering MaxServerMemory: " + $srv.configuration.MaxServerMemory.ConfigValue)


                        ############################################
                        # Configure SQL Server Agent Service
                        ############################################
                        $sw.WriteLine("$(Get-Date -Format g) Configure SQL Server Agent Service....")
                         try {

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
                            $CurrentSettings | ft -AutoSize ;
                            $TargetMaximumHistoryRows = 100000;
                            $TargetMaximumJobHistoryRows = 1000 ;

                            $SQLAgent.MaximumHistoryRows = $TargetMaximumHistoryRows ;
                            $SQLAgent.MaximumJobHistoryRows = $TargetMaximumJobHistoryRows ; 
                            $db.Parent.JobServer.SqlServerRestart=1
                            $db.Parent.JobServer.SqlAgentRestart=1
                            $SQLAgent.Alter();
                     
                            # ensuring we have the latest information
                            $SQLAgent.Refresh();
                            $SQLAgent | select @{n="SQLInstance";e={$db.parent.Name}},MaximumHistoryRows, MaximumJobHistoryRows ;
                            $db.Parent.ConnectionContext.Disconnect();

                            CD HKLM:\
                            $Registry_Key ="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SQLSERVERAGENT\"
                            Set-ItemProperty -Path $Registry_Key -Name Start  -Value 2 
                            CD C:\
                        }catch{
                            [string]$errorMessage = $Error[0].Exception
		                    $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                        }                                            
                        
                        ############################################
                        # Configure Master, Model and MSDB DBs 
                        ############################################
                        $sw.WriteLine("$(Get-Date -Format g) Configure Master, Model and MSDB DBs ")
                         try{
                            INVOKE-sqlcmd  -Database model -Query "Alter database [model] set recovery simple with no_wait"
                         }catch{
                            [string]$errorMessage = $Error[0].Exception
		                    $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                        }
                        try{
                            INVOKE-sqlcmd  -Database master -Query "Alter database [master] modify file (Name = [master], Size = 50 MB)"
                        }catch{
                            [string]$errorMessage = $Error[0].Exception
		                    $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                        }
                        try {
                            INVOKE-sqlcmd  -Database master -Query "Alter database [master] modify file (Name = [master], Filegrowth = 5 MB)"
                         }catch{
                            [string]$errorMessage = $Error[0].Exception
		                    $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                        }
                        try {
                            INVOKE-sqlcmd  -Database master -Query "Alter database [master] modify file (Name = [mastLog], Size = 20 MB)"
                         }catch{
                            [string]$errorMessage = $Error[0].Exception
		                    $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                        }
                        try{
                                INVOKE-sqlcmd  -Database master -Query "Alter database [master] modify file (Name = [mastLog], Filegrowth = 5 MB)"
                        }catch{
                            [string]$errorMessage = $Error[0].Exception
		                    $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                        }
                        try{
                            INVOKE-sqlcmd  -Database msdb -Query "Alter database [msdb] modify file (Name = [msdbData], Size = 50 MB)"
                         }catch{
                            [string]$errorMessage = $Error[0].Exception
		                    $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                        }
                        try {
                            INVOKE-sqlcmd  -Database msdb -Query "Alter database [msdb] modify file (Name = [msdbData], Filegrowth = 5 MB)"
                        }catch{
                            [string]$errorMessage = $Error[0].Exception
		                    $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                        }
                        try{
                            INVOKE-sqlcmd  -Database msdb -Query "Alter database [msdb] modify file (Name = [msdbLog], Size = 20 MB)"
                         }catch{
                            [string]$errorMessage = $Error[0].Exception
		                    $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                        }
                        try{
                            INVOKE-sqlcmd  -Database msdb -Query "Alter database [msdb] modify file (Name = [msdbLog], Filegrowth = 5 MB)"
                         }catch{
                            [string]$errorMessage = $Error[0].Exception
		                    $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                        }
                        try{
                            INVOKE-sqlcmd  -Database model -Query "Alter database [model] modify file (Name = [modeldev], Size = 50 MB)"
                         }catch{
                            [string]$errorMessage = $Error[0].Exception
		                    $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                        }
                        try{
                            INVOKE-sqlcmd  -Database model -Query "Alter database [model] modify file (Name = [modeldev], Filegrowth = 5 MB)"
                         }catch{
                            [string]$errorMessage = $Error[0].Exception
		                    $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                        }
                        try{
                            INVOKE-sqlcmd  -Database model -Query "Alter database [model] modify file (Name = [modellog], Size = 20 MB)"
                         }catch{
                            [string]$errorMessage = $Error[0].Exception
		                    $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                        }
                        try{
                            INVOKE-sqlcmd  -Database model -Query "Alter database [model] modify file (Name = [modellog], Filegrowth = 5 MB)"
                         }catch{
                            [string]$errorMessage = $Error[0].Exception
		                    $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                         }
                        ############################################
                        # Set BUILTIN Administrators group = Removed
                        ############################################
                        $sw.WriteLine("$(Get-Date -Format g) Set BUILTIN Administrators group = Removed")

                        try {
                            $q = "if Exists(select 1 from sys.syslogins where name='[BUILTIN\Administrators]') drop login [BUILTIN\Administrators]"
				            Invoke-Sqlcmd -Database master -Query $q
                         }catch{
                            [string]$errorMessage = $Error[0].Exception
		                    $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                         }

                        ############################################
                        # Configure Auditing
                        ############################################
                        $sw.WriteLine("$(Get-Date -Format g) Configure Auditing")
                        try{
                            INVOKE-sqlcmd  -Database master -Query "Exec [master].[sys].[xp_instance_regwrite] N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs', REG_DWORD, 30"
                         }catch{
                            [string]$errorMessage = $Error[0].Exception
		                    $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                         }
                        ############################################
                        # Configure TCP ports 
                        ############################################
                        $sw.WriteLine("$(Get-Date -Format g) Configure TCP ports")


                        ############################################
                        # Set Public role:
                        # not allowed to execute any extended sprocs
                        ############################################
                        $sw.WriteLine("$(Get-Date -Format g) # Set Public role not allowed to execute any extended sprocs")


                        ############################################
                        # Configure Temp DB:  
                        # num of data files = num of procs, equi-sized, autogrow
                        ############################################
                        #$drive = Get-WmiObject -Class win32_volume -Filter "DriveLetter = 'T:'"
                      
                            $TempDrive=$($using:TempDbPath).split("\")[0] 
                            $TempPath = $($using:TempDbPath)
                                                   
                            #$sw.WriteLine("$(Get-Date -Format g) Configuting Temp DB on ?:...")
				            "$(Get-Date -Format g) Configuring Temp DB on  $TempDrive..."

	                        # get the spavce avail on T: and subtract 50 GB.  From that, divide it up to the number of files:
                            $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                            $TempDBSpaceAvailGB = $FreeSpaceGB - 50
	                        $TempDBSpaceAvailMB = $TempDBSpaceAvailGB * 1024

                            $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                            $fileCount = $cpu.NumberOfCores

                            $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                            $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)
	                        $fileSize     = '1000'
                            $fileGrowthMB = '50'            
                            	                        

                            if(!$TempPath) {
                            $TempPath = $Srv.RootDirectory -Replace "C:", $TempDrive
	                        $TempPath = $TempPath + '\'
                            $TempLogPath = $TempPath 
                            }
                            
                            ################################################################
	                        # Build the sql commands to move/create the files and invoke them...
                            ################################################################
	                        # 1st data file	
                            $sw.WriteLine("$(Get-Date -Format g) Moving first data file...")	
				            "$(Get-Date -Format g) Moving first data file..."
  
                                do {
                                    try{
	                                    $q = "ALTER DATABASE [tempdb] MODIFY FILE (NAME = tempdev, FILENAME = '$($TempPath)\tempdb.mdf')"
				                        $sw.WriteLine("$(Get-Date -Format g)  - $($q)")
	                                    Invoke-Sqlcmd -Database master -Query $q

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

                                          }catch{
                                            [string]$errorMessage = $Error[0].Exception
		                                    $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                                          }

                                    $ready = $(test-path -Path $("$($TempPath)\tempdb.mdf"))
                                    
                                    $CurrentTime = $Time.Elapsed
                                    if($CurrentTime.minutes -gt 5) {$ready = $true}

                                    if(!$ready) {start-sleep 60} else {$msg="Done"}
                                    $sw.WriteLine("$(Get-Date -Format g) $msg") 

                                }until ($ready)

                            ################################################################
	                        # ALTER DATABASE [tempdb] MODIFY FILE (NAME = tempdev
                            ################################################################                                                            
                             $ready=$false
                             $Time = [System.Diagnostics.Stopwatch]::StartNew()

                                do {
                                    try{
	                                    $q = "ALTER DATABASE [tempdb] MODIFY FILE (NAME = tempdev, SIZE = $($fileSize)MB, MAXSIZE = $($maxFileGrowthSizeMB)MB, FILEGROWTH = $($fileGrowthMB)MB)"
				                        $sw.WriteLine("$(Get-Date -Format g)  - $($q)")
	                                    Invoke-Sqlcmd -Database master -Query $q
                                        $ready=$true
                                    }catch{
                                        $ready=$false
                                        [string]$errorMessage = $Error[0].Exception
		                                $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                                    }
  
                                        $CurrentTime = $Time.Elapsed
                                        if($CurrentTime.minutes -gt 5) {$ready = $true}

                                        if(!$ready) {start-sleep 30} else {$msg="Done"}
                                        $sw.WriteLine("$(Get-Date -Format g) $msg") 

                                 }until ($ready)

                            ################################################################
	                        # remaining data files
                            ################################################################

	                        $sw.WriteLine("$(Get-Date -Format g) Creating remaining data files...")	
				            "$(Get-Date -Format g) Creating remaining data files..."
                            for ($i = 2; $i -le $fileCount; $i++) {

                                $ready=$false
                                $First=$false
                                $Time = [System.Diagnostics.Stopwatch]::StartNew()
                                $msg="Create tempdev$($i)"
                                do {
                                    try{
                                    
                                        $q = "IF NOT EXISTS(SELECT 1 FROM tempdb.dbo.sysfiles WHERE name = 'tempdev$($i)') Begin ALTER DATABASE [tempdb] ADD FILE ( NAME = tempdev$($i), SIZE = $($fileSize)MB, MAXSIZE = $($maxFileGrowthSizeMB)MB, FILEGROWTH = $($fileGrowthMB)MB, FILENAME = '$($TempPath)\tempdb$($i).mdf') END "; 
		                                Invoke-Sqlcmd -Database master -Query $q
                                    
                                    }catch{
                                        [string]$errorMessage = $Error[0].Exception
		                                $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                                    }

                                    $ready = $(test-path -Path $("$TempPath\tempdb$($i).mdf"))
                                    
                                    $CurrentTime = $Time.Elapsed
                                    if($CurrentTime.minutes -gt 5) {$ready = $true}

                                    if(!$ready) {
                                        if($first) { #long intial sleep, short checks
                                                start-sleep 240
                                                $msg+=" ? "
                                            }else{
                                                start-sleep 60
                                                $msg+="."
                                            }
                                        $first=$true
                                        } else {$msg="Done"}
                                    $sw.WriteLine("$(Get-Date -Format g) $msg") 

                                }until ($ready)

		                        	                        
                            }

                            ################################################################
                            $sw.WriteLine("$(Get-Date -Format g) Restarting SQL...")	
				            ################################################################
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

                            ################################################################
	                        # log file
                            ################################################################
                            $sw.WriteLine("$(Get-Date -Format g) Moving log file...")	
				            "$(Get-Date -Format g) Moving log file..."
                        
                             $ready=$false
                             $Time = [System.Diagnostics.Stopwatch]::StartNew()

                                do {
                                    try{

	                                    $q = "ALTER DATABASE [tempdb] MODIFY FILE (NAME = templog, FILENAME = '$($TempPath)\templog.ldf')"
				                        $sw.WriteLine("$(Get-Date -Format g)  - $($q)")

                                            $sw.WriteLine("$(Get-Date -Format g) Restarting SQL Server.")	
       				                        Invoke-Sqlcmd -Database master -Query $q
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

                                    }catch{}
  
                                    $ready = $(test-path -Path $("$($TempPath)\templog.ldf"))
                                    
                                    $CurrentTime = $Time.Elapsed
                                    if($CurrentTime.minutes -gt 5) {$ready = $true}

                                    if(!$ready) {start-sleep 30} else {$msg="Done"}
                                    $sw.WriteLine("$(Get-Date -Format g) $msg") 

                             }until ($ready)
                                                         
                             ################################################################
                             ##ALTER DATABASE [tempdb] MODIFY FILE (NAME = templog
                             ################################################################

                             $ready=$false
                             $Time = [System.Diagnostics.Stopwatch]::StartNew()

                               do {
                                    try{

	                                    $q = "ALTER DATABASE [tempdb] MODIFY FILE (NAME = templog, SIZE = $($fileSize)MB, MAXSIZE = $($maxFileGrowthSizeMB)MB, FILEGROWTH = $($fileGrowthMB)MB)"
				                        $sw.WriteLine("$(Get-Date -Format g)  - $($q)")
				                        Invoke-Sqlcmd -Database master -Query $q
                                        $ready=$true
                                    }catch{
                                        $ready=$false
                                        [string]$errorMessage = $Error[0].Exception
		                                $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
                                    }
  
                                        $CurrentTime = $Time.Elapsed
                                        if($CurrentTime.minutes -gt 5) {$ready = $true}

                                        if(!$ready) {start-sleep 30} else {$msg="Done"}
                                        $sw.WriteLine("$(Get-Date -Format g) $msg") 

                                 }until ($ready)

                                $sw.WriteLine("$(Get-Date -Format g) Restarting SQL Server.")	
       				            Invoke-Sqlcmd -Database master -Query $q
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
                                
                            
                        

                    }

                    catch {
                    
                        [string]$errorMessage = $Error[0].Exception
		                $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
        
                    }
                    
                    finally{
        
                    ###############################################
                    #
                    # OK, lets wrap it up...
                    #
                    ###############################################
                    
                    $sw.WriteLine("$(Get-Date -Format g) Fin.")	
                    $sw.Close()

                    $ErrorActionPreference = 'Stop'
            
                    }

                   
                    
                }
            
            }  
            TestScript = {$false}

        }
    }
}