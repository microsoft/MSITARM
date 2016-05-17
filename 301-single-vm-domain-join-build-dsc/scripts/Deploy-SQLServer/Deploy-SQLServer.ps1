
Configuration DeploySQLServer
{
  param (  
   $Disks
  )

  Node localhost
  {
	   
   
    Script ConfigureSQLServerLocal{
            GetScript = {
                @{
                }
            }

            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } | % { $_.Caption }
                $ret = $false

                if($sqlInstances -ne $null -and $sqlInstances -gt 0){


                    #
                    # Start
                    #

                    cd\
                    if($(test-path -path c:\temp) -eq $false){
                        md Temp
                    }
                    $sw = New-Object System.IO.StreamWriter(“C:\Temp\sqlinstall.log”)
                    $sw.WriteLine("$(Get-Date -Format g) Starting.")    
                    $sw.WriteLine("$(Get-Date -Format g) -----------------------------------------------------.")    
                    $sw.WriteLine("$(Get-Date -Format g) Set DataPath=$($using:disks.SQLServer.DataPath)")    
                    $sw.WriteLine("$(Get-Date -Format g) Set LogPath=$($using:disks.SQLServer.LogPath)")    
                    $sw.WriteLine("$(Get-Date -Format g) Set TempDbPath=$($using:disks.SQLServer.TempDbPath)")    
                    $sw.WriteLine("$(Get-Date -Format g) Set BackupPath=$($using:disks.SQLServer.BackupPath)")    
                    $sw.WriteLine("$(Get-Date -Format g) -----------------------------------------------------.")    
                    try{      
                
                        $ErrorActionPreference = "SilentlyContinue"
       

                        ###############################################
                        #
                        # SQL COnfiguration
                        #
                        ###############################################
                         $sw.WriteLine("$(Get-Date -Format g) Creating Data, Log, Tempdb, and backup paths if they dont exist.")

                        if($(test-path -Path $($using:disks.SQLServer.DataPath)) -eq $false){
                            md $($using:disks.SQLServer.DataPath)
                        }
                        if($(test-path -Path $($using:disks.SQLServer.LogPath)) -eq $false){
                            md $($using:disks.SQLServer.LogPath)
                        }
                        if($(test-path -Path $($using:disks.SQLServer.BackupPath)) -eq $false){
                            md $($using:disks.SQLServer.BackupPath)
                        }
                        if($(test-path -Path $($using:disks.SQLServer.tempdbpath)) -eq $false){
                            md $($using:disks.SQLServer.tempdbpath)
                        }

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

                        
                        ###########################################
                        #  Set Auth Mode to Windows Integrated
                        ############################################
                        $srv.Settings.LoginMode = [Microsoft.SqlServer.Management.SMO.ServerLoginMode]::Integrated
                        $srv.Alter()

                        ###########################################
                        #  Set the backup location to $disks.SQLServer.backupPath
                        ############################################
                        $BackupDir = $($using:disks.SQLServer.backupPath)
                        $sw.WriteLine("$(Get-Date -Format g) Set Backup location to $($BackupDir)")

                        $sw.WriteLine("$(Get-Date -Format g) Updating SQL...")
                        $srv.BackupDirectory = $BackupDir
                        $srv.Alter()

                        ###########################################
                        #  Set the data location to $disks.SQLServer.backupPath
                        ############################################
                        $DefaultFileDir = $($using:disks.SQLServer.DataPath)
                        $sw.WriteLine("$(Get-Date -Format g) Set Backup location to $($DefaultFileDir)")

                        $sw.WriteLine("$(Get-Date -Format g) Updating SQL...")
                        $srv.defaultfile = $DefaultFileDir
                        $srv.Alter()

                        ###########################################
                        #  Set the backup location to $disks.SQLServer.backupPath
                        ############################################
                        $DefaultLog = $($using:disks.SQLServer.LogPath)
                        $sw.WriteLine("$(Get-Date -Format g) Set Backup location to $($DefaultLog)")
                        
                        $sw.WriteLine("$(Get-Date -Format g) Updating SQL...")
                        $srv.DefaultLog = $DefaultLog
                        $srv.Alter()


                        ############################################
                        # Set Max D.O.P.:  n=num of procs
                        ############################################
                        $sw.WriteLine("$(Get-Date -Format g) Set Max D.O.P.:  n=num of procs")
                        $sw.WriteLine("$(Get-Date -Format g) Before: altering MaxDegreeOfParallelism" + $srv.configuration.MaxDegreeOfParallelism.ConfigValue)
                        $srv.configuration.MaxDegreeOfParallelism.ConfigValue;
                        $srv.configuration.MaxDegreeOfParallelism.ConfigValue =$NumberOfProcessors.NumberOfProcessors;
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
                        net start SQLSERVERAGENT
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
                                                                       
                        
                        ############################################
                        # Configure Master, Model and MSDB DBs 
                        ############################################
                        $sw.WriteLine("$(Get-Date -Format g) Configure Master, Model and MSDB DBs ")
                        INVOKE-sqlcmd  -Database model -Query "Alter database [model] set recovery simple with no_wait"

                        INVOKE-sqlcmd  -Database master -Query "Alter database [master] modify file (Name = [master], Size = 50 MB)"

                        INVOKE-sqlcmd  -Database master -Query "Alter database [master] modify file (Name = [master], Filegrowth = 5 MB)"

                        INVOKE-sqlcmd  -Database master -Query "Alter database [master] modify file (Name = [mastLog], Size = 20 MB)"

                        INVOKE-sqlcmd  -Database master -Query "Alter database [master] modify file (Name = [mastLog], Filegrowth = 5 MB)"


                        INVOKE-sqlcmd  -Database msdb -Query "Alter database [msdb] modify file (Name = [msdbData], Size = 50 MB)"

                        INVOKE-sqlcmd  -Database msdb -Query "Alter database [msdb] modify file (Name = [msdbData], Filegrowth = 5 MB)"

                        INVOKE-sqlcmd  -Database msdb -Query "Alter database [msdb] modify file (Name = [msdbLog], Size = 20 MB)"

                        INVOKE-sqlcmd  -Database msdb -Query "Alter database [msdb] modify file (Name = [msdbLog], Filegrowth = 5 MB)"


                        INVOKE-sqlcmd  -Database model -Query "Alter database [model] modify file (Name = [modeldev], Size = 50 MB)"

                        INVOKE-sqlcmd  -Database model -Query "Alter database [model] modify file (Name = [modeldev], Filegrowth = 5 MB)"

                        INVOKE-sqlcmd  -Database model -Query "Alter database [model] modify file (Name = [modellog], Size = 20 MB)"

                        INVOKE-sqlcmd  -Database model -Query "Alter database [model] modify file (Name = [modellog], Filegrowth = 5 MB)"

                        ############################################
                        # Set BUILTIN Administrators group = Removed
                        ############################################
                        $sw.WriteLine("$(Get-Date -Format g) Set BUILTIN Administrators group = Removed")

                        
                        $q = "if Exists(select 1 from sys.syslogins where name='[BUILTIN\Administrators]') drop login [BUILTIN\Administrators]"
				        Invoke-Sqlcmd -Database master -Query $q



                        ############################################
                        # Configure Auditing
                        ############################################
                        $sw.WriteLine("$(Get-Date -Format g) Configure Auditing")
                        INVOKE-sqlcmd  -Database master -Query "Exec [master].[sys].[xp_instance_regwrite] N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs', REG_DWORD, 30"

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
                        $drive = Get-WmiObject -Class win32_volume -Filter "DriveLetter = 'T:'"
                            if ($drive){
                                $TempDrive="T:"
                                $TempLogDrive="T:"

                                $TempPath = $($using:disks.SQLServer.TempDbPath)
                                $TempLogPath = $($using:disks.SQLServer.TempDbPath) 

                            }else{
                                $TempDrive="H:"
                                $TempLogDrive="O:"

                                $TempPath = $($using:disks.SQLServer.TempDbPath)
                                $TempLogPath = $($using:disks.SQLServer.LogPath) 

                            }
                        
                            #$sw.WriteLine("$(Get-Date -Format g) Configuting Temp DB on T:...")
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
	                        # Create the folder for our temp db files
                            if($(test-path -path $($tempPath)) -eq $false) {
                                $sw.WriteLine("$(Get-Date -Format g) Creating $($TempPath)")
				                "$(Get-Date -Format g) Creating $($TempPath)"
                                md $($TempPath) 
                            }
                            ################################################################


	                        # Build the sql commands to move/create the files and invoke them...
	
                            ################################################################
	                        # 1st data file	
                            $sw.WriteLine("$(Get-Date -Format g) Moving first data file...")	
				            "$(Get-Date -Format g) Moving first data file..."

	                        $q = "ALTER DATABASE [tempdb] MODIFY FILE (NAME = tempdev, FILENAME = '$($TempPath)\tempdb.mdf')"
				            $sw.WriteLine("$(Get-Date -Format g)  - $($q)")
	                        Invoke-Sqlcmd -Database master -Query $q

                            "$(Get-Date -Format g) Restarting SQL Server."
                            net stop sqlserveragent
                            net stop mssqlserver
                            Start-Sleep 15
                            net start mssqlserver

	                        $q = "ALTER DATABASE [tempdb] MODIFY FILE (NAME = tempdev, SIZE = $($fileSize)MB, MAXSIZE = $($maxFileGrowthSizeMB)MB, FILEGROWTH = $($fileGrowthMB)MB)"
				            $sw.WriteLine("$(Get-Date -Format g)  - $($q)")
	                        Invoke-Sqlcmd -Database master -Query $q

	                        # remaining data files
	                        $sw.WriteLine("$(Get-Date -Format g) Creating remaining data files...")	
				            "$(Get-Date -Format g) Creating remaining data files..."
                            for ($i = 2; $i -le $fileCount; $i++) {
		                        $q = "ALTER DATABASE [tempdb] ADD FILE ( NAME = tempdev$($i), SIZE = $($fileSize)MB, MAXSIZE = $($maxFileGrowthSizeMB)MB, FILEGROWTH = $($fileGrowthMB)MB, FILENAME = '$($TempPath)\tempdb$($i).mdf')"; 
		                        Invoke-Sqlcmd -Database master -Query $q	                        
                            }
	                        ################################################################

                            ################################################################
                            if($(test-path -path $($tempLogPath)) -eq $false) {
                                $sw.WriteLine("$(Get-Date -Format g) Creating $($TempLogPath)")
				                "$(Get-Date -Format g) Creating $($TempLogPath)"
                                md $TempLogPath 
                            }
                            ################################################################
	                        # log file
                            ################################################################
                            $sw.WriteLine("$(Get-Date -Format g) Moving log file...")	
				            "$(Get-Date -Format g) Moving log file..."

	                        $q = "ALTER DATABASE [tempdb] MODIFY FILE (NAME = templog, FILENAME = '$($TempLogPath)\templog.ldf')"
				            $sw.WriteLine("$(Get-Date -Format g)  - $($q)")
				            Invoke-Sqlcmd -Database master -Query $q

                            "$(Get-Date -Format g) Restarting SQL Server."
	                        net stop mssqlserver
                            Start-Sleep 15
                            net start mssqlserver

	                        $q = "ALTER DATABASE [tempdb] MODIFY FILE (NAME = templog, SIZE = $($fileSize)MB, MAXSIZE = $($maxFileGrowthSizeMB)MB, FILEGROWTH = $($fileGrowthMB)MB)"
				            $sw.WriteLine("$(Get-Date -Format g)  - $($q)")
				            Invoke-Sqlcmd -Database master -Query $q
                            
                            $sw.WriteLine("$(Get-Date -Format g) Restarting SQL Server.")	
				            "$(Get-Date -Format g) Restarting SQL Server."

                            net stop mssqlserver
                            Start-Sleep 15
                            net start mssqlserver
                            net start sqlserveragent
                            
                        

                    }

                    catch {
                    
                        [string]$errorMessage = $Error[0].Exception
		                $sw.WriteLine("$(Get-Date -Format g) An error occurred: $($errorMessage)")
        
                    }
                    
                    finally{
        
                        $ErrorActionPreference = 'Stop'
            
                    }

                    ###############################################
                    #
                    # OK, lets wrap it up...
                    #
                    ###############################################
                    
                    $sw.WriteLine("$(Get-Date -Format g) Fin.")	
                    $sw.Close()
                    
                }
            
            }

            TestScript = {$false}
            
        }

    }

}