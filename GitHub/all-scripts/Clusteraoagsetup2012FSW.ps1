param(
	[Parameter(Mandatory = $true)]
    $ClusterName,
    [Parameter(Mandatory = $true)]
    $VMName,
	[Parameter(Mandatory = $true)]
    $InstanceCount,
    [Parameter(Mandatory = $true)]
    $ILBStaticIP,
    [Parameter(Mandatory = $true)]
    $AOAGListenerName,
    [Parameter(Mandatory = $true)]
    $ClusterSetupAccount,
    [Parameter(Mandatory = $true)]
    $ClusterSetupPassword,
    [Parameter(Mandatory = $true)]
    $FSWPath)
	
#region Variable Declaration
$Errors = $null
$workingdir = $pwd
$AOAGSeedDbName = "AOSeed"
$AOAGName = $VMName
$Shouldcontinue = $true
$currentserver = $env:computername
$serverName = "localhost"
$serverdomain=(Get-WmiObject Win32_ComputerSystem).Domain
$LocalMachineName = $env:computername
$currentserverfqdn= "$env:computername.$serverdomain"
$secpasswd = ConvertTo-SecureString $ClusterSetupPassword -AsPlainText -Force
[System.Management.Automation.PSCredential ]$cred1 = New-Object System.Management.Automation.PSCredential ($ClusterSetupAccount, $secpasswd)
function o> {
    param([string]$logstring)
    $logstring

    if ($(Test-Path $logFile)) {
        Add-Content $Logfile -Value $logstring
    }
    else {
        Write-Host $logstring
    }
}
$logDir = "D:\Logs"
if ((Test-Path -Path $logDir) -eq $false) {
    New-Item -Path $logDir -ItemType directory
}
$logfile = "$logDir\ConfigureAOAG2012FSW$($(get-date).toString(‘yyyyMMddhhmm’)).log"
Add-Content $Logfile -Value "$(Get-Date) #########################Configure AOAG 2012 FSW##########################"
Add-Content $Logfile -Value "$(Get-Date) ################Running as $(whoami)###################"
#endregion

#region Checking if the other nodes are discovered via DNS
if ($Shouldcontinue) {
	o> "$(Get-Date) Checking if the other nodes are discovered via DNS"
    try {
        #start-sleep -Seconds 1200
		$ClusterNodes = @()
		if (($VMName.Length -gt 0) -and ($InstanceCount -gt 0)) {
		    for ($icount = 1; $icount -le $InstanceCount; $icount++) {
		        $ClusterNodes = $ClusterNodes + "$VMName$icount.$serverdomain"
		    }
		}
		@($ClusterNodes) | Foreach-Object { 
		    if ([string]::Compare(($_).Split(".")[0], $LocalMachineName, $true) -ne 0) { 
				while($true)
				{
					if(Test-Connection $_ -ErrorAction SilentlyContinue)
					{
						o> "$(Get-Date) Able to ping the node: $_"
						break;
					}
					else 
					{
						o> "$(Get-Date) Not able to ping the node: $_ , Sleeping for 1 minute"
				        sleep -Seconds 60  
					}
				}
			}
		}
    }
    catch [System.Exception] {
        $ErrorMessage = $_
        $ShouldContinue = $false
        $Errors += "[E] : Could not sleep:  $_.Exception.Message "
        o> "$(Get-Date) Error while discovering other nodes over DNS"
    }
}
#endregion

#region Cleanup
if ($Shouldcontinue) {
    try {
		$ClusterNodes = @()
		if (($VMName.Length -gt 0) -and ($InstanceCount -gt 0)) {
		    for ($icount = 1; $icount -le $InstanceCount; $icount++) {
		        $ClusterNodes = $ClusterNodes + "$VMName$icount.$serverdomain"
		    }
		}
		o> "$(Get-Date) Going to cleanup if any AOAG traces are present"
		if(Test-SqlAvailabilityGroup -Path "SQLSERVER:\sql\localhost\default\AvailabilityGroups\$AOAGName" -ErrorAction SilentlyContinue)
		{
			o> "$(Get-Date) Found AOAG Configured , Deleting"
		    Remove-SqlAvailabilityGroup -Path  "SQLSERVER:\sql\localhost\default\AvailabilityGroups\$AOAGName" 
		}
		o> "$(Get-Date) Going to cleanup if any Endpoints Configured"
		foreach ($ClusterNode in $ClusterNodes) {
        	Invoke-Command -ScriptBlock {
                Import-Module sqlps -Force -DisableNameChecking
				$connection = New-Object Microsoft.SqlServer.Management.Common.ServerConnection -ArgumentList $($env:computername)
				$smo = New-Object Microsoft.SqlServer.Management.Smo.Server -ArgumentList $connection
				$endpointname="SqlHADREndpoint"
				if ($smo.Endpoints[$endpointname]) {
                	$smo.Endpoints[$endpointname].Drop()
                }
            } -Credential $cred1 -ComputerName $ClusterNode
    	}
		o> "$(Get-Date) Going to cleanup if AOSeed DB if present"
		foreach ($ClusterNode in $ClusterNodes) {
			if ([string]::Compare(($clusternode).Split(".")[0], $LocalMachineName, $true) -ne 0) { 
        	Invoke-Command -ScriptBlock {
                Import-Module sqlps -Force -DisableNameChecking
				$connection = New-Object Microsoft.SqlServer.Management.Common.ServerConnection -ArgumentList $($env:computername)
				$smo = New-Object Microsoft.SqlServer.Management.Smo.Server -ArgumentList $connection
                $dbname="AOSeed"
				    if ($smo.Databases[$dbname]) {
                        $smo.Databases[$dbname].Drop()
                    }
                } -Credential $cred1 -ComputerName $ClusterNode
            }
            else
            {
                Import-Module sqlps -Force -DisableNameChecking
				$connection = New-Object Microsoft.SqlServer.Management.Common.ServerConnection -ArgumentList $clusternode
				$smo = New-Object Microsoft.SqlServer.Management.Smo.Server -ArgumentList $connection
                $dbname="AOSeed"
				    if ($smo.Databases[$dbname]) {
                        $smo.Databases[$dbname].Drop()
                    } 
            }

    	}
		o> "$(Get-Date) Going to cleanup the cluster if present"
		if(get-cluster)
		{
		    remove-cluster -Force
		}
		sleep -Seconds 60
		foreach ($ClusterNode in $ClusterNodes) {
			if ([string]::Compare(($ClusterNode).Split(".")[0], $LocalMachineName, $true) -ne 0)
			{
			    Invoke-Command -ScriptBlock {
				Clear-ClusterNode -force
				}-Credential $cred1 -ComputerName $ClusterNode
			}
		}
		#@($ClusterNodes) | Foreach-Object { Clear-ClusterNode "$_" -Force } 
    }
    catch [System.Exception] {
        $ErrorMessage = $_
        $ShouldContinue = $false
        $Errors += "[E] :  Cleanup nodes failed:  $_.Exception.Message "
        o> "$(Get-Date) Cleanup nodes failed"
    }
}
#endregion

#region Enable CredSSP
if ($Shouldcontinue) {
    try {
		o> "$(Get-Date) Enable CredSSP for the Primary node to Create cluster"
		$workingdir = $pwd
		cd wsman:
		cd .\localhost
		set-item .\Service\Auth\CredSSP true
		set-item .\service\AllowUnencrypted true
		set-item .\service\EnableCompatibilityHttpListener true
		winrm qc /force
		start-sleep 15
		Enable-wsmancredssp -role client -delegatecomputer *.microsoft.com -Force
		cd $workingdir.Path
    }
    catch [System.Exception] {
        $ErrorMessage = $_
        $ShouldContinue = $false
        $Errors += "[E] : Enable Credssp Failed:  $_.Exception.Message "
        o> "$(Get-Date) Enable Credssp Failed"
    }
}
#endregion

#region Cluster Creation
if ($Shouldcontinue) {
    try {
    	o> "$(Get-Date) WSFC Creation"
		Invoke-Command -ScriptBlock {
			param($logfile)
			function w> {
			    param([string]$logstring)
			    $logstring

			    if ($(Test-Path $logFile)) {
			        Add-Content $Logfile -Value $logstring
			    }
			    else {
			        Write-Host $logstring
			    }
			}
            $serverdomain=$using:serverdomain
			$ClusterName = $using:ClusterName
		    $VMName = $using:VMName
		    $InstanceCount = $using:InstanceCount
		    $FSWPath=$using:FSWPath
			w> "$(Get-Date) Input::Cluster Name:  $ClusterName"
			w> "$(Get-Date) Input::Instance Count:  $InstanceCount"
			w> "$(Get-Date) Input::VMName:  $VMName"
			w> "$(Get-Date) Input::FSWPath:  $FSWPath"
		    import-module FailoverClusters
		    $ClusterNodes = @()
		    if (($VMName.Length -gt 0) -and ($InstanceCount -gt 0)) {
		        for ($icount = 1; $icount -le $InstanceCount; $icount++) {
		            $ClusterNodes = $ClusterNodes + "$VMName$icount.$serverdomain"
		        }
		    }
			w> "$(Get-Date) Cluster Nodes are $ClusterNodes "
		    Import-Module ServerManager
		    $LocalMachineName = $env:computername                   
		    #@($ClusterNodes) | Foreach-Object { Clear-ClusterNode "$_" -Force } 
		    $CurrentCluster = $null
		    $CurrentCluster = Get-Cluster 2> $null
		    if ($CurrentCluster -ne $null) {
		        throw "There is an existing cluster on this machine. Please remove any existing cluster settings from the current machine before running this script"
		        exit 1
		    }   
		    $VLength = 5
		    $Random = 1..$VLength | ForEach-Object {Get-Random -Maximum 9}  
		    $ClusterName = $ClusterName + [string]::join('', $Random)
		    Sleep -Seconds 5
			w> "$(Get-Date) Cluster Name: $ClusterName will be created on primary node"
		    $result = New-Cluster -Name $ClusterName -NoStorage -Node $LocalMachineName -Verbose
		    $CurrentCluster = $null
		    $CurrentCluster = Get-Cluster

		    if ($CurrentCluster -eq $null) {
				w> "$(Get-Date) Cluster Name: $ClusterName could not be created"
		        throw "Cluster does not exist"
		        exit 1
		    }

		    Sleep -Seconds 5
		    Stop-ClusterResource "Cluster Name" -Verbose
			w> "$(Get-Date) Stopping Cluster resource for Cluster Name: $ClusterName"
		    $AllClusterGroupIPs = Get-Cluster | Get-ClusterGroup | Get-ClusterResource | Where-Object {$_.ResourceType.Name -eq "IP Address" -or $_.ResourceType.Name -eq "IPv6 Tunnel Address" -or $_.ResourceType.Name -eq "IPv6 Address"}
		    $NumberOfIPs = @($AllClusterGroupIPs).Count

		    Sleep -Seconds 5
		    $AllClusterGroupIPs | Stop-ClusterResource
		    $AllIPv4Resources = Get-Cluster | Get-ClusterGroup | Get-ClusterResource | Where-Object {$_.ResourceType.Name -eq "IP Address"}
		    $FirstIPv4Resource = @($AllIPv4Resources)[0]
		  
		    Sleep -Seconds 5
		    $AllClusterGroupIPs | Where-Object {$_.Name -ne $FirstIPv4Resource.Name} | Remove-ClusterResource -Force
		    $NameOfIPv4Resource = $FirstIPv4Resource.Name

		    Sleep -Seconds 5
			w> "$(Get-Date) Setting Cluster IP"
		    Get-ClusterResource $NameOfIPv4Resource | Set-ClusterParameter -Multiple @{"Address" = "169.254.1.1"; "SubnetMask" = "255.255.0.0"; "Network" = "Cluster Network 1"; "OverrideAddressMatch" = 1; "EnableDHCP" = 0}
		    $ClusterNameResource = Get-ClusterResource "Cluster Name"
		    $ClusterNameResource | Start-ClusterResource -Wait 60

		    if ((Get-ClusterResource "Cluster Name").State -ne "Online") {
				w> "$(Get-Date) There was an error onlining the cluster name resource"
		        throw "There was an error onlining the cluster name resource"
		        exit 1
		    }
		    Sleep -Seconds 60
			w> "$(Get-Date) Going to add other nodes into the cluster"
		    @($ClusterNodes) | Foreach-Object { 
		        if ([string]::Compare(($_).Split(".")[0], $LocalMachineName, $true) -ne 0) { 
		            #Add-ClusterNode "$_" -NoStorage
					while($true)
						{
							w> "$(Get-Date) Going to add the node: $_"
					        Add-ClusterNode "$_" -NoStorage
							if((get-clusternode -Name $_.Tostring() -ErrorAction SilentlyContinue) -ne $null )
							{
								w> "$(Get-Date) Node:$_ has been successfully added to the cluster"
								break;
							}
							else 
							{
								w> "$(Get-Date) The Node $_ is not added to the Cluster , Sleeping for 1 minute"
			                    sleep -Seconds 60  
							}
		                }
		                       
		        } 
			}
			#Convert storage Account name to lower case
			#Set-ClusterQuorum –CloudWitness -AccountName $saName -AccessKey $accessKey
			$witnesspath=Join-Path $FSWPath $ClusterName
			md "$witnesspath"
			Set-ClusterQuorum -NodeAndFileShareMajority "$witnesspath"

		} -Credential $cred1 -ComputerName localhost -Authentication credssp -ArgumentList ($logfile)
    }
    catch [System.Exception] {
        $ErrorMessage = $_
        $ShouldContinue = $false
        $Errors += "[E] : Could not Create Cluster:  $_.Exception.Message "
        o> "$(Get-Date) Error while Creating Cluster"
    }
}
#endregion

#region Extract the Cluster name and Nodes
if ($Shouldcontinue) {
    try {
        $ClusterName = (Get-Cluster).Name
        $ClusterNodes = @()
        if (($VMName.Length -gt 0) -and ($InstanceCount -gt 0)) {
            for ($icount = 1; $icount -le $InstanceCount; $icount++) {
                $ClusterNodes = $ClusterNodes + "$VMName$icount.$serverdomain"
            }
        }	
    }
    catch [System.Exception] {
        $ErrorMessage = $_
        $ShouldContinue = $false
        $Errors += "[E] : Error while extracting Custer Name and Nodes:  $_.Exception.Message "
        o> "$(Get-Date) Error while extracting Custer Name and Nodes"
    }
	
    o> "$(Get-Date) Cluster Name:  $ClusterName"
    o> "$(Get-Date) Cluster Nodes are $ClusterNodes "
}
#endregion

#region Prereq in all nodes
if ($Shouldcontinue) {
    foreach ($ClusterNode in $ClusterNodes) {
        o> "$(Get-Date) Running prereq in node: $ClusterNode"
        try {
            Invoke-Command -ScriptBlock {
				$ServerInstance = "."
                $sqlConnection = New-Object System.Data.SqlClient.SqlConnection
            	$sqlConnection.ConnectionString = "Server=$ServerInstance;Database=master;Trusted_Connection=True;"
				$Command = New-Object System.Data.SqlClient.SqlCommand
				$Command.CommandType = 1
				$Command.Connection = $sqlConnection
				$Command.CommandText = "create login [NT AUTHORITY\SYSTEM] from windows with default_database=[master], default_language=[us_english]"
				$sqlConnection.Open()
				$Command.ExecuteNonQuery()
				$Command.CommandText = "exec master..sp_addsrvrolemember @loginame = N'NT AUTHORITY\SYSTEM', @rolename = N'sysadmin'"
				$Command.ExecuteNonQuery()
                Import-Module sqlps -Force -DisableNameChecking
                Disable-SqlAlwaysOn -Path SQLSERVER:\sql\localhost\default -Force -Confirm:$false
                Enable-SqlAlwaysOn -Path SQLSERVER:\sql\localhost\default -Force -Confirm:$false
                #Subrat Commented as it is failing
                #Set-NetFirewallProfile -Profile Domain,Private -DefaultInboundAction Allow
            } -Credential $cred1 -ComputerName $ClusterNode
        }
        catch [System.Exception] {
            $ErrorMessage = $_
            $ShouldContinue = $false
            $Errors += "[E] : Error while applying Prereq in $ClusterNode :  $_.Exception.Message "
            o> "$(Get-Date) Error while applying Prereq in $ClusterNode"
        }
    }
}
#endregion
	
#region Extract the Instance name
if ($Shouldcontinue) {
    o> "$(Get-Date) Extracting the Instance Name"
    try {
        $InstanceName = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -Name InstalledInstances `
            | Select-Object -ExpandProperty InstalledInstances | Where-Object { $_ -eq 'MSSQLSERVER' }
        $InstanceFullName = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -Name $InstanceName `
            | Select-Object -ExpandProperty $InstanceName
        $SqlDir = $InstanceFullName
    }
    catch [System.Exception] {
        $ErrorMessage = $_
        $ShouldContinue = $false
        $Errors += "[E] : Error while Extracting the Instance Name:  $_.Exception.Message "
        o> "$(Get-Date) Error while Extracting the Instance Name"
    }
    o> "$(Get-Date) Instance Name is $InstanceFullName"
}
#endregion
	
#region Create AOSeed db
if ($Shouldcontinue) {
    o> "$(Get-Date) Going to create AOSeed DB in Primary node"
    $dbname = $AOAGSeedDbName
    Import-Module sqlps -Force -DisableNameChecking
    [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | Out-Null
    $s = New-Object ('Microsoft.SqlServer.Management.Smo.Server') $serverName
    # Create the filegroup for the system tables
    $db = New-Object ('Microsoft.SqlServer.Management.Smo.Database') ($s, $dbname)
    $sysfg = New-Object ('Microsoft.SqlServer.Management.Smo.FileGroup') ($db, 'PRIMARY')
    $db.FileGroups.Add($sysfg)
    # Create the file for the system tables
    $syslogname = $dbname
    $dbdsysfile = New-Object ('Microsoft.SqlServer.Management.Smo.DataFile') ($sysfg, $syslogname)
    $sysfg.Files.Add($dbdsysfile)
    $dbdsysfile.FileName = "H:\$($SqlDir)\MSSQL\DATA\" + $syslogname + '.mdf'
    # Create the file for the log
    $loglogname = $dbname + '_Log'
    $dblfile = New-Object ('Microsoft.SqlServer.Management.Smo.LogFile') ($db, $loglogname)
    $db.LogFiles.Add($dblfile)
    $dblfile.FileName = "O:\$($SqlDir)\MSSQL\DATA\" + $loglogname + '.ldf'
    # Create the database
    $DbDataFile = "H:\$($SqlDir)\MSSQL\DATA\" + $syslogname + '.mdf'
    if (Test-Path $DbDataFile) {
        o> "$(Get-Date) Create failed: $DbDataFile already exists"
    }
    else {
        o> "$(Get-Date) Creating $AOAGSeedDbName database"
        try {
            $ErrorActionPreference = "Stop"
            $db.Create()
            o> "$(Get-Date) AOSeed DB Creation Done"
        }
        catch [System.Exception] {
            $ErrorMessage = $_
            $ShouldContinue = $false
            $Errors += "[E] : AOSeed DB Create failed:  $_.Exception.Message "
            o> "$(Get-Date) AOSeed DB Create failed: $_.Exception.Message "
        }
        #Set the database to full recovery mode
        if ($Shouldcontinue) {
            o> "$(Get-Date) Setting $AOAGSeedDbName DB recovery mode to full"
            try {
                $s.Databases | Where-Object { $_.Name -ieq $dbname } | ForEach-Object { $_.RecoveryModel = [Microsoft.SqlServer.Management.Smo.RecoveryModel]::Full; $_.Alter() }
                o> "$(Get-Date) Recovery mode set to Full Done"
            }
            catch [System.Exception] {
                $ErrorMessage = $_
                $ShouldContinue = $false
                $Errors += "[E] : Change recoverymode failed:  $_.Exception.Message "
                o> "$(Get-Date) Change recoverymode failed: $_.Exception.Message "
            }
        }
		
        #Backup the New DB
        if ($Shouldcontinue) {
            o> "$(Get-Date) Backing up $AOAGSeedDbName DB"
            try {
                Remove-Item "D:\$($SqlDir)\MSSQL\$AOAGSeedDbName.bak" -Force -ErrorAction SilentlyContinue
                Remove-Item "D:\$($SqlDir)\MSSQL\$AOAGSeedDbName.log" -Force -ErrorAction SilentlyContinue
                Set-Location SQLSERVER:\sql\localhost\default
                Backup-SqlDatabase -Database $AOAGSeedDbName -BackupFile "D:\$($SqlDir)\MSSQL\$AOAGSeedDbName.bak"
                Backup-SqlDatabase -Database $AOAGSeedDbName -BackupFile "D:\$($SqlDir)\MSSQL\$AOAGSeedDbName.log" -BackupAction Log
                o> "$(Get-Date) Backup Done"
            }
            catch [System.Exception] {
                $ErrorMessage = $_
                $ShouldContinue = $false
                $Errors += "[E] : $AOAGSeedDbName DB backup failed:  $_.Exception.Message "
                o> "$(Get-Date) $AOAGSeedDbName DB backup failed: $_.Exception.Message "
            }
        }
    }
}
#endregion
	
#region Restore AOSeed db in all instance	
if ($Shouldcontinue) {
    o> "$(Get-Date) Restore $AOAGSeedDbName DB in all nondes"
    try {
        @($ClusterNodes) | Foreach-Object { 
            if ([string]::Compare(($_).Split(".")[0], $currentserver, $true) -ne 0) { 
                o> "$(Get-Date) Restore $AOAGSeedDbName DB in node: $($_)"
                #copy-item \\$currentserver\E$\$($InstanceFullName)\MSSQL\Bak\$($AOAGSeedDbName)*.* \\$_\E$\$($InstanceFullName)\MSSQL\Bak\. -Force
                #copy-item E:\$($InstanceFullName)\MSSQL\Bak\$($AOAGSeedDbName).* \\$_\E$\$($InstanceFullName)\MSSQL\Bak -Force
                #copy-item "Microsoft.PowerShell.Core\FileSystem::\\$currentserver\E$\$($InstanceFullName)\MSSQL\Bak\$($AOAGSeedDbName).*" "Microsoft.PowerShell.Core\FileSystem::\\$_\E$\$($InstanceFullName)\MSSQL\Bak" -Force
                Invoke-Command -ScriptBlock {
                    param($currentserverfqdn)
                    $AOAGSeedDbName = "AOSeed"
                    # get the version in our folder path         
                    $InstanceName = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -Name InstalledInstances `
                        | Select-Object -ExpandProperty InstalledInstances | ? {$_ -eq 'MSSQLSERVER'}
                    $InstanceFullName = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -Name $InstanceName `
                        | Select-Object -ExpandProperty $InstanceName
                    import-module sqlps -force -DisableNameChecking
                    cd SQLSERVER:\sql\localhost\default
                    Restore-SqlDatabase -Database $AOAGSeedDbName -BackupFile "\\$currentserverfqdn\D$\$($InstanceFullName)\MSSQL\$($AOAGSeedDbName).bak" -NoRecovery
                    Restore-SqlDatabase -Database $AOAGSeedDbName -BackupFile "\\$currentserverfqdn\D$\$($InstanceFullName)\MSSQL\$($AOAGSeedDbName).log" -NoRecovery -RestoreAction Log
                } -Credential $cred1 -ComputerName $_ -ArgumentList ($currentserverfqdn)
            } 
        }
    }
    catch [System.Exception] {
        $ErrorMessage = $_
        $ShouldContinue = $false
        $Errors += "[E] : $AOAGSeedDbName DB restore failed in one of the node:  $_.Exception.Message "
        o> "$(Get-Date) $AOAGSeedDbName DB restore failed in one of the node: $_.Exception.Message "
    }
}
#endregion
	
#region CreateSqlHadrEndpoints
if ($Shouldcontinue) {
    o> "$(Get-Date) CreateSqlHadrEndpoints in all nondes"
    try {
        @($ClusterNodes) | Foreach-Object { 
            Invoke-Command -ScriptBlock {
                $endpoint = New-SqlHadrEndpoint SqlHadrEndpoint -Port 5022 -Path SQLSERVER:\sql\localhost\default
                Set-SqlHadrEndpoint -InputObject $endpoint -State "Started"   
            } -Credential $cred1 -ComputerName $_
        }
    }
    catch [System.Exception] {
        $ErrorMessage = $_
        $ShouldContinue = $false
        $Errors += "[E] : CreateSqlHadrEndpoints failed in one of the nonde:  $_.Exception.Message "
        o> "$(Get-Date) CreateSqlHadrEndpoints failed in one of the nonde: $_.Exception.Message "
    }
}
#endregion
	
#region Set Ownership of HA
if ($Shouldcontinue) {
    o> "$(Get-Date) Set Ownership of HA in all nondes"
    try {
        @($ClusterNodes) | Foreach-Object { 
            Invoke-Command -ScriptBlock {
                $AOAGSeedDbName = "AOSeed"
                $ServerInstance = "."
                $sqlConnection = New-Object System.Data.SqlClient.SqlConnection
                $sqlConnection.ConnectionString = "Server=$ServerInstance;Database=master;Trusted_Connection=True;"
                $Command = New-Object System.Data.SqlClient.SqlCommand
                $Command.CommandType = 1
                $Command.Connection = $sqlConnection
                $Command.CommandText = "ALTER SERVER ROLE [sysadmin] ADD MEMBER [NT AUTHORITY\SYSTEM]"
                $sqlConnection.Open()
                $Command.ExecuteNonQuery()
                $Command.CommandText = "ALTER AUTHORIZATION ON ENDPOINT::[SqlHadrEndpoint] TO sa"
                $Command.ExecuteNonQuery()                            
                $sqlConnection.Close() 
            } -Credential $cred1 -ComputerName $_
        }
    }
    catch [System.Exception] {
        $ErrorMessage = $_
        $ShouldContinue = $false
        $Errors += "[E] : Set Ownership of HA failed in one of the nonde:  $_.Exception.Message "
        o> "$(Get-Date) Set Ownership of HA failed in one of the nonde: $_.Exception.Message "
    }
}
#endregion
	
#region Create AOAG	
if ($Shouldcontinue) {
    o> "$(Get-Date) Creating Availability Group $AOAGName on $PrimaryReplica "
    try {  
        import-module sqlps -force -DisableNameChecking
        cd SQLSERVER:\sql\localhost
        $ServerObject = (Get-Item SQLSERVER:\sql\localhost\default)
        $ServerVersion = $ServerObject.Version
        $PrimaryReplica = New-SqlAvailabilityReplica `
            -Name $ClusterNodes[0].Split(".")[0]`
            -EndpointURL $("TCP://$($ClusterNodes[0].Split(".")[0]):5022") `
            -AvailabilityMode "SynchronousCommit" `
            -FailoverMode "Automatic" `
            -Version $ServerVersion `
            -AsTemplate	
        $SecondaryReplica = New-SqlAvailabilityReplica `
            -Name $ClusterNodes[1].Split(".")[0] `
            -EndpointURL $("TCP://$($ClusterNodes[1].Split(".")[0]):5022") `
            -AvailabilityMode "SynchronousCommit" `
            -FailoverMode "Automatic" `
            -Version $ServerVersion `
            -AsTemplate
        New-SqlAvailabilityGroup `
            -Name $AOAGName `
            -AvailabilityReplica @($PrimaryReplica, $SecondaryReplica) `
            -Path "SQLSERVER:\sql\localhost\default" `
            -Database $AOAGSeedDbName
        o> "$(Get-Date) Completed creating AOAG"
    }
    catch [System.Exception] {
        $ErrorMessage = $_
        $ShouldContinue = $false
        $Errors += "[E] : AOAG creation Failed:  $_.Exception.Message "
        o> "$(Get-Date) AOAG creation Failed: $_.Exception.Message "
    }
}
#endregion
	
#region Join secondary replicas
if ($Shouldcontinue) {
    o> "$(Get-Date) Join all secondary replicas to the Availability Group $AOAGName "
    try {
        @($ClusterNodes) | Foreach-Object { 
            if ([string]::Compare(($_).Split(".")[0], $currentserver, $true) -ne 0) { 
                o> "$(Get-Date) Join Server $_ to the Availability Group $AOAGName "
                Invoke-Command -ScriptBlock {
                    param($VMName)
                    $AOAGSeedDbName = "AOSeed"
                    $ErrorActionPreference = "Stop"
                    $AOAGName = $VMName
                    try {
                        import-module sqlps -force -DisableNameChecking
                        Join-SqlAvailabilityGroup -Path "SQLSERVER:\SQL\localhost\default" -Name $AOAGName
                        Add-SqlAvailabilityDatabase -Path "SQLSERVER:\SQL\localhost\default\AvailabilityGroups\$AOAGName" -Database $AOAGSeedDbName
                    }
                    catch {
                        return "Failed to join secondary replica. '$($_.Exception.Message)'"
                    }
                } -Credential $cred1 -ComputerName $_ -ArgumentList ($VMName)
            } 
        }
    }
    catch [System.Exception] {
        $ErrorMessage = $_
        $ShouldContinue = $false
        $Errors += "[E] : Secondary Replica join failed for one of the node:  $_.Exception.Message "
        o> "$(Get-Date) Secondary Replica join failed for one of the node: $_.Exception.Message "
    }
}
#endregion
	
#region EnableExtendedEventingForAO	
if ($Shouldcontinue) {
    o> "$(Get-Date) EnableExtendedEventingForAO "
    try {
        @($ClusterNodes) | Foreach-Object { 
            o> "$(Get-Date) Configuring AlwaysOn_health extended events to auto start on $($_)"
            Invoke-Command -ScriptBlock {
                $ServerInstance = "."
                $sqlConnection = New-Object System.Data.SqlClient.SqlConnection
                $sqlConnection.ConnectionString = "Server=$ServerInstance;Database=master;Trusted_Connection=True;"
                $Command = New-Object System.Data.SqlClient.SqlCommand
                $Command.CommandType = 1
                $Command.Connection = $sqlConnection
                $Command.CommandText = "ALTER EVENT SESSION [AlwaysOn_health] ON SERVER WITH (STARTUP_STATE=ON)"
                $sqlConnection.Open()
                $Command.ExecuteNonQuery()
                #net stop MSSQLSERVER /y
                #net start MSSQLSERVER /y
                #start-sleep 120		 
            } -Credential $cred1 -ComputerName $_
        }
    }
    catch [System.Exception] {
        $ErrorMessage = $_
        $ShouldContinue = $false
        $Errors += "[E] : EnableExtendedEventingForAO Failed:  $_.Exception.Message "
        o> "$(Get-Date) EnableExtendedEventingForAO Failed: $_.Exception.Message "
    }
}
#endregion
	
#region Listener Creation
if ($Shouldcontinue) {
    o> "$(Get-Date) Creating AOAG listener $AOAGListenerName "
    try {
        $ILBSubnetMask = $null
        $NetworkName = "Cluster Network 1"
        $listnerPort = 1433
        $Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -EA SilentlyContinue | ? {$_.IPEnabled}
        foreach ($Network in $Networks) {            
            foreach ($subnet in $Network.IPSubnet) {
                if ($subnet -match '255.255.255') {
                    $ILBSubnetMask = $subnet
                }
            }
        }
        o> "$(Get-Date) ILB Static IP is $ILBStaticIP"	
        o> "$(Get-Date) Subnet Mask is $ILBSubnetMask"	
        Add-ClusterResource "IP Address" -ResourceType "IP Address" -Group $AOAGName | `
            Set-ClusterParameter -Multiple @{"Address" = "$ILBStaticIP"; "SubnetMask" = "$ILBSubnetMask"; "Network" = "$networkName"; "OverrideAddressMatch" = 1; "EnableNetBIOS" = 1; "ProbePort" = 50001}
        Add-ClusterResource -Name $AOAGListenerName -ResourceType "Network Name" -Group $AOAGName | `
            Set-ClusterParameter -Multiple @{"Name" = $AOAGListenerName; "DnsName" = $AOAGListenerName}  
        Get-ClusterResource -Name $AOAGListenerName | Set-ClusterResourceDependency "[IP Address]"
        Start-ClusterResource -Name $AOAGListenerName
        Get-ClusterResource -Name $AOAGName | Set-ClusterResourceDependency "[$AOAGListenerName]"
        Start-ClusterResource -Name $AOAGListenerName
        Set-SqlAvailabilityGroupListener -Path SQLSERVER:\SQL\$($env:COMPUTERNAME)\DEFAULT\AvailabilityGroups\$AOAGName\AvailabilityGroupListeners\$AOAGListenerName -Port $listnerPort
    }
    catch [System.Exception] {
        $ErrorMessage = $_
        $ShouldContinue = $false
        $Errors += "[E] : Listener Creation Failed:  $_.Exception.Message "
        o> "$(Get-Date) Listener Creation Failed: $_.Exception.Message "
    }
}
#endregion
	
#region FinalConfiguration
if ($Shouldcontinue) {
    o> "$(Get-Date) Starting Final configuration on all nodes "
    try {
        @($ClusterNodes) | Foreach-Object {
            Invoke-Command -ScriptBlock {
                param($AOAGName)
                # HostRecordTTL = 300
				#Subrat commented
                #Get-ClusterResource -Name $AOAGName | Set-ClusterParameter -Name HostRecordTTL -Value 300
                # RegisterAllProvidersIP - 0
				#Subrat commented
                #Get-ClusterResource -Name $AOAGName | Set-ClusterParameter RegisterAllProvidersIP 0
                # Maxfailovers in Time Period = 20
                cluster group $AOAGName /prop FailoverThreshold=20
                # Failback Settings - Prevent Failback
                cluster group $AOAGName /prop AutoFailbackType=0			
            } -Credential $cred1 -ComputerName $_ -ArgumentList ($AOAGName)
        }
        @($ClusterNodes) | Foreach-Object {
            Set-SqlAvailabilityReplica –SessionTimeout 20 -Path SQLSERVER:\sql\localhost\default\AvailabilityGroups\$AOAGName\AvailabilityReplicas\$(($_).Split(".")[0])
            Set-SqlAvailabilityReplica -ConnectionModeInSecondaryRole "AllowAllConnections" -Path SQLSERVER:\sql\localhost\default\AvailabilityGroups\$AOAGName\AvailabilityReplicas\$(($_).Split(".")[0])
        }
		#Does not want to fail if the Final Configuration has any issue, can be setup latter by user
    }
    catch [System.Exception] {
        $ErrorMessage = $_
        #$ShouldContinue = $false
		$ShouldContinue = $true
        $Errors += "[E] : FinalConfiguration Failed:  $_.Exception.Message "
        o> "$(Get-Date) FinalConfiguration Failed: $_.Exception.Message , Still continuing "
    }
}
#endregion

#region Disable CredSSP
if ($Shouldcontinue) {
    try {
		o> "$(Get-Date) Disable CredSSP at Primary node"
		Disable-WSManCredSSP -Role client
    }
    catch [System.Exception] {
        $ErrorMessage = $_
        $ShouldContinue = $false
        $Errors += "[E] : Disble Credssp Failed:  $_.Exception.Message "
        o> "$(Get-Date) Disble Credssp Failed"
    }
}
#endregion

#region Throw Error
if ($ShouldContinue -eq $false) {
    throw "AOAG setup Failed with error: $Errors "
}
o> "$(Get-Date) ######################Setup AOAG Completed#######################"
#endregion