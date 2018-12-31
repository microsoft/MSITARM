param(
    [Parameter(Mandatory = $true)]
    $ClusterName,
    [Parameter(Mandatory = $true)]
    $VMName,
    [Parameter(Mandatory = $true)]
    $InstanceCount,
    [Parameter(Mandatory = $true)]
    $ClusterSetupAccount,
    [Parameter(Mandatory = $true)]
    $ClusterSetupPassword,
    [Parameter(Mandatory = $true)]
    $FSWPath)
	
#Start-Transcript C:\deploylogs\delpoy.log

# Sleep Time for the other nodes to be discovered in DNS(reduced from 1200 to 100)
start-sleep -Seconds 100

#CredSSP Enablement
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

$secpasswd = ConvertTo-SecureString $ClusterSetupPassword -AsPlainText -Force
[System.Management.Automation.PSCredential ]$cred1 = New-Object System.Management.Automation.PSCredential ($ClusterSetupAccount, $secpasswd)
             
Invoke-Command -ScriptBlock {
$logDir="D:\Logs"
if((Test-Path -Path $logDir) -eq $false)
    {
        New-Item -Path $logDir -ItemType directory
    }
    $logfile ="$logDir\ConfigureCluster$($(get-date).toString(‘yyyyMMddhhmm’)).log"
    Add-content $Logfile -value "$(Get-Date) ##############################start#################################"
		Function O> 
        {
            Param ([string]$logstring)
            $logstring

            if($(test-path $logFile)) 
            {
                Add-content $Logfile -value $logstring
            } 
            else 
            {
                write-host $logstring
            }
        }
    $ClusterName = $using:ClusterName
    $VMName = $using:VMName
    $InstanceCount = $using:InstanceCount
	$FSWPath=$using:FSWPath
o> "$(Get-Date) #####################################################################"
o> "$(Get-Date) Input::Cluster Name:  $ClusterName"
o> "$(Get-Date) Input::Instance Count:  $InstanceCount"
o> "$(Get-Date) Input::VMName:  $VMName"
o> "$(Get-Date) Input::FSWPath:  $FSWPath"
    import-module FailoverClusters
    $ClusterNodes = @()
    if (($VMName.Length -gt 0) -and ($InstanceCount -gt 0)) {
        for ($icount = 1; $icount -le $InstanceCount; $icount++) {
            $ClusterNodes = $ClusterNodes + "$VMName$icount"
        }
    }
o> "$(Get-Date) Cluster Nodes are $ClusterNodes "
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
o> "$(Get-Date) Cluster Name: $ClusterName will be created on primary node"
    $result = New-Cluster -Name $ClusterName -NoStorage -Node $LocalMachineName -Verbose
    $CurrentCluster = $null
    $CurrentCluster = Get-Cluster

    if ($CurrentCluster -eq $null) {
o> "$(Get-Date) Cluster Name: $ClusterName could not be created"
        throw "Cluster does not exist"
        exit 1
    }

    Sleep -Seconds 5
o> "$(Get-Date) Stopping Cluster resource for Cluster Name: $ClusterName"
    Stop-ClusterResource "Cluster Name" -Verbose
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
o> "$(Get-Date) Setting Cluster IP"
    Get-ClusterResource $NameOfIPv4Resource | Set-ClusterParameter -Multiple @{"Address" = "169.254.1.1"; "SubnetMask" = "255.255.0.0"; "Network" = "Cluster Network 1"; "OverrideAddressMatch" = 1; "EnableDHCP" = 0}
    $ClusterNameResource = Get-ClusterResource "Cluster Name"
    $ClusterNameResource | Start-ClusterResource -Wait 60

    if ((Get-ClusterResource "Cluster Name").State -ne "Online") {
o> "$(Get-Date) There was an error onlining the cluster name resource"
        throw "There was an error onlining the cluster name resource"
        exit 1
    }
    Sleep -Seconds 60
o> "$(Get-Date) Going to add other nodes into the cluster"
    @($ClusterNodes) | Foreach-Object { 
        if ([string]::Compare(($_).Split(".")[0], $LocalMachineName, $true) -ne 0) { 
            #Add-ClusterNode "$_" -NoStorage
			$connectionretrycount =3
			for ($i = 1; $i -le $connectionretrycount; $i++) 
				{
	                if(Test-Connection $_ -ErrorAction SilentlyContinue)
					{
					o> "$(Get-Date) Able to ping the node: $_"
					o> "$(Get-Date) Going to add the node: $_"
			           	Add-ClusterNode "$_" -NoStorage
						Sleep -Seconds 60
						if((get-clusternode -Name $_.Tostring() -ErrorAction SilentlyContinue) -ne $null )
						{
							o> "$(Get-Date) Node:$_ has been successfully added to the cluster"
							break;
						}
					}
					else 
					{
					o> "$(Get-Date) Not able to ping the node: $_ , Sleeping for 10 minutes"
	                    sleep -Seconds 600
	                    
					}
                }
                       
        } }
	$witnesspath=Join-Path $FSWPath $ClusterName
	md "$witnesspath"
	Set-ClusterQuorum -NodeAndFileShareMajority "$witnesspath"

} -Credential $cred1 -ComputerName localhost -Authentication credssp



Disable-WSManCredSSP -Role client
#Stop-Transcript