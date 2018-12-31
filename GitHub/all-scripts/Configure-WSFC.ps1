param(
   [Parameter(Mandatory=$true)]
   $ClusterName,
   [Parameter(Mandatory=$true)]
   $VMName,
   [Parameter(Mandatory=$true)]
   $InstanceCount)

##################################################################### 
#"Initialize Log"
##################################################################### 
    #$logDir=[System.IO.Path]::GetTempPath()
    $logDir="D:\Logs"
    if((Test-Path -Path $logDir) -eq $false)
    {
        New-Item -Path $logDir -ItemType directory
    }
    $logfile ="$logDir\CreateCluster-WSFC$($(get-date).toString(‘yyyyMMddhhmm’)).log"
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
##################################################################### 

o> "$(Get-Date) #####################################################################"
o> "$(Get-Date) Input::Cluster Name:  $ClusterName"
o> "$(Get-Date) Input::Instance Count:  $InstanceCount"
o> "$(Get-Date) Input::VMName:  $VMName"

#Updating the VMname that user has provided in template
$VMName=$VMName.Substring(0,$VMName.Length-1)
o> "$(Get-Date) User provided Data for VMName in template::  '$VMName'"

#get current execution directory
$scriptPath=$MyInvocation.MyCommand.Path
$currentDirectory = $scriptPath.Substring(0, $scriptPath.LastIndexOf("\"))
$statusFilePath = "$currentDirectory\SchedulerExecutionStatus.txt"
o> "$(Get-Date) SchedulerExecutionStatusFilePath->$statusFilePath"


try
{
    #update the status in the scheduler status file
    Add-Content $statusFilePath -Value "started"
    $Force = $true
    $ClusterNodes = @()
    if(($VMName.Length -gt 0) -and ($InstanceCount -gt 0))
    {
        #create the cluster node names using vm name and instance count
        for($icount=1; $icount -le $InstanceCount; $icount++)
        {
            $ClusterNodes=$ClusterNodes +"$VMName$icount"
        }
    }
    o> "$(Get-Date) ClusterNodes:  '$ClusterNodes'"

    Import-Module ServerManager

    $OsBuildNumber = [System.Environment]::OSVersion.Version.Build

    if ($OsBuildNumber -lt 7600)
    {
      throw "Not support on Windows Visa or lower"
      exit 1
    }
    elseif ($OsBuildNumber -lt 9200)
    {
      Write-Output "Windows Server 2008 R2 detected" 
      o> "$(Get-Date) Windows Server 2008 R2 detected"
      
      $ClusterFeature = Get-WindowsFeature "Failover-Clustering"
      if ($ClusterFeature.Installed -eq $false)
      {
        throw "Needed cluster features were not found on the machine. Please run the following command to install them:Add-WindowsFeature 'Failover-Clustering'"
        exit 1
      }
  
    }
    Import-Module FailoverClusters

    $LocalMachineName = $env:computername
    $LocalNodePresent = $false

    # The below line will make sure that the script is running on one of the specified cluster nodes
    # The Spplit(".") is needed, because user might specify machines using their fully qualified domain name, but we only care about the machine name in the below verification
    @($ClusterNodes) | Foreach-Object { 
                           if ([string]::Compare(($_).Split(".")[0], $LocalMachineName, $true) -eq 0) { 
                                 $LocalNodePresent = $true } }


    if ($LocalNodePresent -eq $false)
    {
      throw "Local machine where this script is running, must be one of the cluster nodes"
      exit 1
    }

    if ($Force)
    {
      Write-Output "Forcing cleanup of the specified nodes"
      o> "$(Get-Date) Forcing cleanup of the specified nodes"

      @($ClusterNodes) | Foreach-Object { Clear-ClusterNode "$_" -Force } 

    }
    else
    {

      Write-Output "Making sure that there is no cluster currently running on the current node"
      o> "$(Get-Date) Making sure that there is no cluster currently running on the current node"

      $CurrentCluster = $null
      # In case there is no cluster presetn, we don't want to show an ugly error message, so we eat it out by redirecting
      # the error output to null
      $CurrentCluster = Get-Cluster 2> $null


      if ($CurrentCluster -ne $null)
      {
        throw "There is an existing cluster on this machine. Please remove any existing cluster settings from the current machine before running this script"
        exit 1
      }

    }

    ##################################################################### 
    # make the WSFC name unique
    ##################################################################### 

    $VLength = 5

    $Random = 1..$VLength | ForEach-Object {Get-Random -Maximum 9}
    
    $ClusterName = $ClusterName + [string]::join('',$Random)

    Write-Output "Trying to create a one node cluster on the current machine - '$ClusterName'"
    o> "$(Get-Date) Trying to create a one node cluster on the current machine - '$ClusterName'"

    Sleep 5

    
    $result = New-Cluster -Name $ClusterName -NoStorage -Node $LocalMachineName -Verbose
    
    Write-Output "New-Cluster execution result->$result"
    o> "$(Get-Date) New-Cluster execution result->$result"

    Write-Output "Verify that cluster is present after creation"
    o> "$(Get-Date) Verify that cluster is present after creation"

    $CurrentCluster = $null
    $CurrentCluster = Get-Cluster

    if ($CurrentCluster -eq $null)
    {
      throw "Cluster does not exist"
      exit 1
    }



    Write-Output "Bring offline the cluster name resource"
    o> "$(Get-Date) Bring offline the cluster name resource"
    
    Sleep 5
    Stop-ClusterResource "Cluster Name" -Verbose

    Write-Output "Get all IP addresses associated with cluster group"
    o> "$(Get-Date) Get all IP addresses associated with cluster group"
    
    $AllClusterGroupIPs = Get-Cluster | Get-ClusterGroup | Get-ClusterResource | Where-Object {$_.ResourceType.Name -eq "IP Address" -or $_.ResourceType.Name -eq "IPv6 Tunnel Address" -or $_.ResourceType.Name -eq "IPv6 Address"}

    $NumberOfIPs = @($AllClusterGroupIPs).Count
    Write-Output "Found $NumberOfIPs IP addresses"
    o> "$(Get-Date) Found $NumberOfIPs IP addresses"
    
    Write-Output "Bringing all IPs offline"
    o> "$(Get-Date) Bringing all IPs offline"
    
    Sleep 5
    $AllClusterGroupIPs | Stop-ClusterResource

    Write-Output "Get the first IPv4 resource"
    o> "$(Get-Date) Get the first IPv4 resource"

    $AllIPv4Resources = Get-Cluster | Get-ClusterGroup | Get-ClusterResource | Where-Object {$_.ResourceType.Name -eq "IP Address"}
    $FirstIPv4Resource = @($AllIPv4Resources)[0];

    Write-Output "Removing all IPs except one IPv4 resource"
    o> "$(Get-Date) Removing all IPs except one IPv4 resource"
    
    Sleep 5
    $AllClusterGroupIPs | Where-Object {$_.Name -ne $FirstIPv4Resource.Name} | Remove-ClusterResource -Force

    $NameOfIPv4Resource = $FirstIPv4Resource.Name

    Write-Output "Setting the cluster IP address to a link local address"
    o> "$(Get-Date) Setting the cluster IP address to a link local address"
    
    Sleep 5
    Get-ClusterResource $NameOfIPv4Resource | Set-ClusterParameter -Multiple @{"Address"="169.254.1.1";"SubnetMask"="255.255.0.0";"Network"="Cluster Network 1";"OverrideAddressMatch"=1;"EnableDHCP"=0}

    $ClusterNameResource = Get-ClusterResource "Cluster Name"

    $ClusterNameResource | Start-ClusterResource -Wait 60

    if ((Get-ClusterResource "Cluster Name").State -ne "Online")
    {
      throw "There was an error onlining the cluster name resource"
      exit 1
    }


    Write-Output "Adding other nodes to the cluster" 
    o> "$(Get-Date) Adding other nodes to the cluster" 

    @($ClusterNodes) | Foreach-Object { 
                           if ([string]::Compare(($_).Split(".")[0],$LocalMachineName, $true) -ne 0) { 
                                 Add-ClusterNode "$_" } }

    Write-Output "Cluster creation finished !"
    o> "$(Get-Date) Cluster creation finished !"

    #update the status in the scheduler status file
    Add-Content $statusFilePath -Value "success"
    
    sleep -Seconds 5
    o> "$(Get-Date) Last statement of the try block Executed after sleep 5.."
}
catch
{
    #update the status in the scheduler status file
    Add-Content $statusFilePath -Value "failed"
    $ErrorMessage = $_.Exception.Message
    o> "$(Get-Date) Exception occured. Exp->$ErrorMessage"
    sleep -Seconds 5
}
finally
{
    try
    {
        $unRegPSPath="$currentDirectory\UnRegisterTask.ps1"
        #un register the task
        Start-Process -FilePath $unRegPSPath
        Unregister-ScheduledTask CreateWSFC  -Confirm:$false
        o> "$(Get-Date) Started the process unRegisterTask.ps1."
    }
    catch
    {
        #ignore the exceptions
        $ErrorMessage = $_.Exception.Message
        o> "$(Get-Date) Exception occured in invoking the unRegisterTask.ps1.  Exp->$ErrorMessage"
    }
}