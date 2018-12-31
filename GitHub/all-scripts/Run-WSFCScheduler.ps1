param(
   [Parameter(Mandatory=$true)]
   $ClusterName,
   [Parameter(Mandatory=$true)]
   $VMName,
   [Parameter(Mandatory=$true)]
   $InstanceCount,
   [Parameter(Mandatory=$true)]
   $domainUserName,
   [Parameter(Mandatory=$true)]
   $domainUserPWD,
   [Parameter(Mandatory=$true)]
   $scriptFileName)

##################################################################### 
#"Initialize Log"
##################################################################### 
    #$logDir=[System.IO.Path]::GetTempPath()
    $tempDir=[System.IO.Path]::GetTempPath()
    $logDir="D:\Logs"
    if((Test-Path -Path $logDir) -eq $false)
    {
        New-Item -Path $logDir -ItemType directory
    }
    $logfile ="$logDir\CreateScheduler-WSFC$($(get-date).toString(‘yyyyMMddhhmm’)).log"
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
o> "$(Get-Date) Input::domainUserName:  $domainUserName"
o> "$(Get-Date) Input::domainUserPWD:  *********"
o> "$(Get-Date) Input::scriptFileName:  $scriptFileName"

o> "$(Get-Date) Temp Directory:  $tempDir"

#create scheduled task to run the ps script
$scriptPath=$MyInvocation.MyCommand.Path
$currentDirectory = $scriptPath.Substring(0, $scriptPath.LastIndexOf("\"))
$scriptPath = "$currentDirectory\$scriptFileName"
$statusFilePath = "$currentDirectory\SchedulerExecutionStatus.txt"

$schedulerArgs = "-ExecutionPolicy Unrestricted -File $scriptPath -VMName $VMName -InstanceCount $InstanceCount -ClusterName $ClusterName"

o> "$(Get-Date) CurrentDirectory:  $currentDirectory"
o> "$(Get-Date) ScriptFilePath:  $scriptPath"
o> "$(Get-Date) schedulerArgs:  $schedulerArgs"

o> "$(Get-Date) SchedulerExecutionStatusFilePath->$statusFilePath"


$A = New-ScheduledTaskAction  -Execute "powershell.exe" -Argument $schedulerArgs
$T = New-ScheduledTaskTrigger -Once -At $((Get-Date).AddMinutes(2))
$S = New-ScheduledTaskSettingsSet

$D = New-ScheduledTask -Action $A -Trigger $T -Settings $S

Register-ScheduledTask CreateWSFC -InputObject $D -User $domainUserName -Password $domainUserPWD

$maxDT = Get-Date
sleep -Seconds 5

$maxDT=$maxDT.AddMinutes(4)
sleep -Seconds 5

o> "$(Get-Date) Registered the task to run after 2 minute."
o> "$(Get-Date) Maximum time to wait to start the scheduled tasks is 4mnts maxDT:  $maxDT"

#wait for the task to begin
$taskNotstarted = $true
while($taskNotstarted -and $maxDT.Subtract((Get-Date)).TotalSeconds -gt 0)
{
    #check if the scheduler task status file is created
    if((Test-path -Path $statusFilePath) -eq $true)
    {
        o> "$(Get-Date) $statusFilePath found....."
        sleep -Seconds 5
        $text=Get-Content -Path $statusFilePath
        if($text.Contains("started") -eq $true)
        {
            o> "$(Get-Date) The scheduler task execution has started."
        }
        $taskNotstarted=$false
    }
    else
    {
        sleep -Seconds 5
        o> "$(Get-Date) sleeping for 5 second......"
    }
}

if($taskNotstarted -eq $false)
{
    #wait for the task to complete and maximum waiting time is 10mnts
    $maxDT = Get-Date
    $maxDT=$maxDT.AddMinutes(10)
    sleep -Seconds 5
    o> "$(Get-Date) Maximum time to wait to complete the scheduled tasks is maxDT:  $maxDT"

    $taskNotcompleted = $true
    while($taskNotcompleted -eq $true -and $maxDT.Subtract((Get-Date)).TotalSeconds -gt 0)
    {
        $text = Get-Content -Path $statusFilePath
        if(($text.Contains("success") -eq $true) -or ($text.Contains("failed") -eq $true))
        {
            o> "$(Get-Date) The task execution has completed. Status content::$text"
            if($text.Contains("success") -eq $true)
            {
                $taskStatus = "success"
            }
            else
            {
                $taskStatus = "failed"
            }
            $taskNotcompleted=$false
        }
        else
        {
            sleep -Seconds 5
            o> "$(Get-Date) sleeping for 5 second......"
        }
    }
}
else
{
    o> "$(Get-Date) The scheduler task execution has not started yet. Now exited the loop...."
}

if($taskNotstarted -eq $true)
{
    o> "$(Get-Date) The scheduler task has not yet started. So exiting with failure"
    exit 1
}
else
{
    if($taskNotcompleted -eq $true)
    {
        o> "$(Get-Date) The scheduler task has started. But didn't completed in the stipulated time. So exiting with 1."
        exit 1
    }
    else
    {
        if($taskStatus -ne $null)
        {
            #task execution completed successuflly
            if($taskStatus.Contains("success"))
            {
                o> "$(Get-Date) The scheduler task has started and completed successfully."
                exit 0
            }
            if($taskStatus.Contains("failed"))
            {
                o> "$(Get-Date) The scheduler task has started and completed with failed status. So exiting with 1."
                exit 1
            }
        }
        else
        {
            o> "$(Get-Date) Unknow error."
            exit 1
        }
    }
}
