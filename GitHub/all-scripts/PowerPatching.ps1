# Name: PowerPatching
#
# Install: PowerPatching.ps1
#
# example:
# install: c:\PowerPatch\PowerPatching.ps1
#
# Run at startup, delay 30 seconds
# Run: powershell.exe
# Args: -NoLogo -NonInteractive -ExecutionPolicy ByPass -Command "c:\\PowerPatch\\PowerPatching.ps1"
# Run as: SYSTEM


$outfile = "C:\PowerPatch\PowerPatchingLog.txt"
$schedulerName="E2SPowerPatching"
$scriptPath ="C:\\PowerPatch\\PowerPatching.ps1 "
if(!(Test-Path $outfile))
{
    New-Item -Path "$outfile" -ItemType file
}
$dt = Get-Date

Write-Output "Welcome to powerpatching.... $dt" |Out-File -FilePath $outfile -Append

# Avoid the non-terminating error so that DSC does not report a failure
if ((Get-ScheduledTask -TaskPath '\' -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -eq $schedulerName; }) -eq $null)
{
    Write-Output "Scheduler task '$schedulerName' doesnot exist. So creating the scheduler task." |Out-File -FilePath $outfile -Append

    $TaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $("-NoLogo -NonInteractive -ExecutionPolicy ByPass -Command $scriptPath ");
    $TaskTrigger = New-ScheduledTaskTrigger -Once -at $($([DateTime] $(get-date).ToUniversalTime()).addHours(2)) -RepetitionDuration  (New-TimeSpan  -Days 30) -RepetitionInterval  (New-TimeSpan -hour 2)
    $TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Limited ;
    $TaskSettings = New-ScheduledTaskSettingsSet -Compatibility Win8 -ExecutionTimeLimit (New-TimeSpan -Hours 1);
    $ScheduledTask = Register-ScheduledTask -TaskName $schedulerName -TaskPath '\' -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings -Principal $TaskPrincipal
    Write-Output "Scheduler task '$schedulerName' registered." |Out-File -FilePath $outfile -Append
} 
else 
{
    Write-Output "Scheduler task '$schedulerName' exists. Now checking the simpleupdater for new updatesdoesnot exist. So creating the scheduler task." |Out-File -FilePath $outfile -Append
    
    $patchOutput = $(c:\PowerPatch\supdate_v4.0.exe -preview)
    

    Write-Output $patchOutput |Out-File -FilePath $outfile -Append

    if($($patchOutput | ?{$_ -Contains 'No Updates Found!'}) -ne "No Updates Found!" ) 
    {
        Write-Output "New updates are found. Now invoking to install the updates....." |Out-File -FilePath $outfile -Append
    
        #patch server
        $patchOutput = $(c:\PowerPatch\supdate_v4.0.exe -Install)
        Write-Output $patchOutput |Out-File -FilePath $outfile -Append
        Write-Output "Supdate_v4.exe execution completed. Now exiting the script.." |Out-File -FilePath $outfile -Append
    } 
    elseif($($patchOutput | ?{$_ -Contains 'No Updates Found!'}) -eq "No Updates Found!" ) 
    { 
       Write-Output "No New updates are found. Now un-registering the scheduler task....." |Out-File -FilePath $outfile -Append
    
       #remove scheduled task
       Unregister-ScheduledTask -TaskName $schedulerName -Confirm:$false
       Write-Output "Unregister the scheduler task - '$schedulerName'" |Out-File -FilePath $outfile -Append
    }
}