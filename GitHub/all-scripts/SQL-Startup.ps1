# Name: SqlTempdriveAndStartup
#
# Install: SQL-Startup.ps1 [tempdbpath]
#
# example:
# install: c:\SQLStartup\SQL-Startup.ps1 D:\MSSQL13.MSSQLSERVER\MSSQL\DATA
#
# Run at startup, delay 30 seconds
# Run: powershell.exe
# Args: -NoLogo -NonInteractive -ExecutionPolicy ByPass -Command "c:\\SQLStartup\\SQL-Startup.ps1 D:\MSSQL13.MSSQLSERVER\MSSQL\DATA"
# Run as: SYSTEM

$TemporaryStorageVolume = $args
$TemporaryStorageDisk = $(split-Path -path $TemporaryStorageVolume -Qualifier);
$TempPathConfigFile = 'C:\SQLStartup\TempPathForSqlStartup.cfg'

# we only run this if the temporary storage account is used.

if($TemporaryStorageDisk -eq 'D:') {

    Write-Host -ForegroundColor Yellow "Temporary storage = $TemporaryStorageDisk";

# Avoid the non-terminating error so that DSC does not report a failure
if ((Get-ScheduledTask -TaskPath '\' -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -eq 'SqlTempdriveAndStartup'; }) -eq $null)
{
    $TaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $('-NoLogo -NonInteractive -ExecutionPolicy ByPass -Command "c:\\SQLStartup\\SQL-Startup.ps1 ' +$TemporaryStorageVolume +'"');
    $TaskTrigger = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Seconds 30);
    $TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Limited ;
    $TaskSettings = New-ScheduledTaskSettingsSet -Compatibility Win8 -ExecutionTimeLimit (New-TimeSpan -Hours 1);

    # Unregister-ScheduledTask -TaskName SqlTempdriveAndStartup -Confirm
    $ScheduledTask = Register-ScheduledTask -TaskName SqlTempdriveAndStartup -TaskPath '\' -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings -Principal $TaskPrincipal
}





$InstalledInstances = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -Name InstalledInstances | Select-Object -ExpandProperty InstalledInstances;

foreach ( $InstanceName in $InstalledInstances )
{
    Write-Host -ForegroundColor Green $InstanceName;


    if ( -not (Test-Path $TempPathConfigFile)){
    
        <#
 
          The first time this script has been run on this computer. Lets save the temp folder path to a file on the C: drive and continue to use 
          this value.

          If SQL is ever upgraded, we don't want the path to change because a new version is found, SQL will not start

        #>

        $InstanceFullName = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -Name $InstanceName | Select-Object -ExpandProperty $InstanceName;

        $InstanceTempFilePath = "{0}\{1}\MSSQL\Data" -f $TemporaryStorageDisk, $InstanceFullName;
        Write-Host -ForegroundColor Cyan $InstanceTempFilePath;

        # Create the config file
        New-Item  -Path $TempPathConfigFile -ItemType File | Out-Null

        # Add the path to our new file
        $InstanceTempFilePath | Set-Content $TempPathConfigFile | Out-Null

        # Hide it and set readonly
        Set-ItemProperty $TempPathConfigFile -Name IsReadOnly -value $true | Out-Null
        Set-ItemProperty $TempPathConfigFile -Name attributes -Value ([io.fileattributes]::Hidden) | Out-Null
    
    }
    Else{

        <#
 
          We've already figured out the correct temp path before, lets roll with it....

        #>

        $InstanceTempFilePath = Get-Content $TempPathConfigFile

    }

    #  OK, we know how to create the temp folder, lets get it done and configured...

    if ( -not (Test-Path -Path $InstanceTempFilePath) )
    {
        New-Item -Path $InstanceTempFilePath -ItemType directory | Out-Null
    }

    icacls "$InstanceTempFilePath" /inheritance:d;
    icacls "$InstanceTempFilePath" /remove "CREATOR OWNER";

    if ( $InstanceName -ne 'MSSQLSERVER' )
    {
        $SQLServiceName = 'MSSQL${0}' -f $InstanceName;
        $SQLAgentServiceName = 'SQLAgent${0}' -f $InstanceName;
        $ServerInstance = '.\{0}' -f $InstanceName;
    }
    else
    {
        $SQLServiceName = 'MSSQLSERVER';
        $SQLAgentServiceName = 'SQLSERVERAGENT';
        $ServerInstance = '.';
    }

    Write-Debug $SQLServiceName;
    Write-Debug $SQLAgentServiceName;

    $SQLService = Get-Service -Name $SQLServiceName;
    $SQLAgentService = Get-Service -Name $SQLAgentServiceName;

    if ( $SQLService.StartType -eq 'Automatic' )
    {
        $SQLService | Set-Service -StartupType Manual;
    }

    if ( $SQLAgentService.StartType -eq 'Automatic' )
    {
        $SQLAgentService | Set-Service -StartupType Manual;
    }

    $Args = @($InstanceTempFilePath, '/grant:r', """NT SERVICE\$($SQLService.ServiceName)"":`(OI`)`(CI`)`(F`)");
    # $Args;

    icacls $args;
    icacls "$InstanceTempFilePath";

    if ( $SQLService.Status -eq 'running' )
    {
        $Query = 'SELECT name, type_desc, physical_name, SizeMB = size * 8 / 1024, growth = CASE WHEN is_percent_growth = 0 THEN growth * 8 / 1024 ELSE growth END, is_percent_growth FROM tempdb.sys.database_files'
        $TempDBFiles = Invoke-Sqlcmd -ServerInstance $ServerInstance -Query $Query -QueryTimeout 10;

        $AverageFileSize = ($TempDBFiles | ? { $_.type_desc -eq 'ROWS' } | Measure-Object -Average SizeMB).Average;

        $TargetFileSize = 100 * [Math]::Ceiling($AverageFileSize / 100);
        Write-Debug "Target file size = $TargetFileSize MB";

        $TargetFileGrowth = 100 * [Math]::Ceiling($AverageFileSize / 1000);
        Write-Debug "Target file growth = $TargetFileGrowth MB";
        
        foreach ( $TempFile in $TempDBFiles)
        {
            $Query = "ALTER DATABASE tempdb MODIFY FILE (NAME='{0}', FILENAME='{1}', SIZE={2}MB, FILEGROWTH={3}MB)" -f $TempFile.name, ($TemporaryStorageDisk + $TempFile.physical_name.Remove(0,2)), $TargetFileSize, $TargetFileGrowth;
            Write-Debug $Query;
            
            Invoke-Sqlcmd -ServerInstance $ServerInstance -Query $Query -QueryTimeout 10;
        }
    }

    # Fire it up!

    if ( $SQLService.Status -eq 'Stopped' )
    {
        $SQLService | Start-Service;
    }

    if ( $SQLAgentService.Status -eq 'Stopped')
    {
        $SQLAgentService | Start-Service;
    }

  }
}
