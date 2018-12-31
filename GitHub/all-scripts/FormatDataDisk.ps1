# Name: FormatDataDisks
#
configuration FormatDataDisks 
{ 
      param (
         $vmDiskData
    ) 

    node localhost
    {
       
        Script FormatVolumnes
        {
            GetScript = {
              get-disk
              Get-Partition
            }
            SetScript = {

                #get alll disks in local machine
                $localDisks = Get-Disk

                #convert the input vmdisks data into json
                #$vmdisks = $vmdisksInJson | ConvertFrom-Json 
                $vmdisks=$using:vmDiskData

                #Run through all the disks and find out the data disks.
                #the assumption for the logica below here the data disk path will have the string 'virtual_disk#' follwed by the lun number
                #if the logic goes wrong in the subsequent images of VM then the below code will not work and it should be revisited.
                foreach($disk in $localDisks)
                {
                    $path = $disk.path
                    if($path.Contains('virtual_disk#'))
                    {
                        $indexOfLun=$path.IndexOf('virtual_disk#')+'virtual_disk#'.Length
                        $pathRight=$path.Substring($indexOfLun,($path.Length-$indexOfLun))
                        $arrPatsplit=$pathRight -split '#'

                        #get the lunno from the path
                        $luNo = [convert]::ToInt32($arrPatsplit[0], 10)
                        #Write-Output "Disk number-$($disk.Number); Lun Number-$luNo"

                        #run through the input data and add the disk number corresponding to the lun number
                        foreach($vmdisk in $vmdisks)
                        {
                
                            if($vmdisk.LunNo -eq $luNo)
                            {
                                $vmdisk |Add-Member @{DiskNumber=$disk.Number}  
                                break
                            }
                        }
                    }
                    else
                    {
                        #in case of of temp and OS disks there won't be lun number in the path
                        $luNo = -1
                    }
                }


                #run through all disk info to configure the disks
                foreach($vmdisk in $vmdisks)
                {
                    if($vmdisk.DiskNumber -ne $null)
                    {
                        #get disk object in VM
                        $disk = Get-Disk -Number $vmdisk.DiskNumber
        
                        #if the disk object is not null
                        if($disk -ne $null)
                        {
                            #check the partiation is RAW
                            if($disk.PartitionStyle -eq 'RAW')
                            {
                                Initialize-Disk -Number $vmdisk.DiskNumber -PartitionStyle GPT -Confirm -Verbose        
    
                                #partition the new disk
                                New-Partition -DiskNumber $vmdisk.DiskNumber -UseMaximumSize -DriveLetter $vmdisk.DiskName

                                #format the volume
                                Format-Volume -NewFileSystemLabel $vmdisk.DiskLabel -FileSystem NTFS -Confirm:$false -Force -DriveLetter $vmdisk.DiskName
                            }
                        }
    
                    }
                }

               
            }
            TestScript = {
                $pass = $true
                $vmdisks=$using:vmDiskData
                
                $localDisks = get-psdrive –psprovider filesystem
                foreach($vmdisk in $vmdisks)
                {
                    $foundDrive = $false
                    foreach($disk in $localDisks)
                    {
                        if($disk.Name -eq $vmdisk.DiskName)
                        {
                            $foundDrive = $true
                            break
                        }
                    }
                    if($foundDrive -eq $false)
                    {
                        $pass = $false
                        break
                    }
                }
                return $pass
            }

        }
    }
}