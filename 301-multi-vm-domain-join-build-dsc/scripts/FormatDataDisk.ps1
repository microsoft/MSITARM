﻿configuration FormatDataDisks 
{ 
      param (
         $Disks
    ) 

    #$DiskArray = $Disks | convertfrom-Json $disks
   
    node localhost
    {
       
        Script FormatVolumnes
        {
            GetScript = {
              get-disk
              Get-Partition
            }
            SetScript = {
               try {
               foreach($disk in $using:Disks.values) {

                $diskArray = get-disk 
                $partArray = Get-Partition

                    $thisExists =$partArray  | Where-Object {$_.DriveLetter -eq $($disk.DiskName)} | Select -First 1
        
                    if($thisExists -eq $null) {
                                 
                        $DiskExists =  $diskArray  | ? {$($_.Size/1GB) -eq $($disk.Disksize)} | ?{$_.Number -notin $partarray.DiskNumber} | Sort-Object DiskNumber | select -First 1
            
                        try {
                            if($DiskExists) {      
                            
                                if($DiskExists.PartitionStyle -eq 'Raw') {
                                        $DiskExists |  Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter $($disk.DiskName) -UseMaximumSize | Format-Volume -NewFileSystemLabel $($disk.DiskLabel) -FileSystem NTFS -Confirm:$false     
                                    } else {
                                        $DiskExists |  New-Partition -DriveLetter $($disk.DiskName) -UseMaximumSize | Format-Volume -NewFileSystemLabel $($disk.DiskLabel) -FileSystem NTFS -Confirm:$false    
                                    } 
                          
                            } else {
                                write-verbose "No Drive avail"
                            }
                        } catch {
                                write-verbose  "`t[FAIL] $VM Setting Drive $($Disk.DiskName) Failed.`n"
                        
                        }

                    } else {
                        Write-verbose "`t[PASS] $VM Drive $($Disk.DiskName) exists.`n"
                    }
                }
               } catch {}
            }
            TestScript = {
                 $diskArray = get-disk | ? {$_.PartitionStyle -eq 'RAW'}
                 $partArray = Get-Partition

                 $vols =@()
                 $disks | ? {
                    $d=$_
                    $v =  $($partArray  | Where-Object {$_.DriveLetter -eq $($d.DiskName)} | Select -First 1)
                    if(!$v){
                        $vols+=$d
                    }
                 }

            if($vols) {return $true} else {return $false}
            }    
            
        }

      }

    }


