
Configuration DeployWinServer
{
  param (  
  [string[]]$MachineName = $env:COMPUTERNAME
  )

  Node localhost
  {
	
        cd\
        if($(test-path -path c:\temp) -eq $false){
            md Temp
        }
        
        Script NoOp
        {
         SetScript = { 
            $sw = New-Object System.IO.StreamWriter(“C:\Temp\Wininstall.log”)
            $sw.WriteLine("$(Get-Date -Format g) $MachineName Completed.") 
	        $sw.Close()
         }
        TestScript = { Test-Path "C:\Temp\Wininstall.log" }
        GetScript = { <# This must return a hash table #> }          
       }  


  }

}

