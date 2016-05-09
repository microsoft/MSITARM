
Configuration DeployWebServer
{
  param (  
  [string[]]$MachineName = "localhost"
  )

  Node ($MachineName)
  {
	   
    foreach ($Feature in @("Web-Server", `
                           "Web-App-Dev", `
                           "Web-Asp-Net45", `
                           "Web-Net-Ext45", `
                           "Web-Ftp-Server", `
                           "Web-Mgmt-Compat", `
                           "Web-ISAPI-Ext", `
                           "Web-ISAPI-Filter", `
                           "Web-Log-Libraries", `
                           "Web-Request-Monitor", `
                           "Web-Mgmt-Tools", `
                           "Web-Mgmt-Console", `
                           "WAS", `
                           "WAS-Process-Model", `
                           "WAS-Config-APIs")){
            
        WindowsFeature "$Feature$Number"{  
                        Ensure = “Present”  
                        Name = $Feature  
        } 
    } 

    #script block to download WebPI MSI from the Azure storage blob
    Script DownloadWebPIImage
    {
        GetScript = {
            @{
                Result = "WebPIInstall"
            }
        }
        TestScript = {
            Test-Path "C:\WindowsAzure\wpilauncher.exe"
        }
        SetScript ={
            $source = "http://go.microsoft.com/fwlink/?LinkId=255386"
            $destination = "C:\WindowsAzure\wpilauncher.exe"
            Invoke-WebRequest $source -OutFile $destination
       
        }
    }

    Package WebPi_Installation
        {
            Ensure = "Present"
            Name = "Microsoft Web Platform Installer 5.0"
            Path = "C:\WindowsAzure\wpilauncher.exe"
            ProductId = '4D84C195-86F0-4B34-8FDE-4A17EB41306A'
            Arguments = ''
        }

    
	    
  }

}

