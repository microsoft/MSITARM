
Configuration DeployWebServer
{
  param (  
  [string[]]$MachineName = "localhost"
  )

  Node localhost
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

       
	    
  }

}

