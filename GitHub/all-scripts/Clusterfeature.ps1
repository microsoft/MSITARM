# Name: Deploypre configurations for WSFS
#
Configuration Clusterfeature
{
  param (  
   )

  Node localhost
  {
    LocalConfigurationManager
    {
        RebootNodeIfNeeded = $true
    }
  
    WindowsFeature FC
    {
        Name = "Failover-Clustering"
        Ensure = "Present"
    }
	WindowsFeature PowershellFC
    {
        Ensure    = 'Present'
        Name      = 'RSAT-Clustering-PowerShell'
        DependsOn = '[WindowsFeature]FC'
    }
	WindowsFeature CmdInterfaceFC
    {
        Ensure    = 'Present'
        Name      = 'RSAT-Clustering-CmdInterface'
        DependsOn = '[WindowsFeature]PowershellFC'
    }
    WindowsFeature MgmtFC 
    { 
        Ensure = "Present" 
        Name = "RSAT-Clustering-Mgmt"
		DependsOn = "[WindowsFeature]CmdInterfaceFC"
    } 
	Registry Registry1
    {
        Ensure      = "Present"  # You can also set Ensure to "Absent"
        Key         = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredentialsDelegation"
        ValueName   = "AllowFreshCredentialsWhenNTLMOnly"
        ValueData   = "1"
        ValueType = "DWORD"
		DependsOn = "[WindowsFeature]MgmtFC"
        
    }
    Registry Registry2
    {
        Ensure      = "Present"  # You can also set Ensure to "Absent"
        Key         = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredentialsDelegation"
        ValueName   = "ConcatenateDefaults_AllowFreshNTLMOnly"
        ValueData   = "1"
        ValueType = "DWORD"
        DependsOn = "[Registry]Registry1"
    }
    Registry Registry3
    {
        Ensure      = "Present"  # You can also set Ensure to "Absent"
        Key         = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly"
        ValueName   = "1"
        ValueData   = "wsman/*.microsoft.com"
        ValueType = "String"
        DependsOn = "[Registry]Registry2"
    }
	Script ConfigureFirewall
	{
            GetScript = {
                @{
                }
            }
            SetScript = {
                try {

                    New-NetFirewallRule -DisplayName "SQLAO_Default" -Direction Inbound -LocalPort 1433, 1434, 5022, 50001 -Protocol TCP -Action allow

                } catch{
                    [string]$errorMessage = $Error[0].Exception
                    $errorMessage
                }
            }
            TestScript = {
                
              return $false
            }
            DependsOn= '[Registry]Registry3'
        }
  }
}