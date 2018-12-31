# Name: Deploypre configurations for WSFS
#
Configuration DeployPreConfigWSFC
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

    WindowsFeature FailoverClusteringMGMT 
    { 
        Ensure = "Present" 
        Name = "RSAT-Clustering-Mgmt"
		DependsOn = "[WindowsFeature]FC"
    } 
  }
}