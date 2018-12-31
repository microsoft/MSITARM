# Name: ConfigureWebILB
#
param
    (
[string] $DeploymentName,
[string] $servernamepart,
[string] $domain,
[int]    $InstanceCount,
[string] $SubscriptionId,
[string] $WebILBName,
[string] $SQLILBName,
[string] $WebHookKey,
[string] $Dashboardsvr
)
try {

 $nodes=""
 write-host "deploymentName=$deploymentName"
 write-host "servernamepart=$servernamepart"
 write-host "domain=$domain"
 write-host "InstanceCount=$InstanceCount"
 write-host "SubscriptionId=$SubscriptionId"
 write-host "webhook=$webhook"
 write-host "Dashboardsvr=$Dashboardsvr"

 (1..$InstanceCount) | %{ if($_ -ne $instanceCount) { $nodes += "$servernamepart$_,"} else {$nodes += "$servernamepart$_"} }
   
 
        Import-Module cloudmsaad
         
        $response = $null
        $uri = "https://s1events.azure-automation.net/webhooks?token={0}" -f $WebHookKey
        
        $headers = @{"From"="user@contoso.com";"Date"="$($(get-date).ToShortDateString())"}
               

        $Params  = @(
                    @{ Nodes=$Nodes;DeploymentName=$DeploymentName;webilbname=$webilbname;sqlibname=$sqlibname;SubscriptionId=$SubscriptionId }
                    )

        $body = ConvertTo-Json -InputObject $params
    
        $startRunbook = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body
        $jobID = $startRunbook.JobIds[0]

            if($jobID) {
                            
               $jobstatusURL = "see Dashboard. 'http://{0}/?searchText={0}&f_mtype=WebILB-Configuration&f_dateType=all'  " -f $Dashboardsvr,$webilbname
                
               write-host $jobstatusURL

            }

        } catch {
         [string]$errorMessage = $_.Exception.Message
         if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureDataPath: $errorMessage"
         }
            throw $errorMessage
        }