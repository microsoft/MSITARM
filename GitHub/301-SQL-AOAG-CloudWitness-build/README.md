#301-SQL-AOAG-CloudWitness-build

Deploy from Azure Portal (UI Experience)

Steps:

	1.  This template uses Managed disk, there is no need to create a storage account to hold your Disks.

	2.  Logon to http://portal.azure.com
	3.  New and search for "Template Deployment"
	4.  Copy and paste the contents of azuredeploy.json into "Edit Template"
	
		Edit the template: you will need to populate the Domain data for the VM to join. 
		the FQDN and OU path need to be updated to match your Domain. 
		You may add more Domains in an allowed list that will map to the domainName variable and used by the template.
	
	5.  Update all Parameters
	6.  Follow the rest of the UI
	