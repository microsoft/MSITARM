#301-Windows-VirtualMachines-WebILB-build

Deployment of Single/multiple VMs that includes ILB and availability group set-up as well.  

Features include:

•	Creates Domain Joined VMs
•	Adds them to availability set
•	Create Internal Load Balancer
•	Configures ILB Rules
•	Configures Probe
•	Creates Probe Test
•	Configures Backed Pool for ILB
•	Adds Availability Set to backend pool
		
Deploy from Azure Portal (UI Experience)

Steps:

	1.  This template uses Managed disk, there is no need to create a storage account to hold your Disks.

	2.  Logon to http://portal.azure.com
	3.  New and search for "Template Deployment"
	4.  Copy and paste the contents of azuredeploy.json into "Edit Template"
	
		Edit the template: you will need to populate the Domain data for the VM to join. 
		the FQDN and OU path need to be updated to match your Domain. 
		You may add more Domains in an allowed list that will map to the domain variable and used by the template.
	
	5.  Update all Parameters
	6.  Follow the rest of the UI