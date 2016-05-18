Deploy from Azure Portal (UI Experience) 

\301-multi-vm-domain-join-build-dsc\azuredeploy.json
Description: SingleVM that leverages DSC for domain join
Steps:
	1.  Create your storage acount that you want to deploy to.  
		New-AzureRmStorageAccount -ResourceGroupName "yourRG" -AccountName "yourStorageAccountName" -Location "centralus" -Type "Standard_GRS" -Tags @{Name = "AppID"; Value = "enteryourValue"}, @{Name="OrgID";Value="enteryourValue"},@{Name="Env";Value="enteryourValue"}
		Create a blob container called "vhds".  You can do this through the Azure Portal. 
	2.  Logon to http://portal.azure.com
	3.  New and search for "Template Deployment"
	4.  Copy and paste the contents of azuredeploy.json into "Edit Template"
	5.  Update all Parameters
	6.  Follow the rest of the UI


Deploy from Github (under development)

Go to: https://github.com/toddrob/cloudms

# Solution name

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Ftoddrob%2Fcloudms%2Fmaster%2F301-vm-domain-join-build-automation-dsc%2Fazuredeploy.json" target="_blank">
<img src="http://azuredeploy.net/deploybutton.png"/>
</a>



cloudms/301-vm-domain-join-build-automation-dsc/azuredeploy.json
<a href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2FAzure%2Fazure-quickstart-templates%2Fmaster%2F100-STARTER-TEMPLATE-with-VALIDATION%2Fazuredeploy.json" target="_blank">
<img src="http://armviz.io/visualizebutton.png"/>
</a>


This template deploys a **solution name**. The **solution name** is a **description**

`Tags: Tag1, Tag2, Tag3`

## Solution overview and deployed resources

This is an overview of the solution

The following resources are deployed as part of the solution

#### Resource provider 1

Description Resource Provider 1

+ **Resource type 1A**: Description Resource type 1A
+ **Resource type 1B**: Description Resource type 1B
+ **Resource type 1C**: Description Resource type 1C

#### Resource provider 2

Description Resource Provider 2

+ **Resource type 2A**: Description Resource type 2A

#### Resource provider 3

Description Resource Provider 3

+ **Resource type 3A**: Description Resource type 3A
+ **Resource type 3B**: Description Resource type 3B

## Prerequisites

Decscription of the prerequistes for the deployment

## Deployment steps

You can click the "deploy to Azure" button at the beginning of this document.

## Usage

#### Connect

How to connect to the solution

#### Management

How to manage the solution

## Notes

Solution notes
