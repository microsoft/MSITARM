using System;
using System.Collections.Generic;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.KeyVault;

using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Azure.KeyVault.Models;

namespace Microsoft.CPE.CloudMS.TelemetryLib
{
    public class TelemetryTableManager
    {
        private const string StorageAccountName = @"armcloudms";

        public TelemetryTableManager()
        {
            
        }

        public string keyVaultSecretURI
        {
            get
            {
                return string.Format(@"https://{0}.vault.azure.net/secrets/{1}",
                    "armsecrets",
                    "armtelemetrystoragekey");
            }
        }

        public async Task<string> RetriveStorakeKeyFromKV()
        {
            var serviceTokenProvider = new AzureServiceTokenProvider();
            var keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(serviceTokenProvider.KeyVaultTokenCallback));
            SecretBundle secretValue = await keyVaultClient.GetSecretAsync(keyVaultSecretURI);
            return secretValue.Value;
        }

        public string StorageKey
        {
            set;
            private get;
        }

        public string Branch { get; set; }

        public string ConnectionString
        {
            get
            {
                if(StorageKey == null || StorageKey.Length==0)
                {
                    StorageKey= RetriveStorakeKeyFromKV().Result;
                }
                return string.Format(@"DefaultEndpointsProtocol=https;AccountName={0};AccountKey={1};EndpointSuffix=core.windows.net", 
                    StorageAccountName, 
                    StorageKey);
            }
        }

        private string ARMTeleLogTableName
        {
            get
            {
                return string.Format(@"armtelelog{0}", Branch);
            }
        }
        private string ARMTeleLogDetailsTableName
        {
            get
            {
                return string.Format(@"armtelelogdetails{0}", Branch);
            }
        }

        public CloudTable GetTelemetryLogTable()
        {

            CloudStorageAccount cloudStorageAccount = CloudStorageAccount.Parse(ConnectionString);
            CloudTableClient tableClient = cloudStorageAccount.CreateCloudTableClient();
            CloudTable cloudTable = tableClient.GetTableReference(ARMTeleLogTableName);
            return cloudTable;
        }

        public CloudTable GetTelemetryLogDetailsTable()
        {

            CloudStorageAccount cloudStorageAccount = CloudStorageAccount.Parse(ConnectionString);
            CloudTableClient tableClient = cloudStorageAccount.CreateCloudTableClient();
            CloudTable cloudTable = tableClient.GetTableReference(ARMTeleLogDetailsTableName);
            return cloudTable;
        }

        public TelemetryEntity RetrieveRecord(CloudTable table, string partitionKey, string rowKey)
        {
            TableOperation tableOperation = TableOperation.Retrieve<TelemetryEntity>(partitionKey, rowKey);
            TableResult tableResult = table.Execute(tableOperation);
            return tableResult.Result as TelemetryEntity;
        }

        public void UpdateDeploymentStatus(string telemetryId, bool status)
        {
            CloudTable tblTelemetry = GetTelemetryLogTable();
            TableQuery<TelemetryEntity> query = new TableQuery<TelemetryEntity>().Where(
                    TableQuery.GenerateFilterCondition("RowKey", QueryComparisons.Equal, telemetryId));
            IEnumerable<TelemetryEntity> queryResult = tblTelemetry.ExecuteQuery(query);

            string userName = "";
            foreach (TelemetryEntity item in queryResult)
            {
                userName = item.PartitionKey;
                break;
            }
            if (userName.Length == 0)
            {
                throw new Exception("Deployment ID is not found in the azure table");
            }

            //UpdateDeploymentStatus(userName, telemetryId, status);
        }
        //public void UpdateDeploymentStatus(string userName, string telemetryId, bool status)
        //{
        //    CloudTable tblTelemetry = GetTelemetryLogTable();
        //    TelemetryEntity tblEntityObj = RetrieveRecord(tblTelemetry, userName, telemetryId);

        //    if (tblEntityObj != null)
        //    {
        //        if (status)
        //        {
        //            tblEntityObj.Status = "DeploymentSuccess";
        //        }
        //        else
        //        {
        //            tblEntityObj.Status = "DeploymentFailed";
        //        }

        //        TableOperation tableOperation = TableOperation.Replace(tblEntityObj);
        //        tblTelemetry.Execute(tableOperation);
        //        Console.WriteLine("Record inserted");
        //    }
        //    else
        //    {
        //        Console.WriteLine("Record not exists");
        //        throw new Exception(string.Format("No record found for the Partition key -{0}; Row key - {1} to update", userName, telemetryId));
        //    }
        //}

        public void AddTemplateDeployentLogs(string telemetryId, Dictionary<string,string> dctKeyValues)
        {
            CloudTable tblTelemetry = GetTelemetryLogDetailsTable();

            LogEntity tblEntity = new LogEntity();
            foreach (string key in dctKeyValues.Keys)
            {
                tblEntity.AddKeyValue(key, dctKeyValues[key]);
            }
            tblEntity.AssignPartitionKey(telemetryId);
            tblEntity.AssignRowKey(Guid.NewGuid().ToString());

            if (tblEntity.PartitionKey == null || tblEntity.PartitionKey.Length == 0)
            {
                throw new Exception("Partiong key/user Name is missing in the keyvalue pairs");
            }

            TelemetryEntity tblEntityObj = RetrieveRecord(tblTelemetry, tblEntity.PartitionKey, telemetryId);
            if (tblEntityObj == null)
            {
                TableOperation tableOperation = TableOperation.Insert(tblEntity);
                tblTelemetry.Execute(tableOperation);
                Console.WriteLine("Record inserted");
            }
            else
            {
                Console.WriteLine("Record exists");
                throw new Exception(string.Format("Partition key -{0}; Row key - {1} already exit.", tblEntity.PartitionKey, telemetryId));
            }
        }
        public void AddDeploymentInitiatedDetails(string telemetryId, Dictionary<string, string> dctKeyValues)
        {
            CloudTable tblTelemetry = GetTelemetryLogTable();

            TelemetryEntity tblEntity = new TelemetryEntity();
            foreach (string key in dctKeyValues.Keys)
            {
                tblEntity.AddKeyValue(key, dctKeyValues[key]);
            }
            tblEntity.AssignRowKey(telemetryId);

            if (tblEntity.PartitionKey == null || tblEntity.PartitionKey.Length == 0)
            {
                throw new Exception("Partiong key/user Name is missing in the keyvalue pairs");
            }

            TelemetryEntity tblEntityObj = RetrieveRecord(tblTelemetry, tblEntity.PartitionKey, telemetryId);
            if (tblEntityObj == null)
            {
                TableOperation tableOperation = TableOperation.Insert(tblEntity);
                tblTelemetry.Execute(tableOperation);
                Console.WriteLine("Record inserted");
            }
            else
            {
                Console.WriteLine("Record exists");
                throw new Exception(string.Format("Partition key -{0}; Row key - {1} already exit.", tblEntity.PartitionKey, telemetryId));
            }
            
        }
        //public void AddDeploymentInitiatedDetails(string userName, string teleMetryId, int noOfVms, string subName, string rgName, string templateName)
        //{
        //    CloudTable tblTelemetry = GetTelemetryLogTable();

        //    TelemetryEntity tblEntity = new TelemetryEntity();

        //    tblEntity.NumberOfVMs = noOfVms;
        //    tblEntity.SubscriptionName = subName;
        //    tblEntity.ResourceGroupName = rgName;
        //    tblEntity.TemplateName = templateName;
        //    tblEntity.Status = "DeploymentInprogress";
        //    tblEntity.AssignPartitionKey(userName);
        //    tblEntity.AssignRowKey(teleMetryId);

        //    TelemetryEntity tblEntityObj = RetrieveRecord(tblTelemetry, userName, teleMetryId);
        //    if (tblEntityObj == null)
        //    {
        //        TableOperation tableOperation = TableOperation.Insert(tblEntity);
        //        tblTelemetry.Execute(tableOperation);
        //        Console.WriteLine("Record inserted");
        //    }
        //    else
        //    {
        //        Console.WriteLine("Record exists");
        //        throw new Exception(string.Format("Partition key -{0}; Row key - {1} already exit.", userName, teleMetryId));
        //    }
        //}
        public static Dictionary<string, string> CreateKeyvalueDictionary(string strKeyValuepairs)
        {
            Dictionary<string, string> dctKeyValuePairs = new Dictionary<string, string>();
            string[] arrPairs = strKeyValuepairs.Split(';');
            for (int iCount = 0; iCount < arrPairs.Length; ++iCount)
            {
                string[] arrString = arrPairs[iCount].Split(':');
                if (arrString.Length == 2)
                {
                    dctKeyValuePairs.Add(arrString[0], arrString[1]);
                }
            }

            return dctKeyValuePairs;
        }
    }
}
