using System;
using Microsoft.WindowsAzure.Storage.Table;

namespace Microsoft.CPE.CloudMS.TelemetryLib
{
    public class LogEntity : TableEntity
    {
        public void AssignRowKey(string depId)
        {
            this.RowKey = depId;
        }
        public void AssignPartitionKey(string partkey)
        {
            this.PartitionKey = partkey;
        }

        public void AddKeyValue(string key, string value)
        {
            switch (key)
            {
                case "TemplateName":
                    TemplateName=value;
                    break;
                case "ResourceType":
                    ResourceType = value;
                    break;
                case "ResourceName":
                    ResourceName = value;
                    break;
                case "Logtype":
                    Logtype = value;
                    break;
                case "Message":
                    Message = value;
                    break;
                default:
                    break;
            }
        }
        public string TemplateName { get; set; }
        public string ResourceName { get; set; }
        public string Logtype { get; set; }
        public string ResourceType { get; set; }
        public string Message { get; set; }
    }
}
