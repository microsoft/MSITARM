using System;
using Microsoft.WindowsAzure.Storage.Table;

namespace Microsoft.CPE.CloudMS.TelemetryLib
{
    public class TelemetryEntity : TableEntity
    {
        public void AssignRowKey(string depId)
        {
            this.RowKey = depId;
        }
        public void AssignPartitionKey(string partkey)
        {
            partkey = partkey.Replace(@"\", @"_");
            this.PartitionKey = partkey;
        }

        public void AddKeyValue(string key, string value)
        {
            switch (key)
            {
                case "userName":
                    AssignPartitionKey(value);
                    break;
                case "NumberOfVMs":
                    try
                    {
                        NumberOfVMs = int.Parse(value);
                    }
                    catch (Exception exp)
                    {
                        Console.WriteLine(string.Format(@"Error in parsing the string into integer. Exp->{0}", exp.Message));
                    }
                    break;
                case "SubscriptionName":
                    SubscriptionName = value;
                    break;
                case "ResourceGroupName":
                    ResourceGroupName = value;
                    break; 
                case "TemplateName":
                    TemplateName = value;
                    break;
                case "InvokedBy":
                    InvokedBy = value;
                    break;
                default:
                    break;
            }
        }
        public int NumberOfVMs { get; set; }
        public string SubscriptionName { get; set; }
        public string ResourceGroupName { get; set; }
        public string TemplateName { get; set; }
        public string InvokedBy { get; set; }

    }
}
