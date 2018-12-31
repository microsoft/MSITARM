using System;
using System.Net;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.CPE.CloudMS.TelemetryLib;

namespace ARMTelemetryFunctions
{
    public static class Telemetry
    {
        [FunctionName("Telemetry")]
        public static async Task<HttpResponseMessage> Run([HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)]HttpRequestMessage req, TraceWriter log)
        {

            log.Info("Harifunctionhello - HttpTriggerCSharpARMTelemetry - Started");
            string armTempText = "";
            try
            {
                // parse query parameter
                //e.g. branch=develop or beta or master
                string branchName = req.GetQueryNameValuePairs()
                    .FirstOrDefault(q => string.Compare(q.Key, "branch", true) == 0)
                    .Value;

                //depId is the guid.
                //e.g. depId=c4bb4926-9011-47d2-8b77-1f912e5340c5
                string depId = req.GetQueryNameValuePairs()
                    .FirstOrDefault(q => string.Compare(q.Key, "depId", true) == 0)
                    .Value;

                //contains the info on new deployment called from master template. This will be the 1st linked template in the master template
                //e.g. newDeployment=userName:hari;NumberOfVMs:2;SubscriptionName:mysub;ResourceGroupName:myRG;TemplateName:mymastertemplate;InvokedBy:CSEOTemplate
                string newDeployment = req.GetQueryNameValuePairs()
                    .FirstOrDefault(q => string.Compare(q.Key, "newDeployment", true) == 0)
                    .Value;

                //contains the logdetails or nested/linked template succes details of the master template
                //e.g. logDepDetails=TemplateName:CreateVM;ResourceType:VM;ResourceName:hajs1;Logtype:status;Message:success
                //     logDepDetails=TemplateName:CreateVM;ResourceType:VM;ResourceName:hajs1;Logtype:info;Message:deployment initiated with the below values
                string logDepDetails = req.GetQueryNameValuePairs()
                    .FirstOrDefault(q => string.Compare(q.Key, "logDepDetails", true) == 0)
                    .Value;

                //string status = req.GetQueryNameValuePairs()
                //    .FirstOrDefault(q => string.Compare(q.Key, "status", true) == 0)
                //    .Value;

                if(branchName == null || 
                    branchName.Trim().Length == 0)
                {
                    throw new Exception("Invalid URI");
                }
                try
                {
                    TelemetryTableManager mgr = new TelemetryTableManager();
                    if (branchName == "master" || branchName == "beta")
                    {
                        mgr.Branch = branchName;
                    }
                    else
                        mgr.Branch = "develop";

                    if (depId == null)
                    {
                        log.Info(string.Format(@"ARM Template Telemetry DeploymentID Created->{0}", armTempText));
                        armTempText = TeleMetry.GetARMSuccessTemplateWithGUID();
                    }
                    else
                    {
                        if (newDeployment != null)
                        {
                            Dictionary<string, string> dctKeyValuePairs = TelemetryTableManager.CreateKeyvalueDictionary(newDeployment);
                            log.Info(string.Format(@"ARM Template Deployment Initiated with DeploymentID->{0}", depId));
                            mgr.AddDeploymentInitiatedDetails(depId, dctKeyValuePairs);
                            armTempText = TeleMetry.GetARMSuccessTemplate();
                        }
                        else
                        {
                            if (logDepDetails != null)
                            {
                                Dictionary<string, string> dctKeyValuePairs = TelemetryTableManager.CreateKeyvalueDictionary(logDepDetails);
                                log.Info(string.Format(@"ARM Template Deployment Log Initiated with DeploymentID->{0}", depId));
                                mgr.AddTemplateDeployentLogs(depId, dctKeyValuePairs);
                                armTempText = TeleMetry.GetARMSuccessTemplate();
                            }
                        }
                    }
                }
                catch (Exception exp)
                {
                    string strExp = exp.Message;
                    log.Info(strExp);
                }
            }
            catch (Exception exp)
            {
                string strExp = exp.Message;
                log.Info(strExp);
                armTempText = string.Format("<Exception>{0}</Exception>", strExp);
            }
            log.Info("Harifunctionhello - HttpTriggerCSharpARMTelemetry - Ended");
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(armTempText, Encoding.UTF8, "application/json")
            };
        }
    }
}
