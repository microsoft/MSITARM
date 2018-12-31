using System;
using System.IO;
using System.Reflection;

namespace Microsoft.CPE.CloudMS.TelemetryLib
{
    public class TeleMetry
    {
        public TeleMetry()
        {
        }
        public static string GetARMSuccessTemplate()
        {
            string strText = "";

            Assembly _assembly = Assembly.GetExecutingAssembly();
            StreamReader _textStreamReader = new StreamReader(_assembly.GetManifestResourceStream("Microsoft.CPE.CloudMS.TelemetryLib.Success.json"));
            if (_textStreamReader.Peek() != -1)
            {
                strText = _textStreamReader.ReadToEnd();
            }
            return strText;
        }
        public static string GetARMFailureTemplate()
        {
            string strText = "";
            Assembly _assembly = Assembly.GetExecutingAssembly();
            StreamReader _textStreamReader = new StreamReader(_assembly.GetManifestResourceStream("Microsoft.CPE.CloudMS.TelemetryLib.Failure.json"));
            if (_textStreamReader.Peek() != -1)
            {
                strText = _textStreamReader.ReadToEnd();
            }
            return strText;
        }
        public static string GetARMSuccessTemplateWithGUID()
        {
            string strText = "";
            Assembly _assembly = Assembly.GetExecutingAssembly();
            StreamReader _textStreamReader = new StreamReader(_assembly.GetManifestResourceStream("Microsoft.CPE.CloudMS.TelemetryLib.SuccessWithGUID.json"));
            if (_textStreamReader.Peek() != -1)
            {
                strText = _textStreamReader.ReadToEnd();
            }
            strText = strText.Replace("#PH-TelemetryID#", Guid.NewGuid().ToString());
            return strText;
        }
    }
}
