using PluginFramework;
using PluginFramework.Attributes;
using RuriLib;
using RuriLib.LS;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Anomaly
{
    /// <summary>
    /// This Block is made Specifically for the AWSAPI from Pure.
    /// </summary>
    public class AWSApi : BlockBase, IBlockPlugin
    {
        public string Name => "AWSAPI";
        public string Color => "LightCoral";
        public bool LightForeground => false;

        [Text("Variable Name", "The output variable name")]
        public string VariableName { get; set; } = "";

        [Dropdown("HTTPMethod", "HTTP Method", options = new string[] { "GET", "POST", "GIT", "PATCH", "HEAD", "PUT" })]
        public string awshttpmethod { get; set; } = "GET";

        [Text("AwsHost", "AWS Host Value")]
        public string awshost { get; set; } = "";

        [Text("AwsPath", "AwsPath Value ex: /execute-api")]
        public string awspath { get; set; } = "";

        [Text("AwsRegion", "Aws Region Value (default us-east1)")]
        public string awsregion { get; set; } = "";

        [Text("AwsCredential", "AwsCredential Value")]
        public string awscredential { get; set; } = "";

        [Text("AwsKey", "AwsKey key Value")]
        public string awskey { get; set; } = "";

        [Text("AwsSecretkey", "AwsKey Secret Key Value")]
        public string awssecretkey { get; set; } = "";

        [Text("AwsSession", "Aws Session Value. (Can Sometimes be used in place of a Key)")]
        public string awssession { get; set; } = "";

        [Text("AwsBodyData", "AwsKey Body Data")]
        public string awsbodydata { get; set; } = "";

        [Text("AwsCustomHeaders", "Put Custom Headers Here")]
        public string awscustomheader { get; set; } = "";

        [Checkbox("Is Capture", "Should the output variable be marked as capture?")]
        public bool IsCapture { get; set; } = false;

        public AWSApi()
        {
            Label = Name;
        }

        public override BlockBase FromLS(string line)
        {
            var input = line.Trim();
            if (input.StartsWith("#")) // If the input actually has a label
                Label = LineParser.ParseLabel(ref input); // Parse the label and remove it from the original string
            awshost = LineParser.ParseLiteral(ref input, "First Number");
            awspath = LineParser.ParseLiteral(ref input, "Second Number");
            awsregion = LineParser.ParseLiteral(ref input, "Third Number");
            awscredential = LineParser.ParseLiteral(ref input, "Fourth Number");
            awskey = LineParser.ParseLiteral(ref input, "Fifth Number");
            awssecretkey = LineParser.ParseLiteral(ref input, "Sixth Number");
            awssession = LineParser.ParseLiteral(ref input, "Seventh Number");
            awshttpmethod = LineParser.ParseLiteral(ref input, "Eigth Number");
            awsbodydata = LineParser.ParseLiteral(ref input, "Ninth Number");
            awscustomheader = LineParser.ParseLiteral(ref input, "Tenth Number");

            if (LineParser.ParseToken(ref input, TokenType.Arrow, false) == "")
                return this;
            try
            {
                var varType = LineParser.ParseToken(ref input, TokenType.Parameter, true);
                if (varType.ToUpper() == "VAR" || varType.ToUpper() == "CAP")
                    IsCapture = varType.ToUpper() == "CAP";
            }
            catch { throw new ArgumentException("Invalid or missing variable type"); }
            try { VariableName = LineParser.ParseToken(ref input, TokenType.Literal, true); }
            catch { throw new ArgumentException("Variable name not specified"); }
            return this;
        }

        public override string ToLS(bool indent = true)
        {
            var writer = new BlockWriter(GetType(), indent, Disabled)
                .Label(Label) // Write the label. If the label is the default one, nothing is written.
                .Token(Name) // Write the block name. This cannot be changed.
                .Literal(awshost)
                .Literal(awspath)
                .Literal(awsregion)
                .Literal(awscredential)
                .Literal(awskey)
                .Literal(awssecretkey)
                .Literal(awssession)
                .Literal(awshttpmethod)
                .Literal(awsbodydata)
                .Literal(awscustomheader);
            if (!writer.CheckDefault(VariableName, nameof(VariableName)))
            {
                writer
                     .Arrow() // Write the -> arrow.
                     .Token(IsCapture ? "CAP" : "VAR") // Write CAP or VAR depending on IsCapture.
                     .Literal(VariableName); // Write the Variable Name as a literal.
            }
            return writer.ToString();
        }

        private static readonly HttpClient client = new HttpClient();

        public override async void Process(BotData data)
        {
            var result = "";
            using (var requestMessage = new HttpRequestMessage(HttpMethod.Get, "http://127.0.0.1:8080/AwsSign"))
                try
                {   //Swaps with input data
                    var AwsHostHeader = (ReplaceValues(awshost, data));
                    var AwsPathHeader = (ReplaceValues(awspath, data));
                    var AwsRegionHeader = (ReplaceValues(awsregion, data));
                    var AwsCredentialHeader = (ReplaceValues(awscredential, data));
                    var AwsKeyHeader = (ReplaceValues(awskey, data));
                    var AwsSecretKeyHeader = (ReplaceValues(awssecretkey, data));
                    var AwsSession = (ReplaceValues(awssession, data));
                    var AwsHttpMethod = (ReplaceValues(awshttpmethod, data));
                    var AwsBodyData = (ReplaceValues(awsbodydata, data));
                    var AwsCustomHeader = (ReplaceValues(awscustomheader, data));
                    //Sets headers for request
                    requestMessage.Headers.Add("awshost", AwsHostHeader);
                    requestMessage.Headers.Add("awspath", AwsPathHeader);
                    requestMessage.Headers.Add("awsregion", AwsRegionHeader);
                    requestMessage.Headers.Add("awscredential", AwsCredentialHeader);
                    requestMessage.Headers.Add("awskey", AwsKeyHeader);
                    requestMessage.Headers.Add("awssecretkey", AwsSecretKeyHeader);
                    requestMessage.Headers.Add("awssession", AwsSession);
                    requestMessage.Headers.Add("awshttpmethod", AwsHttpMethod);
                    requestMessage.Headers.Add("awsbody", AwsBodyData);
                    requestMessage.Headers.Add("awsheaders",AwsCustomHeader);
                    var Response = await client.SendAsync(requestMessage);

                    result = await Response.Content.ReadAsStringAsync();
                    if (Response.StatusCode.ToString() == "OK")
                    {
                        InsertVariable(data, IsCapture, result, VariableName, "", "", false, false);
                        data.Log($"Generated Signature.");
                    }
                    else if (Response.StatusCode.ToString() != "200")
                    {
                        data.Status = BotStatus.ERROR;
                        data.Log($"Error contacting API. Response Code:{Response.StatusCode}");
                    }
                }
                catch (Exception ex)
                {
                    data.Status = BotStatus.ERROR;
                    data.Log($"Error Running AWSAPI Block{ex}");
                }
        }
    }
}