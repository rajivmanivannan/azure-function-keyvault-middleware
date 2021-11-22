using System;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.KeyVault;
using System.Net.Http;
using System.Net;
using System.Text;

namespace KeyVaultMiddleware
{
    public static class KeyVaultMiddleware
    {
        [FunctionName("GetSecret")]
        public static async Task<HttpResponseMessage> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequestMessage req,
            ILogger log)
        {
            log.LogInformation("KeyVaultMiddleware: GetSecret function processed a request");

            // Parse the query parameter "key"
            var query = System.Web.HttpUtility.ParseQueryString(req.RequestUri.Query);
            string keyName = query.Get("key");

            if (String.IsNullOrEmpty(keyName))
            {
                var errorObj = new { error = "Parameter is missing", message = "Query parameter 'key' or it's value is missing" };

                // Error Response
                return GetHttpResponseMessage(HttpStatusCode.BadRequest, errorObj);
            }

            // Retrive the Azure Key Vault URL from the Application settings
            string keyVaultUrl = Environment.GetEnvironmentVariable("AZURE_KEYVAULT_URL");

            if (String.IsNullOrEmpty(keyVaultUrl))
            {
                var errorObj = new { error = "Not configured properly", message = "Azure Key Vault URL is not configured in Application settings of Azure Cloud" };

                // Error Response
                return GetHttpResponseMessage(HttpStatusCode.FailedDependency, errorObj);
            }

            try
            {
                var azureServiceTokenProvider = new AzureServiceTokenProvider();
                var keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));

                // Retrive the secret for the given key from Azure KeyVault
                var retriveSecret = await keyVaultClient.GetSecretAsync(keyVaultUrl + keyName).ConfigureAwait(false); ;

                var successObj = new { key = keyName, secret = retriveSecret.Value };

                // Success Response
                return GetHttpResponseMessage(HttpStatusCode.OK, successObj);

            }
            catch (Exception e)
            {
                string errorMessage = e.Message;

                if (errorMessage.Contains("NotFound"))
                {
                    var notFoundObj = new { error = "Not found", message = keyName + " not found in the Azure Key Vault" };
                    // Error Response
                    return GetHttpResponseMessage(HttpStatusCode.NotFound, notFoundObj);

                }

                if (errorMessage.Contains("Forbidden"))
                {
                    var forbiddenObj = new { error = "Forbidden access", message = "You don't have permission to access or application not configured properly" };
                    // Error Response
                    return GetHttpResponseMessage(HttpStatusCode.Forbidden, forbiddenObj);

                }

                var unknowErrorObj = new { error = "Internal server error", message = errorMessage };
                // Error Response
                return GetHttpResponseMessage(HttpStatusCode.InternalServerError, unknowErrorObj);
            }
        }


        //Method to construct Http Response Message.
        private static HttpResponseMessage GetHttpResponseMessage(HttpStatusCode httpStatusCode, Object responseObj)
        {
            var jsonToReturn = JsonConvert.SerializeObject(responseObj);

            return new HttpResponseMessage(httpStatusCode)
            {
                Content = new StringContent(jsonToReturn, Encoding.UTF8, "application/json")
            };
        }

    }
}
