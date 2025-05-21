using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Chilkat;
using Newtonsoft.Json;

namespace AddPayWrapper
{
    public class Authentication
    {
        const string appRsaPrivateKey = "";
        const string gatewayRsaPublicKey = "";
        const string gatewayUrl = "";
        const string appId = "";

        public void Test()
        {
            Dictionary<string, string> parameters = new Dictionary<string, string>
            {
                // Common parameters
                { "app_id", appId },
                { "charset", "UTF-8" },
                { "format", "JSON" },
                { "sign_type", "RSA2" },
                { "version", "1.0" },
                { "timestamp", "" + DateTimeOffset.Now.ToUnixTimeMilliseconds() },
                { "method", "order.query" },
                // API owned parameters
                { "merchant_no", "" },
                { "merchant_order_no", "" }
            };

            // 3. Build a string to be signed
            string stringToBeSigned = buildToBeSignString(parameters);
            Console.WriteLine("StringToBeSigned : {0} \n", stringToBeSigned);

            // 4. Calculate signature
            string appRsaPrivateKeyPem = ReformatPemKey(appRsaPrivateKey);
            string sign = GenerateSign(stringToBeSigned, appRsaPrivateKeyPem);
            parameters.Add("sign", sign);

            // 5. Send HTTP request
            JsonObject json = new JsonObject();

            // Add dictionary entries to the JsonObject
            foreach (var kvp in parameters)
            {
                json.UpdateString(kvp.Key, kvp.Value);
            }

            Http http = new Http();
            http.SetRequestHeader("User-Agent", "AddPay");
            HttpResponse resp = http.PostJson3(gatewayUrl, "application/json", json);
            string responseStr = resp.BodyStr;
            Console.WriteLine("Response from gateway[" + gatewayUrl + "] receive data <<-- " + responseStr + "\n");
            if (http.LastMethodSuccess != true)
            {
                Console.WriteLine("Error: " + http.LastErrorText);
                return;
            }

            //6.Verify the signature of the response message
            Dictionary<string, string> respParameters = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseStr);
            string respStringToBeSigned = buildToBeSignString(respParameters);
            Console.WriteLine("RespStringToBeSigned : {0} \n", respStringToBeSigned);
            string respSignature = respParameters["sign"];
            string gatewayRsaPublicKeyPem = ReformatPemKey(gatewayRsaPublicKey, "PUBLIC");
            bool verified = VerifySignature(respStringToBeSigned, respSignature, gatewayRsaPublicKeyPem);
            Console.WriteLine("SignVerifyResult : {0}", verified);
        }

        //Calculate signature
        static string GenerateSign(string data, string privateKeyPem)
        {
            TextReader reader = new StringReader(privateKeyPem);
            PemReader pemReader = new PemReader(reader);

            var privateKey = (RsaPrivateCrtKeyParameters)pemReader.ReadObject();

            // Initialize the signer
            ISigner signer = SignerUtilities.GetSigner("SHA256withRSA");
            signer.Init(true, privateKey);

            // Compute the signature
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            signer.BlockUpdate(dataBytes, 0, dataBytes.Length);
            byte[] signatureBytes = signer.GenerateSignature();

            // Return the signature as a base64 string
            return Convert.ToBase64String(signatureBytes);
        }

        static string ReformatPemKey(string rawKey, string keyType = "PRIVATE")
        {
            // Wrap the key to 64-character lines
            System.Text.StringBuilder formattedKey = new System.Text.StringBuilder();
            for (int i = 0; i < rawKey.Length; i += 64)
            {
                formattedKey.AppendLine(rawKey.Substring(i, Math.Min(64, rawKey.Length - i)));
            }

            // Add the PEM header and footer back
            return $"-----BEGIN {keyType} KEY-----\n{formattedKey}-----END {keyType} KEY-----";
        }

        // verify signature
        public static bool VerifySignature(string content, string sign, string publicKey)
        {
            try
            {
                using (RSACryptoServiceProvider rsaService = new RSACryptoServiceProvider())
                {
                    rsaService.PersistKeyInCsp = false;
                    rsaService.ImportParameters(ConvertFromPemPublicKey(publicKey));
                    return rsaService.VerifyData(Encoding.GetEncoding("UTF-8").GetBytes(content),
                        "SHA256", Convert.FromBase64String(sign));
                }
            }
            catch (Exception e)
            {
                string errorMessage = "The signature verification encountered an exception. Please check if the public key format or signature is correct. content=" + content + " sign=" + sign +
                                      " publicKey=" + publicKey + " reason=" + e.Message;
                throw new Exception(errorMessage);
            }
        }

        // Generate public key objects for c # from public keys in PEM format
        private static RSAParameters ConvertFromPemPublicKey(string pemPublicKey)
        {
            if (string.IsNullOrEmpty(pemPublicKey))
            {
                throw new Exception("The PEM format public key cannot be empty.");
            }

            // Remove interfering text
            pemPublicKey = pemPublicKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace("\n", "").Replace("\r", "");

            byte[] keyData = Convert.FromBase64String(pemPublicKey);
            bool keySize2048 = (keyData.Length == 294);
            if (!keySize2048)
            {
                throw new Exception("The public key length only supports 2048.");
            }
            byte[] pemModulus = new byte[256];
            byte[] pemPublicExponent = new byte[3];
            Array.Copy(keyData, 33, pemModulus, 0, 256);
            Array.Copy(keyData, 291, pemPublicExponent, 0, 3);
            RSAParameters para = new RSAParameters
            {
                Modulus = pemModulus,
                Exponent = pemPublicExponent
            };
            return para;
        }

        // Build a string to be signed
        private static string buildToBeSignString(Dictionary<string, string> parameters)
        {
            IEnumerator<KeyValuePair<string, string>> enumerator = ((IEnumerable<KeyValuePair<string, string>>)new SortedDictionary<string, string>(parameters, StringComparer.Ordinal)).GetEnumerator();
            System.Text.StringBuilder stringBuilder = new System.Text.StringBuilder();
            while (enumerator.MoveNext())
            {
                string key = enumerator.Current.Key;
                string value = enumerator.Current.Value;
                if (!string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(value) && key != "sign")
                {
                    stringBuilder.Append(key).Append("=").Append(value).Append("&");
                }
            }
            return stringBuilder.ToString().Substring(0, stringBuilder.Length - 1);
        }
    }
}
