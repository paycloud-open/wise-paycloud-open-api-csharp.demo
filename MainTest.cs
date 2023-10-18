using Newtonsoft.Json;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

namespace APITestDemo
{
    class MainTest
    {
        static void Main(string[] args)
        {
            // 1. Global parameter settings
            string appRsaPrivateKeyPem = "<YOUR APP RSA PRIVATE KEY>";
            string gatewayRsaPublicKeyPem = "<YOUR GATEWAY RSA PUBLIC KEY>";
            string gatewayUrl = "<YOUR GATEWAY URL>";
            string appId = "<YOUR APP ID>";

            // 2. Set parameters
            Dictionary<string, string> parameters = new Dictionary<string, string>();
                // Common parameters
            parameters.Add("app_id", appId);
            parameters.Add("charset", "UTF-8");
            parameters.Add("format", "JSON");
            parameters.Add("sign_type", "RSA2");
            parameters.Add("version", "1.0");
            parameters.Add("timestamp", "" + DateTimeOffset.Now.ToUnixTimeMilliseconds());
            parameters.Add("method", "order.query");
                // API owned parameters
            parameters.Add("merchant_no", "312100000164");
            parameters.Add("merchant_order_no", "TEST_1685946062143");

            // 3. Build a string to be signed
            string stringToBeSigned = buildToBeSignString(parameters);
            Console.WriteLine("StringToBeSigned : {0} \n", stringToBeSigned);

            // 4. Calculate signature
            string sign = GenerateSign(stringToBeSigned, appRsaPrivateKeyPem);
            parameters.Add("sign", sign);

            // 5. Send HTTP request
            string jsonString = JsonConvert.SerializeObject(parameters);
            
            Console.WriteLine("Request to gateway[" + gatewayUrl + "] send data  -->> " + jsonString + "\n");

            var responseStr = "";
            try{
                var httpClient = new HttpClient();
                httpClient.DefaultRequestHeaders.Accept.Clear();
                httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                var response = httpClient.PostAsync(gatewayUrl, new StringContent(jsonString, Encoding.UTF8, "application/json")).Result;
                if (response.IsSuccessStatusCode){
                    responseStr = response.Content.ReadAsStringAsync().Result;
                    Console.WriteLine("Response from gateway[" + gatewayUrl + "] receive data <<-- " + responseStr + "\n");
                }
                else{
                    Console.WriteLine("Request to gateway[" + gatewayUrl + "] failed: " + response);
                    return;
                }
            }catch (Exception ex){
                Console.WriteLine("Request exception: " + ex.Message);
            }

            // 6. Verify the signature of the response message
            Dictionary<string, string> respParameters = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseStr);
            string respStringToBeSigned = buildToBeSignString(respParameters);
            Console.WriteLine("RespStringToBeSigned : {0} \n", respStringToBeSigned);
            string respSignature = respParameters["sign"];
            bool verified = VerifySignature(respStringToBeSigned, respSignature, gatewayRsaPublicKeyPem);
            Console.WriteLine("SignVerifyResult : {0}", verified);

        }

        //Calculate signature
        private static string GenerateSign(string content, string privateKeyPem)
        {
            try
            {
                using (RSACryptoServiceProvider rsaService = BuildRSAServiceProvider(Convert.FromBase64String(privateKeyPem)))
                {
                    byte[] data = Encoding.GetEncoding("UTF-8").GetBytes(content);
                    byte[] sign = rsaService.SignData(data, "SHA256");
                    return Convert.ToBase64String(sign);
                }
            }
            catch (Exception e)
            {
                string errorMessage = "Signature encountered an exception. Please check if the private key format is correct.content=" + content + " privateKeySize=" + privateKeyPem.Length + " reason=" + e.Message;
                throw new Exception(errorMessage);
            }
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

        // Building an RSA Signature Provider Object
        private static RSACryptoServiceProvider BuildRSAServiceProvider(byte[] privateKey)
        {
            byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;
            byte bt = 0;
            ushort twobytes = 0;
            int elems = 0;

            //set up stream to decode the asn.1 encoded RSA private key
            //wrap Memory Stream with BinaryReader for easy reading
            using (BinaryReader binaryReader = new BinaryReader(new MemoryStream(privateKey)))
            {
                twobytes = binaryReader.ReadUInt16();
                //data read as little endian order (actual data order for Sequence is 30 81)
                if (twobytes == 0x8130)
                {
                    //advance 1 byte
                    binaryReader.ReadByte();
                }
                else if (twobytes == 0x8230)
                {
                    //advance 2 bytes
                    binaryReader.ReadInt16();
                }
                else
                {
                    return null;
                }

                twobytes = binaryReader.ReadUInt16();
                //version number
                if (twobytes != 0x0102)
                {
                    return null;
                }
                bt = binaryReader.ReadByte();
                if (bt != 0x00)
                {
                    return null;
                }

                //all private key components are Integer sequences
                elems = GetIntegerSize(binaryReader);
                MODULUS = binaryReader.ReadBytes(elems);

                elems = GetIntegerSize(binaryReader);
                E = binaryReader.ReadBytes(elems);

                elems = GetIntegerSize(binaryReader);
                D = binaryReader.ReadBytes(elems);

                elems = GetIntegerSize(binaryReader);
                P = binaryReader.ReadBytes(elems);

                elems = GetIntegerSize(binaryReader);
                Q = binaryReader.ReadBytes(elems);

                elems = GetIntegerSize(binaryReader);
                DP = binaryReader.ReadBytes(elems);

                elems = GetIntegerSize(binaryReader);
                DQ = binaryReader.ReadBytes(elems);

                elems = GetIntegerSize(binaryReader);
                IQ = binaryReader.ReadBytes(elems);

                //create RSACryptoServiceProvider instance and initialize with public key
                RSACryptoServiceProvider rsaService = new RSACryptoServiceProvider();
                RSAParameters rsaParams = new RSAParameters
                {
                    Modulus = MODULUS,
                    Exponent = E,
                    D = D,
                    P = P,
                    Q = Q,
                    DP = DP,
                    DQ = DQ,
                    InverseQ = IQ
                };
                rsaService.ImportParameters(rsaParams);
                return rsaService;
            }
        }

        private static int GetIntegerSize(BinaryReader binaryReader)
        {
            byte bt = 0;
            byte lowbyte = 0x00;
            byte highbyte = 0x00;
            int count = 0;

            bt = binaryReader.ReadByte();

            //expect integer
            if (bt != 0x02)
            {
                return 0;
            }
            bt = binaryReader.ReadByte();

            if (bt == 0x81)
            {
                //data size in next byte
                count = binaryReader.ReadByte();
            }
            else if (bt == 0x82)
            {
                //data size in next 2 bytes
                highbyte = binaryReader.ReadByte();
                lowbyte = binaryReader.ReadByte();
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                //we already have the data size
                count = bt;
            }
            while (binaryReader.ReadByte() == 0x00)
            {   //remove high order zeros in data
                count -= 1;
            }
            //last ReadByte wasn't a removed zero, so back up a byte
            binaryReader.BaseStream.Seek(-1, SeekOrigin.Current);
            return count;
        }

        // Build a string to be signed
        private static string buildToBeSignString(Dictionary<string, string> parameters)
        {
            IEnumerator<KeyValuePair<string, string>> enumerator = ((IEnumerable<KeyValuePair<string, string>>)new SortedDictionary<string, string>(parameters, StringComparer.Ordinal)).GetEnumerator();
            StringBuilder stringBuilder = new StringBuilder();
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