using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Text;

namespace APITestDemo
{
    class MainTest
    {
        static void Main(string[] args)
        {
            // 1. Global parameter settings
            string appRsaPrivateKeyPem = "MIIEowIBAAKCAQEAlDy3zuoa/f6X7GnmxzHAuEn2zNAqCX0sAwyOzVtPlooHO3csG0yaOt5MAzOgZirgWZpnxnHvyq2Y9VIjTqAj3t/ZEafePQTwuaTP3+oyDNRxzn4FoRwwai+6q8AnanESdZyR+ZwMgNVRLAACChQlzIfi9G4/MnnofUEOg7kFGevK9K+svIqS6EUQ2ePpXXBsnp/YMBYAG4hCD/lEbZhRTlCoU2b6qauq+CDjTDtMBK26Y+pro/RezIcS9d2UCUzf7EBeFaiirYoz2jQjkDYg8E/qz7seTqeTHgJC1ih0ffhHfUKKpk6S04dIYWYMWVqDkaRAkR+HbxL6AkmY1JhEMwIDAQABAoIBAGclgLjHiRSnrMriPaTpZ7JUNRj61+VWZeORP2SBXvXfAX1NRTGRsde4iqfHqpqsxwNSP1eEPFiJRt+c0diJ8avJkt+IMUnAQEjM96BU85Kd2LrYUc5zMPUSVQ/hWwvjtfaEhcZr4P9cb2jwcHrW3h5dh3yRogPbc/yD4jeh7HzF1j/Oyt5WdBL2VSgTzz3aT+aES5KIo4eWsKiGwEksfUDpy87WTvzKu19lPpsrpVnS24XfxufchrXylMhW4SGzbP1rMJ7jZbHX5PG40bJsolaCfLHbpGBVGLA7Ly2QHbETFBJ5UmC+lPubHbKw3IyfGRK4GQh0sZy18OaglWySmVECgYEA3fLnwYalT9xecJ4NhRYFIb8Anf+Pxm3psqRHsTye9siozhmdWvGgKDnfVNDxHPnKtUHWEg+at0DeaGMoSI6qR5gOzYz7XOV3DK5HOKl6v/7XsP5CR+VUcyGbd2W4SBhhzk5RjShVM3iEM+xxYSlJbcI0auDSQVY6ghSU4/i+eC0CgYEAqvrE4jA9nAGAegvj6d3ZRJqX/wm7WpW/kWPQsXj1/oEUhSacOHbE94gf3NNHZXoPpGGHzHkr4z1q93cw+DZKLIoVwO9/uBJB+pPqpyLJUa204baonuzE1+W+uJ4azZiAIqHqSFWyBdNkwKTiFIFeG6wQO7jHu41Vjp3Et3rECd8CgYBK25p/E0K+ZL0VjrlQodSpRRqYL5H2gyvHLNFhXejfo14L5WfFPKmf56UDnlU0SKut5r6k6M5t8FsTKh50GmokK40SlvJQqrQ0erNa0Q6tou5sq9T/GsIY8sTUyGIXLuIOCyxGR8w0x/kO6jhzZNF3S4ESazF/B+5D4V02ZrcXIQKBgA1wPk9E2WLMn2t4ScaU4EHLIM0z15zsDi2AOePpDPSe8pzwhvDNLPgDo/V4SbFJIbeaztCcaX2n0yN2I8wugC/1/nW2nUQ7cyIdxCC01DvuOjxPXft3wpTxgscB7jtglBmkvkRHMAHTNqUJkJdp/5qPMItxH4m3NxVJgy+kn4njAoGBAMiW5KEYwMsEgo9cu2n8jOuyaiqxve0K19akG4PHywZTJNj0IN7M5RHiA6ZJCRh+PO9TPCpYw1VwZcEQ7tAvwCqkSfJ4ZoeuXOSuw0+sGkYr11eJpGS813KFb10xtIeWCLD/GYhDptNJohjH7qiv0vFL3hGs7TkJ9mj472qOAcrn";
            string gatewayRsaPublicKeyPem = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2m4nkQKyQAxJc8VVsz/L6qVbtDWRTBolUK8Dwhi9wH6aygA6363PVNEPM8eRI5W19ssCyfdtNFy6DRAureoYV053ETPUefEA5bHDOQnjbb9PuNEfT651v8cqwEaTptaxj2zujsWI8Ad3R50EyQHsskQWms/gv2aB36XUM4vyOIk4P1f3dxtqigH0YROEYiuwFFqsyJuNSjJzNbCmfgqlQv/+pE/pOV9MIQe0CAdD26JF10QpSssEwKgvKvnXPUynVu09cjSEipev5cLJSApKSDZxrRjSFBXrh6nzg8JK05ehkI8wdsryRUneh0PGN0PgYLP/wjKiqlgTJaItxnb/JQIDAQAB";
            string gatewayUrl = "https://gw.paycloud.world/api/entry";
            string appId = "wz715fc0d10ee9d156";

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
            Chilkat.Http http = new Chilkat.Http();
            Console.WriteLine("Request to gateway[" + gatewayUrl + "] send data  -->> " + jsonString + "\n");
            Chilkat.HttpResponse resp = http.PostJson2(gatewayUrl, "application/json", jsonString);
            string responseStr = resp.BodyStr;
            Console.WriteLine("Response from gateway[" + gatewayUrl + "] receive data <<-- " + responseStr + "\n");
            if (http.LastMethodSuccess != true)
            {
                Console.WriteLine("Error: " + http.LastErrorText);
                return;
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