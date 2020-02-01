using System;
using System.Configuration;
using System.Security.Cryptography;
using System.Text;

namespace eip.dl.util
{
    class Program
    {
        static void Main(string[] args)
        {
            switch (args[0])
            {
                case "initnode":
                    {
                        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                        string sk = rsa.ToXmlString(true);
                        string pk = rsa.ToXmlString(false);

                        ConsoleColor savedFG = Console.ForegroundColor;

                        Console.WriteLine("-----------------------------------");
                        Console.WriteLine($"Secret Key [DO NOT SHARE]: {sk}");
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine(sk);
                        Console.ForegroundColor = savedFG;
                        Console.WriteLine("-----------------------------------");
                        Console.WriteLine($"Public Key: {pk}");
                        Console.WriteLine("-----------------------------------");
                    }
                    break;
                case "show_node":
                    {
                        RSAKeyValueSection section = (RSAKeyValueSection)ConfigurationManager.GetSection("NodeIdentity/RSAKeyValue");
                        RSAParameters keyInfo = section.CreateRSAParametersFromConfig();

                        ConsoleColor savedFG = Console.ForegroundColor;

                        Console.WriteLine("-----------------------------------");
                        Console.WriteLine($"Modulus : { Convert.ToBase64String(keyInfo.Modulus)}");
                        Console.WriteLine($"Exponent : { Convert.ToBase64String(keyInfo.Exponent)}");

                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"P : { Convert.ToBase64String(keyInfo.P)}");
                        Console.WriteLine($"Q : { Convert.ToBase64String(keyInfo.Q)}");
                        Console.WriteLine($"DP : { Convert.ToBase64String(keyInfo.DP)}");
                        Console.WriteLine($"DQ : { Convert.ToBase64String(keyInfo.DQ)}");
                        Console.WriteLine($"InverseQ : { Convert.ToBase64String(keyInfo.InverseQ)}");
                        Console.WriteLine($"D : { Convert.ToBase64String(keyInfo.D)}");
                        Console.ForegroundColor = savedFG;

                        Console.WriteLine("-----------------------------------");
                    }
                    break;
                case "encrypt_pk":
                    {   // The secret message is in arg[1]

                        RSAKeyValueSection section = (RSAKeyValueSection)ConfigurationManager.GetSection("NodeIdentity/RSAKeyValue");
                        RSAParameters keyInfo = section.CreateRSAParametersFromConfig(false);

                        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                        {
                            rsa.ImportParameters(keyInfo);
                            rsa.ImportParameters(rsa.ExportParameters(false));

                            byte[] encrypted = rsa.Encrypt(Encoding.Unicode.GetBytes(args[1]), false);

                            Console.WriteLine("-----------------------------------");
                            Console.WriteLine(Convert.ToBase64String(encrypted));
                            Console.WriteLine("-----------------------------------");
                        }
                        break;
                    }
                case "decrypt_sk":
                    {   // The encrypted bytes in base 64 are in arg[1]

                        RSAKeyValueSection section = (RSAKeyValueSection)ConfigurationManager.GetSection("NodeIdentity/RSAKeyValue");
                        RSAParameters keyInfo = section.CreateRSAParametersFromConfig(true);

                        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                        {
                            rsa.ImportParameters(keyInfo);
                            rsa.ImportParameters(rsa.ExportParameters(true));

                            byte[] encryptedMessage = Convert.FromBase64String(args[1]);
                            byte[] decrypted = rsa.Decrypt(encryptedMessage, false);

                            Console.WriteLine("-----------------------------------");
                            Console.WriteLine(Encoding.Unicode.GetString(decrypted));
                            Console.WriteLine("-----------------------------------");
                        }
                        break;
                    }
                case "hash":
                    {   // The message to hash is in arg[1]

                        using (var hash = new SHA256Managed())
                        {
                            byte[] hashedData = hash.ComputeHash(Encoding.Unicode.GetBytes(args[1]));
                            Console.WriteLine("-----------------------------------");
                            Console.WriteLine(Convert.ToBase64String(hashedData));
                            Console.WriteLine("-----------------------------------");
                        }
                        break;
                    }
                case "sign_sk":
                    {   // The secret message is in arg[1]

                        RSAKeyValueSection section = (RSAKeyValueSection)ConfigurationManager.GetSection("NodeIdentity/RSAKeyValue");
                        RSAParameters keyInfo = section.CreateRSAParametersFromConfig(true);

                        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                        {
                            rsa.ImportParameters(keyInfo);
                            rsa.ImportParameters(rsa.ExportParameters(true));

                            byte[] encrypted = rsa.SignHash(Convert.FromBase64String(args[1]), CryptoConfig.MapNameToOID("SHA256"));

                            Console.WriteLine("-----------------------------------");
                            Console.WriteLine(Convert.ToBase64String(encrypted));
                            Console.WriteLine("-----------------------------------");
                        }
                        break;
                    }
                case "verify_pk":
                    {   // arg[1] is the signed data
                        // arg[2] is the signature

                        RSAKeyValueSection section = (RSAKeyValueSection)ConfigurationManager.GetSection("NodeIdentity/RSAKeyValue");
                        RSAParameters keyInfo = section.CreateRSAParametersFromConfig(false);

                        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                        {
                            rsa.ImportParameters(keyInfo);
                            bool signValid = rsa.VerifyData(
                                Encoding.Unicode.GetBytes(args[1]),
                                CryptoConfig.MapNameToOID("SHA256"),
                                Convert.FromBase64String(args[2]));

                            Console.WriteLine("-----------------------------------");
                            Console.WriteLine("The signature is " + (signValid ? "Valid" : "Invalid"));
                            Console.WriteLine("-----------------------------------");
                        }
                        break;
                    }
                case "verify_hash_pk":
                    {   // arg[1] is the hash of signed data
                        // arg[2] is the signature

                        RSAKeyValueSection section = (RSAKeyValueSection)ConfigurationManager.GetSection("NodeIdentity/RSAKeyValue");
                        RSAParameters keyInfo = section.CreateRSAParametersFromConfig(false);

                        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                        {
                            rsa.ImportParameters(keyInfo);
                            bool signValid = rsa.VerifyHash(
                                Convert.FromBase64String(args[1]),
                                CryptoConfig.MapNameToOID("SHA256"),
                                Convert.FromBase64String(args[2]));

                            Console.WriteLine("-----------------------------------");
                            Console.WriteLine("The signature is " + (signValid ? "Valid" : "Invalid"));
                            Console.WriteLine("-----------------------------------");
                        }
                        break;
                    }
            }
        }
    }
}
