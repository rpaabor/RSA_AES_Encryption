using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace RSA_Standard
{
    public class RSAcrypto : IDisposable
    {
        public string _publicKey;
        public RSAParameters _privateKey;
        public string SessionKey;

        public RSAcrypto()
        {
            AssignNewKey();
            
        }

        public void AssignNewKey()
        {           
            using (var rsa = new RSACryptoServiceProvider(4096))
            {
                rsa.PersistKeyInCsp = false;
                _publicKey = rsa.ToXmlString(false);
                _privateKey = rsa.ExportParameters(true);
            }
        }

        public byte[] DecryptData(byte[] dataToDecrypt)
        {
            byte[] plain;
            using (var rsa = new RSACryptoServiceProvider(4096))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(_privateKey);
                plain = rsa.Decrypt(dataToDecrypt, true);
            }
            return plain;
        }

        public void Dispose()
        {
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }
    }



}
