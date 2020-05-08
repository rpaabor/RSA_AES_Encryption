using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace ClientCrypto
{
    internal class SessionKey : IDisposable
    {
        public byte[] _privateSessionKey;
        public byte[] _publicEnryptedSessionKey;

        internal SessionKey(string ServerPublicKey)
        {
            _privateSessionKey = GenerateNewSessionKey();
            _publicEnryptedSessionKey = EncryptSessionKey(_privateSessionKey, ServerPublicKey);
        }

        private byte[] GenerateNewSessionKey()
        {
            using (var rndgen = new RNGCryptoServiceProvider())
            {
                var randomNumber = new byte[32];
                rndgen.GetBytes(randomNumber);
                return randomNumber;
            }
        }
        public byte[] EncryptSessionKey(byte[] dataToEncrypt, string publicKey)
        {
            byte[] cipherbytes;
            using (var rsa = new RSACryptoServiceProvider(4096))
            {
                rsa.PersistKeyInCsp = false;
                rsa.FromXmlString(publicKey);
                cipherbytes = rsa.Encrypt(dataToEncrypt, true);
            }
            return cipherbytes;
        }

        public void Dispose()
        {
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }
    }
}
