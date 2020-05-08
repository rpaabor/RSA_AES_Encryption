using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace EncryptedConnection
{
    internal class AES_KeyExchange : IDisposable
    {

        public string _publicKey { get; set; }
        internal string _privateKey;
        public string SessionKey;
        private Settings settings;
        public byte[] _privateSessionKey;
        public byte[] _publicEnryptedSessionKey;

        public AES_KeyExchange(Settings settings)
        {
            this.settings = settings;
            switch (settings.GetRunMode)
            {
                case Settings.RunMode.Client:
                    RunAsClient();
                    break;
                case Settings.RunMode.Server:
                    RunAsServer();
                    break;
                default:
                    break;
            }

        }
        public AES_KeyExchange(string rsakey,Settings settings)
        {
            this.settings = settings;
            _privateKey = rsakey;
        }

        private void RunAsServer()
        {
            AssignNewKey();
        }
        private void RunAsClient()
        {
            var ServerPublicKey = settings.publicRSAkey;
            _privateSessionKey = GenerateNewSessionKey();
            _publicEnryptedSessionKey = EncryptSessionKey(_privateSessionKey, ServerPublicKey);
        }


        /// <summary>
        /// Server
        /// </summary>
        public void AssignNewKey()
        {
            using (var rsa = new RSACryptoServiceProvider((int)settings.GetRSALenght))
            {
                rsa.PersistKeyInCsp = false;
                _publicKey = rsa.ToXmlString(false);
                _privateKey = rsa.ToXmlString(true);
            }
        }

        public byte[] DecryptData(byte[] dataToDecrypt)
        {
            byte[] plain;
            using (var rsa = new RSACryptoServiceProvider((int)settings.GetRSALenght))
            {
                rsa.PersistKeyInCsp = false;
                rsa.FromXmlString(_privateKey);
                plain = rsa.Decrypt(dataToDecrypt, true);
            }
            return plain;
        }

        /// <summary>
        /// Client
        /// </summary>
        /// <returns></returns>
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
            using (var rsa = new RSACryptoServiceProvider((int)settings.GetRSALenght))
            {
                rsa.PersistKeyInCsp = false;
                rsa.FromXmlString(publicKey);
                cipherbytes = rsa.Encrypt(dataToEncrypt, true);
            }
            return cipherbytes;
        }


        public void Dispose()
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
        }
    }
}
