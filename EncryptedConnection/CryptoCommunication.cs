using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;

namespace EncryptedConnection
{
    public class CryptoCommunication
    {

        private byte[] encrypedsessionkey;
        public string RsaPublicKey;
        private byte[] _sessionKey;
        public byte[] _publicSessionKey
        {
            get
            {
                return encrypedsessionkey;
            }
            set //only server uses set
            {
                using (var exchange = new AES_KeyExchange(RSAPrivateKey,_settings))
                {
                    _sessionKey = exchange.DecryptData(value);
                }
            }
        }
        private string RSAPrivateKey;
        private AES_Communication AES;
        private Settings _settings;


        public CryptoCommunication(Settings settings)
        {
            ValidateSettings(settings);
            switch (settings.GetRunMode)
            {
                case Settings.RunMode.Client:
                    ClientMode(settings);
                    break;
                case Settings.RunMode.Server:
                    ServerMode(settings);
                    break;
                default:
                    break;
            }
            _settings = settings;
        }

        private void ValidateSettings(Settings settings)
        {
            if (settings.GetRSALenght == 0)
                throw new SettingsException("RSA lenght not set.");
            if (settings.GetRunMode == 0)
                throw new SettingsException("Runmode needs to be set.");

            switch (settings.GetRunMode)
            {
                case Settings.RunMode.Client:
                    if (settings.publicRSAkey == "")
                        throw new SettingsException("Client needs public RSA key");
                    break;
                case Settings.RunMode.Server:
                    break;
                default:
                    break;
            }
        }


        private void ServerMode(Settings settings)
        {
            if (RSAPrivateKey == null)
            {
                using (var exchange = new AES_KeyExchange(settings))
                {
                    RsaPublicKey = exchange._publicKey;
                    RSAPrivateKey = exchange._privateKey;
                }
            }
            else
            {
                using (var exchange = new AES_KeyExchange(settings))
                {
                    if (settings.encryptedSessionKey.Length >= 0)
                        throw new SettingsException("Needs a encrypted session key from client");
                    exchange._privateKey = RSAPrivateKey;
                    _sessionKey = exchange.DecryptData(Encoding.UTF8.GetBytes(settings.encryptedSessionKey));
                }
            }
        }
        private void ClientMode(Settings settings)
        {
            if (settings.publicRSAkey == "")
                throw new SettingsException("Client needs public RSA key from server");
            using (var exchange = new AES_KeyExchange(settings))
            {
               
                _sessionKey = exchange._privateSessionKey;
                encrypedsessionkey = exchange._publicEnryptedSessionKey;
            }
        }




        public byte[] EncryptData(byte[] data)
        {
            var test = new AES_Communication(_sessionKey);
            //first 16 iv
            //second 32 is hmac
            //rest is data;
            var packet = test.EncryptData(data);
            var a1 = packet.Iv;
            var a2 = packet.Hmac;
            var a3 = packet.EncryptedData;
            return a1.Concat(a2).ToArray().Concat(a3).ToArray();
        }
        public byte[] DecryptData(byte[] data)
        {
            var test = new AES_Communication(_sessionKey);

            var packet = new EncryptedPacket()
            {
                Iv = data.Take(16).ToArray(),
                Hmac = data.Skip(16).Take(32).ToArray(),
                EncryptedData = data.Skip(48).ToArray()
            };
            return test.DecryptPacket(packet);
        }
    }
}
