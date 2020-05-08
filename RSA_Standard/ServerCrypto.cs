using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace RSA_Standard
{
    public class ServerCrypto
    {
        private AESCrypto AES;
        public string PublicKey { get; private set; }

        public ServerCrypto()
        {

        }


        public byte[] EncryptData(byte[] data)
        {
            //first 16 iv
            //second 32 is hmac
            //rest is data;
            var packet = AES.EncryptData(data);
            var a1 = packet.Iv;
            var a2 = packet.Hmac;
            var a3 = packet.EncryptedData;
            return a1.Concat(a2).ToArray().Concat(a3).ToArray();
        }
        public byte[] DecryptData(byte[] data)
        {
            var packet = new EncryptedPacket()
            {
                Iv = data.Take(16).ToArray(),
                Hmac = data.Skip(16).Take(32).ToArray(),
                EncryptedData = data.Skip(48).ToArray()
            };
            return AES.DecryptPacket(packet);
        }
    }
}
