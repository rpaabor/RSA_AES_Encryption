using System;
using System.Collections.Generic;
using System.Text;

namespace RSA_Standard
{
    public class EncryptedPacket
    {
        public byte[] EncryptedData;
        public byte[] Hmac;
        public byte[] Iv;
    }
}
