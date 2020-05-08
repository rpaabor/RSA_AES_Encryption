using System;
using System.Collections.Generic;
using System.Text;

namespace ClientCrypto
{
    public class EncryptedPacket
    {       
        public byte[] EncryptedData; 
        public byte[] Hmac; //256 bit 
        public byte[] Iv; //128 bit
    }
}
