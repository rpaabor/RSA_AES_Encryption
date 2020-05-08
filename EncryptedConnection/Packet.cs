namespace EncryptedConnection
{

    public class EncryptedPacket
    {
        public byte[] EncryptedData;
        public byte[] Hmac;
        public byte[] Iv;
    }
}

