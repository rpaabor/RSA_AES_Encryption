using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ClientCrypto
{
    internal class AESCrypto
    {
        private byte[] _sessionKey;


        internal AESCrypto(byte[] SessionKey)
        {
            _sessionKey = SessionKey;
        }

        internal EncryptedPacket EncryptData(byte[] data)
        {
            //Create new encrypted packet with random Iv
            var encryptedpacket = new EncryptedPacket() { Iv = GenerateRanomNumber(16) };

            //Encrypt data with AES
            encryptedpacket.EncryptedData = Encrypt(data, _sessionKey, encryptedpacket.Iv);

            //Generate HMAC using session key for data integrety check
            using (var hmac = new HMACSHA256(_sessionKey))
            {
                encryptedpacket.Hmac = hmac.ComputeHash(encryptedpacket.EncryptedData);
            }
            return encryptedpacket;
        }
        internal byte[] DecryptPacket(EncryptedPacket packet)
        {
            using (var hmac = new HMACSHA256(_sessionKey))
            {
                var hmacToCheck = hmac.ComputeHash(packet.EncryptedData);

                if (!Compare(packet.Hmac, hmacToCheck))
                    throw new CryptographicException("HMAC for decryption does not match encrypted packet, data has been tamperd with");
            }
            return Decrypt(packet.EncryptedData, _sessionKey, packet.Iv);
        }

        private static bool Compare(byte[] arr1, byte[] arr2)
        {
            var reslult = arr1.Length == arr2.Length;

            for (int i = 0; i < arr1.Length && i < arr2.Length; i++)
            {
                reslult &= arr1[i] == arr2[i];
            }
            return reslult;
        }
        private byte[] GenerateRanomNumber(int lenght)
        {
            using (var rndgen = new RNGCryptoServiceProvider())
            {
                var randomNumber = new byte[lenght];
                rndgen.GetBytes(randomNumber);
                return randomNumber;
            }
        }
        private byte[] Encrypt(byte[] dataToEncrypt, byte[] key, byte[] iv)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.KeySize = 256;
                aes.Key = key;
                aes.IV = iv;

                using (var ms = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);

                    cryptoStream.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                    cryptoStream.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }
        private byte[] Decrypt(byte[] dataToDecrypt, byte[] key, byte[] iv)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;
                using (var ms = new MemoryStream())
                {
                    var cryptostream = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write);
                    cryptostream.Write(dataToDecrypt, 0, dataToDecrypt.Length);
                    cryptostream.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }


    }
}
