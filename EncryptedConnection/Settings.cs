using System;
using System.Collections.Generic;
using System.Text;

namespace EncryptedConnection
{
    public class Settings
    {
        public enum RSALenght
        {
            Low = 1024,
            Medium = 2048,
            High = 4096
        }

        public enum RunMode
        {
            Client = 1,
            Server = 2
        }

        private RunMode _runMode;
        private RSALenght _rsaLenght;


        public string serverUrl { get; set; }
        public string encryptedSessionKey { get; set; }
        public string publicRSAkey { get; set; }

        public RunMode GetRunMode
        {
            get
            {
                return _runMode;
            }
        }
        public RSALenght GetRSALenght
        {
            get
            {
                return _rsaLenght;
            }
        }

        public RunMode SetRunmode
        {
            set
            {
                _runMode = value;
            }

        }
        public RSALenght SetRSALenght
        {
            set
            {
                _rsaLenght = value;
            }
        }

       



    }
}
