using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;


namespace PasswordGenerator.Hashes
{
    public class SimpleSha1
    {
        private static readonly SHA1Managed Sha1 = new();
        
        public static byte[] GenerateHash(string password)
        {
            var passwordAsBytes = Encoding.UTF8.GetBytes(password);

            var hash = Sha1.ComputeHash(passwordAsBytes);
            
            return hash;            
        }
        
    }
}