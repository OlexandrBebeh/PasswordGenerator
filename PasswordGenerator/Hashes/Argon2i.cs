using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace PasswordGenerator.Hashes
{
    public class Argon2i
    {
        private const string Name = "libsodium";
        private const int CryptoPwhashArgon2IdAlgArgon2Id13 = 2;
        private const long CryptoPwhashArgon2IdOpslimitSensitive = 4;
        private const int CryptoPwhashArgon2IdMemlimitSensitive = 65536;
        private const int HashLength = 256;

        private readonly RNGCryptoServiceProvider saltProvider = new();
        private readonly int memLimit;
        private readonly long opsLimit;

        [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_init();

        [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void randombytes_buf(byte[] buffer, int size);

        [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash(byte[] buffer, long bufferLen, byte[] password, long passwordLen,
            byte[] salt, long opsLimit, int memLimit, int alg);

        [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str_alg(
            byte[] buffer, string password, long passwordLength,
            long opsLimit, int memLimit, int alg);

        [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int
            crypto_pwhash_str_verify(string hashedPassword, string password, long passwordLength);

        static Argon2i()
        {
            sodium_init();
        }

        public Argon2i() : this(CryptoPwhashArgon2IdMemlimitSensitive, CryptoPwhashArgon2IdOpslimitSensitive)
        {
        }

        public Argon2i(int memLimit, long opsLimit)
        {
            this.memLimit = memLimit;
            this.opsLimit = opsLimit;
        }

        public bool Verify(string password, string hashedPassword)
        {
            var result = crypto_pwhash_str_verify(hashedPassword, password, password.Length);
            return result == 0;
        }

        public byte[] HashPassword(string password, byte[] salt)
        {
            var hash = new byte[HashLength];

            var result = crypto_pwhash(
                hash,
                hash.Length,
                Encoding.UTF8.GetBytes(password),
                password.Length,
                salt,
                opsLimit,
                memLimit,
                CryptoPwhashArgon2IdAlgArgon2Id13
            );

            if (result != 0)
                throw new Exception("An unexpected error has occurred.");

            return hash;
        }

        public byte[] HashPasswordWithSalt(string password)
        {
            var hash = new byte[HashLength];

            var result = crypto_pwhash_str_alg(
                hash,
                password,
                password.Length,
                CryptoPwhashArgon2IdOpslimitSensitive,
                CryptoPwhashArgon2IdMemlimitSensitive,
                CryptoPwhashArgon2IdAlgArgon2Id13);

            if (result != 0)
                throw new Exception("An unexpected error has occurred.");

            int lastIndex = Array.FindLastIndex(hash, b => b != 0);

            Array.Resize(ref hash, lastIndex + 1);

            return hash;
        }

        public byte[] GenerateRandomSequence(int length)
        {
            byte[] bytes = new byte[length];

            saltProvider.GetNonZeroBytes(bytes);

            return bytes;
        }
    }
}
