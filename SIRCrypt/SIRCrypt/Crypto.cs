namespace SIRCrypt
{
    using System;
    using System.Runtime.InteropServices;

    internal class Crypto
    {
        public const int AT_KEYEXCHANGE = 1;
        public const int AT_SIGNATURE = 2;
        public const int CALG_GR3411 = 0x801e;
        public const string CP_GR3410_2001_PROV = "Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider";
        public const int CRYPT_VERIFYCONTEXT = -268435456;
        public const int GR3411_HASH_VALUE_LENGTH = 0x20;
        public const int HP_HASHSIZE = 4;
        public const int HP_HASHVAL = 2;
        public const int KP_CERTIFICATE = 0x1a;
        public const int PROV_GOST_2001_DH = 0x4b;

        [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
        public static extern bool CryptAcquireContext(ref IntPtr hProv, string pszContainer, string pszProvider, int dwProvType, int dwFlags);
        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool CryptCreateHash(IntPtr hProv, int Algid, IntPtr hKey, int dwFlags, ref IntPtr phHash);
        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool CryptDestroyHash(IntPtr hHash);
        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool CryptGetHashParam(IntPtr hHash, int dwParam, [Out] byte[] pbData, ref int pdwDataLen, int dwFlags);
        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool CryptGetKeyParam(IntPtr hKey, int dwParam, [Out] byte[] pbData, ref int pdwDataLen, int dwFlags);
        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool CryptGetUserKey(IntPtr hProv, int dwKeySpec, ref IntPtr phUserKey);
        [DllImport("Advapi32.dll", SetLastError=true)]
        public static extern bool CryptHashData(IntPtr hHash, byte[] pbData, int dwDataLen, int dwFlags);
        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool CryptReleaseContext(IntPtr hProv, int dwFlags);
        [DllImport("Advapi32.dll", SetLastError=true)]
        public static extern bool CryptSignHash(IntPtr hHash, int dwKeySpec, string sDescription, int dwFlags, byte[] pbSignature, ref int pdwSigLen);
    }
}

