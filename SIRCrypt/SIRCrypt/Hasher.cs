namespace SIRCrypt
{
    using System;
    using System.Text;

    public class Hasher
    {
        public string Content;
        public string HashValueAsBase64;

        public bool Hash()
        {
            try
            {
                IntPtr zero = IntPtr.Zero;
                if (Crypto.CryptAcquireContext(ref zero, null, "Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider", 0x4b, -268435456))
                {
                    IntPtr phHash = IntPtr.Zero;
                    if (!Crypto.CryptCreateHash(zero, 0x801e, IntPtr.Zero, 0, ref phHash))
                    {
                        return false;
                    }
                    byte[] bytes = Encoding.UTF8.GetBytes(this.Content);
                    if (!Crypto.CryptHashData(phHash, bytes, bytes.Length, 0))
                    {
                        return false;
                    }
                    int pdwDataLen = 0x20;
                    byte[] pbData = new byte[pdwDataLen];
                    if (!Crypto.CryptGetHashParam(phHash, 2, pbData, ref pdwDataLen, 0))
                    {
                        return false;
                    }
                    this.HashValueAsBase64 = Convert.ToBase64String(pbData);
                    if (phHash != IntPtr.Zero)
                    {
                        Crypto.CryptDestroyHash(phHash);
                    }
                    if (zero != IntPtr.Zero)
                    {
                        Crypto.CryptReleaseContext(zero, 0);
                    }
                    bytes = null;
                    pbData = null;
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}

