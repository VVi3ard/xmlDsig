namespace SIRCrypt
{
    using System;
    using System.Text;

    public class Signer
    {
        public string BESignatureValueAsBase64;
        public string CertificateAsPEM;
        public string ContainerName;
        public string Content;
        public string LESignatureValueAsBase64;

        public bool Sign()
        {
            try
            {
                IntPtr zero = IntPtr.Zero;
                if (Crypto.CryptAcquireContext(ref zero, this.ContainerName, "Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider", 0x4b, 0))
                {
                    IntPtr phUserKey = IntPtr.Zero;
                    int dwKeySpec = 1;
                    if (!Crypto.CryptGetUserKey(zero, dwKeySpec, ref phUserKey))
                    {
                        dwKeySpec = 2;
                        if (!Crypto.CryptGetUserKey(zero, dwKeySpec, ref phUserKey))
                        {
                            return false;
                        }
                    }
                    int pdwDataLen = 0;
                    if (!Crypto.CryptGetKeyParam(phUserKey, 0x1a, null, ref pdwDataLen, 0))
                    {
                        return false;
                    }
                    byte[] pbData = new byte[pdwDataLen];
                    if (!Crypto.CryptGetKeyParam(phUserKey, 0x1a, pbData, ref pdwDataLen, 0))
                    {
                        return false;
                    }
                    this.CertificateAsPEM = Convert.ToBase64String(pbData);
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
                    int pdwSigLen = 0;
                    if (!Crypto.CryptSignHash(phHash, dwKeySpec, null, 0, null, ref pdwSigLen))
                    {
                        return false;
                    }
                    byte[] pbSignature = new byte[pdwSigLen];
                    if (!Crypto.CryptSignHash(phHash, dwKeySpec, null, 0, pbSignature, ref pdwSigLen))
                    {
                        return false;
                    }
                    this.LESignatureValueAsBase64 = Convert.ToBase64String(pbSignature);
                    Array.Reverse(pbSignature);
                    this.BESignatureValueAsBase64 = Convert.ToBase64String(pbSignature);
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
                    pbSignature = null;
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

