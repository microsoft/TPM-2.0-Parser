/*++

Copyright (c) 2010-2015 Microsoft Corporation
Microsoft Confidential

*/
using System;

using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace Tpm2Lib
{
    /// <summary>
    /// A helper class for doing symmetric cryptography based on 
    /// TPM structure definitions.
    /// </summary>
    public sealed class SymmCipher : IDisposable
    {
        public bool LimitedSupport = false;

        private CryptographicKey Key;
        private byte[] KeyBuffer;
        private byte[] IV;

        private SymmCipher(CryptographicKey key, byte[] keyData, byte[] iv)
        {
            Key = key;
            KeyBuffer = keyData;
            IV = Globs.CopyData(iv) ?? new byte[BlockSize];
        }

        public byte[] KeyData { get { return KeyBuffer; } }

        public int BlockSize { get { return 16; } }

        public static int GetBlockSize(SymDefObject symDef)
        {
            if (symDef.Algorithm == TpmAlgId.Tdes)
            {
                return 8;
            }
            if (symDef.Algorithm != TpmAlgId.Aes)
            {
                Globs.Throw<ArgumentException>("Unsupported algorithm " + symDef.Algorithm);
                return 0;
            }
            return 16;
        }

        /// <summary>
        /// Create a new SymmCipher object with a random key based on the alg and mode supplied.
        /// </summary>
        /// <param name="algId"></param>
        /// <param name="numBits"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static SymmCipher Create(SymDefObject symDef = null, byte[] keyData = null, byte[] iv = null)
        {
            if (symDef == null)
            {
                symDef = new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb);
            }

            string algName = "";
            switch (symDef.Algorithm)
            {
                case TpmAlgId.Aes:
                    switch (symDef.Mode)
                    {
                        case TpmAlgId.Cbc:
                            algName = SymmetricAlgorithmNames.AesCbc;
                            break;
                        case TpmAlgId.Ecb:
                            algName = SymmetricAlgorithmNames.AesEcb;
                            break;
                        case TpmAlgId.Cfb:
                            algName = SymmetricAlgorithmNames.AesCbcPkcs7;
                            break;
                        default:
                            Globs.Throw<ArgumentException>("Unsupported mode (" + symDef.Mode + ") for algorithm " + symDef.Algorithm);
                            break;
                    }
                    break;
                case TpmAlgId.Tdes:
                    switch (symDef.Mode)
                    {
                        case TpmAlgId.Cbc:
                            algName = SymmetricAlgorithmNames.TripleDesCbc;
                            break;
                        case TpmAlgId.Ecb:
                            algName = SymmetricAlgorithmNames.TripleDesEcb;
                            break;
                        default:
                            Globs.Throw<ArgumentException>("Unsupported mode (" + symDef.Mode + ") for algorithm " + symDef.Algorithm);
                            break;
                    }
                    break;
                default:
                    Globs.Throw<ArgumentException>("Unsupported symmetric algorithm " + symDef.Algorithm);
                    break;
            }

            if (keyData == null)
            {
                keyData = Globs.GetRandomBytes(symDef.KeyBits / 8);
            }

            SymmetricKeyAlgorithmProvider algProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(algName);
            var key = algProvider.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(keyData));

            return key == null ? null : new SymmCipher(key, keyData, iv);
        }

        public static SymmCipher CreateFromPublicParms(IPublicParmsUnion parms)
        {
            switch (parms.GetUnionSelector())
            {
                case TpmAlgId.Rsa:
                    return Create((parms as RsaParms).symmetric);
                case TpmAlgId.Ecc:
                    return Create((parms as EccParms).symmetric);
                default:
                    Globs.Throw<ArgumentException>("CreateFromPublicParms: Unsupported algorithm");
                    return null;
            }
        }

        public static byte[] Encrypt(SymDefObject symDef, byte[] key, byte[] iv, byte[] dataToEncrypt)
        {
            using (SymmCipher cipher = Create(symDef, key, iv))
            {
                return cipher.Encrypt(dataToEncrypt);
            }
        }

        public static byte[] Decrypt(SymDefObject symDef, byte[] key, byte[] iv, byte[] dataToDecrypt)
        {
            using (SymmCipher cipher = Create(symDef, key, iv))
            {
                return cipher.Decrypt(dataToDecrypt);
            }
        }

        /// <summary>
        /// Performs the TPM-defined CFB encrypt using the associated algorithm.  This routine assumes that 
        /// the integrity value has been prepended.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] data, byte[] iv = null)
        {
            byte[] paddedData;
            int unpadded = data.Length % BlockSize;
            paddedData = unpadded == 0 ? data : Globs.AddZeroToEnd(data, BlockSize - unpadded);
            IBuffer buf = CryptographicEngine.Encrypt(Key, CryptographicBuffer.CreateFromByteArray(paddedData), CryptographicBuffer.CreateFromByteArray(iv ?? IV));
            CryptographicBuffer.CopyToByteArray(buf, out paddedData);
            return unpadded == 0 ? paddedData : Globs.CopyData(paddedData, 0, data.Length);
        }

        public byte[] Decrypt(byte[] data, byte[] iv = null)
        {
            byte[] paddedData;
            int unpadded = data.Length % BlockSize;
            paddedData = unpadded == 0 ? data : Globs.AddZeroToEnd(data, BlockSize - unpadded);
            IBuffer buf = CryptographicEngine.Decrypt(Key, CryptographicBuffer.CreateFromByteArray(paddedData), CryptographicBuffer.CreateFromByteArray(iv ?? IV));
            CryptographicBuffer.CopyToByteArray(buf, out paddedData);
            return paddedData;
        }

        /// <summary>
        /// De-envelope inner-wrapped duplication blob.
        /// TODO: Move this to TpmPublic and make it fully general
        /// </summary>
        /// <param name="exportedPrivate"></param>
        /// <param name="encAlg"></param>
        /// <param name="encKey"></param>
        /// <param name="nameAlg"></param>
        /// <param name="name"></param>
        /// <returns></returns>
        public static Sensitive SensitiveFromDuplicateBlob(TpmPrivate exportedPrivate, SymDefObject encAlg, byte[] encKey, TpmAlgId nameAlg, byte[] name)
        {
            byte[] dupBlob = exportedPrivate.buffer;
            byte[] sensNoLen;
            using (SymmCipher c = Create(encAlg, encKey))
            {
                byte[] innerObject = c.Decrypt(dupBlob);
                byte[] innerIntegrity, sensitive;

                KDF.Split(innerObject,
                          16 + CryptoLib.DigestSize(nameAlg) * 8,
                          out innerIntegrity,
                          8 * (innerObject.Length - CryptoLib.DigestSize(nameAlg) - 2),
                          out sensitive);

                byte[] expectedInnerIntegrity = Marshaller.ToTpm2B(CryptoLib.HashData(nameAlg, sensitive, name));

                if (!Globs.ArraysAreEqual(expectedInnerIntegrity, innerIntegrity))
                {
                    Globs.Throw("SensitiveFromDuplicateBlob: Bad inner integrity");
                }

                sensNoLen = Marshaller.Tpm2BToBuffer(sensitive);
            }
            var sens = Marshaller.FromTpmRepresentation<Sensitive>(sensNoLen);
            return sens;
        }

        public void Dispose()
        {
        }
    }
}
