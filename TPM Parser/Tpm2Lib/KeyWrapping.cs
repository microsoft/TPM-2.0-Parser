/*++

Copyright (c) 2010-2015 Microsoft Corporation
Microsoft Confidential

*/
using System.Diagnostics;

namespace Tpm2Lib
{
    /// <summary>
    /// This class contains algorithms for wrapping and unwrapping TPM objects
    /// </summary>
    internal class KeyWrapper
    {
        private KeyWrapper()
        {
        }

        /// <summary>
        /// Create an enveloped (encrypted and integrity protected) private area from a provided sensitive.
        /// </summary>
        /// <param name="iv"></param>
        /// <param name="sens"></param>
        /// <param name="nameHash"></param>
        /// <param name="publicName"></param>
        /// <param name="symWrappingAlg"></param>
        /// <param name="symKey"></param>
        /// <param name="parentNameAlg"></param>
        /// <param name="parentSeed"></param>
        /// <param name="f"></param>
        /// <returns></returns>
        public static byte[] CreatePrivateFromSensitive(
            SymDefObject symWrappingAlg,
            byte[] symKey,
            byte[] iv,
            Sensitive sens,
            TpmAlgId nameHash,
            byte[] publicName,
            TpmAlgId parentNameAlg,
            byte[] parentSeed)
        {
            // ReSharper disable once InconsistentNaming
            byte[] tpm2bIv = Marshaller.ToTpm2B(iv);

            byte[] sensitive = sens.GetTpmRepresentation();

            // ReSharper disable once InconsistentNaming
            byte[] tpm2bSensitive = Marshaller.ToTpm2B(sensitive);

            byte[] encSensitive = SymmCipher.Encrypt(symWrappingAlg, symKey, iv, tpm2bSensitive);
            byte[] decSensitive = SymmCipher.Decrypt(symWrappingAlg, symKey, iv, encSensitive);

            var hmacKeyBits = CryptoLib.DigestSize(parentNameAlg) * 8;
            byte[] hmacKey = KDF.KDFa(parentNameAlg, parentSeed, "INTEGRITY", new byte[0], new byte[0], hmacKeyBits);

            byte[] dataToHmac = Marshaller.GetTpmRepresentation(tpm2bIv,
                                                                encSensitive,
                                                                publicName);

            byte[] outerHmac = CryptoLib.HmacData(parentNameAlg, hmacKey, dataToHmac);

            byte[] priv = Marshaller.GetTpmRepresentation(Marshaller.ToTpm2B(outerHmac),
                                                          tpm2bIv,
                                                          encSensitive);
            return priv;
        }
    }
}
