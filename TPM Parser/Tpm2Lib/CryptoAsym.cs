/*++

Copyright (c) 2010-2015 Microsoft Corporation
Microsoft Confidential

*/

using System;
using System.Linq;
using System.Numerics;
using System.Diagnostics;
using System.Text;
using Windows.Storage.Streams;

using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;

namespace Tpm2Lib
{
    public class BCryptRsaKeyBlob : TpmStructureBase
    {
        [MarshalAs(0)]
        public uint Magic;
        [MarshalAs(1)]
        public uint BitLength;
        [MarshalAs(2)]
        public uint cbPublicExp;
        [MarshalAs(3)]
        public uint cbModulus;
        [MarshalAs(4)]
        public uint cbPrime1;
        [MarshalAs(5)]
        public uint cbPrime2;
    } // struct RsaPubKey

    /// <summary>
    /// AsymCryptoSystem is a helper class for doing asymmetric cryptography using TPM data
    /// structures. It currently does ECC and RSA signing, decryption and ECDH key exchange.
    /// 
    /// NOTE: The methods of this class do not attempt to replicate parameters validation
    ///       performed by the TPM.
    /// </summary>
    public sealed class AsymCryptoSystem : IDisposable
    {
        private TpmPublic PublicParms;

        public const uint BCRYPT_RSAPUBLIC_MAGIC = 0x31415352;      // RSA1
        public const uint BCRYPT_RSAPRIVATE_MAGIC = 0x32415352;     // RSA2

        public const string BCRYPT_RSAPUBLIC_BLOB = "RSAPUBLICBLOB";
        public const string BCRYPT_RSAPRIVATE_BLOB = "RSAPRIVATEBLOB";
        public const string BCRYPT_RSAFULLPRIVATE_BLOB = "RSAFULLPRIVATEBLOB";
        public const string BCRYPT_ECCPUBLIC_BLOB = "ECCPUBLICBLOB";

        private CryptographicKey Key;

        public AsymCryptoSystem()
        {
        }

        /// <summary>
        /// Create a new random software key (public and private) matching the parameters in keyParams.
        /// </summary>
        /// <param name="keyParams"></param>
        /// <returns></returns>
        public AsymCryptoSystem(TpmPublic keyParams)
        {
            TpmAlgId keyAlgId = keyParams.type;
            PublicParms = keyParams.Copy();

            switch (keyAlgId)
            {
                case TpmAlgId.Rsa:
                    {
                        var rsaParams = keyParams.parameters as RsaParms;
                        AsymmetricKeyAlgorithmProvider RsaProvider = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaOaepSha256);
                        Key = RsaProvider.CreateKeyPair(rsaParams.keyBits);
                        IBuffer keyBlobBuffer = Key.ExportPublicKey(CryptographicPublicKeyBlobType.BCryptPublicKey);
                        byte[] blob;
                        CryptographicBuffer.CopyToByteArray(keyBlobBuffer, out blob);
                        var m = new Marshaller(blob, DataRepresentation.LittleEndian);
                        var header = m.Get<BCryptRsaKeyBlob>();
                        var modulus = m.GetArray<byte>((int)header.cbModulus);
                        var pubId = new Tpm2bPublicKeyRsa(modulus);
                        PublicParms.unique = pubId;
                        break;
                    }
                case TpmAlgId.Ecc:
                    {
                        var eccParms = keyParams.parameters as EccParms;
                        var alg = RawEccKey.GetEccAlg(keyParams);
                        if (alg == null)
                        {
                            Globs.Throw<ArgumentException>("Unknown ECC curve");
                            return;
                        }
                        AsymmetricKeyAlgorithmProvider EccProvider = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(alg);
                        Key = EccProvider.CreateKeyPair((uint)RawEccKey.GetKeyLength(eccParms.curveID));
                        break;
                    }
                default:
                    Globs.Throw<ArgumentException>("Algorithm not supported");
                    break;
            }
        }

        private static void WriteToBuffer(ref byte[] buffer, ref int offset, uint value)
        {
            buffer[offset + 3] = (byte)((value >> 24) & 0xff);
            buffer[offset + 2] = (byte)((value >> 16) & 0xff);
            buffer[offset + 1] = (byte)((value >> 8) & 0xff);
            buffer[offset + 0] = (byte)(value & 0xff);
            offset += 4;
        }

        private static void WriteToBuffer(ref byte[] buffer, ref int offset, byte[] value)
        {
            if (value.Length <= buffer.Length - offset)
            {
                Array.Copy(value, 0, buffer, offset, value.Length);
                offset += value.Length;
            }
        }

        /// <summary>
        /// Create a new AsymCryptoSystem from TPM public parameter. This can then
        /// be used to validate TPM signatures or encrypt data destined for a TPM.  
        /// </summary>
        /// <param name="pubKey"></param>
        /// <returns></returns>
        public static AsymCryptoSystem CreateFrom(TpmPublic pubKey, TpmPrivate privKey = null)
        {
            var cs = new AsymCryptoSystem();

            TpmAlgId keyAlgId = pubKey.type;
            cs.PublicParms = pubKey.Copy();

            // Create an algorithm provider from the provided PubKey
            switch (keyAlgId)
            {
                case TpmAlgId.Rsa:
                    {
                        RawRsa rr = null;
                        byte[] prime1 = null,
                                prime2 = null;
                        if (privKey != null)
                        {
                            rr = new RawRsa(pubKey, privKey);
                            prime1 = RawRsa.ToBigEndian(rr.P);
                            prime2 = RawRsa.ToBigEndian(rr.Q);
                        }
                        var rsaParams = (RsaParms)pubKey.parameters;
                        var exponent = rsaParams.exponent != 0
                                                ? Globs.HostToNet(rsaParams.exponent)
                                                : RsaParms.DefaultExponent;
                        var modulus = (pubKey.unique as Tpm2bPublicKeyRsa).buffer;
                        AsymmetricKeyAlgorithmProvider rsaProvider = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaOaepSha256);

                        uint primeLen1 = 0, primeLen2 = 0;
                        // Compute the size of BCRYPT_RSAKEY_BLOB
                        int rsaKeySize = exponent.Length + modulus.Length + 24;
                        if (prime1 != null && prime1.Length > 0)
                        {
                            if (prime2 == null || prime2.Length == 0)
                            {
                                Globs.Throw<ArgumentException>("LoadRSAKey(): The second prime is missing");
                                return null;
                            }
                            primeLen1 = (uint)prime1.Length;
                            primeLen2 = (uint)prime2.Length;
                            rsaKeySize += prime1.Length + prime2.Length;
                        }
                        else if (prime2 != null && prime2.Length > 0)
                        {
                            Globs.Throw<ArgumentException>("LoadRSAKey(): The first prime is missing");
                            return null;
                        }

                        var rsaKey = new byte[rsaKeySize];

                        // Initialize BCRYPT_RSAKEY_BLOB
                        int offset = 0;
                        WriteToBuffer(ref rsaKey, ref offset, primeLen1 == 0 ?
                                        BCRYPT_RSAPUBLIC_MAGIC : BCRYPT_RSAPRIVATE_MAGIC);
                        WriteToBuffer(ref rsaKey, ref offset, (uint)modulus.Length * 8);
                        WriteToBuffer(ref rsaKey, ref offset, (uint)exponent.Length);
                        WriteToBuffer(ref rsaKey, ref offset, (uint)modulus.Length);
                        WriteToBuffer(ref rsaKey, ref offset, primeLen1);
                        WriteToBuffer(ref rsaKey, ref offset, primeLen1);
                        WriteToBuffer(ref rsaKey, ref offset, exponent);
                        WriteToBuffer(ref rsaKey, ref offset, modulus);
                        if (primeLen1 != 0)
                        {
                            WriteToBuffer(ref rsaKey, ref offset, prime1);
                            WriteToBuffer(ref rsaKey, ref offset, prime2);
                        }

                        IBuffer rsaBuffer = CryptographicBuffer.CreateFromByteArray(rsaKey);

                        if (primeLen1 == 0)
                        {
                            cs.Key = rsaProvider.ImportPublicKey(rsaBuffer, CryptographicPublicKeyBlobType.BCryptPublicKey);
                        }
                        else
                        {
                            cs.Key = rsaProvider.ImportKeyPair(rsaBuffer, CryptographicPrivateKeyBlobType.BCryptPrivateKey);
                        }
                        break;
                    }
                case TpmAlgId.Ecc:
                    {
                        var eccParms = (EccParms)pubKey.parameters;
                        var eccPub = (EccPoint)pubKey.unique;
                        var algId = RawEccKey.GetEccAlg(pubKey);
                        if (algId == null)
                        {
                            return null;
                        }
                        bool isEcdsa = eccParms.scheme.GetUnionSelector() == TpmAlgId.Ecdsa;
                        byte[] keyBlob = RawEccKey.GetKeyBlob(eccPub.x, eccPub.y, keyAlgId,
                                                                !isEcdsa, eccParms.curveID);
                        AsymmetricKeyAlgorithmProvider eccProvider = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(algId);
                        cs.Key = eccProvider.ImportKeyPair(CryptographicBuffer.CreateFromByteArray(keyBlob));
                        break;
                    }
                default:
                    Globs.Throw<ArgumentException>("Algorithm not supported");
                    cs = null;
                    break;
            }
            return cs;
        }

        public byte[] Export(string bcryptBlobType)
        {
            if (string.IsNullOrEmpty(bcryptBlobType))
            {
                return null;
            }
            IBuffer buf;
            if (bcryptBlobType == BCRYPT_RSAPRIVATE_BLOB)
            {
                buf = Key.Export(CryptographicPrivateKeyBlobType.BCryptPrivateKey);
            }
            else if (bcryptBlobType == BCRYPT_RSAPUBLIC_BLOB)
            {
                buf = Key.ExportPublicKey(CryptographicPublicKeyBlobType.BCryptPublicKey);
            }
            else
            {
                return null;
            }
            byte[] keyBlob;
            CryptographicBuffer.CopyToByteArray(buf, out keyBlob);
            return keyBlob;
        }

        public byte[] ExportLegacyBlob()
        {
            IBuffer buf = Key.Export(CryptographicPrivateKeyBlobType.BCryptPrivateKey);
            byte[] privBlob;
            CryptographicBuffer.CopyToByteArray(buf, out privBlob);
            return privBlob;
        }

        public byte[] ExportCspBlob()
        {
            return ExportLegacyBlob();
        }

        /// <summary>
        /// Get PublicParams.
        /// </summary>
        /// <returns></returns>
        public TpmPublic GetPublicParms()
        {
            return PublicParms;
        }

        public Sensitive GetSensitive()
        {
            TpmPublic fromCspPublic;
            TpmPrivate fromCspPrivate = Csp.CspToTpm(ExportCspBlob(), out fromCspPublic);
            var m = new Marshaller(fromCspPrivate.buffer);
            ushort privSize = m.Get<UInt16>();
            if (fromCspPrivate.buffer.Length != privSize + 2)
            {
                Globs.Throw("Invalid key blob");
            }
            return m.Get<Sensitive>();
        }

        /// <summary>
        /// Sign using the hash algorithm specified during object instantiation. 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public ISignatureUnion Sign(byte[] data)
        {
            return SignData(data, TpmAlgId.Null);
        }

        /// <summary>
        /// Sign using a non-default hash algorithm.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="sigHash"></param>
        /// <returns></returns>
        public ISignatureUnion SignData(byte[] data, TpmAlgId sigHash)
        {
            var rsaParams = PublicParms.parameters as RsaParms;
            if (rsaParams != null)
            {
                TpmAlgId sigScheme = rsaParams.scheme.GetUnionSelector();

                switch (sigScheme)
                {
                    case TpmAlgId.Rsassa:
                        {
                            if (sigHash == TpmAlgId.Null)
                            {
                                sigHash = (rsaParams.scheme as SigSchemeRsassa).hashAlg;
                            }
                            byte[] digest = CryptoLib.HashData(sigHash, data);
                            IBuffer sigBuffer = CryptographicEngine.SignHashedData(Key, CryptographicBuffer.CreateFromByteArray(digest));
                            byte[] sig;
                            CryptographicBuffer.CopyToByteArray(sigBuffer, out sig);
                            return new SignatureRsassa(sigHash, sig);
                        }
                    case TpmAlgId.Rsapss:
                        {
                            Globs.Throw<ArgumentException>("SignData(): PSS scheme is not supported");
                            return null;
                        }
                }
                Globs.Throw<ArgumentException>("Unsupported signature scheme");
                return null;
            }

            var eccParms = PublicParms.parameters as EccParms;
            if (eccParms != null)
            {
                if (eccParms.scheme.GetUnionSelector() != TpmAlgId.Ecdsa)
                {
                    Globs.Throw<ArgumentException>("Unsupported ECC sig scheme");
                    return null;
                }
                if (sigHash == TpmAlgId.Null)
                {
                    sigHash = (eccParms.scheme as SigSchemeEcdsa).hashAlg;
                }
                byte[] digest = CryptoLib.HashData(sigHash, data);
                IBuffer buf = CryptographicEngine.SignHashedData(Key, CryptographicBuffer.CreateFromByteArray(digest));
                byte[] sig;
                CryptographicBuffer.CopyToByteArray(buf, out sig);
                int len = sig.Length / 2;
                return new SignatureEcdsa(sigHash, Globs.CopyData(sig, 0, len), Globs.CopyData(sig, len, len));
            }

            // Should never be here
            Globs.Throw("VerifySignature: Unrecognized asymmetric algorithm");
            return null;
        } // SignData()

        /// <summary>
        /// Verifies the signature over a digest.
        /// 
        /// If sigHashAlg parameter specifies non-null hash algorithm, it is used for
        /// the signature checking purposes. Otherwise the hash from the signing scheme
        /// of the signing key specification is used.
        /// 
        /// NOTE: Procedure of the hash algorithm selection used by this method does
        ///       not attempt to reproduce the the one used by the TPM.
        /// </summary>
        /// <param name="signedData">Digest to check against the signature</param>
        /// <param name="signature">The signature</param>
        /// <param name="sigHashAlg">Optional hash algorithm to override the one in the signing key specification</param>
        /// <returns>True if the verification succeeds.</returns>
        public bool VerifySignatureOverHash(byte[] digest, ISignatureUnion signature, TpmAlgId sigHashAlg = TpmAlgId.Null)
        {
            return VerifySignature(digest ?? new byte[0], true, signature, sigHashAlg);
        }

        /// <summary>
        /// Verifies the signature over the digest computed from the specified data buffer.
        /// 
        /// If sigHashAlg parameter specifies non-null hash algorithm, it is used to compute
        /// the digest and for the signature checking purposes. Otherwise the hash from
        /// the signing scheme of the signing key specification is used.
        /// 
        /// NOTE: Procedure of the hash algorithm selection used by this method does
        ///       not attempt to reproduce the the one used by the TPM.
        /// </summary>
        /// <param name="signedData">Data buffer used to check against the signature</param>
        /// <param name="signature">The signature</param>
        /// <param name="sigHashAlg">Optional hash algorithm to override the one in the signing key specification</param>
        /// <returns>True if the verification succeeds.</returns>
        public bool VerifySignatureOverData(byte[] signedData, ISignatureUnion signature, TpmAlgId sigHashAlg = TpmAlgId.Null)
        {
            return VerifySignature(signedData, false, signature, sigHashAlg);
        }

        private bool VerifySignature(byte[] data, bool dataIsDigest, ISignatureUnion signature, TpmAlgId sigHash)
        {
            var rsaParams = PublicParms.parameters as RsaParms;
            if (rsaParams != null)
            {
                var sig = signature as SignatureRsa;
                TpmAlgId sigScheme = sig.GetUnionSelector();
                TpmAlgId keyScheme = rsaParams.scheme.GetUnionSelector();

                if (keyScheme != TpmAlgId.Null && keyScheme != sigScheme)
                {
                    Globs.Throw<ArgumentException>("Key scheme and signature scheme do not match");
                    return false;
                }
                if (sigHash == TpmAlgId.Null)
                {
                    sigHash = (rsaParams.scheme as SchemeHash).hashAlg;
                }
                if (sigHash != sig.hash)
                {
                    Globs.Throw<ArgumentException>("Key scheme hash and signature scheme hash do not match");
                    return false;
                }

                byte[] digest = dataIsDigest ? data : CryptoLib.HashData(sigHash, data);

                if (sigScheme == TpmAlgId.Rsassa)
                {
                    return CryptographicEngine.VerifySignatureWithHashInput(Key, CryptographicBuffer.CreateFromByteArray(digest), CryptographicBuffer.CreateFromByteArray(sig.sig));
                }
                if (sigScheme == TpmAlgId.Rsapss)
                {
                    Globs.Throw<ArgumentException>("VerifySignature(): PSS scheme is not supported");
                    return false;
                }
                Globs.Throw<ArgumentException>("VerifySignature(): Unrecognized scheme");
                return false;
            }

            var eccParms = PublicParms.parameters as EccParms;
            if (eccParms != null)
            {
                if (eccParms.scheme.GetUnionSelector() != TpmAlgId.Ecdsa)
                {
                    Globs.Throw<ArgumentException>("Unsupported ECC sig scheme");
                    return false;
                }
                if (sigHash == TpmAlgId.Null)
                {
                    sigHash = (eccParms.scheme as SigSchemeEcdsa).hashAlg;
                }

                byte[] digest = dataIsDigest ? data : CryptoLib.HashData(sigHash, data);
                var sig = signature as SignatureEcdsa;
                byte[] sigBlob = Globs.Concatenate(sig.signatureR, sig.signatureS);
                return CryptographicEngine.VerifySignatureWithHashInput(Key, CryptographicBuffer.CreateFromByteArray(digest), CryptographicBuffer.CreateFromByteArray(sigBlob));
            }

            // Should never be here
            Globs.Throw("VerifySignature: Unrecognized asymmetric algorithm");
            return false;
        } // VerifySignature()

        /// <summary>
        /// Generates the key exchange key and the public part of the ephemeral key
        /// using specified encoding parameters in the KDF (ECC only).
        /// </summary>
        /// <param name="encodingParms"></param>
        /// <param name="decryptKeyNameAlg"></param>
        /// <param name="ephemPub"></param>
        /// <returns>key exchange key blob</returns>
        public byte[] EcdhGetKeyExchangeKey(byte[] encodingParms, TpmAlgId decryptKeyNameAlg, out EccPoint ephemPub)
        {
            var eccParms = (EccParms)PublicParms.parameters;
            int keyBits = RawEccKey.GetKeyLength(eccParms.curveID);
            byte[] keyExchangeKey = null;
            ephemPub = new EccPoint();

            // Make a new ephemeral key
            var prov = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(RawEccKey.GetEccAlg(PublicParms));
            var ephKey = prov.CreateKeyPair((uint)keyBits);
            IBuffer ephPubBuf = ephKey.ExportPublicKey(CryptographicPublicKeyBlobType.BCryptEccFullPublicKey);
            byte[] ephPub;
            CryptographicBuffer.CopyToByteArray(ephPubBuf, out ephPub);

            IBuffer otherPubBuf = Key.ExportPublicKey(CryptographicPublicKeyBlobType.BCryptEccFullPublicKey);
            byte[] otherPub;
            CryptographicBuffer.CopyToByteArray(otherPubBuf, out otherPub);

            byte[] herPubX, herPubY;
            RawEccKey.KeyInfoFromPublicBlob(otherPub, out herPubX, out herPubY);

            byte[] myPubX, myPubY;
            RawEccKey.KeyInfoFromPublicBlob(ephPub, out myPubX, out myPubY);

            byte[] otherInfo = Globs.Concatenate(new[] { encodingParms, myPubX, herPubX });

            // The TPM uses the following number of bytes from the KDF
            int bytesNeeded = CryptoLib.DigestSize(decryptKeyNameAlg);
            keyExchangeKey = new byte[bytesNeeded];

            for (int pos = 0, count = 1, bytesToCopy = 0;
                 pos < bytesNeeded;
                 ++count, pos += bytesToCopy)
            {
                byte[] secretPrepend = Marshaller.GetTpmRepresentation((UInt32)count);
                string algName;
                KeyDerivationParameters deriveParams;
                switch (decryptKeyNameAlg)
                {
                    case TpmAlgId.Kdf1Sp800108:
                        algName = KeyDerivationAlgorithmNames.Sp800108CtrHmacSha256;
                        deriveParams = KeyDerivationParameters.BuildForSP800108(CryptographicBuffer.CreateFromByteArray(secretPrepend), CryptographicBuffer.CreateFromByteArray(otherInfo));
                        break;
                    case TpmAlgId.Kdf1Sp80056a:
                        algName = KeyDerivationAlgorithmNames.Sp80056aConcatSha256;
                        deriveParams = KeyDerivationParameters.BuildForSP80056a(CryptographicBuffer.ConvertStringToBinary(algName, BinaryStringEncoding.Utf8),
                            CryptographicBuffer.ConvertStringToBinary("TPM", BinaryStringEncoding.Utf8),
                            CryptographicBuffer.CreateFromByteArray(secretPrepend),
                            CryptographicBuffer.ConvertStringToBinary("", BinaryStringEncoding.Utf8),
                            CryptographicBuffer.CreateFromByteArray(otherInfo));
                        break;
                    case TpmAlgId.Kdf2:
                        algName = KeyDerivationAlgorithmNames.Pbkdf2Sha256;
                        deriveParams = KeyDerivationParameters.BuildForPbkdf2(CryptographicBuffer.CreateFromByteArray(secretPrepend), 1000);
                        break;
                    default:
                        Globs.Throw<ArgumentException>("wrong KDF name");
                        return null;
                }
                KeyDerivationAlgorithmProvider deriveProv = KeyDerivationAlgorithmProvider.OpenAlgorithm(algName);
                IBuffer keyMaterial = CryptographicEngine.DeriveKeyMaterial(Key, deriveParams, (uint)keyBits);
                byte[] fragment;
                CryptographicBuffer.CopyToByteArray(keyMaterial, out fragment);
                bytesToCopy = Math.Min(bytesNeeded - pos, fragment.Length);
                Array.Copy(fragment, 0, keyExchangeKey, pos, bytesToCopy);
            }
            ephemPub = new EccPoint(myPubX, myPubY);
            return keyExchangeKey;
        }

        TpmAlgId OaepHash
        {
            get
            {
                var rsaParams = (RsaParms)PublicParms.parameters;
                var hashAlg = PublicParms.nameAlg;
                if (rsaParams.scheme is SchemeOaep)
                    hashAlg = (rsaParams.scheme as SchemeOaep).hashAlg;
                else if (rsaParams.scheme is EncSchemeOaep)
                    hashAlg = (rsaParams.scheme as EncSchemeOaep).hashAlg;
                return hashAlg;
            }
        }

        /// <summary>
        /// Encrypt dataToEncrypt using the specified encodingParams (RSA only).
        /// </summary>
        /// <param name="dataToEncrypt"></param>
        /// <param name="label"></param>
        /// <returns></returns>
        public byte[] EncryptOaep(byte[] plainText, byte[] label)
        {
            if (plainText == null)
                plainText = new byte[0];
            if (label == null)
                label = new byte[0];
            var rr = new RawRsa(Key);
            byte[] cipherText = rr.OaepEncrypt(plainText, OaepHash, label); ;
            return cipherText;
        }

        public byte[] DecryptOaep(byte[] cipherText, byte[] label)
        {
            var rr = new RawRsa(Key);
            byte[] plainText = rr.OaepDecrypt(cipherText, OaepHash, label);
            return plainText;
        }

        public void Dispose()
        {
        }

        public class Csp
        {
            public enum AlgId : uint
            {
                CAlgRsaKeyX = 0x0000a400,   // CALG_RSA_KEYX
                CAlgRsaSign = 0x00002400    // CALG_RSA_SIGN
            }

            // _PUBLICKEYSTRUC
            public class PublicKeyStruc : TpmStructureBase
            {
                [MarshalAs(0)]
                public byte bType;
                [MarshalAs(1)]
                public byte bVersion;
                [MarshalAs(2)]
                public ushort reserved;
                [MarshalAs(3)]
                public AlgId aiKeyAlg;
            } // struct PublicKeyStruc

            // _RSAPUBKEY
            public class RsaPubKey : TpmStructureBase
            {
                [MarshalAs(0)]
                public uint magic;
                [MarshalAs(1)]
                public uint bitlen;
                [MarshalAs(2)]
                public uint pubexp;
            } // struct RsaPubKey


            public class PrivateKeyBlob : TpmStructureBase
            {
                [MarshalAs(0)]
                public PublicKeyStruc publicKeyStruc;

                [MarshalAs(1)]
                public RsaPubKey rsaPubKey
                {
                    get { return _rsaPubKey; }

                    set
                    {
                        _rsaPubKey = value;

                        int keyLen = (int)value.bitlen / 8;
                        modulus = new byte[keyLen];
                        prime1 = new byte[keyLen / 2];
                        prime2 = new byte[keyLen / 2];
                        exponent1 = new byte[keyLen / 2];
                        exponent2 = new byte[keyLen / 2];
                        coefficient = new byte[keyLen / 2];
                        privateExponent = new byte[keyLen / 2];
                    }
                }
                RsaPubKey _rsaPubKey;

                [MarshalAs(2, MarshalType.FixedLengthArray)]
                public byte[] modulus;
                [MarshalAs(3, MarshalType.FixedLengthArray)]
                public byte[] prime1;
                [MarshalAs(4, MarshalType.FixedLengthArray)]
                public byte[] prime2;
                [MarshalAs(5, MarshalType.FixedLengthArray)]
                public byte[] exponent1;
                [MarshalAs(6, MarshalType.FixedLengthArray)]
                public byte[] exponent2;
                [MarshalAs(7, MarshalType.FixedLengthArray)]
                public byte[] coefficient;
                [MarshalAs(8, MarshalType.FixedLengthArray)]
                public byte[] privateExponent;
            } // class PrivateKeyBlob


            // Trailing parameters are used to populate TpmPublic generated for the key from the blob.
            public static TpmPrivate CspToTpm(byte[] cspPrivateBlob, out TpmPublic tpmPub,
                                                TpmAlgId nameAlg = TpmAlgId.Sha1,
                                                ObjectAttr keyAttrs = ObjectAttr.Decrypt | ObjectAttr.UserWithAuth,
                                                IAsymSchemeUnion scheme = null,
                                                SymDefObject symDef = null)
            {
                if (scheme == null)
                {
                    scheme = new NullAsymScheme();
                }
                if (symDef == null)
                {
                    symDef = new SymDefObject();
                }

                var m = new Marshaller(cspPrivateBlob, DataRepresentation.LittleEndian);
                var cspPrivate = m.Get<Csp.PrivateKeyBlob>();
                var keyAlg = cspPrivate.publicKeyStruc.aiKeyAlg;
                if (keyAlg != Csp.AlgId.CAlgRsaKeyX && keyAlg != Csp.AlgId.CAlgRsaSign)
                {
                    Globs.Throw<NotSupportedException>("CSP blobs for keys of type " + keyAlg.ToString("X") + " are not supported");
                    tpmPub = new TpmPublic();
                    return new TpmPrivate();
                }

                var rsaPriv = new Tpm2bPrivateKeyRsa(Globs.ReverseByteOrder(cspPrivate.prime1));
                var sens = new Sensitive(new byte[0], new byte[0], rsaPriv);

                tpmPub = new TpmPublic(nameAlg, keyAttrs, new byte[0],
                                        new RsaParms(symDef,
                                                    scheme,
                                                    (ushort)cspPrivate.rsaPubKey.bitlen,
                                                    cspPrivate.rsaPubKey.pubexp),
                                        new Tpm2bPublicKeyRsa(Globs.ReverseByteOrder(cspPrivate.modulus)));

                return new TpmPrivate(sens.GetTpm2BRepresentation());
            }
        } // class Csp
    } // class AsymCryptoSystem

    public class RawRsa
    {
        internal int NumBits = 0;

        /// <summary>
        /// Modulus (internal key) = P * Q
        /// </summary>
        internal BigInteger N;

        /// <summary>
        /// Public (encryption) exponent (typically 65537)
        /// </summary>
        internal BigInteger E;

        /// <summary>
        ///  The first prime factor (private key)
        /// </summary>
        internal BigInteger P;

        /// <summary>
        ///  The second prime factor
        /// </summary>
        internal BigInteger Q;

        /// <summary>
        /// Private (decryption) exponent
        /// </summary>
        internal BigInteger D;

        internal BigInteger InverseQ;
        internal BigInteger DP;
        internal BigInteger DQ;

        internal int KeySize { get { return (NumBits + 7) / 8; } }

        /// <summary>
        /// Returns the public key in TPM-format
        /// </summary>
        /// <returns></returns>
        public byte[] Public { get { return ToBigEndian(N); } }

        /// <summary>
        /// Returns the RSA private key in TPM format (the first prime number)
        /// </summary>
        /// <returns></returns>
        public byte[] Private { get { return ToBigEndian(P); } }

        /// <summary>
        ///  Generates new key pair using OS CSP
        /// </summary>
        /// <param name="numBits"></param>
        /// <param name="publicExponent"></param>
        public RawRsa(int numBits, int publicExponent = 65537)
        {
            AsymmetricKeyAlgorithmProvider prov = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaOaepSha256);
            CryptographicKey key = prov.CreateKeyPair((uint)numBits);
            IBuffer buf = key.Export(CryptographicPrivateKeyBlobType.BCryptPrivateKey);
            byte[] blob;
            CryptographicBuffer.CopyToByteArray(buf, out blob);

            var m = new Marshaller(blob, DataRepresentation.LittleEndian);
            var header = m.Get<BCryptRsaKeyBlob>();
            E = FromBigEndian(m.GetArray<byte>((int)header.cbPublicExp));
            N = FromBigEndian(m.GetArray<byte>((int)header.cbModulus));
            P = FromBigEndian(m.GetArray<byte>((int)header.cbPrime1));
            Q = FromBigEndian(m.GetArray<byte>((int)header.cbPrime2));
            DP = FromBigEndian(m.GetArray<byte>((int)header.cbPrime1));
            DQ = FromBigEndian(m.GetArray<byte>((int)header.cbPrime2));
            InverseQ = FromBigEndian(m.GetArray<byte>((int)header.cbPrime1));
            D = FromBigEndian(m.GetArray<byte>((int)header.cbModulus));
        }

        public RawRsa(CryptographicKey key)
        {
            IBuffer buf = key.Export(CryptographicPrivateKeyBlobType.BCryptPrivateKey);
            byte[] blob;
            CryptographicBuffer.CopyToByteArray(buf, out blob);

            var m = new Marshaller(blob, DataRepresentation.LittleEndian);
            var header = m.Get<BCryptRsaKeyBlob>();
            E = FromBigEndian(m.GetArray<byte>((int)header.cbPublicExp));
            N = FromBigEndian(m.GetArray<byte>((int)header.cbModulus));
            P = FromBigEndian(m.GetArray<byte>((int)header.cbPrime1));
            Q = FromBigEndian(m.GetArray<byte>((int)header.cbPrime2));
            DP = FromBigEndian(m.GetArray<byte>((int)header.cbPrime1));
            DQ = FromBigEndian(m.GetArray<byte>((int)header.cbPrime2));
            InverseQ = FromBigEndian(m.GetArray<byte>((int)header.cbPrime1));
            D = FromBigEndian(m.GetArray<byte>((int)header.cbModulus));
        }

    /// <summary>
    /// Instantiates the object using a TPM generated key pair
    /// </summary>
    /// <param name="pub"></param>
    /// <param name="priv"></param>
    public RawRsa(TpmPublic pub, TpmPrivate priv)
        {
            var m = new Marshaller(priv.buffer);
            var privSize = m.Get<UInt16>();
            // Assert that the private key blob is in plain text 
            Debug.Assert(priv.buffer.Length == privSize + 2);
            var sens = m.Get<Sensitive>();
            Init(pub, sens.sensitive as Tpm2bPrivateKeyRsa);
        }

        void Init(TpmPublic pub, Tpm2bPrivateKeyRsa priv)
        {
            var parms = pub.parameters as RsaParms;

            NumBits = parms.keyBits;

            E = new BigInteger(parms.exponent == 0 ? RsaParms.DefaultExponent
                                                    : BitConverter.GetBytes(parms.exponent));
            N = FromBigEndian((pub.unique as Tpm2bPublicKeyRsa).buffer);
            P = FromBigEndian(priv.buffer);
            Q = N / P;
            Debug.Assert(N % P == BigInteger.Zero);

            BigInteger PHI = N - (P + Q - BigInteger.One);
            D = ModInverse(E, PHI);
            InverseQ = ModInverse(Q, P);
            DP = D % (P - BigInteger.One);
            DQ = D % (Q - BigInteger.One);
        }

        public static byte[] GetLabel(string label)
        {
            return GetLabel(Encoding.ASCII.GetBytes(label));
        }

        public static byte[] GetLabel(byte[] data)
        {
            if (data.Length == 0)
            {
                return data;
            }
            int labelSize = 0;
            while (labelSize < data.Length && data[labelSize++] != 0)
            {
                continue;
            }
            var label = new byte[labelSize + (data[labelSize - 1] != 0 ? 1 : 0)];
            Array.Copy(data, label, labelSize);
            return label;
        }

        internal static BigInteger ModInverse(BigInteger a, BigInteger b)
        {
            BigInteger dividend = a % b;
            BigInteger divisor = b;

            BigInteger lastX = BigInteger.One;
            BigInteger currX = BigInteger.Zero;

            while (divisor.Sign > 0)
            {
                BigInteger quotient = dividend / divisor;
                BigInteger remainder = dividend % divisor;

                if (remainder.Sign <= 0)
                {
                    break;
                }

                BigInteger nextX = lastX - currX * quotient;

                lastX = currX;
                currX = nextX;

                dividend = divisor;
                divisor = remainder;
            }

            if (divisor != BigInteger.One)
            {
                throw new Exception("ModInverse(): Not coprime");
            }

            return (currX.Sign < 0 ? currX + b : currX);
        }

        /// <summary>
        /// Translate a byte array representing a big-endian (MSB first, possibly > 0x7F)
        /// TPM-style number to a BigInteger.
        /// </summary>
        /// <param name="b"></param>
        /// <returns></returns>
        public static BigInteger FromBigEndian(byte[] b)
        {
            return new BigInteger(ToLittleEndian(b));
        }

        /// <summary>
        /// Translates a BigInt into a TPM-style big-endian byte array.
        /// By default removes MSB-zeros.
        /// If sizeWanted is specified, pads with MSB-zeros to desired length.
        /// </summary>
        /// <param name="b"></param>
        /// <param name="sizeWanted"></param>
        /// <returns></returns>
        public static byte[] ToBigEndian(BigInteger b, int sizeWanted = -1)
        {
            return ToBigEndian(b.ToByteArray());
        }

        /// <summary>
        /// Translate a byte array representing a big-endian (MSB first, possibly > 0x7F)
        /// TPM-style number to the little endian representation.
        /// </summary>
        /// <param name="b"></param>
        /// <returns></returns>
        internal static byte[] ToLittleEndian(byte[] b)
        {
            int len = b.Length;
            var b2 = new byte[len + (b[0] > 0x7F ? 1 : 0)];

            for (int j = 0; j < len; j++)
            {
                b2[j] = b[len - 1 - j];
            }
            return b2;
        }

        /// <summary>
        /// Translates a little endian number represented as a byte array to TPM-style
        /// big-endian byte array. By default removes MSB-zeros.
        /// If sizeWanted is specified, pads with MSB-zeros to desired length.
        /// </summary>
        /// <param name="b"></param>
        /// <param name="sizeWanted"></param>
        /// <returns></returns>
        internal static byte[] ToBigEndian(byte[] b, int sizeWanted = -1)
        {
            int len = b.Length;

            // Count trailing zeros (MSB zeros to be removed)
            while (len > 0 && b[len - 1] == 0)
            {
                --len;
            }
            if (sizeWanted == -1)
            {
                sizeWanted = len;
            }

            int pad = sizeWanted - len;
            if (pad < 0)
            {
                Globs.Throw<ArgumentException>("ToBigEndian(): Too short size requested");
                return new byte[0];
            }

            var b2 = new byte[sizeWanted];

            for (int j = 0; j < len; j++)
            {
                b2[j + pad] = b[len - 1 - j];
            }
            return b2;
        }

        public byte[] RawEncrypt(byte[] plain)
        {
            BigInteger plainX = FromBigEndian(plain);
            BigInteger cipher = BigInteger.ModPow(plainX, E, N);
            byte[] cipherX = ToBigEndian(cipher, KeySize);
            return cipherX;
        }

        public byte[] RawDecrypt(byte[] cipher)
        {
            BigInteger cipherX = FromBigEndian(cipher);
            BigInteger plain = BigInteger.ModPow(cipherX, D, N);
            byte[] plainX = ToBigEndian(plain, KeySize);
            return plainX;
        }

        public byte[] OaepEncrypt(byte[] data, TpmAlgId hashAlg, byte[] encodingParms)
        {
            if (data.Length == 0)
            {
                Globs.Throw<ArgumentException>("OaepEncrypt: Empty data buffer");
                return new byte[0];
            }
            int encLen = NumBits / 8;
            byte[] zeroTermEncoding = GetLabel(encodingParms);
            byte[] encoded = CryptoEncoders.OaepEncode(data, zeroTermEncoding, hashAlg, encLen);
            BigInteger message = FromBigEndian(encoded);
            BigInteger cipher = BigInteger.ModPow(message, E, N);
            byte[] encMessageBigEnd = ToBigEndian(cipher, KeySize);
            return encMessageBigEnd;
        }

        public byte[] OaepDecrypt(byte[] cipherText, TpmAlgId hashAlg, byte[] encodingParms)
        {
            byte[] zeroTermEncoding = GetLabel(encodingParms);
            BigInteger cipher = FromBigEndian(cipherText);
            BigInteger plain = BigInteger.ModPow(cipher, D, N);
            byte[] encMessage = ToBigEndian(plain, KeySize - 1);
            byte[] message;

            // Hack - be robust to leading zeros
            while (true)
            {
                bool decodeOk = CryptoEncoders.OaepDecode(encMessage, zeroTermEncoding, hashAlg, out message);
                if (decodeOk)
                {
                    break;
                }
                encMessage = Globs.AddZeroToBeginning(encMessage);
            }
            return message;
        }

        public byte[] PssSign(byte[] m, TpmAlgId hashAlg)
        {
            // The TPM uses the maximum salt length
            int defaultPssSaltLength = 0; // KeySize - CryptoLib.DigestSize(hashAlg) - 1 - 1;

            // Encode
            byte[] em = CryptoEncoders.PssEncode(m, hashAlg, defaultPssSaltLength, NumBits - 1);
            BigInteger message = FromBigEndian(em);

            // Sign
            BigInteger sig = BigInteger.ModPow(message, D, N);
            byte[] signature = ToBigEndian(sig, KeySize);
            return signature;
        }

        public bool PssVerify(byte[] m, byte[] signature, TpmAlgId hashAlg)
        {
            // The TPM uses the maximum salt length
            int defaultPssSaltLength = 0; //  KeySize - CryptoLib.DigestSize(hashAlg) - 1 - 1;
            BigInteger sig = FromBigEndian(signature);
            BigInteger emx = BigInteger.ModPow(sig, E, N);

            byte[] em = ToBigEndian(emx, KeySize);

            bool ok = CryptoEncoders.PssVerify(m, em, defaultPssSaltLength, NumBits - 1, hashAlg);
            return ok;
        }

        public byte[] PkcsSign(byte[] m, TpmAlgId hashAlg)
        {
            int k = KeySize;
            byte[] em = CryptoEncoders.Pkcs15Encode(m, k, hashAlg);
            BigInteger message = FromBigEndian(em);
            BigInteger sig = BigInteger.ModPow(message, D, N);
            byte[] signature = ToBigEndian(sig, KeySize);
            return signature;
        }

        public bool PkcsVerify(byte[] m, byte[] s, TpmAlgId hashAlg)
        {
            if (s.Length != KeySize)
            {
                Globs.Throw<ArgumentException>("PkcsVerify: Invalid signature");
                return false;
            }
            int k = KeySize;
            BigInteger sig = FromBigEndian(s);
            BigInteger emx = BigInteger.ModPow(sig, E, N);

            byte[] emDecrypted = ToBigEndian(emx, KeySize);

            byte[] emPrime = CryptoEncoders.Pkcs15Encode(m, k, hashAlg);
            if (!Globs.ArraysAreEqual(emPrime, emDecrypted))
            {
                return false;
            }
            return true;
        }
    }

    internal class RawEccKey
    {
        internal struct EccInfo
        {
            internal uint Magic;
            internal bool Public;   // Not private
            internal int KeyLength; // Bits
            internal bool Ecdh;     // Not ECDSA
        }

        internal static EccInfo[] AlgInfo = {

            //#define BCRYPT_ECDH_PUBLIC_P256_MAGIC   0x314B4345  // ECK1
            new EccInfo {Magic = 0x314B4345, KeyLength = 256, Ecdh = true, Public = true},
            //#define BCRYPT_ECDH_PRIVATE_P256_MAGIC  0x324B4345  // ECK2
            new EccInfo {Magic = 0x324B4345, KeyLength = 256, Ecdh = true, Public = false},
            //#define BCRYPT_ECDH_PUBLIC_P384_MAGIC   0x334B4345  // ECK3
            new EccInfo {Magic = 0x334B4345, KeyLength = 384, Ecdh = true, Public = true},
            //#define BCRYPT_ECDH_PRIVATE_P384_MAGIC  0x344B4345  // ECK4
            new EccInfo {Magic = 0x344B4345, KeyLength = 384, Ecdh = true, Public = false},
            //#define BCRYPT_ECDH_PUBLIC_P521_MAGIC   0x354B4345  // ECK5
            new EccInfo {Magic = 0x354B4345, KeyLength = 521, Ecdh = true, Public = true},
            //#define BCRYPT_ECDH_PRIVATE_P521_MAGIC  0x364B4345  // ECK6
            new EccInfo {Magic = 0x364B4345, KeyLength = 521, Ecdh = true, Public = false},

            //#define BCRYPT_ECDSA_PUBLIC_P256_MAGIC  0x31534345  // ECS1
            new EccInfo {Magic = 0x31534345, KeyLength = 256, Ecdh = false, Public = true},
            //#define BCRYPT_ECDSA_PRIVATE_P256_MAGIC 0x32534345  // ECS2
            new EccInfo {Magic = 0x32534345, KeyLength = 256, Ecdh = false, Public = false},
            //#define BCRYPT_ECDSA_PUBLIC_P384_MAGIC  0x33534345  // ECS3
            new EccInfo {Magic = 0x33534345, KeyLength = 384, Ecdh = false, Public = true},
            //#define BCRYPT_ECDSA_PRIVATE_P384_MAGIC 0x34534345  // ECS4
            new EccInfo {Magic = 0x34534345, KeyLength = 384, Ecdh = false, Public = false},
            //#define BCRYPT_ECDSA_PUBLIC_P521_MAGIC  0x35534345  // ECS5
            new EccInfo {Magic = 0x35534345, KeyLength = 521, Ecdh = false, Public = true},
            //#define BCRYPT_ECDSA_PRIVATE_P521_MAGIC 0x36534345  // ECS6
            new EccInfo {Magic = 0x36534345, KeyLength = 521, Ecdh = false, Public = false}
        };

        internal static int GetKeyLength(EccCurve curve)
        {
            switch (curve)
            {
                case EccCurve.TpmEccNistP256:
                    return 256;
                case EccCurve.TpmEccNistP384:
                    return 384;
                case EccCurve.TpmEccNistP521:
                    return 521;
            }
            Globs.Throw<ArgumentException>("GetKeyLength(): Invalid ECC curve");
            return -1;
        }

        internal static uint MagicFromTpmAlgId(TpmAlgId algId, bool isEcdh, EccCurve curve, bool publicKey)
        {
            uint res = AlgInfo.FirstOrDefault(x => (x.Public == publicKey && 
                                                    x.KeyLength == GetKeyLength(curve) &&
                                                    x.Ecdh == isEcdh)).Magic;
            if (res == 0)
            {
                Globs.Throw("Unrecognized ECC parameter set");
            }
            return res;
        }

        internal static byte[] GetKeyBlob(byte[] x, byte[] y, TpmAlgId alg, bool isEcdh, EccCurve curve)
        {
            var m = new Marshaller();
            byte[] magic = BitConverter.GetBytes(MagicFromTpmAlgId(alg, isEcdh, curve, true));
            m.Put(magic, "");
            int keyBits = GetKeyLength(curve);
            int keySizeBytes = (keyBits + 7) / 8;

            if (x.Length != keySizeBytes || y.Length != keySizeBytes)
            {
                Globs.Throw<ArgumentException>("GetKeyBlob: Malformed ECC key");
                return new byte[0];
            }

            var size = Globs.ReverseByteOrder(Globs.HostToNet(keySizeBytes));
            m.Put(size, "len");
            m.Put(x, "x");
            m.Put(y, "y");
            var res = m.GetBytes();
            return res;
        }

        internal static void KeyInfoFromPublicBlob(byte[] blob, out byte[] x, out byte[] y)
        {
            x = null;
            y = null;
            var m = new Marshaller(blob);
            uint magic = BitConverter.ToUInt32(m.GetNBytes(4), 0);
            bool magicOk = AlgInfo.Any(xx => xx.Magic == magic);

            if (!magicOk)
            {
                Globs.Throw<ArgumentException>("KeyInfoFromPublicBlob: Public key blob magic not recognized");
            }

            uint cbKey = BitConverter.ToUInt32(m.GetNBytes(4), 0);

            x = m.GetNBytes((int)cbKey);
            y = m.GetNBytes((int)cbKey);
        }

        static string[] EcdsaCurveIDs = { null, null, null,
                            AsymmetricAlgorithmNames.EcdsaP256Sha256,
                            AsymmetricAlgorithmNames.EcdsaP256Sha256,
                            AsymmetricAlgorithmNames.EcdsaP256Sha256
                        };
        static string[] NistCurveIDs = { null, null, null,
                            EccCurveNames.NistP256,
                            EccCurveNames.NistP384,
                            EccCurveNames.NistP521
                        };

        internal static string
        GetEccAlg(TpmPublic pub)
        {
            if (pub.unique.GetUnionSelector() != TpmAlgId.Ecc)
            {
                return null;
            }

            var eccParms = (EccParms)pub.parameters;

            bool signing = pub.objectAttributes.HasFlag(ObjectAttr.Sign);
            bool encrypting = pub.objectAttributes.HasFlag(ObjectAttr.Decrypt);
            if (!(signing ^ encrypting))
            {
                Globs.Throw<ArgumentException>("ECC Key must either sign or decrypt");
                return null;
            }
            var scheme = eccParms.scheme.GetUnionSelector();
            if (signing && scheme != TpmAlgId.Ecdsa && scheme != TpmAlgId.Null)
            {
                Globs.Throw<ArgumentException>("Unsupported ECC signing scheme");
                return null;
            }

            int curveIndex = (int)eccParms.curveID;
            if (curveIndex >= EcdsaCurveIDs.Length)
            {
                Globs.Throw<ArgumentException>("Unsupported ECC curve");
                return null;
            }
            return signing ? EcdsaCurveIDs[curveIndex] : NistCurveIDs[curveIndex];
        }
    } // class CngEccKey
}
