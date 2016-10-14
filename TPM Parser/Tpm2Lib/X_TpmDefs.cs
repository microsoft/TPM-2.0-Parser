using System;
using System.Runtime.Serialization;
using System.Diagnostics.CodeAnalysis;
namespace Tpm2Lib {
    //-----------------------------------------------------------------------------
    //------------------------- CONSTANTS -----------------------------------------
    //-----------------------------------------------------------------------------
    [DataContract]
    [SpecTypeName("NameUnionTagValues")]
    /// <summary>
    /// Selector type for TPMU_NAME [TSS]
    /// </summary>
    public enum NameUnionTagValues : byte
    {
        None = 0,
        [EnumMember]
        [SpecTypeName("TAG_TPMU_NAME_TPMT_HA")]
        TagTpmuNameTpmtHa = 0,
        [EnumMember]
        [SpecTypeName("TAG_TPMU_NAME_TPM_HANDLE")]
        TagTpmuNameTpmHandle = 1
    }
    [DataContract]
    [SpecTypeName("TPM_ALG_ID")]
    /// <summary>
    /// Table 2 is the list of algorithms to which the TCG has assigned an algorithm identifier along with its numeric identifier.
    /// </summary>
    public enum TpmAlgId : ushort
    {
        None = 0,
        /// <summary>
        /// should not occur
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ERROR")]
        Error = 0x0000,
        /// <summary>
        /// the RSA algorithm
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_FIRST")]
        First = 0x0001,
        /// <summary>
        /// the RSA algorithm
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_RSA")]
        Rsa = 0x0001,
        /// <summary>
        /// the SHA1 algorithm
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SHA")]
        Sha = 0x0004,
        /// <summary>
        /// redefinition for documentation consistency
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SHA1")]
        Sha1 = 0x0004,
        [EnumMember]
        [SpecTypeName("TPM_ALG_TDES")]
        Tdes = 0x0003,
        /// <summary>
        /// Hash Message Authentication Code (HMAC) algorithm
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_HMAC")]
        Hmac = 0x0005,
        /// <summary>
        /// the AES algorithm with various key sizes
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_AES")]
        Aes = 0x0006,
        /// <summary>
        /// hash-based mask-generation function
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_MGF1")]
        Mgf1 = 0x0007,
        /// <summary>
        /// an object type that may use XOR for encryption or an HMAC for signing and may also refer to a data object that is neither signing nor encrypting
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_KEYEDHASH")]
        Keyedhash = 0x0008,
        /// <summary>
        /// the XOR encryption algorithm
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_XOR")]
        Xor = 0x000A,
        /// <summary>
        /// the SHA 256 algorithm
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SHA256")]
        Sha256 = 0x000B,
        /// <summary>
        /// the SHA 384 algorithm
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SHA384")]
        Sha384 = 0x000C,
        /// <summary>
        /// the SHA 512 algorithm
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SHA512")]
        Sha512 = 0x000D,
        /// <summary>
        /// Null algorithm
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_NULL")]
        Null = 0x0010,
        /// <summary>
        /// SM3 hash algorithm
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SM3_256")]
        Sm3256 = 0x0012,
        /// <summary>
        /// SM4 symmetric block cipher
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SM4")]
        Sm4 = 0x0013,
        /// <summary>
        /// a signature algorithm defined in section 8.2 (RSASSA-PKCS1-v1_5)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_RSASSA")]
        Rsassa = 0x0014,
        /// <summary>
        /// a padding algorithm defined in section 7.2 (RSAES-PKCS1-v1_5)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_RSAES")]
        Rsaes = 0x0015,
        /// <summary>
        /// a signature algorithm defined in section 8.1 (RSASSA-PSS)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_RSAPSS")]
        Rsapss = 0x0016,
        /// <summary>
        /// a padding algorithm defined in section 7.1 (RSAES_OAEP)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_OAEP")]
        Oaep = 0x0017,
        /// <summary>
        /// signature algorithm using elliptic curve cryptography (ECC)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ECDSA")]
        Ecdsa = 0x0018,
        /// <summary>
        /// secret sharing using ECC Based on context, this can be either One-Pass Diffie-Hellman, C(1, 1, ECC CDH) defined in 6.2.2.2 or Full Unified Model C(2, 2, ECC CDH) defined in 6.1.1.2
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ECDH")]
        Ecdh = 0x0019,
        /// <summary>
        /// elliptic-curve based, anonymous signing scheme
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ECDAA")]
        Ecdaa = 0x001A,
        /// <summary>
        /// SM2  depending on context, either an elliptic-curve based, signature algorithm or a key exchange protocol
        /// NOTE	Type listed as signing but, other uses are allowed according to context.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SM2")]
        Sm2 = 0x001B,
        /// <summary>
        /// elliptic-curve based Schnorr signature
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ECSCHNORR")]
        Ecschnorr = 0x001C,
        /// <summary>
        /// two-phase elliptic-curve key exchange  C(2, 2, ECC MQV) section 6.1.1.4
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ECMQV")]
        Ecmqv = 0x001D,
        /// <summary>
        /// concatenation key derivation function (approved alternative 1) section 5.8.1
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_KDF1_SP800_56A")]
        Kdf1Sp80056a = 0x0020,
        /// <summary>
        /// key derivation function KDF2 section 13.2
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_KDF2")]
        Kdf2 = 0x0021,
        /// <summary>
        /// a key derivation method Section 5.1 KDF in Counter Mode
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_KDF1_SP800_108")]
        Kdf1Sp800108 = 0x0022,
        /// <summary>
        /// prime field ECC
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ECC")]
        Ecc = 0x0023,
        /// <summary>
        /// the object type for a symmetric block cipher
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SYMCIPHER")]
        Symcipher = 0x0025,
        /// <summary>
        /// Camellia is symmetric block cipher. The Camellia algorithm with various key sizes
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_CAMELLIA")]
        Camellia = 0x0026,
        /// <summary>
        /// Counter mode  if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_CTR")]
        Ctr = 0x0040,
        /// <summary>
        /// Output Feedback mode  if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_OFB")]
        Ofb = 0x0041,
        /// <summary>
        /// Cipher Block Chaining mode  if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_CBC")]
        Cbc = 0x0042,
        /// <summary>
        /// Cipher Feedback mode  if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_CFB")]
        Cfb = 0x0043,
        /// <summary>
        /// Electronic Codebook mode  if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode.
        /// NOTE This mode is not recommended for uses unless the key is frequently rotated such as in video codecs
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ECB")]
        Ecb = 0x0044,
        [EnumMember]
        [SpecTypeName("TPM_ALG_LAST")]
        Last = 0x0044,
        /// <summary>
        /// Phony alg ID to be used for the first union member with no selector
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ANY")]
        Any = 0x7FFF,
        /// <summary>
        /// Phony alg ID to be used for the second union member with no selector
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ANY2")]
        Any2 = 0x7FFE
    }
    [DataContract]
    [SpecTypeName("TPM_ECC_CURVE")]
    /// <summary>
    /// Table 3 is the list of identifiers for TCG-registered curve ID values for elliptic curve cryptography.
    /// </summary>
    public enum EccCurve : ushort
    {
        None = 0,
        [EnumMember]
        [SpecTypeName("TPM_ECC_NONE")]
        TpmEccNone = 0x0000,
        [EnumMember]
        [SpecTypeName("TPM_ECC_NIST_P192")]
        TpmEccNistP192 = 0x0001,
        [EnumMember]
        [SpecTypeName("TPM_ECC_NIST_P224")]
        TpmEccNistP224 = 0x0002,
        [EnumMember]
        [SpecTypeName("TPM_ECC_NIST_P256")]
        TpmEccNistP256 = 0x0003,
        [EnumMember]
        [SpecTypeName("TPM_ECC_NIST_P384")]
        TpmEccNistP384 = 0x0004,
        [EnumMember]
        [SpecTypeName("TPM_ECC_NIST_P521")]
        TpmEccNistP521 = 0x0005,
        /// <summary>
        /// curve to support ECDAA
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ECC_BN_P256")]
        TpmEccBnP256 = 0x0010,
        /// <summary>
        /// curve to support ECDAA
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ECC_BN_P638")]
        TpmEccBnP638 = 0x0011,
        [EnumMember]
        [SpecTypeName("TPM_ECC_SM2_P256")]
        TpmEccSm2P256 = 0x0020
    }
    [DataContract]
    [SpecTypeName("SHA1")]
    /// <summary>
    /// Table 12  Defines for SHA1 Hash Values
    /// </summary>
    public enum Sha1 : uint
    {
        None = 0,
        /// <summary>
        /// size of digest in octets
        /// </summary>
        [EnumMember]
        [SpecTypeName("SHA1_DIGEST_SIZE")]
        DigestSize = 20,
        /// <summary>
        /// size of hash block in octets
        /// </summary>
        [EnumMember]
        [SpecTypeName("SHA1_BLOCK_SIZE")]
        BlockSize = 64,
        /// <summary>
        /// size of the DER in octets
        /// </summary>
        [EnumMember]
        [SpecTypeName("SHA1_DER_SIZE")]
        DerSize = 15,
    }
    [DataContract]
    [SpecTypeName("SHA256")]
    /// <summary>
    /// Table 13  Defines for SHA256 Hash Values
    /// </summary>
    public enum Sha256 : uint
    {
        None = 0,
        /// <summary>
        /// size of digest
        /// </summary>
        [EnumMember]
        [SpecTypeName("SHA256_DIGEST_SIZE")]
        DigestSize = 32,
        /// <summary>
        /// size of hash block
        /// </summary>
        [EnumMember]
        [SpecTypeName("SHA256_BLOCK_SIZE")]
        BlockSize = 64,
        /// <summary>
        /// size of the DER in octets
        /// </summary>
        [EnumMember]
        [SpecTypeName("SHA256_DER_SIZE")]
        DerSize = 19,
    }
    [DataContract]
    [SpecTypeName("SHA384")]
    /// <summary>
    /// Table 14  Defines for SHA384 Hash Values
    /// </summary>
    public enum Sha384 : uint
    {
        None = 0,
        /// <summary>
        /// size of digest in octets
        /// </summary>
        [EnumMember]
        [SpecTypeName("SHA384_DIGEST_SIZE")]
        DigestSize = 48,
        /// <summary>
        /// size of hash block in octets
        /// </summary>
        [EnumMember]
        [SpecTypeName("SHA384_BLOCK_SIZE")]
        BlockSize = 128,
        /// <summary>
        /// size of the DER in octets
        /// </summary>
        [EnumMember]
        [SpecTypeName("SHA384_DER_SIZE")]
        DerSize = 19,
    }
    [DataContract]
    [SpecTypeName("SHA512")]
    /// <summary>
    /// Table 15  Defines for SHA512 Hash Values
    /// </summary>
    public enum Sha512 : uint
    {
        None = 0,
        /// <summary>
        /// size of digest in octets
        /// </summary>
        [EnumMember]
        [SpecTypeName("SHA512_DIGEST_SIZE")]
        DigestSize = 64,
        /// <summary>
        /// size of hash block in octets
        /// </summary>
        [EnumMember]
        [SpecTypeName("SHA512_BLOCK_SIZE")]
        BlockSize = 128,
        /// <summary>
        /// size of the DER in octets
        /// </summary>
        [EnumMember]
        [SpecTypeName("SHA512_DER_SIZE")]
        DerSize = 19,
    }
    [DataContract]
    [SpecTypeName("SM3_256")]
    /// <summary>
    /// Table 16  Defines for SM3_256 Hash Values
    /// </summary>
    public enum Sm3256 : uint
    {
        None = 0,
        /// <summary>
        /// size of digest in octets
        /// </summary>
        [EnumMember]
        [SpecTypeName("SM3_256_DIGEST_SIZE")]
        DigestSize = 32,
        /// <summary>
        /// size of hash block in octets
        /// </summary>
        [EnumMember]
        [SpecTypeName("SM3_256_BLOCK_SIZE")]
        BlockSize = 64,
        /// <summary>
        /// size of the DER in octets
        /// </summary>
        [EnumMember]
        [SpecTypeName("SM3_256_DER_SIZE")]
        DerSize = 18,
    }
    [DataContract]
    [SpecTypeName("ImplementationConstants")]
    /// <summary>
    /// Architecturally defined constants
    /// </summary>
    public enum ImplementationConstants : uint
    {
        None = 0,
        [EnumMember]
        [SpecTypeName("HASH_COUNT")]
        HashCount = 3,
        [EnumMember]
        [SpecTypeName("MAX_SYM_KEY_BITS")]
        MaxSymKeyBits = 256,
        [EnumMember]
        [SpecTypeName("MAX_SYM_KEY_BYTES")]
        MaxSymKeyBytes = ((256 + 7) / 8), // 0x20
        [EnumMember]
        [SpecTypeName("MAX_SYM_BLOCK_SIZE")]
        MaxSymBlockSize = 16,
        [EnumMember]
        [SpecTypeName("MAX_CAP_CC")]
        MaxCapCc = 0x00000192, // 0x192
        [EnumMember]
        [SpecTypeName("MAX_RSA_KEY_BYTES")]
        MaxRsaKeyBytes = 256,
        [EnumMember]
        [SpecTypeName("MAX_AES_KEY_BYTES")]
        MaxAesKeyBytes = 32,
        [EnumMember]
        [SpecTypeName("MAX_ECC_KEY_BYTES")]
        MaxEccKeyBytes = 48,
        [EnumMember]
        [SpecTypeName("LABEL_MAX_BUFFER")]
        LabelMaxBuffer = 32,
        [EnumMember]
        [SpecTypeName("MAX_CAP_DATA")]
        MaxCapData = (1024-sizeof(Cap)-sizeof(uint)), // 0x3F8
        [EnumMember]
        [SpecTypeName("MAX_CAP_ALGS")]
        MaxCapAlgs = (0x0044 - 0x0001 + 1), // 0x44
        [EnumMember]
        [SpecTypeName("MAX_CAP_HANDLES")]
        MaxCapHandles = ((1024-sizeof(Cap)-sizeof(uint)) / 0x4 /*sizeof(TPM_HANDLE)*/), // 0xFE
        [EnumMember]
        [SpecTypeName("MAX_TPM_PROPERTIES")]
        MaxTpmProperties = ((1024-sizeof(Cap)-sizeof(uint)) / 0x8 /*sizeof(TPMS_TAGGED_PROPERTY)*/), // 0x7F
        [EnumMember]
        [SpecTypeName("MAX_PCR_PROPERTIES")]
        MaxPcrProperties = ((1024-sizeof(Cap)-sizeof(uint)) / 0x8 /*sizeof(TPMS_TAGGED_PCR_SELECT)*/), // 0x7F
        [EnumMember]
        [SpecTypeName("MAX_ECC_CURVES")]
        MaxEccCurves = ((1024-sizeof(Cap)-sizeof(uint)) / sizeof(EccCurve)) // 0x1FC
    }
    [DataContract]
    [SpecTypeName("Logic")]
    /// <summary>
    /// Table 4  Defines for Logic Values
    /// </summary>
    public enum Logic : byte
    {
        None = 0,
        [EnumMember]
        [SpecTypeName("TRUE")]
        True = 1,
        [EnumMember]
        [SpecTypeName("FALSE")]
        False = 0,
        [EnumMember]
        [SpecTypeName("YES")]
        Yes = 1,
        [EnumMember]
        [SpecTypeName("NO")]
        No = 0,
        [EnumMember]
        [SpecTypeName("SET")]
        Set = 1,
        [EnumMember]
        [SpecTypeName("CLEAR")]
        Clear = 0
    }
    [DataContract]
    [SpecTypeName("TPM_SPEC")]
    /// <summary>
    /// These values are readable with TPM2_GetCapability().
    /// </summary>
    public enum Spec : uint
    {
        None = 0,
        /// <summary>
        /// ASCII 2.0 with null terminator
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_SPEC_FAMILY")]
        Family = 0x322E3000,
        /// <summary>
        /// the level number for the specification
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_SPEC_LEVEL")]
        Level = 00,
        /// <summary>
        /// the version number of the spec (001.28 * 100)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_SPEC_VERSION")]
        Version = 131,
        /// <summary>
        /// the year of the version
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_SPEC_YEAR")]
        Year = 2016,
        /// <summary>
        /// the day of the year (February 20, 2016)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_SPEC_DAY_OF_YEAR")]
        DayOfYear = 133
    }
    [DataContract]
    [SpecTypeName("TPM_GENERATED")]
    /// <summary>
    /// This constant value differentiates TPM-generated structures from non-TPM structures.
    /// </summary>
    public enum Generated : uint
    {
        None = 0,
        /// <summary>
        /// 0xFF TCG (FF 54 43 4716)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_GENERATED_VALUE")]
        Value = 0xff544347
    }
    [DataContract]
    [SpecTypeName("TPM_CC")]
    /// <summary>
    /// Table 12 lists the command codes and their attributes. The only normative column in this table is the column indicating the command code assigned to a specific command (the "Command Code" column). For all other columns, the command and response tables in TPM 2.0 Part 3 are definitive.
    /// </summary>
    public enum TpmCc : uint
    {
        None = 0,
        /// <summary>
        /// Compile variable. May decrease based on implementation.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_FIRST")]
        First = 0x0000011F,
        [EnumMember]
        [SpecTypeName("TPM_CC_NV_UndefineSpaceSpecial")]
        NvUndefineSpaceSpecial = 0x0000011F,
        [EnumMember]
        [SpecTypeName("TPM_CC_EvictControl")]
        EvictControl = 0x00000120,
        [EnumMember]
        [SpecTypeName("TPM_CC_HierarchyControl")]
        HierarchyControl = 0x00000121,
        [EnumMember]
        [SpecTypeName("TPM_CC_NV_UndefineSpace")]
        NvUndefineSpace = 0x00000122,
        [EnumMember]
        [SpecTypeName("TPM_CC_ChangeEPS")]
        ChangeEPS = 0x00000124,
        [EnumMember]
        [SpecTypeName("TPM_CC_ChangePPS")]
        ChangePPS = 0x00000125,
        [EnumMember]
        [SpecTypeName("TPM_CC_Clear")]
        Clear = 0x00000126,
        [EnumMember]
        [SpecTypeName("TPM_CC_ClearControl")]
        ClearControl = 0x00000127,
        [EnumMember]
        [SpecTypeName("TPM_CC_ClockSet")]
        ClockSet = 0x00000128,
        [EnumMember]
        [SpecTypeName("TPM_CC_HierarchyChangeAuth")]
        HierarchyChangeAuth = 0x00000129,
        [EnumMember]
        [SpecTypeName("TPM_CC_NV_DefineSpace")]
        NvDefineSpace = 0x0000012A,
        [EnumMember]
        [SpecTypeName("TPM_CC_PCR_Allocate")]
        PcrAllocate = 0x0000012B,
        [EnumMember]
        [SpecTypeName("TPM_CC_PCR_SetAuthPolicy")]
        PcrSetAuthPolicy = 0x0000012C,
        [EnumMember]
        [SpecTypeName("TPM_CC_PP_Commands")]
        PpCommands = 0x0000012D,
        [EnumMember]
        [SpecTypeName("TPM_CC_SetPrimaryPolicy")]
        SetPrimaryPolicy = 0x0000012E,
        [EnumMember]
        [SpecTypeName("TPM_CC_FieldUpgradeStart")]
        FieldUpgradeStart = 0x0000012F,
        [EnumMember]
        [SpecTypeName("TPM_CC_ClockRateAdjust")]
        ClockRateAdjust = 0x00000130,
        [EnumMember]
        [SpecTypeName("TPM_CC_CreatePrimary")]
        CreatePrimary = 0x00000131,
        [EnumMember]
        [SpecTypeName("TPM_CC_NV_GlobalWriteLock")]
        NvGlobalWriteLock = 0x00000132,
        [EnumMember]
        [SpecTypeName("TPM_CC_GetCommandAuditDigest")]
        GetCommandAuditDigest = 0x00000133,
        [EnumMember]
        [SpecTypeName("TPM_CC_NV_Increment")]
        NvIncrement = 0x00000134,
        [EnumMember]
        [SpecTypeName("TPM_CC_NV_SetBits")]
        NvSetBits = 0x00000135,
        [EnumMember]
        [SpecTypeName("TPM_CC_NV_Extend")]
        NvExtend = 0x00000136,
        [EnumMember]
        [SpecTypeName("TPM_CC_NV_Write")]
        NvWrite = 0x00000137,
        [EnumMember]
        [SpecTypeName("TPM_CC_NV_WriteLock")]
        NvWriteLock = 0x00000138,
        [EnumMember]
        [SpecTypeName("TPM_CC_DictionaryAttackLockReset")]
        DictionaryAttackLockReset = 0x00000139,
        [EnumMember]
        [SpecTypeName("TPM_CC_DictionaryAttackParameters")]
        DictionaryAttackParameters = 0x0000013A,
        [EnumMember]
        [SpecTypeName("TPM_CC_NV_ChangeAuth")]
        NvChangeAuth = 0x0000013B,
        /// <summary>
        /// PCR
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PCR_Event")]
        PcrEvent = 0x0000013C,
        /// <summary>
        /// PCR
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PCR_Reset")]
        PcrReset = 0x0000013D,
        [EnumMember]
        [SpecTypeName("TPM_CC_SequenceComplete")]
        SequenceComplete = 0x0000013E,
        [EnumMember]
        [SpecTypeName("TPM_CC_SetAlgorithmSet")]
        SetAlgorithmSet = 0x0000013F,
        [EnumMember]
        [SpecTypeName("TPM_CC_SetCommandCodeAuditStatus")]
        SetCommandCodeAuditStatus = 0x00000140,
        [EnumMember]
        [SpecTypeName("TPM_CC_FieldUpgradeData")]
        FieldUpgradeData = 0x00000141,
        [EnumMember]
        [SpecTypeName("TPM_CC_IncrementalSelfTest")]
        IncrementalSelfTest = 0x00000142,
        [EnumMember]
        [SpecTypeName("TPM_CC_SelfTest")]
        SelfTest = 0x00000143,
        [EnumMember]
        [SpecTypeName("TPM_CC_Startup")]
        Startup = 0x00000144,
        [EnumMember]
        [SpecTypeName("TPM_CC_Shutdown")]
        Shutdown = 0x00000145,
        [EnumMember]
        [SpecTypeName("TPM_CC_StirRandom")]
        StirRandom = 0x00000146,
        [EnumMember]
        [SpecTypeName("TPM_CC_ActivateCredential")]
        ActivateCredential = 0x00000147,
        [EnumMember]
        [SpecTypeName("TPM_CC_Certify")]
        Certify = 0x00000148,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyNV")]
        PolicyNV = 0x00000149,
        [EnumMember]
        [SpecTypeName("TPM_CC_CertifyCreation")]
        CertifyCreation = 0x0000014A,
        [EnumMember]
        [SpecTypeName("TPM_CC_Duplicate")]
        Duplicate = 0x0000014B,
        [EnumMember]
        [SpecTypeName("TPM_CC_GetTime")]
        GetTime = 0x0000014C,
        [EnumMember]
        [SpecTypeName("TPM_CC_GetSessionAuditDigest")]
        GetSessionAuditDigest = 0x0000014D,
        [EnumMember]
        [SpecTypeName("TPM_CC_NV_Read")]
        NvRead = 0x0000014E,
        [EnumMember]
        [SpecTypeName("TPM_CC_NV_ReadLock")]
        NvReadLock = 0x0000014F,
        [EnumMember]
        [SpecTypeName("TPM_CC_ObjectChangeAuth")]
        ObjectChangeAuth = 0x00000150,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicySecret")]
        PolicySecret = 0x00000151,
        [EnumMember]
        [SpecTypeName("TPM_CC_Rewrap")]
        Rewrap = 0x00000152,
        [EnumMember]
        [SpecTypeName("TPM_CC_Create")]
        Create = 0x00000153,
        [EnumMember]
        [SpecTypeName("TPM_CC_ECDH_ZGen")]
        EcdhZGen = 0x00000154,
        [EnumMember]
        [SpecTypeName("TPM_CC_HMAC")]
        Hmac = 0x00000155,
        [EnumMember]
        [SpecTypeName("TPM_CC_Import")]
        Import = 0x00000156,
        [EnumMember]
        [SpecTypeName("TPM_CC_Load")]
        Load = 0x00000157,
        [EnumMember]
        [SpecTypeName("TPM_CC_Quote")]
        Quote = 0x00000158,
        [EnumMember]
        [SpecTypeName("TPM_CC_RSA_Decrypt")]
        RsaDecrypt = 0x00000159,
        [EnumMember]
        [SpecTypeName("TPM_CC_HMAC_Start")]
        HmacStart = 0x0000015B,
        [EnumMember]
        [SpecTypeName("TPM_CC_SequenceUpdate")]
        SequenceUpdate = 0x0000015C,
        [EnumMember]
        [SpecTypeName("TPM_CC_Sign")]
        Sign = 0x0000015D,
        [EnumMember]
        [SpecTypeName("TPM_CC_Unseal")]
        Unseal = 0x0000015E,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicySigned")]
        PolicySigned = 0x00000160,
        /// <summary>
        /// Context
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_ContextLoad")]
        ContextLoad = 0x00000161,
        /// <summary>
        /// Context
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_ContextSave")]
        ContextSave = 0x00000162,
        [EnumMember]
        [SpecTypeName("TPM_CC_ECDH_KeyGen")]
        EcdhKeyGen = 0x00000163,
        [EnumMember]
        [SpecTypeName("TPM_CC_EncryptDecrypt")]
        EncryptDecrypt = 0x00000164,
        /// <summary>
        /// Context
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_FlushContext")]
        FlushContext = 0x00000165,
        [EnumMember]
        [SpecTypeName("TPM_CC_LoadExternal")]
        LoadExternal = 0x00000167,
        [EnumMember]
        [SpecTypeName("TPM_CC_MakeCredential")]
        MakeCredential = 0x00000168,
        /// <summary>
        /// NV
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_NV_ReadPublic")]
        NvReadPublic = 0x00000169,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyAuthorize")]
        PolicyAuthorize = 0x0000016A,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyAuthValue")]
        PolicyAuthValue = 0x0000016B,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyCommandCode")]
        PolicyCommandCode = 0x0000016C,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyCounterTimer")]
        PolicyCounterTimer = 0x0000016D,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyCpHash")]
        PolicyCpHash = 0x0000016E,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyLocality")]
        PolicyLocality = 0x0000016F,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyNameHash")]
        PolicyNameHash = 0x00000170,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyOR")]
        PolicyOR = 0x00000171,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyTicket")]
        PolicyTicket = 0x00000172,
        [EnumMember]
        [SpecTypeName("TPM_CC_ReadPublic")]
        ReadPublic = 0x00000173,
        [EnumMember]
        [SpecTypeName("TPM_CC_RSA_Encrypt")]
        RsaEncrypt = 0x00000174,
        [EnumMember]
        [SpecTypeName("TPM_CC_StartAuthSession")]
        StartAuthSession = 0x00000176,
        [EnumMember]
        [SpecTypeName("TPM_CC_VerifySignature")]
        VerifySignature = 0x00000177,
        [EnumMember]
        [SpecTypeName("TPM_CC_ECC_Parameters")]
        EccParameters = 0x00000178,
        [EnumMember]
        [SpecTypeName("TPM_CC_FirmwareRead")]
        FirmwareRead = 0x00000179,
        [EnumMember]
        [SpecTypeName("TPM_CC_GetCapability")]
        GetCapability = 0x0000017A,
        [EnumMember]
        [SpecTypeName("TPM_CC_GetRandom")]
        GetRandom = 0x0000017B,
        [EnumMember]
        [SpecTypeName("TPM_CC_GetTestResult")]
        GetTestResult = 0x0000017C,
        [EnumMember]
        [SpecTypeName("TPM_CC_Hash")]
        Hash = 0x0000017D,
        /// <summary>
        /// PCR
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PCR_Read")]
        PcrRead = 0x0000017E,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyPCR")]
        PolicyPCR = 0x0000017F,
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyRestart")]
        PolicyRestart = 0x00000180,
        [EnumMember]
        [SpecTypeName("TPM_CC_ReadClock")]
        ReadClock = 0x00000181,
        [EnumMember]
        [SpecTypeName("TPM_CC_PCR_Extend")]
        PcrExtend = 0x00000182,
        [EnumMember]
        [SpecTypeName("TPM_CC_PCR_SetAuthValue")]
        PcrSetAuthValue = 0x00000183,
        [EnumMember]
        [SpecTypeName("TPM_CC_NV_Certify")]
        NvCertify = 0x00000184,
        [EnumMember]
        [SpecTypeName("TPM_CC_EventSequenceComplete")]
        EventSequenceComplete = 0x00000185,
        [EnumMember]
        [SpecTypeName("TPM_CC_HashSequenceStart")]
        HashSequenceStart = 0x00000186,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyPhysicalPresence")]
        PolicyPhysicalPresence = 0x00000187,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyDuplicationSelect")]
        PolicyDuplicationSelect = 0x00000188,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyGetDigest")]
        PolicyGetDigest = 0x00000189,
        [EnumMember]
        [SpecTypeName("TPM_CC_TestParms")]
        TestParms = 0x0000018A,
        [EnumMember]
        [SpecTypeName("TPM_CC_Commit")]
        Commit = 0x0000018B,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyPassword")]
        PolicyPassword = 0x0000018C,
        [EnumMember]
        [SpecTypeName("TPM_CC_ZGen_2Phase")]
        ZGen2Phase = 0x0000018D,
        [EnumMember]
        [SpecTypeName("TPM_CC_EC_Ephemeral")]
        EcEphemeral = 0x0000018E,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyNvWritten")]
        PolicyNvWritten = 0x0000018F,
        /// <summary>
        /// Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyTemplate")]
        PolicyTemplate = 0x00000190,
        [EnumMember]
        [SpecTypeName("TPM_CC_CreateLoaded")]
        CreateLoaded = 0x00000191,
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyAuthorizeNV")]
        PolicyAuthorizeNV = 0x00000192,
        /// <summary>
        /// Compile variable. May increase based on implementation.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_LAST")]
        Last = 0x00000192,
        [EnumMember]
        [SpecTypeName("CC_VEND")]
        CcVend = 0x20000000,
        /// <summary>
        /// Used for testing of command dispatch
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_Vendor_TCG_Test")]
        VendorTcgTest = 0x20000000+0x0000 // 0x20000000
    }
    [DataContract]
    [SpecTypeName("TPM_RC")]
    /// <summary>
    /// In general, response codes defined in TPM 2.0 Part 2 will be unmarshaling errors and will have the F (format) bit SET. Codes that are unique to TPM 2.0 Part 3 will have the F bit CLEAR but the V (version) attribute will be SET to indicate that it is a TPM 2.0 response code. See Response Code Details in TPM 2.0 Part 1.
    /// </summary>
    public enum TpmRc : uint
    {
        None = 0,
        [EnumMember]
        [SpecTypeName("TPM_RC_SUCCESS")]
        Success = 0x000,
        /// <summary>
        /// defined for compatibility with TPM 1.2
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_BAD_TAG")]
        BadTag = 0x01E,
        /// <summary>
        /// set for all format 0 response codes
        /// </summary>
        [EnumMember]
        [SpecTypeName("RC_VER1")]
        RcVer1 = 0x100,
        /// <summary>
        /// TPM not initialized by TPM2_Startup or already initialized
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_INITIALIZE")]
        Initialize = 0x100 + 0x000, // 0x100
        /// <summary>
        /// commands not being accepted because of a TPM failure
        /// NOTE	This may be returned by TPM2_GetTestResult() as the testResult parameter.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_FAILURE")]
        Failure = 0x100 + 0x001, // 0x101
        /// <summary>
        /// improper use of a sequence handle
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SEQUENCE")]
        Sequence = 0x100 + 0x003, // 0x103
        /// <summary>
        /// not currently used
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_PRIVATE")]
        Private = 0x100 + 0x00B, // 0x10B
        /// <summary>
        /// not currently used
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_HMAC")]
        Hmac = 0x100 + 0x019, // 0x119
        /// <summary>
        /// the command is disabled
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_DISABLED")]
        Disabled = 0x100 + 0x020, // 0x120
        /// <summary>
        /// command failed because audit sequence required exclusivity
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_EXCLUSIVE")]
        Exclusive = 0x100 + 0x021, // 0x121
        /// <summary>
        /// authorization handle is not correct for command
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_AUTH_TYPE")]
        AuthType = 0x100 + 0x024, // 0x124
        /// <summary>
        /// command requires an authorization session for handle and it is not present.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_AUTH_MISSING")]
        AuthMissing = 0x100 + 0x025, // 0x125
        /// <summary>
        /// policy failure in math operation or an invalid authPolicy value
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_POLICY")]
        Policy = 0x100 + 0x026, // 0x126
        /// <summary>
        /// PCR check fail
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_PCR")]
        Pcr = 0x100 + 0x027, // 0x127
        /// <summary>
        /// PCR have changed since checked.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_PCR_CHANGED")]
        PcrChanged = 0x100 + 0x028, // 0x128
        /// <summary>
        /// for all commands other than TPM2_FieldUpgradeData(), this code indicates that the TPM is in field upgrade mode; for TPM2_FieldUpgradeData(), this code indicates that the TPM is not in field upgrade mode
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_UPGRADE")]
        Upgrade = 0x100 + 0x02D, // 0x12D
        /// <summary>
        /// context ID counter is at maximum.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_TOO_MANY_CONTEXTS")]
        TooManyContexts = 0x100 + 0x02E, // 0x12E
        /// <summary>
        /// authValue or authPolicy is not available for selected entity.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_AUTH_UNAVAILABLE")]
        AuthUnavailable = 0x100 + 0x02F, // 0x12F
        /// <summary>
        /// a _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REBOOT")]
        Reboot = 0x100 + 0x030, // 0x130
        /// <summary>
        /// the protection algorithms (hash and symmetric) are not reasonably balanced. The digest size of the hash must be larger than the key size of the symmetric algorithm.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_UNBALANCED")]
        Unbalanced = 0x100 + 0x031, // 0x131
        /// <summary>
        /// command commandSize value is inconsistent with contents of the command buffer; either the size is not the same as the octets loaded by the hardware interface layer or the value is not large enough to hold a command header
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_COMMAND_SIZE")]
        CommandSize = 0x100 + 0x042, // 0x142
        /// <summary>
        /// command code not supported
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_COMMAND_CODE")]
        CommandCode = 0x100 + 0x043, // 0x143
        /// <summary>
        /// the value of authorizationSize is out of range or the number of octets in the Authorization Area is greater than required
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_AUTHSIZE")]
        Authsize = 0x100 + 0x044, // 0x144
        /// <summary>
        /// use of an authorization session with a context command or another command that cannot have an authorization session.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_AUTH_CONTEXT")]
        AuthContext = 0x100 + 0x045, // 0x145
        /// <summary>
        /// NV offset+size is out of range.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_RANGE")]
        NvRange = 0x100 + 0x046, // 0x146
        /// <summary>
        /// Requested allocation size is larger than allowed.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_SIZE")]
        NvSize = 0x100 + 0x047, // 0x147
        /// <summary>
        /// NV access locked.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_LOCKED")]
        NvLocked = 0x100 + 0x048, // 0x148
        /// <summary>
        /// NV access authorization fails in command actions (this failure does not affect lockout.action)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_AUTHORIZATION")]
        NvAuthorization = 0x100 + 0x049, // 0x149
        /// <summary>
        /// an NV Index is used before being initialized or the state saved by TPM2_Shutdown(STATE) could not be restored
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_UNINITIALIZED")]
        NvUninitialized = 0x100 + 0x04A, // 0x14A
        /// <summary>
        /// insufficient space for NV allocation
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_SPACE")]
        NvSpace = 0x100 + 0x04B, // 0x14B
        /// <summary>
        /// NV Index or persistent object already defined
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_DEFINED")]
        NvDefined = 0x100 + 0x04C, // 0x14C
        /// <summary>
        /// context in TPM2_ContextLoad() is not valid
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_BAD_CONTEXT")]
        BadContext = 0x100 + 0x050, // 0x150
        /// <summary>
        /// cpHash value already set or not correct for use
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_CPHASH")]
        Cphash = 0x100 + 0x051, // 0x151
        /// <summary>
        /// handle for parent is not a valid parent
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_PARENT")]
        Parent = 0x100 + 0x052, // 0x152
        /// <summary>
        /// some function needs testing.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NEEDS_TEST")]
        NeedsTest = 0x100 + 0x053, // 0x153
        /// <summary>
        /// returned when an internal function cannot process a request due to an unspecified problem. This code is usually related to invalid parameters that are not properly filtered by the input unmarshaling code.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NO_RESULT")]
        NoResult = 0x100 + 0x054, // 0x154
        /// <summary>
        /// the sensitive area did not unmarshal correctly after decryption  this code is used in lieu of the other unmarshaling errors so that an attacker cannot determine where the unmarshaling error occurred
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SENSITIVE")]
        Sensitive = 0x100 + 0x055, // 0x155
        /// <summary>
        /// largest version 1 code that is not a warning
        /// </summary>
        [EnumMember]
        [SpecTypeName("RC_MAX_FM0")]
        RcMaxFm0 = 0x100 + 0x07F, // 0x17F
        /// <summary>
        /// This bit is SET in all format 1 response codes
        /// The codes in this group may have a value added to them to indicate the handle, session, or parameter to which they apply.
        /// </summary>
        [EnumMember]
        [SpecTypeName("RC_FMT1")]
        RcFmt1 = 0x080,
        /// <summary>
        /// asymmetric algorithm not supported or not correct
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_ASYMMETRIC")]
        Asymmetric = 0x080 + 0x001, // 0x81
        /// <summary>
        /// inconsistent attributes
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_ATTRIBUTES")]
        Attributes = 0x080 + 0x002, // 0x82
        /// <summary>
        /// hash algorithm not supported or not appropriate
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_HASH")]
        Hash = 0x080 + 0x003, // 0x83
        /// <summary>
        /// value is out of range or is not correct for the context
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_VALUE")]
        Value = 0x080 + 0x004, // 0x84
        /// <summary>
        /// hierarchy is not enabled or is not correct for the use
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_HIERARCHY")]
        Hierarchy = 0x080 + 0x005, // 0x85
        /// <summary>
        /// key size is not supported
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_KEY_SIZE")]
        KeySize = 0x080 + 0x007, // 0x87
        /// <summary>
        /// mask generation function not supported
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_MGF")]
        Mgf = 0x080 + 0x008, // 0x88
        /// <summary>
        /// mode of operation not supported
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_MODE")]
        Mode = 0x080 + 0x009, // 0x89
        /// <summary>
        /// the type of the value is not appropriate for the use
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_TYPE")]
        Type = 0x080 + 0x00A, // 0x8A
        /// <summary>
        /// the handle is not correct for the use
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_HANDLE")]
        Handle = 0x080 + 0x00B, // 0x8B
        /// <summary>
        /// unsupported key derivation function or function not appropriate for use
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_KDF")]
        Kdf = 0x080 + 0x00C, // 0x8C
        /// <summary>
        /// value was out of allowed range.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_RANGE")]
        Range = 0x080 + 0x00D, // 0x8D
        /// <summary>
        /// the authorization HMAC check failed and DA counter incremented
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_AUTH_FAIL")]
        AuthFail = 0x080 + 0x00E, // 0x8E
        /// <summary>
        /// invalid nonce size or nonce value mismatch
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NONCE")]
        Nonce = 0x080 + 0x00F, // 0x8F
        /// <summary>
        /// authorization requires assertion of PP
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_PP")]
        Pp = 0x080 + 0x010, // 0x90
        /// <summary>
        /// unsupported or incompatible scheme
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SCHEME")]
        Scheme = 0x080 + 0x012, // 0x92
        /// <summary>
        /// structure is the wrong size
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SIZE")]
        Size = 0x080 + 0x015, // 0x95
        /// <summary>
        /// unsupported symmetric algorithm or key size, or not appropriate for instance
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SYMMETRIC")]
        Symmetric = 0x080 + 0x016, // 0x96
        /// <summary>
        /// incorrect structure tag
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_TAG")]
        Tag = 0x080 + 0x017, // 0x97
        /// <summary>
        /// union selector is incorrect
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SELECTOR")]
        Selector = 0x080 + 0x018, // 0x98
        /// <summary>
        /// the TPM was unable to unmarshal a value because there were not enough octets in the input buffer
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_INSUFFICIENT")]
        Insufficient = 0x080 + 0x01A, // 0x9A
        /// <summary>
        /// the signature is not valid
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SIGNATURE")]
        Signature = 0x080 + 0x01B, // 0x9B
        /// <summary>
        /// key fields are not compatible with the selected use
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_KEY")]
        Key = 0x080 + 0x01C, // 0x9C
        /// <summary>
        /// a policy check failed
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_POLICY_FAIL")]
        PolicyFail = 0x080 + 0x01D, // 0x9D
        /// <summary>
        /// integrity check failed
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_INTEGRITY")]
        Integrity = 0x080 + 0x01F, // 0x9F
        /// <summary>
        /// invalid ticket
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_TICKET")]
        Ticket = 0x080 + 0x020, // 0xA0
        /// <summary>
        /// authorization failure without DA implications
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_BAD_AUTH")]
        BadAuth = 0x080 + 0x022, // 0xA2
        /// <summary>
        /// the policy has expired
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_EXPIRED")]
        Expired = 0x080 + 0x023, // 0xA3
        /// <summary>
        /// the commandCode in the policy is not the commandCode of the command or the command code in a policy command references a command that is not implemented
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_POLICY_CC")]
        PolicyCc = 0x080 + 0x024, // 0xA4
        /// <summary>
        /// public and sensitive portions of an object are not cryptographically bound
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_BINDING")]
        Binding = 0x080 + 0x025, // 0xA5
        /// <summary>
        /// curve not supported
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_CURVE")]
        Curve = 0x080 + 0x026, // 0xA6
        /// <summary>
        /// point is not on the required curve.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_ECC_POINT")]
        EccPoint = 0x080 + 0x027, // 0xA7
        /// <summary>
        /// set for warning response codes
        /// </summary>
        [EnumMember]
        [SpecTypeName("RC_WARN")]
        RcWarn = 0x900,
        /// <summary>
        /// gap for context ID is too large
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_CONTEXT_GAP")]
        ContextGap = 0x900 + 0x001, // 0x901
        /// <summary>
        /// out of memory for object contexts
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_OBJECT_MEMORY")]
        ObjectMemory = 0x900 + 0x002, // 0x902
        /// <summary>
        /// out of memory for session contexts
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SESSION_MEMORY")]
        SessionMemory = 0x900 + 0x003, // 0x903
        /// <summary>
        /// out of shared object/session memory or need space for internal operations
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_MEMORY")]
        Memory = 0x900 + 0x004, // 0x904
        /// <summary>
        /// out of session handles  a session must be flushed before a new session may be created
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SESSION_HANDLES")]
        SessionHandles = 0x900 + 0x005, // 0x905
        /// <summary>
        /// out of object handles  the handle space for objects is depleted and a reboot is required
        /// NOTE 1	This cannot occur on the reference implementation.
        /// NOTE 2	There is no reason why an implementation would implement a design that would deplete handle space. Platform specifications are encouraged to forbid it.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_OBJECT_HANDLES")]
        ObjectHandles = 0x900 + 0x006, // 0x906
        /// <summary>
        /// bad locality
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_LOCALITY")]
        Locality = 0x900 + 0x007, // 0x907
        /// <summary>
        /// the TPM has suspended operation on the command; forward progress was made and the command may be retried
        /// See TPM 2.0 Part 1, Multi-tasking.
        /// NOTE	This cannot occur on the reference implementation.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_YIELDED")]
        Yielded = 0x900 + 0x008, // 0x908
        /// <summary>
        /// the command was canceled
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_CANCELED")]
        Canceled = 0x900 + 0x009, // 0x909
        /// <summary>
        /// TPM is performing self-tests
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_TESTING")]
        Testing = 0x900 + 0x00A, // 0x90A
        /// <summary>
        /// the 1st handle in the handle area references a transient object or session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_H0")]
        ReferenceH0 = 0x900 + 0x010, // 0x910
        /// <summary>
        /// the 2nd handle in the handle area references a transient object or session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_H1")]
        ReferenceH1 = 0x900 + 0x011, // 0x911
        /// <summary>
        /// the 3rd handle in the handle area references a transient object or session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_H2")]
        ReferenceH2 = 0x900 + 0x012, // 0x912
        /// <summary>
        /// the 4th handle in the handle area references a transient object or session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_H3")]
        ReferenceH3 = 0x900 + 0x013, // 0x913
        /// <summary>
        /// the 5th handle in the handle area references a transient object or session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_H4")]
        ReferenceH4 = 0x900 + 0x014, // 0x914
        /// <summary>
        /// the 6th handle in the handle area references a transient object or session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_H5")]
        ReferenceH5 = 0x900 + 0x015, // 0x915
        /// <summary>
        /// the 7th handle in the handle area references a transient object or session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_H6")]
        ReferenceH6 = 0x900 + 0x016, // 0x916
        /// <summary>
        /// the 1st authorization session handle references a session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_S0")]
        ReferenceS0 = 0x900 + 0x018, // 0x918
        /// <summary>
        /// the 2nd authorization session handle references a session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_S1")]
        ReferenceS1 = 0x900 + 0x019, // 0x919
        /// <summary>
        /// the 3rd authorization session handle references a session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_S2")]
        ReferenceS2 = 0x900 + 0x01A, // 0x91A
        /// <summary>
        /// the 4th authorization session handle references a session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_S3")]
        ReferenceS3 = 0x900 + 0x01B, // 0x91B
        /// <summary>
        /// the 5th session handle references a session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_S4")]
        ReferenceS4 = 0x900 + 0x01C, // 0x91C
        /// <summary>
        /// the 6th session handle references a session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_S5")]
        ReferenceS5 = 0x900 + 0x01D, // 0x91D
        /// <summary>
        /// the 7th authorization session handle references a session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_S6")]
        ReferenceS6 = 0x900 + 0x01E, // 0x91E
        /// <summary>
        /// the TPM is rate-limiting accesses to prevent wearout of NV
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_RATE")]
        NvRate = 0x900 + 0x020, // 0x920
        /// <summary>
        /// authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_LOCKOUT")]
        Lockout = 0x900 + 0x021, // 0x921
        /// <summary>
        /// the TPM was not able to start the command
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_RETRY")]
        Retry = 0x900 + 0x022, // 0x922
        /// <summary>
        /// the command may require writing of NV and NV is not current accessible
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_UNAVAILABLE")]
        NvUnavailable = 0x900 + 0x023, // 0x923
        /// <summary>
        /// this value is reserved and shall not be returned by the TPM
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NOT_USED")]
        NotUsed = 0x900 + 0x7F, // 0x97F
        /// <summary>
        /// add to a handle-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_H")]
        H = 0x000,
        /// <summary>
        /// add to a parameter-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_P")]
        P = 0x040,
        /// <summary>
        /// add to a session-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_S")]
        S = 0x800,
        /// <summary>
        /// add to a parameter-, handle-, or session-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_1")]
        TpmRc1 = 0x100,
        /// <summary>
        /// add to a parameter-, handle-, or session-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_2")]
        TpmRc2 = 0x200,
        /// <summary>
        /// add to a parameter-, handle-, or session-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_3")]
        TpmRc3 = 0x300,
        /// <summary>
        /// add to a parameter-, handle-, or session-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_4")]
        TpmRc4 = 0x400,
        /// <summary>
        /// add to a parameter-, handle-, or session-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_5")]
        TpmRc5 = 0x500,
        /// <summary>
        /// add to a parameter-, handle-, or session-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_6")]
        TpmRc6 = 0x600,
        /// <summary>
        /// add to a parameter-, handle-, or session-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_7")]
        TpmRc7 = 0x700,
        /// <summary>
        /// add to a parameter-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_8")]
        TpmRc8 = 0x800,
        /// <summary>
        /// add to a parameter-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_9")]
        TpmRc9 = 0x900,
        /// <summary>
        /// add to a parameter-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_A")]
        A = 0xA00,
        /// <summary>
        /// add to a parameter-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_B")]
        B = 0xB00,
        /// <summary>
        /// add to a parameter-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_C")]
        C = 0xC00,
        /// <summary>
        /// add to a parameter-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_D")]
        D = 0xD00,
        /// <summary>
        /// add to a parameter-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_E")]
        E = 0xE00,
        /// <summary>
        /// add to a parameter-related error
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_F")]
        F = 0xF00,
        /// <summary>
        /// number mask
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_N_MASK")]
        NMask = 0xF00
    }
    [DataContract]
    [SpecTypeName("TPM_CLOCK_ADJUST")]
    /// <summary>
    /// A TPM_CLOCK_ADJUST value is used to change the rate at which the TPM internal oscillator is divided. A change to the divider will change the rate at which Clock and Time change.
    /// </summary>
    public enum ClockAdjust : sbyte
    {
        None = 0,
        /// <summary>
        /// Slow the Clock update rate by one coarse adjustment step.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CLOCK_COARSE_SLOWER")]
        TpmClockCoarseSlower = -3,
        /// <summary>
        /// Slow the Clock update rate by one medium adjustment step.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CLOCK_MEDIUM_SLOWER")]
        TpmClockMediumSlower = -2,
        /// <summary>
        /// Slow the Clock update rate by one fine adjustment step.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CLOCK_FINE_SLOWER")]
        TpmClockFineSlower = -1,
        /// <summary>
        /// No change to the Clock update rate.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CLOCK_NO_CHANGE")]
        TpmClockNoChange = 0,
        /// <summary>
        /// Speed the Clock update rate by one fine adjustment step.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CLOCK_FINE_FASTER")]
        TpmClockFineFaster = 1,
        /// <summary>
        /// Speed the Clock update rate by one medium adjustment step.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CLOCK_MEDIUM_FASTER")]
        TpmClockMediumFaster = 2,
        /// <summary>
        /// Speed the Clock update rate by one coarse adjustment step.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CLOCK_COARSE_FASTER")]
        TpmClockCoarseFaster = 3
    }
    [DataContract]
    [SpecTypeName("TPM_EO")]
    /// <summary>
    /// Table 18  Definition of (UINT16) TPM_EO Constants <IN/OUT>
    /// </summary>
    public enum Eo : ushort
    {
        None = 0,
        /// <summary>
        /// A = B
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_EQ")]
        Eq = 0x0000,
        /// <summary>
        /// A  B
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_NEQ")]
        Neq = 0x0001,
        /// <summary>
        /// A > B signed
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_SIGNED_GT")]
        SignedGt = 0x0002,
        /// <summary>
        /// A > B unsigned
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_UNSIGNED_GT")]
        UnsignedGt = 0x0003,
        /// <summary>
        /// A < B signed
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_SIGNED_LT")]
        SignedLt = 0x0004,
        /// <summary>
        /// A < B unsigned
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_UNSIGNED_LT")]
        UnsignedLt = 0x0005,
        /// <summary>
        /// A  B signed
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_SIGNED_GE")]
        SignedGe = 0x0006,
        /// <summary>
        /// A  B unsigned
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_UNSIGNED_GE")]
        UnsignedGe = 0x0007,
        /// <summary>
        /// A  B signed
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_SIGNED_LE")]
        SignedLe = 0x0008,
        /// <summary>
        /// A  B unsigned
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_UNSIGNED_LE")]
        UnsignedLe = 0x0009,
        /// <summary>
        /// All bits SET in B are SET in A. ((A&B)=B)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_BITSET")]
        Bitset = 0x000A,
        /// <summary>
        /// All bits SET in B are CLEAR in A. ((A&B)=0)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_BITCLEAR")]
        Bitclear = 0x000B
    }
    [DataContract]
    [SpecTypeName("TPM_ST")]
    /// <summary>
    /// Structure tags are used to disambiguate structures. They are 16-bit values with the most significant bit SET so that they do not overlap TPM_ALG_ID values. A single exception is made for the value associated with TPM_ST_RSP_COMMAND (0x00C4), which has the same value as the TPM_TAG_RSP_COMMAND tag from earlier versions of this specification. This value is used when the TPM is compatible with a previous TPM specification and the TPM cannot determine which family of response code to return because the command tag is not valid.
    /// </summary>
    public enum TpmSt : ushort
    {
        None = 0,
        /// <summary>
        /// tag value for a response; used when there is an error in the tag. This is also the value returned from a TPM 1.2 when an error occurs. This value is used in this specification because an error in the command tag may prevent determination of the family. When this tag is used in the response, the response code will be TPM_RC_BAD_TAG (0 1E16), which has the same numeric value as the TPM 1.2 response code for TPM_BADTAG.
        /// NOTE	In a previously published version of this specification, TPM_RC_BAD_TAG was incorrectly assigned a value of 0x030 instead of 30 (0x01e). Some implementations my return the old value instead of the new value.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_RSP_COMMAND")]
        RspCommand = 0x00C4,
        /// <summary>
        /// no structure type specified
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_NULL")]
        Null = 0X8000,
        /// <summary>
        /// tag value for a command/response for a command defined in this specification; indicating that the command/response has no attached sessions and no authorizationSize/parameterSize value is present
        /// If the responseCode from the TPM is not TPM_RC_SUCCESS, then the response tag shall have this value.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_NO_SESSIONS")]
        NoSessions = 0x8001,
        /// <summary>
        /// tag value for a command/response for a command defined in this specification; indicating that the command/response has one or more attached sessions and the authorizationSize/parameterSize field is present
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_SESSIONS")]
        Sessions = 0x8002,
        /// <summary>
        /// tag for an attestation structure
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_ATTEST_NV")]
        AttestNv = 0x8014,
        /// <summary>
        /// tag for an attestation structure
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_ATTEST_COMMAND_AUDIT")]
        AttestCommandAudit = 0x8015,
        /// <summary>
        /// tag for an attestation structure
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_ATTEST_SESSION_AUDIT")]
        AttestSessionAudit = 0x8016,
        /// <summary>
        /// tag for an attestation structure
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_ATTEST_CERTIFY")]
        AttestCertify = 0x8017,
        /// <summary>
        /// tag for an attestation structure
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_ATTEST_QUOTE")]
        AttestQuote = 0x8018,
        /// <summary>
        /// tag for an attestation structure
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_ATTEST_TIME")]
        AttestTime = 0x8019,
        /// <summary>
        /// tag for an attestation structure
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_ATTEST_CREATION")]
        AttestCreation = 0x801A,
        /// <summary>
        /// tag for a ticket type
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_CREATION")]
        Creation = 0x8021,
        /// <summary>
        /// tag for a ticket type
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_VERIFIED")]
        Verified = 0x8022,
        /// <summary>
        /// tag for a ticket type
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_AUTH_SECRET")]
        AuthSecret = 0x8023,
        /// <summary>
        /// tag for a ticket type
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_HASHCHECK")]
        Hashcheck = 0x8024,
        /// <summary>
        /// tag for a ticket type
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_AUTH_SIGNED")]
        AuthSigned = 0x8025,
        /// <summary>
        /// tag for a structure describing a Field Upgrade Policy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_FU_MANIFEST")]
        FuManifest = 0x8029
    }
    [DataContract]
    [SpecTypeName("TPM_SU")]
    /// <summary>
    /// These values are used in TPM2_Startup() to indicate the shutdown and startup mode. The defined startup sequences are:
    /// </summary>
    public enum Su : ushort
    {
        None = 0,
        /// <summary>
        /// on TPM2_Shutdown(), indicates that the TPM should prepare for loss of power and save state required for an orderly startup (TPM Reset).
        /// on TPM2_Startup(), indicates that the TPM should perform TPM Reset or TPM Restart
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_SU_CLEAR")]
        Clear = 0x0000,
        /// <summary>
        /// on TPM2_Shutdown(), indicates that the TPM should prepare for loss of power and save state required for an orderly startup (TPM Restart or TPM Resume)
        /// on TPM2_Startup(), indicates that the TPM should restore the state saved by TPM2_Shutdown(TPM_SU_STATE)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_SU_STATE")]
        State = 0x0001
    }
    [DataContract]
    [SpecTypeName("TPM_SE")]
    /// <summary>
    /// This type is used in TPM2_StartAuthSession() to indicate the type of the session to be created.
    /// </summary>
    public enum TpmSe : byte
    {
        None = 0,
        [EnumMember]
        [SpecTypeName("TPM_SE_HMAC")]
        Hmac = 0x00,
        [EnumMember]
        [SpecTypeName("TPM_SE_POLICY")]
        Policy = 0x01,
        /// <summary>
        /// The policy session is being used to compute the policyHash and not for command authorization.
        /// This setting modifies some policy commands and prevents session from being used to authorize a command.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_SE_TRIAL")]
        Trial = 0x03
    }
    [DataContract]
    [SpecTypeName("TPM_CAP")]
    /// <summary>
    /// The TPM_CAP values are used in TPM2_GetCapability() to select the type of the value to be returned. The format of the response varies according to the type of the value.
    /// </summary>
    public enum Cap : uint
    {
        None = 0,
        [EnumMember]
        [SpecTypeName("TPM_CAP_FIRST")]
        First = 0x00000000,
        /// <summary>
        /// TPML_ALG_PROPERTY
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_ALGS")]
        Algs = 0x00000000,
        /// <summary>
        /// TPML_HANDLE
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_HANDLES")]
        Handles = 0x00000001,
        /// <summary>
        /// TPML_CCA
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_COMMANDS")]
        Commands = 0x00000002,
        /// <summary>
        /// TPML_CC
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_PP_COMMANDS")]
        PpCommands = 0x00000003,
        /// <summary>
        /// TPML_CC
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_AUDIT_COMMANDS")]
        AuditCommands = 0x00000004,
        /// <summary>
        /// TPML_PCR_SELECTION
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_PCRS")]
        Pcrs = 0x00000005,
        /// <summary>
        /// TPML_TAGGED_TPM_PROPERTY
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_TPM_PROPERTIES")]
        TpmProperties = 0x00000006,
        /// <summary>
        /// TPML_TAGGED_PCR_PROPERTY
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_PCR_PROPERTIES")]
        PcrProperties = 0x00000007,
        /// <summary>
        /// TPML_ECC_CURVE
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_ECC_CURVES")]
        EccCurves = 0x00000008,
        [EnumMember]
        [SpecTypeName("TPM_CAP_LAST")]
        Last = 0x00000008,
        /// <summary>
        /// manufacturer-specific values
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_VENDOR_PROPERTY")]
        VendorProperty = 0x00000100
    }
    [DataContract]
    [SpecTypeName("TPM_PT")]
    /// <summary>
    /// The TPM_PT constants are used in TPM2_GetCapability(capability = TPM_CAP_TPM_PROPERTIES) to indicate the property being selected or returned.
    /// </summary>
    public enum Pt : uint
    {
        /// <summary>
        /// indicates no property type
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_NONE")]
        None = 0x00000000,
        /// <summary>
        /// The number of properties in each group.
        /// NOTE The first group with any properties is group 1 (PT_GROUP * 1). Group 0 is reserved.
        /// </summary>
        [EnumMember]
        [SpecTypeName("PT_GROUP")]
        PtGroup = 0x00000100,
        /// <summary>
        /// the group of fixed properties returned as TPMS_TAGGED_PROPERTY
        /// The values in this group are only changed due to a firmware change in the TPM.
        /// </summary>
        [EnumMember]
        [SpecTypeName("PT_FIXED")]
        PtFixed = 0x00000100 * 1, // 0x100
        /// <summary>
        /// a 4-octet character string containing the TPM Family value (TPM_SPEC_FAMILY)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_FAMILY_INDICATOR")]
        FamilyIndicator = 0x00000100 * 1 + 0, // 0x100
        /// <summary>
        /// the level of the specification
        /// NOTE 1	For this specification, the level is zero.
        /// NOTE 2	The level is on the title page of the specification.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_LEVEL")]
        Level = 0x00000100 * 1 + 1, // 0x101
        /// <summary>
        /// the specification Revision times 100
        /// EXAMPLE	Revision 01.01 would have a value of 101.
        /// NOTE	The Revision value is on the title page of the specification.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_REVISION")]
        Revision = 0x00000100 * 1 + 2, // 0x102
        /// <summary>
        /// the specification day of year using TCG calendar
        /// EXAMPLE	November 15, 2010, has a day of year value of 319 (0000013F16).
        /// NOTE The specification date is on the title page of the specification.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_DAY_OF_YEAR")]
        DayOfYear = 0x00000100 * 1 + 3, // 0x103
        /// <summary>
        /// the specification year using the CE
        /// EXAMPLE	The year 2010 has a value of 000007DA16.
        /// NOTE The specification date is on the title page of the specification.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_YEAR")]
        Year = 0x00000100 * 1 + 4, // 0x104
        /// <summary>
        /// the vendor ID unique to each TPM manufacturer
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MANUFACTURER")]
        Manufacturer = 0x00000100 * 1 + 5, // 0x105
        /// <summary>
        /// the first four characters of the vendor ID string
        /// NOTE	When the vendor string is fewer than 16 octets, the additional property values do not have to be present. A vendor string of 4 octets can be represented in one 32-bit value and no null terminating character is required.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_VENDOR_STRING_1")]
        VendorString1 = 0x00000100 * 1 + 6, // 0x106
        /// <summary>
        /// the second four characters of the vendor ID string
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_VENDOR_STRING_2")]
        VendorString2 = 0x00000100 * 1 + 7, // 0x107
        /// <summary>
        /// the third four characters of the vendor ID string
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_VENDOR_STRING_3")]
        VendorString3 = 0x00000100 * 1 + 8, // 0x108
        /// <summary>
        /// the fourth four characters of the vendor ID sting
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_VENDOR_STRING_4")]
        VendorString4 = 0x00000100 * 1 + 9, // 0x109
        /// <summary>
        /// vendor-defined value indicating the TPM model
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_VENDOR_TPM_TYPE")]
        VendorTpmType = 0x00000100 * 1 + 10, // 0x10A
        /// <summary>
        /// the most-significant 32 bits of a TPM vendor-specific value indicating the version number of the firmware. See 10.12.2 and 10.12.8.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_FIRMWARE_VERSION_1")]
        FirmwareVersion1 = 0x00000100 * 1 + 11, // 0x10B
        /// <summary>
        /// the least-significant 32 bits of a TPM vendor-specific value indicating the version number of the firmware. See 10.12.2 and 10.12.8.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_FIRMWARE_VERSION_2")]
        FirmwareVersion2 = 0x00000100 * 1 + 12, // 0x10C
        /// <summary>
        /// the maximum size of a parameter (typically, a TPM2B_MAX_BUFFER)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_INPUT_BUFFER")]
        InputBuffer = 0x00000100 * 1 + 13, // 0x10D
        /// <summary>
        /// the minimum number of transient objects that can be held in TPM RAM
        /// NOTE	This minimum shall be no less than the minimum value required by the platform-specific specification to which the TPM is built.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_TRANSIENT_MIN")]
        HrTransientMin = 0x00000100 * 1 + 14, // 0x10E
        /// <summary>
        /// the minimum number of persistent objects that can be held in TPM NV memory
        /// NOTE	This minimum shall be no less than the minimum value required by the platform-specific specification to which the TPM is built.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_PERSISTENT_MIN")]
        HrPersistentMin = 0x00000100 * 1 + 15, // 0x10F
        /// <summary>
        /// the minimum number of authorization sessions that can be held in TPM RAM
        /// NOTE	This minimum shall be no less than the minimum value required by the platform-specific specification to which the TPM is built.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_LOADED_MIN")]
        HrLoadedMin = 0x00000100 * 1 + 16, // 0x110
        /// <summary>
        /// the number of authorization sessions that may be active at a time
        /// A session is active when it has a context associated with its handle. The context may either be in TPM RAM or be context saved.
        /// NOTE	This value shall be no less than the minimum value required by the platform-specific specification to which the TPM is built.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_ACTIVE_SESSIONS_MAX")]
        ActiveSessionsMax = 0x00000100 * 1 + 17, // 0x111
        /// <summary>
        /// the number of PCR implemented
        /// NOTE	This number is determined by the defined attributes, not the number of PCR that are populated.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_COUNT")]
        PcrCount = 0x00000100 * 1 + 18, // 0x112
        /// <summary>
        /// the minimum number of octets in a TPMS_PCR_SELECT.sizeOfSelect
        /// NOTE	This value is not determined by the number of PCR implemented but by the number of PCR required by the platform-specific specification with which the TPM is compliant or by the implementer if not adhering to a platform-specific specification.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_SELECT_MIN")]
        PcrSelectMin = 0x00000100 * 1 + 19, // 0x113
        /// <summary>
        /// the maximum allowed difference (unsigned) between the contextID values of two saved session contexts
        /// This value shall be 2n-1, where n is at least 16.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_CONTEXT_GAP_MAX")]
        ContextGapMax = 0x00000100 * 1 + 20, // 0x114
        /// <summary>
        /// the maximum number of NV Indexes that are allowed to have the TPM_NT_COUNTER attribute
        /// NOTE	It is allowed for this value to be larger than the number of NV Indexes that can be defined. This would be indicative of a TPM implementation that did not use different implementation technology for different NV Index types.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_NV_COUNTERS_MAX")]
        NvCountersMax = 0x00000100 * 1 + 22, // 0x116
        /// <summary>
        /// the maximum size of an NV Index data area
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_NV_INDEX_MAX")]
        NvIndexMax = 0x00000100 * 1 + 23, // 0x117
        /// <summary>
        /// a TPMA_MEMORY indicating the memory management method for the TPM
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MEMORY")]
        Memory = 0x00000100 * 1 + 24, // 0x118
        /// <summary>
        /// interval, in milliseconds, between updates to the copy of TPMS_CLOCK_INFO.clock in NV
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_CLOCK_UPDATE")]
        ClockUpdate = 0x00000100 * 1 + 25, // 0x119
        /// <summary>
        /// the algorithm used for the integrity HMAC on saved contexts and for hashing the fuData of TPM2_FirmwareRead()
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_CONTEXT_HASH")]
        ContextHash = 0x00000100 * 1 + 26, // 0x11A
        /// <summary>
        /// TPM_ALG_ID, the algorithm used for encryption of saved contexts
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_CONTEXT_SYM")]
        ContextSym = 0x00000100 * 1 + 27, // 0x11B
        /// <summary>
        /// TPM_KEY_BITS, the size of the key used for encryption of saved contexts
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_CONTEXT_SYM_SIZE")]
        ContextSymSize = 0x00000100 * 1 + 28, // 0x11C
        /// <summary>
        /// the modulus - 1 of the count for NV update of an orderly counter
        /// The returned value is MAX_ORDERLY_COUNT.
        /// This will have a value of 2N  1 where 1  N  32
        /// NOTE 1	An orderly counter is an NV Index with an TPM_NT of TPM_NV_COUNTER and TPMA_NV_ORDERLY SET.
        /// NOTE 2	When the low-order bits of a counter equal this value, an NV write occurs on the next increment.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_ORDERLY_COUNT")]
        OrderlyCount = 0x00000100 * 1 + 29, // 0x11D
        /// <summary>
        /// the maximum value for commandSize in a command
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MAX_COMMAND_SIZE")]
        MaxCommandSize = 0x00000100 * 1 + 30, // 0x11E
        /// <summary>
        /// the maximum value for responseSize in a response
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MAX_RESPONSE_SIZE")]
        MaxResponseSize = 0x00000100 * 1 + 31, // 0x11F
        /// <summary>
        /// the maximum size of a digest that can be produced by the TPM
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MAX_DIGEST")]
        MaxDigest = 0x00000100 * 1 + 32, // 0x120
        /// <summary>
        /// the maximum size of an object context that will be returned by TPM2_ContextSave
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MAX_OBJECT_CONTEXT")]
        MaxObjectContext = 0x00000100 * 1 + 33, // 0x121
        /// <summary>
        /// the maximum size of a session context that will be returned by TPM2_ContextSave
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MAX_SESSION_CONTEXT")]
        MaxSessionContext = 0x00000100 * 1 + 34, // 0x122
        /// <summary>
        /// platform-specific family (a TPM_PS value)(see Table 25)
        /// NOTE	The platform-specific values for the TPM_PT_PS parameters are in the relevant platform-specific specification. In the reference implementation, all of these values are 0.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PS_FAMILY_INDICATOR")]
        PsFamilyIndicator = 0x00000100 * 1 + 35, // 0x123
        /// <summary>
        /// the level of the platform-specific specification
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PS_LEVEL")]
        PsLevel = 0x00000100 * 1 + 36, // 0x124
        /// <summary>
        /// the specification Revision times 100 for the platform-specific specification
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PS_REVISION")]
        PsRevision = 0x00000100 * 1 + 37, // 0x125
        /// <summary>
        /// the platform-specific specification day of year using TCG calendar
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PS_DAY_OF_YEAR")]
        PsDayOfYear = 0x00000100 * 1 + 38, // 0x126
        /// <summary>
        /// the platform-specific specification year using the CE
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PS_YEAR")]
        PsYear = 0x00000100 * 1 + 39, // 0x127
        /// <summary>
        /// the number of split signing operations supported by the TPM
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_SPLIT_MAX")]
        SplitMax = 0x00000100 * 1 + 40, // 0x128
        /// <summary>
        /// total number of commands implemented in the TPM
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_TOTAL_COMMANDS")]
        TotalCommands = 0x00000100 * 1 + 41, // 0x129
        /// <summary>
        /// number of commands from the TPM library that are implemented
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_LIBRARY_COMMANDS")]
        LibraryCommands = 0x00000100 * 1 + 42, // 0x12A
        /// <summary>
        /// number of vendor commands that are implemented
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_VENDOR_COMMANDS")]
        VendorCommands = 0x00000100 * 1 + 43, // 0x12B
        /// <summary>
        /// the maximum data size in one NV write command
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_NV_BUFFER_MAX")]
        NvBufferMax = 0x00000100 * 1 + 44, // 0x12C
        /// <summary>
        /// a TPMA_MODES value, indicating that the TPM is designed for these modes.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MODES")]
        Modes = 0x00000100 * 1 + 45, // 0x12D
        /// <summary>
        /// the group of variable properties returned as TPMS_TAGGED_PROPERTY
        /// The properties in this group change because of a Protected Capability other than a firmware update. The values are not necessarily persistent across all power transitions.
        /// </summary>
        [EnumMember]
        [SpecTypeName("PT_VAR")]
        PtVar = 0x00000100 * 2, // 0x200
        /// <summary>
        /// TPMA_PERMANENT
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PERMANENT")]
        Permanent = 0x00000100 * 2 + 0, // 0x200
        /// <summary>
        /// TPMA_STARTUP_CLEAR
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_STARTUP_CLEAR")]
        StartupClear = 0x00000100 * 2 + 1, // 0x201
        /// <summary>
        /// the number of NV Indexes currently defined
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_NV_INDEX")]
        HrNvIndex = 0x00000100 * 2 + 2, // 0x202
        /// <summary>
        /// the number of authorization sessions currently loaded into TPM RAM
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_LOADED")]
        HrLoaded = 0x00000100 * 2 + 3, // 0x203
        /// <summary>
        /// the number of additional authorization sessions, of any type, that could be loaded into TPM RAM
        /// This value is an estimate. If this value is at least 1, then at least one authorization session of any type may be loaded. Any command that changes the RAM memory allocation can make this estimate invalid.
        /// NOTE	A valid implementation may return 1 even if more than one authorization session would fit into RAM.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_LOADED_AVAIL")]
        HrLoadedAvail = 0x00000100 * 2 + 4, // 0x204
        /// <summary>
        /// the number of active authorization sessions currently being tracked by the TPM
        /// This is the sum of the loaded and saved sessions.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_ACTIVE")]
        HrActive = 0x00000100 * 2 + 5, // 0x205
        /// <summary>
        /// the number of additional authorization sessions, of any type, that could be created
        /// This value is an estimate. If this value is at least 1, then at least one authorization session of any type may be created. Any command that changes the RAM memory allocation can make this estimate invalid.
        /// NOTE	A valid implementation may return 1 even if more than one authorization session could be created.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_ACTIVE_AVAIL")]
        HrActiveAvail = 0x00000100 * 2 + 6, // 0x206
        /// <summary>
        /// estimate of the number of additional transient objects that could be loaded into TPM RAM
        /// This value is an estimate. If this value is at least 1, then at least one object of any type may be loaded. Any command that changes the memory allocation can make this estimate invalid.
        /// NOTE	A valid implementation may return 1 even if more than one transient object would fit into RAM.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_TRANSIENT_AVAIL")]
        HrTransientAvail = 0x00000100 * 2 + 7, // 0x207
        /// <summary>
        /// the number of persistent objects currently loaded into TPM NV memory
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_PERSISTENT")]
        HrPersistent = 0x00000100 * 2 + 8, // 0x208
        /// <summary>
        /// the number of additional persistent objects that could be loaded into NV memory
        /// This value is an estimate. If this value is at least 1, then at least one object of any type may be made persistent. Any command that changes the NV memory allocation can make this estimate invalid.
        /// NOTE	A valid implementation may return 1 even if more than one persistent object would fit into NV memory.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_PERSISTENT_AVAIL")]
        HrPersistentAvail = 0x00000100 * 2 + 9, // 0x209
        /// <summary>
        /// the number of defined NV Indexes that have NV the TPM_NT_COUNTER attribute
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_NV_COUNTERS")]
        NvCounters = 0x00000100 * 2 + 10, // 0x20A
        /// <summary>
        /// the number of additional NV Indexes that can be defined with their TPM_NT of TPM_NV_COUNTER and the TPMA_NV_ORDERLY attribute SET
        /// This value is an estimate. If this value is at least 1, then at least one NV Index may be created with a TPM_NT of TPM_NV_COUNTER and the TPMA_NV_ORDERLY attributes. Any command that changes the NV memory allocation can make this estimate invalid.
        /// NOTE	A valid implementation may return 1 even if more than one NV counter could be defined.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_NV_COUNTERS_AVAIL")]
        NvCountersAvail = 0x00000100 * 2 + 11, // 0x20B
        /// <summary>
        /// code that limits the algorithms that may be used with the TPM
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_ALGORITHM_SET")]
        AlgorithmSet = 0x00000100 * 2 + 12, // 0x20C
        /// <summary>
        /// the number of loaded ECC curves
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_LOADED_CURVES")]
        LoadedCurves = 0x00000100 * 2 + 13, // 0x20D
        /// <summary>
        /// the current value of the lockout counter (failedTries)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_LOCKOUT_COUNTER")]
        LockoutCounter = 0x00000100 * 2 + 14, // 0x20E
        /// <summary>
        /// the number of authorization failures before DA lockout is invoked
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MAX_AUTH_FAIL")]
        MaxAuthFail = 0x00000100 * 2 + 15, // 0x20F
        /// <summary>
        /// the number of seconds before the value reported by TPM_PT_LOCKOUT_COUNTER is decremented
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_LOCKOUT_INTERVAL")]
        LockoutInterval = 0x00000100 * 2 + 16, // 0x210
        /// <summary>
        /// the number of seconds after a lockoutAuth failure before use of lockoutAuth may be attempted again
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_LOCKOUT_RECOVERY")]
        LockoutRecovery = 0x00000100 * 2 + 17, // 0x211
        /// <summary>
        /// number of milliseconds before the TPM will accept another command that will modify NV
        /// This value is an approximation and may go up or down over time.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_NV_WRITE_RECOVERY")]
        NvWriteRecovery = 0x00000100 * 2 + 18, // 0x212
        /// <summary>
        /// the high-order 32 bits of the command audit counter
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_AUDIT_COUNTER_0")]
        AuditCounter0 = 0x00000100 * 2 + 19, // 0x213
        /// <summary>
        /// the low-order 32 bits of the command audit counter
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_AUDIT_COUNTER_1")]
        AuditCounter1 = 0x00000100 * 2 + 20 // 0x214
    }
    [DataContract]
    [SpecTypeName("TPM_PT_PCR")]
    /// <summary>
    /// The TPM_PT_PCR constants are used in TPM2_GetCapability() to indicate the property being selected or returned. The PCR properties can be read when capability == TPM_CAP_PCR_PROPERTIES. If there is no property that corresponds to the value of property, the next higher value is returned, if it exists.
    /// </summary>
    public enum PtPcr : uint
    {
        None = 0,
        /// <summary>
        /// bottom of the range of TPM_PT_PCR properties
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_FIRST")]
        First = 0x00000000,
        /// <summary>
        /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR is saved and restored by TPM_SU_STATE
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_SAVE")]
        Save = 0x00000000,
        /// <summary>
        /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from locality 0
        /// This property is only present if a locality other than 0 is implemented.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_EXTEND_L0")]
        ExtendL0 = 0x00000001,
        /// <summary>
        /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 0
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_RESET_L0")]
        ResetL0 = 0x00000002,
        /// <summary>
        /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from locality 1 This property is only present if locality 1 is implemented.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_EXTEND_L1")]
        ExtendL1 = 0x00000003,
        /// <summary>
        /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 1
        /// This property is only present if locality 1 is implemented.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_RESET_L1")]
        ResetL1 = 0x00000004,
        /// <summary>
        /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from locality 2 This property is only present if localities 1 and 2 are implemented.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_EXTEND_L2")]
        ExtendL2 = 0x00000005,
        /// <summary>
        /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 2
        /// This property is only present if localities 1 and 2 are implemented.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_RESET_L2")]
        ResetL2 = 0x00000006,
        /// <summary>
        /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from locality 3
        /// This property is only present if localities 1, 2, and 3 are implemented.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_EXTEND_L3")]
        ExtendL3 = 0x00000007,
        /// <summary>
        /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 3
        /// This property is only present if localities 1, 2, and 3 are implemented.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_RESET_L3")]
        ResetL3 = 0x00000008,
        /// <summary>
        /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from locality 4
        /// This property is only present if localities 1, 2, 3, and 4 are implemented.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_EXTEND_L4")]
        ExtendL4 = 0x00000009,
        /// <summary>
        /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 4
        /// This property is only present if localities 1, 2, 3, and 4 are implemented.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_RESET_L4")]
        ResetL4 = 0x0000000A,
        /// <summary>
        /// a SET bit in the TPMS_PCR_SELECT indicates that modifications to this PCR (reset or Extend) will not increment the pcrUpdateCounter
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_NO_INCREMENT")]
        NoIncrement = 0x00000011,
        /// <summary>
        /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR is reset by a D-RTM event
        /// These PCR are reset to -1 on TPM2_Startup() and reset to 0 on a _TPM_Hash_End event following a _TPM_Hash_Start event.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_DRTM_RESET")]
        DrtmReset = 0x00000012,
        /// <summary>
        /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR is controlled by policy
        /// This property is only present if the TPM supports policy control of a PCR.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_POLICY")]
        Policy = 0x00000013,
        /// <summary>
        /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR is controlled by an authorization value
        /// This property is only present if the TPM supports authorization control of a PCR.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_AUTH")]
        Auth = 0x00000014,
        /// <summary>
        /// top of the range of TPM_PT_PCR properties of the implementation
        /// If the TPM receives a request for a PCR property with a value larger than this, the TPM will return a zero length list and set the moreData parameter to NO.
        /// NOTE	This is an implementation-specific value. The value shown reflects the reference code implementation.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_LAST")]
        Last = 0x00000014
    }
    [DataContract]
    [SpecTypeName("TPM_PS")]
    /// <summary>
    /// The platform values in Table 25 are used for the TPM_PT_PS_FAMILY_INDICATOR.
    /// </summary>
    public enum Ps : uint
    {
        None = 0,
        /// <summary>
        /// not platform specific
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_MAIN")]
        Main = 0x00000000,
        /// <summary>
        /// PC Client
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_PC")]
        Pc = 0x00000001,
        /// <summary>
        /// PDA (includes all mobile devices that are not specifically cell phones)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_PDA")]
        Pda = 0x00000002,
        /// <summary>
        /// Cell Phone
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_CELL_PHONE")]
        CellPhone = 0x00000003,
        /// <summary>
        /// Server WG
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_SERVER")]
        Server = 0x00000004,
        /// <summary>
        /// Peripheral WG
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_PERIPHERAL")]
        Peripheral = 0x00000005,
        /// <summary>
        /// TSS WG
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_TSS")]
        Tss = 0x00000006,
        /// <summary>
        /// Storage WG
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_STORAGE")]
        Storage = 0x00000007,
        /// <summary>
        /// Authentication WG
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_AUTHENTICATION")]
        Authentication = 0x00000008,
        /// <summary>
        /// Embedded WG
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_EMBEDDED")]
        Embedded = 0x00000009,
        /// <summary>
        /// Hardcopy WG
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_HARDCOPY")]
        Hardcopy = 0x0000000A,
        /// <summary>
        /// Infrastructure WG
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_INFRASTRUCTURE")]
        Infrastructure = 0x0000000B,
        /// <summary>
        /// Virtualization WG
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_VIRTUALIZATION")]
        Virtualization = 0x0000000C,
        /// <summary>
        /// Trusted Network Connect WG
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_TNC")]
        Tnc = 0x0000000D,
        /// <summary>
        /// Multi-tenant WG
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_MULTI_TENANT")]
        MultiTenant = 0x0000000E,
        /// <summary>
        /// Technical Committee
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_TC")]
        Tc = 0x0000000F
    }
    [DataContract]
    [SpecTypeName("TPM_HT")]
    /// <summary>
    /// The 32-bit handle space is divided into 256 regions of equal size with 224 values in each. Each of these ranges represents a handle type.
    /// </summary>
    public enum Ht : byte
    {
        None = 0,
        /// <summary>
        /// PCR  consecutive numbers, starting at 0, that reference the PCR registers
        /// A platform-specific specification will set the minimum number of PCR and an implementation may have more.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_PCR")]
        Pcr = 0x00,
        /// <summary>
        /// NV Index  assigned by the caller
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_NV_INDEX")]
        NvIndex = 0x01,
        /// <summary>
        /// HMAC Authorization Session  assigned by the TPM when the session is created
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_HMAC_SESSION")]
        HmacSession = 0x02,
        /// <summary>
        /// Loaded Authorization Session  used only in the context of TPM2_GetCapability
        /// This type references both loaded HMAC and loaded policy authorization sessions.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_LOADED_SESSION")]
        LoadedSession = 0x02,
        /// <summary>
        /// Policy Authorization Session  assigned by the TPM when the session is created
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_POLICY_SESSION")]
        PolicySession = 0x03,
        /// <summary>
        /// Saved Authorization Session  used only in the context of TPM2_GetCapability
        /// This type references saved authorization session contexts for which the TPM is maintaining tracking information.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_SAVED_SESSION")]
        SavedSession = 0x03,
        /// <summary>
        /// Permanent Values  assigned by this specification in Table 28
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_PERMANENT")]
        Permanent = 0x40,
        /// <summary>
        /// Transient Objects  assigned by the TPM when an object is loaded into transient-object memory or when a persistent object is converted to a transient object
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_TRANSIENT")]
        Transient = 0x80,
        /// <summary>
        /// Persistent Objects  assigned by the TPM when a loaded transient object is made persistent
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_PERSISTENT")]
        Persistent = 0x81
    }
    [DataContract]
    [SpecTypeName("TPM_RH")]
    /// <summary>
    /// Table 28 lists the architecturally defined handles that cannot be changed. The handles include authorization handles, and special handles.
    /// </summary>
    public enum TpmRh : uint
    {
        None = 0,
        [EnumMember]
        [SpecTypeName("TPM_RH_FIRST")]
        First = 0x40000000,
        /// <summary>
        /// not used1
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_SRK")]
        Srk = 0x40000000,
        /// <summary>
        /// handle references the Storage Primary Seed (SPS), the ownerAuth, and the ownerPolicy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_OWNER")]
        Owner = 0x40000001,
        /// <summary>
        /// not used1
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_REVOKE")]
        Revoke = 0x40000002,
        /// <summary>
        /// not used1
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_TRANSPORT")]
        Transport = 0x40000003,
        /// <summary>
        /// not used1
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_OPERATOR")]
        Operator = 0x40000004,
        /// <summary>
        /// not used1
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_ADMIN")]
        Admin = 0x40000005,
        /// <summary>
        /// not used1
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_EK")]
        Ek = 0x40000006,
        /// <summary>
        /// a handle associated with the null hierarchy, an EmptyAuth authValue, and an Empty Policy authPolicy.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_NULL")]
        Null = 0x40000007,
        /// <summary>
        /// value reserved to the TPM to indicate a handle location that has not been initialized or assigned
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_UNASSIGNED")]
        Unassigned = 0x40000008,
        /// <summary>
        /// authorization value used to indicate a password authorization session
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RS_PW")]
        TpmRsPw = 0x40000009,
        /// <summary>
        /// references the authorization associated with the dictionary attack lockout reset
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_LOCKOUT")]
        Lockout = 0x4000000A,
        /// <summary>
        /// references the Endorsement Primary Seed (EPS), endorsementAuth, and endorsementPolicy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_ENDORSEMENT")]
        Endorsement = 0x4000000B,
        /// <summary>
        /// references the Platform Primary Seed (PPS), platformAuth, and platformPolicy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_PLATFORM")]
        Platform = 0x4000000C,
        /// <summary>
        /// for phEnableNV
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_PLATFORM_NV")]
        PlatformNv = 0x4000000D,
        /// <summary>
        /// Start of a range of authorization values that are vendor-specific. A TPM may support any of the values in this range as are needed for vendor-specific purposes.
        /// Disabled if ehEnable is CLEAR.
        /// NOTE Any includes none.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_AUTH_00")]
        Auth00 = 0x40000010,
        /// <summary>
        /// End of the range of vendor-specific authorization values.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_AUTH_FF")]
        AuthFf = 0x4000010F,
        /// <summary>
        /// the top of the reserved handle area
        /// This is set to allow TPM2_GetCapability() to know where to stop. It may vary as implementations add to the permanent handle area.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_LAST")]
        Last = 0x4000010F
    }
    [DataContract]
    [SpecTypeName("TPM_NT")]
    /// <summary>
    /// This table lists the values of the TPM_NT field of a TPMA_NV. See Table 203 for usage.
    /// </summary>
    public enum Nt : uint
    {
        None = 0,
        /// <summary>
        /// Ordinary  contains data that is opaque to the TPM that can only be modified using TPM2_NV_Write().
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_NT_ORDINARY")]
        Ordinary = 0x0,
        /// <summary>
        /// Counter  contains an 8-octet value that is to be used as a counter and can only be modified with TPM2_NV_Increment()
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_NT_COUNTER")]
        Counter = 0x1,
        /// <summary>
        /// Bit Field  contains an 8-octet value to be used as a bit field and can only be modified with TPM2_NV_SetBits().
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_NT_BITS")]
        Bits = 0x2,
        /// <summary>
        /// Extend  contains a digest-sized value used like a PCR. The Index can only be modified using TPM2_NV_Extend(). The extend will use the nameAlg of the Index.
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_NT_EXTEND")]
        Extend = 0x4,
        /// <summary>
        /// PIN Fail - contains pinCount that increments on a PIN authorization failure and a pinLimit
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_NT_PIN_FAIL")]
        PinFail = 0x8,
        /// <summary>
        /// PIN Pass - contains pinCount that increments on a PIN authorization success and a pinLimit
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_NT_PIN_PASS")]
        PinPass = 0x9
    }
    [DataContract]
    [SpecTypeName("Implementation")]
    /// <summary>
    /// This table contains a collection of values used in various parts of the reference code. The values shown are illustrative.
    /// </summary>
    public enum Implementation : uint
    {
        None = 0,
        /// <summary>
        /// temporary define
        /// </summary>
        [EnumMember]
        [SpecTypeName("FIELD_UPGRADE_IMPLEMENTED")]
        FieldUpgradeImplemented = 0, // 0x0
        /// <summary>
        /// sets the size granularity for the buffers in a TPM2B structure
        /// TPMxB buffers will be assigned a space that is a multiple of this value. This does not set the size limits for IO. Those are set by the canonical form of the TPMxB
        /// </summary>
        [EnumMember]
        [SpecTypeName("BUFFER_ALIGNMENT")]
        BufferAlignment = 4,
        /// <summary>
        /// the number of PCR in the TPM
        /// </summary>
        [EnumMember]
        [SpecTypeName("IMPLEMENTATION_PCR")]
        ImplementationPcr = 24,
        /// <summary>
        /// the number of PCR required by the relevant platform specification
        /// </summary>
        [EnumMember]
        [SpecTypeName("PLATFORM_PCR")]
        PlatformPcr = 24,
        /// <summary>
        /// the D-RTM PCR
        /// NOTE This value is not defined when the TPM does not implement D-RTM
        /// </summary>
        [EnumMember]
        [SpecTypeName("DRTM_PCR")]
        DrtmPcr = 17,
        /// <summary>
        /// the PCR that will receive the H-CRTM value at TPM2_Startup. This value should not be changed.
        /// </summary>
        [EnumMember]
        [SpecTypeName("HCRTM_PCR")]
        HcrtmPcr = 0,
        /// <summary>
        /// the number of localities supported by the TPM
        /// This is expected to be either 5 for a PC, or 1 for just about everything else.
        /// </summary>
        [EnumMember]
        [SpecTypeName("NUM_LOCALITIES")]
        NumLocalities = 5,
        /// <summary>
        /// the maximum number of handles in the handle area
        /// This should be produced by the Part 3 parser but is here for now.
        /// </summary>
        [EnumMember]
        [SpecTypeName("MAX_HANDLE_NUM")]
        MaxHandleNum = 3,
        /// <summary>
        /// the number of simultaneously active sessions that are supported by the TPM implementation
        /// </summary>
        [EnumMember]
        [SpecTypeName("MAX_ACTIVE_SESSIONS")]
        MaxActiveSessions = 64,
        /// <summary>
        /// the number of sessions that the TPM may have in memory
        /// </summary>
        [EnumMember]
        [SpecTypeName("MAX_LOADED_SESSIONS")]
        MaxLoadedSessions = 3,
        /// <summary>
        /// this is the current maximum value
        /// </summary>
        [EnumMember]
        [SpecTypeName("MAX_SESSION_NUM")]
        MaxSessionNum = 3,
        /// <summary>
        /// the number of simultaneously loaded objects that are supported by the TPM; this number does not include the objects that may be placed in NV memory by TPM2_EvictControl().
        /// </summary>
        [EnumMember]
        [SpecTypeName("MAX_LOADED_OBJECTS")]
        MaxLoadedObjects = 3,
        /// <summary>
        /// the minimum number of evict objects supported by the TPM
        /// </summary>
        [EnumMember]
        [SpecTypeName("MIN_EVICT_OBJECTS")]
        MinEvictObjects = 2,
        [EnumMember]
        [SpecTypeName("PCR_SELECT_MIN")]
        PcrSelectMin = ((24+7)/8), // 0x3
        [EnumMember]
        [SpecTypeName("PCR_SELECT_MAX")]
        PcrSelectMax = ((24+7)/8), // 0x3
        /// <summary>
        /// number of PCR groups that have individual policies
        /// </summary>
        [EnumMember]
        [SpecTypeName("NUM_POLICY_PCR_GROUP")]
        NumPolicyPcrGroup = 1,
        /// <summary>
        /// number of PCR groups that have individual authorization values
        /// </summary>
        [EnumMember]
        [SpecTypeName("NUM_AUTHVALUE_PCR_GROUP")]
        NumAuthvaluePcrGroup = 1,
        /// <summary>
        /// This may be larger than necessary
        /// </summary>
        [EnumMember]
        [SpecTypeName("MAX_CONTEXT_SIZE")]
        MaxContextSize = 2048,
        [EnumMember]
        [SpecTypeName("MAX_DIGEST_BUFFER")]
        MaxDigestBuffer = 1024,
        /// <summary>
        /// maximum data size allowed in an NV Index
        /// </summary>
        [EnumMember]
        [SpecTypeName("MAX_NV_INDEX_SIZE")]
        MaxNvIndexSize = 2048,
        /// <summary>
        /// maximum data size in one NV read or write command
        /// </summary>
        [EnumMember]
        [SpecTypeName("MAX_NV_BUFFER_SIZE")]
        MaxNvBufferSize = 1024,
        /// <summary>
        /// maximum size of a capability buffer
        /// </summary>
        [EnumMember]
        [SpecTypeName("MAX_CAP_BUFFER")]
        MaxCapBuffer = 1024,
        /// <summary>
        /// size of NV memory in octets
        /// </summary>
        [EnumMember]
        [SpecTypeName("NV_MEMORY_SIZE")]
        NvMemorySize = 16384,
        [EnumMember]
        [SpecTypeName("NUM_STATIC_PCR")]
        NumStaticPcr = 16,
        /// <summary>
        /// number of algorithms that can be in a list
        /// </summary>
        [EnumMember]
        [SpecTypeName("MAX_ALG_LIST_SIZE")]
        MaxAlgListSize = 64,
        /// <summary>
        /// nominal value for the pre-scale value of Clock (the number of cycles of the TPM's oscillator for each increment of Clock)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TIMER_PRESCALE")]
        TimerPrescale = 100000,
        /// <summary>
        /// size of the Primary Seed in octets
        /// </summary>
        [EnumMember]
        [SpecTypeName("PRIMARY_SEED_SIZE")]
        PrimarySeedSize = 32,
        /// <summary>
        /// context encryption algorithm
        /// </summary>
        [EnumMember]
        [SpecTypeName("CONTEXT_ENCRYPT_ALG")]
        ContextEncryptAlg = 0x0006, // 0x6
        /// <summary>
        /// context encryption key size in bits
        /// </summary>
        [EnumMember]
        [SpecTypeName("CONTEXT_ENCRYPT_KEY_BITS")]
        ContextEncryptKeyBits = 256, // 0x100
        [EnumMember]
        [SpecTypeName("CONTEXT_ENCRYPT_KEY_BYTES")]
        ContextEncryptKeyBytes = ((256+7)/8), // 0x20
        /// <summary>
        /// context integrity hash algorithm
        /// </summary>
        [EnumMember]
        [SpecTypeName("CONTEXT_INTEGRITY_HASH_ALG")]
        ContextIntegrityHashAlg = 0x000B, // 0xB
        /// <summary>
        /// number of byes in the context integrity digest
        /// </summary>
        [EnumMember]
        [SpecTypeName("CONTEXT_INTEGRITY_HASH_SIZE")]
        ContextIntegrityHashSize = 32, // 0x20
        /// <summary>
        /// size of proof value in octets
        /// This size of the proof should be consistent with the digest size used for context integrity.
        /// </summary>
        [EnumMember]
        [SpecTypeName("PROOF_SIZE")]
        ProofSize = 32, // 0x20
        /// <summary>
        /// the update interval expressed as a power of 2 seconds
        /// A value of 12 is 4,096 seconds (~68 minutes).
        /// </summary>
        [EnumMember]
        [SpecTypeName("NV_CLOCK_UPDATE_INTERVAL")]
        NvClockUpdateInterval = 12,
        /// <summary>
        /// number of PCR groups that allow policy/auth
        /// </summary>
        [EnumMember]
        [SpecTypeName("NUM_POLICY_PCR")]
        NumPolicyPcr = 1,
        /// <summary>
        /// maximum size of a command
        /// </summary>
        [EnumMember]
        [SpecTypeName("MAX_COMMAND_SIZE")]
        MaxCommandSize = 4096,
        /// <summary>
        /// maximum size of a response
        /// </summary>
        [EnumMember]
        [SpecTypeName("MAX_RESPONSE_SIZE")]
        MaxResponseSize = 4096,
        /// <summary>
        /// number between 1 and 32 inclusive
        /// </summary>
        [EnumMember]
        [SpecTypeName("ORDERLY_BITS")]
        OrderlyBits = 8,
        /// <summary>
        /// maximum count of orderly counter before NV is updated
        /// This must be of the form 2N  1 where 1  N  32.
        /// </summary>
        [EnumMember]
        [SpecTypeName("MAX_ORDERLY_COUNT")]
        MaxOrderlyCount = ((1 << 8) - 1), // 0xFF
        /// <summary>
        /// used by TPM2_GetCapability() processing to bound the algorithm search
        /// </summary>
        [EnumMember]
        [SpecTypeName("ALG_ID_FIRST")]
        AlgIdFirst = 0x0001, // 0x1
        /// <summary>
        /// used by TPM2_GetCapability() processing to bound the algorithm search
        /// </summary>
        [EnumMember]
        [SpecTypeName("ALG_ID_LAST")]
        AlgIdLast = 0x0044, // 0x44
        /// <summary>
        /// the maximum number of octets that may be in a sealed blob; 128 is the minimum allowed value
        /// </summary>
        [EnumMember]
        [SpecTypeName("MAX_SYM_DATA")]
        MaxSymData = 128,
        [EnumMember]
        [SpecTypeName("MAX_RNG_ENTROPY_SIZE")]
        MaxRngEntropySize = 64,
        [EnumMember]
        [SpecTypeName("RAM_INDEX_SPACE")]
        RamIndexSpace = 512,
        /// <summary>
        /// 216 + 1
        /// </summary>
        [EnumMember]
        [SpecTypeName("RSA_DEFAULT_PUBLIC_EXPONENT")]
        RsaDefaultPublicExponent = 0x00010001,
        /// <summary>
        /// indicates if the TPM_PT_PCR_NO_INCREMENT group is implemented
        /// </summary>
        [EnumMember]
        [SpecTypeName("ENABLE_PCR_NO_INCREMENT")]
        EnablePcrNoIncrement = 1, // 0x1
        [EnumMember]
        [SpecTypeName("CRT_FORMAT_RSA")]
        CrtFormatRsa = 1, // 0x1
        [EnumMember]
        [SpecTypeName("VENDOR_COMMAND_COUNT")]
        VendorCommandCount = 0,
        /// <summary>
        /// MAX_RSA_KEY_BYTES is auto generated from the RSA key size selection in Table 4. If RSA is not implemented, this may need to be manually removed.
        /// </summary>
        [EnumMember]
        [SpecTypeName("PRIVATE_VENDOR_SPECIFIC_BYTES")]
        PrivateVendorSpecificBytes = ((256/2) * (3 + 1 * 2)), // 0x280
        /// <summary>
        /// Maximum size of the vendor-specific buffer
        /// </summary>
        [EnumMember]
        [SpecTypeName("MAX_VENDOR_BUFFER_SIZE")]
        MaxVendorBufferSize = 1024
    }
    [DataContract]
    [SpecTypeName("TPM_HC")]
    /// <summary>
    /// The definitions in Table 29 are used to define many of the interface data types.
    /// </summary>
    public enum TpmHc : uint
    {
        None = 0,
        /// <summary>
        /// to mask off the HR
        /// </summary>
        [EnumMember]
        [SpecTypeName("HR_HANDLE_MASK")]
        HrHandleMask = 0x00FFFFFF,
        /// <summary>
        /// to mask off the variable part
        /// </summary>
        [EnumMember]
        [SpecTypeName("HR_RANGE_MASK")]
        HrRangeMask = 0xFF000000,
        [EnumMember]
        [SpecTypeName("HR_SHIFT")]
        HrShift = 24,
        [EnumMember]
        [SpecTypeName("HR_PCR")]
        HrPcr = (0x00 << 24), // 0x0
        [EnumMember]
        [SpecTypeName("HR_HMAC_SESSION")]
        HrHmacSession = (0x02 << 24), // 0x2000000
        [EnumMember]
        [SpecTypeName("HR_POLICY_SESSION")]
        HrPolicySession = (0x03 << 24), // 0x3000000
        [EnumMember]
        [SpecTypeName("HR_TRANSIENT")]
        HrTransient = (0x80u << 24), // 0x80000000
        [EnumMember]
        [SpecTypeName("HR_PERSISTENT")]
        HrPersistent = (0x81u << 24), // 0x81000000
        [EnumMember]
        [SpecTypeName("HR_NV_INDEX")]
        HrNvIndex = (0x01 << 24), // 0x1000000
        [EnumMember]
        [SpecTypeName("HR_PERMANENT")]
        HrPermanent = (0x40 << 24), // 0x40000000
        /// <summary>
        /// first PCR
        /// </summary>
        [EnumMember]
        [SpecTypeName("PCR_FIRST")]
        PcrFirst = ((0x00 << 24) + 0), // 0x0
        /// <summary>
        /// last PCR
        /// </summary>
        [EnumMember]
        [SpecTypeName("PCR_LAST")]
        PcrLast = (((0x00 << 24) + 0) + 24-1), // 0x17
        /// <summary>
        /// first HMAC session
        /// </summary>
        [EnumMember]
        [SpecTypeName("HMAC_SESSION_FIRST")]
        HmacSessionFirst = ((0x02 << 24) + 0), // 0x2000000
        /// <summary>
        /// last HMAC session
        /// </summary>
        [EnumMember]
        [SpecTypeName("HMAC_SESSION_LAST")]
        HmacSessionLast = (((0x02 << 24) + 0)+64-1), // 0x200003F
        /// <summary>
        /// used in GetCapability
        /// </summary>
        [EnumMember]
        [SpecTypeName("LOADED_SESSION_FIRST")]
        LoadedSessionFirst = ((0x02 << 24) + 0), // 0x2000000
        /// <summary>
        /// used in GetCapability
        /// </summary>
        [EnumMember]
        [SpecTypeName("LOADED_SESSION_LAST")]
        LoadedSessionLast = (((0x02 << 24) + 0)+64-1), // 0x200003F
        /// <summary>
        /// first policy session
        /// </summary>
        [EnumMember]
        [SpecTypeName("POLICY_SESSION_FIRST")]
        PolicySessionFirst = ((0x03 << 24) + 0), // 0x3000000
        /// <summary>
        /// last policy session
        /// </summary>
        [EnumMember]
        [SpecTypeName("POLICY_SESSION_LAST")]
        PolicySessionLast = (((0x03 << 24) + 0) + 64-1), // 0x300003F
        /// <summary>
        /// first transient object
        /// </summary>
        [EnumMember]
        [SpecTypeName("TRANSIENT_FIRST")]
        TransientFirst = ((0x80u << 24) + 0), // 0x80000000
        /// <summary>
        /// used in GetCapability
        /// </summary>
        [EnumMember]
        [SpecTypeName("ACTIVE_SESSION_FIRST")]
        ActiveSessionFirst = ((0x03 << 24) + 0), // 0x3000000
        /// <summary>
        /// used in GetCapability
        /// </summary>
        [EnumMember]
        [SpecTypeName("ACTIVE_SESSION_LAST")]
        ActiveSessionLast = (((0x03 << 24) + 0) + 64-1), // 0x300003F
        /// <summary>
        /// last transient object
        /// </summary>
        [EnumMember]
        [SpecTypeName("TRANSIENT_LAST")]
        TransientLast = (((0x80u << 24) + 0)+3-1), // 0x80000002
        /// <summary>
        /// first persistent object
        /// </summary>
        [EnumMember]
        [SpecTypeName("PERSISTENT_FIRST")]
        PersistentFirst = ((0x81u << 24) + 0), // 0x81000000
        /// <summary>
        /// last persistent object
        /// </summary>
        [EnumMember]
        [SpecTypeName("PERSISTENT_LAST")]
        PersistentLast = (((0x81u << 24) + 0) + 0x00FFFFFF), // 0x81FFFFFF
        /// <summary>
        /// first platform persistent object
        /// </summary>
        [EnumMember]
        [SpecTypeName("PLATFORM_PERSISTENT")]
        PlatformPersistent = (((0x81u << 24) + 0) + 0x00800000), // 0x81800000
        /// <summary>
        /// first allowed NV Index
        /// </summary>
        [EnumMember]
        [SpecTypeName("NV_INDEX_FIRST")]
        NvIndexFirst = ((0x01 << 24) + 0), // 0x1000000
        /// <summary>
        /// last allowed NV Index
        /// </summary>
        [EnumMember]
        [SpecTypeName("NV_INDEX_LAST")]
        NvIndexLast = (((0x01 << 24) + 0) + 0x00FFFFFF), // 0x1FFFFFF
        [EnumMember]
        [SpecTypeName("PERMANENT_FIRST")]
        PermanentFirst = 0x40000000, // 0x40000000
        [EnumMember]
        [SpecTypeName("PERMANENT_LAST")]
        PermanentLast = 0x4000010F // 0x4000010F
    }
    //-----------------------------------------------------------------------------
    //------------------------- BITFIELDS -----------------------------------------
    //-----------------------------------------------------------------------------
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_ALGORITHM")]
    /// <summary>
    /// This structure defines the attributes of an algorithm.
    /// </summary>
    public enum AlgorithmAttr : uint
    {
        None = 0,
        /// <summary>
        /// SET (1): an asymmetric algorithm with public and private portions
        /// CLEAR (0): not an asymmetric algorithm
        /// </summary>
        [EnumMember]
        Asymmetric = 0x1,
        /// <summary>
        /// SET (1): a symmetric block cipher
        /// CLEAR (0): not a symmetric block cipher
        /// </summary>
        [EnumMember]
        Symmetric = 0x2,
        /// <summary>
        /// SET (1): a hash algorithm
        /// CLEAR (0): not a hash algorithm
        /// </summary>
        [EnumMember]
        Hash = 0x4,
        /// <summary>
        /// SET (1): an algorithm that may be used as an object type
        /// CLEAR (0): an algorithm that is not used as an object type
        /// </summary>
        [EnumMember]
        Object = 0x8,
        /// <summary>
        /// SET (1): a signing algorithm. The setting of asymmetric, symmetric, and hash will indicate the type of signing algorithm.
        /// CLEAR (0): not a signing algorithm
        /// </summary>
        [EnumMember]
        Signing = 0x100,
        /// <summary>
        /// SET (1): an encryption/decryption algorithm. The setting of asymmetric, symmetric, and hash will indicate the type of encryption/decryption algorithm.
        /// CLEAR (0): not an encryption/decryption algorithm
        /// </summary>
        [EnumMember]
        Encrypting = 0x200,
        /// <summary>
        /// SET (1): a method such as a key derivative function (KDF)
        /// CLEAR (0): not a method
        /// </summary>
        [EnumMember]
        Method = 0x400,
    }
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_OBJECT")]
    /// <summary>
    /// This attribute structure indicates an objects use, its authorization types, and its relationship to other objects.
    /// </summary>
    public enum ObjectAttr : uint
    {
        None = 0,
        /// <summary>
        /// SET (1): The hierarchy of the object, as indicated by its Qualified Name, may not change.
        /// CLEAR (0): The hierarchy of the object may change as a result of this object or an ancestor key being duplicated for use in another hierarchy.
        /// </summary>
        [EnumMember]
        FixedTPM = 0x2,
        /// <summary>
        /// SET (1): Previously saved contexts of this object may not be loaded after Startup(CLEAR).
        /// CLEAR (0): Saved contexts of this object may be used after a Shutdown(STATE) and subsequent Startup().
        /// </summary>
        [EnumMember]
        StClear = 0x4,
        /// <summary>
        /// SET (1): The parent of the object may not change.
        /// CLEAR (0): The parent of the object may change as the result of a TPM2_Duplicate() of the object.
        /// </summary>
        [EnumMember]
        FixedParent = 0x10,
        /// <summary>
        /// SET (1): Indicates that, when the object was created with TPM2_Create() or TPM2_CreatePrimary(), the TPM generated all of the sensitive data other than the authValue.
        /// CLEAR (0): A portion of the sensitive data, other than the authValue, was provided by the caller.
        /// </summary>
        [EnumMember]
        SensitiveDataOrigin = 0x20,
        /// <summary>
        /// SET (1): Approval of USER role actions with this object may be with an HMAC session or with a password using the authValue of the object or a policy session.
        /// CLEAR (0): Approval of USER role actions with this object may only be done with a policy session.
        /// </summary>
        [EnumMember]
        UserWithAuth = 0x40,
        /// <summary>
        /// SET (1): Approval of ADMIN role actions with this object may only be done with a policy session.
        /// CLEAR (0): Approval of ADMIN role actions with this object may be with an HMAC session or with a password using the authValue of the object or a policy session.
        /// </summary>
        [EnumMember]
        AdminWithPolicy = 0x80,
        /// <summary>
        /// SET (1): The object is not subject to dictionary attack protections.
        /// CLEAR (0): The object is subject to dictionary attack protections.
        /// </summary>
        [EnumMember]
        NoDA = 0x400,
        /// <summary>
        /// SET (1): If the object is duplicated, then symmetricAlg shall not be TPM_ALG_NULL and newParentHandle shall not be TPM_RH_NULL.
        /// CLEAR (0): The object may be duplicated without an inner wrapper on the private portion of the object and the new parent may be TPM_RH_NULL.
        /// </summary>
        [EnumMember]
        EncryptedDuplication = 0x800,
        /// <summary>
        /// SET (1): Key usage is restricted to manipulate structures of known format; the parent of this key shall have restricted SET.
        /// CLEAR (0): Key usage is not restricted to use on special formats.
        /// </summary>
        [EnumMember]
        Restricted = 0x10000,
        /// <summary>
        /// SET (1): The private portion of the key may be used to decrypt.
        /// CLEAR (0): The private portion of the key may not be used to decrypt.
        /// </summary>
        [EnumMember]
        Decrypt = 0x20000,
        /// <summary>
        /// SET (1): For a symmetric cipher object, the private portion of the key may be used to encrypt. For other objects, the private portion of the key may be used to sign.
        /// CLEAR (0): The private portion of the key may not be used to sign or encrypt.
        /// </summary>
        [EnumMember]
        Sign = 0x40000,
        /// <summary>
        /// Alias to the Sign value.
        /// </summary>
        [EnumMember]
        Encrypt = 0x40000,
    }
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_SESSION")]
    /// <summary>
    /// This octet in each session is used to identify the session type, indicate its relationship to any handles in the command, and indicate its use in parameter encryption.
    /// </summary>
    public enum SessionAttr : byte
    {
        None = 0,
        /// <summary>
        /// SET (1): In a command, this setting indicates that the session is to remain active after successful completion of the command. In a response, it indicates that the session is still active. If SET in the command, this attribute shall be SET in the response.
        /// CLEAR (0): In a command, this setting indicates that the TPM should close the session and flush any related context when the command completes successfully. In a response, it indicates that the session is closed and the context is no longer active.
        /// This attribute has no meaning for a password authorization and the TPM will allow any setting of the attribute in the command and SET the attribute in the response.
        /// This attribute will only be CLEAR in one response for a logical session. If the attribute is CLEAR, the context associated with the session is no longer in use and the space is available. A session created after another session is ended may have the same handle but logically is not the same session.
        /// This attribute has no effect if the command does not complete successfully.
        /// </summary>
        [EnumMember]
        ContinueSession = 0x1,
        /// <summary>
        /// SET (1): In a command, this setting indicates that the command should only be executed if the session is exclusive at the start of the command. In a response, it indicates that the session is exclusive. This setting is only allowed if the audit attribute is SET (TPM_RC_ATTRIBUTES).
        /// CLEAR (0): In a command, indicates that the session need not be exclusive at the start of the command. In a response, indicates that the session is not exclusive.
        /// In this revision, if audit is CLEAR, auditExclusive must be CLEAR in the command and will be CLEAR in the response. In a future, revision, this bit may have a different meaning if audit is CLEAR.
        /// See "Exclusive Audit Session" clause in TPM 2.0 Part 1.
        /// </summary>
        [EnumMember]
        AuditExclusive = 0x2,
        /// <summary>
        /// SET (1): In a command, this setting indicates that the audit digest of the session should be initialized and the exclusive status of the session SET. This setting is only allowed if the audit attribute is SET (TPM_RC_ATTRIBUTES).
        /// CLEAR (0): In a command, indicates that the audit digest should not be initialized.
        /// This bit is always CLEAR in a response.
        /// In this revision, if audit is CLEAR, auditReset must be clear in the command and will be CLEAR in the response. In a future, revision, this bit may have a different meaning if audit is CLEAR.
        /// </summary>
        [EnumMember]
        AuditReset = 0x4,
        /// <summary>
        /// SET (1): In a command, this setting indicates that the first parameter in the command is symmetrically encrypted using the parameter encryption scheme described in TPM 2.0 Part 1. The TPM will decrypt the parameter after performing any HMAC computations and before unmarshaling the parameter. In a response, the attribute is copied from the request but has no effect on the response.
        /// CLEAR (0): Session not used for encryption.
        /// For a password authorization, this attribute will be CLEAR in both the command and response.
        /// This attribute may only be SET in one session per command.
        /// This attribute may be SET in a session that is not associated with a command handle. Such a session is provided for purposes of encrypting a parameter and not for authorization.
        /// This attribute may be SET in combination with any other session attributes.
        /// This attribute may only be SET if the first parameter of the command is a sized buffer (TPM2B_).
        /// </summary>
        [EnumMember]
        Decrypt = 0x20,
        /// <summary>
        /// SET (1): In a command, this setting indicates that the TPM should use this session to encrypt the first parameter in the response. In a response, it indicates that the attribute was set in the command and that the TPM used the session to encrypt the first parameter in the response using the parameter encryption scheme described in TPM 2.0 Part 1.
        /// CLEAR (0): Session not used for encryption.
        /// For a password authorization, this attribute will be CLEAR in both the command and response.
        /// This attribute may only be SET in one session per command.
        /// This attribute may be SET in a session that is not associated with a command handle. Such a session is provided for purposes of encrypting a parameter and not for authorization.
        /// This attribute may only be SET if the first parameter of a response is a sized buffer (TPM2B_).
        /// </summary>
        [EnumMember]
        Encrypt = 0x40,
        /// <summary>
        /// SET (1): In a command or response, this setting indicates that the session is for audit and that auditExclusive and auditReset have meaning. This session may also be used for authorization, encryption, or decryption. The encrypted and encrypt fields may be SET or CLEAR.
        /// CLEAR (0): Session is not used for audit.
        /// This attribute may only be SET in one session per command or response. If SET in the command, then this attribute will be SET in the response.
        /// </summary>
        [EnumMember]
        Audit = 0x80,
    }
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_LOCALITY")]
    /// <summary>
    /// In a TPMS_CREATION_DATA structure, this structure is used to indicate the locality of the command that created the object. No more than one of the locality attributes shall be set in the creation data.
    /// </summary>
    public enum LocalityAttr : byte
    {
        None = 0,
        [EnumMember]
        TpmLocZero = 0x1,
        [EnumMember]
        TpmLocOne = 0x2,
        [EnumMember]
        TpmLocTwo = 0x4,
        [EnumMember]
        TpmLocThree = 0x8,
        [EnumMember]
        TpmLocFour = 0x10,
        /// <summary>
        /// If any of these bits is set, an extended locality is indicated
        /// </summary>
        [EnumMember]
        ExtendedBitMask = 0x000000E0,
        [EnumMember]
        ExtendedBitOffset = 5,
        [EnumMember]
        ExtendedBitLength = 3,
        [EnumMember]
        ExtendedBit0 = 0x00000020,
        [EnumMember]
        ExtendedBit1 = 0x00000040,
        [EnumMember]
        ExtendedBit2 = 0x00000080
    }
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_PERMANENT")]
    /// <summary>
    /// The attributes in this structure are persistent and are not changed as a result of _TPM_Init or any TPM2_Startup(). Some of the attributes in this structure may change as the result of specific Protected Capabilities. This structure may be read using TPM2_GetCapability(capability = TPM_CAP_TPM_PROPERTIES, property = TPM_PT_PERMANENT).
    /// </summary>
    public enum PermanentAttr : uint
    {
        None = 0,
        /// <summary>
        /// SET (1): TPM2_HierarchyChangeAuth() with ownerAuth has been executed since the last TPM2_Clear().
        /// CLEAR (0): ownerAuth has not been changed since TPM2_Clear().
        /// </summary>
        [EnumMember]
        OwnerAuthSet = 0x1,
        /// <summary>
        /// SET (1): TPM2_HierarchyChangeAuth() with endorsementAuth has been executed since the last TPM2_Clear().
        /// CLEAR (0): endorsementAuth has not been changed since TPM2_Clear().
        /// </summary>
        [EnumMember]
        EndorsementAuthSet = 0x2,
        /// <summary>
        /// SET (1): TPM2_HierarchyChangeAuth() with lockoutAuth has been executed since the last TPM2_Clear().
        /// CLEAR (0): lockoutAuth has not been changed since TPM2_Clear().
        /// </summary>
        [EnumMember]
        LockoutAuthSet = 0x4,
        /// <summary>
        /// SET (1): TPM2_Clear() is disabled.
        /// CLEAR (0): TPM2_Clear() is enabled.
        /// NOTE	See TPM2_ClearControl in TPM 2.0 Part 3 for details on changing this attribute.
        /// </summary>
        [EnumMember]
        DisableClear = 0x100,
        /// <summary>
        /// SET (1): The TPM is in lockout, when failedTries is equal to maxTries.
        /// </summary>
        [EnumMember]
        InLockout = 0x200,
        /// <summary>
        /// SET (1): The EPS was created by the TPM.
        /// CLEAR (0): The EPS was created outside of the TPM using a manufacturer-specific process.
        /// </summary>
        [EnumMember]
        TpmGeneratedEPS = 0x400,
    }
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_STARTUP_CLEAR")]
    /// <summary>
    /// This structure may be read using TPM2_GetCapability(capability = TPM_CAP_TPM_PROPERTIES, property = TPM_PT_STARTUP_CLEAR).
    /// </summary>
    public enum StartupClearAttr : uint
    {
        None = 0,
        /// <summary>
        /// SET (1): The platform hierarchy is enabled and platformAuth or platformPolicy may be used for authorization.
        /// CLEAR (0): platformAuth and platformPolicy may not be used for authorizations, and objects in the platform hierarchy, including persistent objects, cannot be used.
        /// NOTE	See TPM2_HierarchyControl in TPM 2.0 Part 3 for details on changing this attribute.
        /// </summary>
        [EnumMember]
        PhEnable = 0x1,
        /// <summary>
        /// SET (1): The Storage hierarchy is enabled and ownerAuth or ownerPolicy may be used for authorization. NV indices defined using owner authorization are accessible.
        /// CLEAR (0): ownerAuth and ownerPolicy may not be used for authorizations, and objects in the Storage hierarchy, persistent objects, and NV indices defined using owner authorization cannot be used.
        /// NOTE	See TPM2_HierarchyControl in TPM 2.0 Part 3 for details on changing this attribute.
        /// </summary>
        [EnumMember]
        ShEnable = 0x2,
        /// <summary>
        /// SET (1): The EPS hierarchy is enabled and Endorsement Authorization may be used to authorize commands.
        /// CLEAR (0): Endorsement Authorization may not be used for authorizations, and objects in the endorsement hierarchy, including persistent objects, cannot be used.
        /// NOTE	See TPM2_HierarchyControl in TPM 2.0 Part 3 for details on changing this attribute.
        /// </summary>
        [EnumMember]
        EhEnable = 0x4,
        /// <summary>
        /// SET (1): NV indices that have TPMA_PLATFORM_CREATE SET may be read or written. The platform can create define and undefine indices.
        /// CLEAR (0): NV indices that have TPMA_PLATFORM_CREATE SET may not be read or written (TPM_RC_HANDLE). The platform cannot define (TPM_RC_HIERARCHY) or undefined (TPM_RC_HANDLE) indices.
        /// NOTE	See TPM2_HierarchyControl in TPM 2.0 Part 3 for details on changing this attribute.
        /// NOTE read refers to these commands: TPM2_NV_Read, TPM2_NV_ReadPublic, TPM_NV_Certify, TPM2_PolicyNV
        /// write refers to these commands: TPM2_NV_Write, TPM2_NV_Increment, TPM2_NV_Extend, TPM2_NV_SetBits
        /// NOTE The TPM must query the index TPMA_PLATFORM_CREATE attribute to determine whether phEnableNV is applicable. Since the TPM will return TPM_RC_HANDLE if the index does not exist, it also returns this error code if the index is disabled. Otherwise, the TPM would leak the existence of an index even when disabled.
        /// </summary>
        [EnumMember]
        PhEnableNV = 0x8,
        /// <summary>
        /// SET (1): The TPM received a TPM2_Shutdown() and a matching TPM2_Startup().
        /// CLEAR (0): TPM2_Startup(TPM_SU_CLEAR) was not preceded by a TPM2_Shutdown() of any type.
        /// NOTE A shutdown is orderly if the TPM receives a TPM2_Shutdown() of any type followed by a TPM2_Startup() of any type. However, the TPM will return an error if TPM2_Startup(TPM_SU_STATE) was not preceded by TPM2_Shutdown(TPM_SU_STATE).
        /// </summary>
        [EnumMember]
        Orderly = 0x80000000,
    }
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_MEMORY")]
    /// <summary>
    /// This structure of this attribute is used to report the memory management method used by the TPM for transient objects and authorization sessions. This structure may be read using TPM2_GetCapability(capability = TPM_CAP_TPM_PROPERTIES, property = TPM_PT_MEMORY).
    /// </summary>
    public enum MemoryAttr : uint
    {
        None = 0,
        /// <summary>
        /// SET (1): indicates that the RAM memory used for authorization session contexts is shared with the memory used for transient objects
        /// CLEAR (0): indicates that the memory used for authorization sessions is not shared with memory used for transient objects
        /// </summary>
        [EnumMember]
        SharedRAM = 0x1,
        /// <summary>
        /// SET (1): indicates that the NV memory used for persistent objects is shared with the NV memory used for NV Index values
        /// CLEAR (0): indicates that the persistent objects and NV Index values are allocated from separate sections of NV
        /// </summary>
        [EnumMember]
        SharedNV = 0x2,
        /// <summary>
        /// SET (1): indicates that the TPM copies persistent objects to a transient-object slot in RAM when the persistent object is referenced in a command. The TRM is required to make sure that an object slot is available.
        /// CLEAR (0): indicates that the TPM does not use transient-object slots when persistent objects are referenced
        /// </summary>
        [EnumMember]
        ObjectCopiedToRam = 0x4,
    }
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_CC")]
    /// <summary>
    /// This structure defines the attributes of a command from a context management perspective. The fields of the structure indicate to the TPM Resource Manager (TRM) the number of resources required by a command and how the command affects the TPMs resources.
    /// </summary>
    public enum CcAttr : uint
    {
        None = 0,
        /// <summary>
        /// indicates the command being selected
        /// </summary>
        [EnumMember]
        commandIndexBitMask = 0x0000FFFF,
        [EnumMember]
        commandIndexBitOffset = 0,
        [EnumMember]
        commandIndexBitLength = 16,
        [EnumMember]
        commandIndexBit0 = 0x00000001,
        [EnumMember]
        commandIndexBit1 = 0x00000002,
        [EnumMember]
        commandIndexBit2 = 0x00000004,
        [EnumMember]
        commandIndexBit3 = 0x00000008,
        [EnumMember]
        commandIndexBit4 = 0x00000010,
        [EnumMember]
        commandIndexBit5 = 0x00000020,
        [EnumMember]
        commandIndexBit6 = 0x00000040,
        [EnumMember]
        commandIndexBit7 = 0x00000080,
        [EnumMember]
        commandIndexBit8 = 0x00000100,
        [EnumMember]
        commandIndexBit9 = 0x00000200,
        [EnumMember]
        commandIndexBit10 = 0x00000400,
        [EnumMember]
        commandIndexBit11 = 0x00000800,
        [EnumMember]
        commandIndexBit12 = 0x00001000,
        [EnumMember]
        commandIndexBit13 = 0x00002000,
        [EnumMember]
        commandIndexBit14 = 0x00004000,
        [EnumMember]
        commandIndexBit15 = 0x00008000,
        /// <summary>
        /// SET (1): indicates that the command may write to NV
        /// CLEAR (0): indicates that the command does not write to NV
        /// </summary>
        [EnumMember]
        Nv = 0x400000,
        /// <summary>
        /// SET (1): This command could flush any number of loaded contexts.
        /// CLEAR (0): no additional changes other than indicated by the flushed attribute
        /// </summary>
        [EnumMember]
        Extensive = 0x800000,
        /// <summary>
        /// SET (1): The context associated with any transient handle in the command will be flushed when this command completes.
        /// CLEAR (0): No context is flushed as a side effect of this command.
        /// </summary>
        [EnumMember]
        Flushed = 0x1000000,
        /// <summary>
        /// indicates the number of the handles in the handle area for this command
        /// </summary>
        [EnumMember]
        cHandlesBitMask = 0x0E000000,
        [EnumMember]
        cHandlesBitOffset = 25,
        [EnumMember]
        cHandlesBitLength = 3,
        [EnumMember]
        cHandlesBit0 = 0x02000000,
        [EnumMember]
        cHandlesBit1 = 0x04000000,
        [EnumMember]
        cHandlesBit2 = 0x08000000,
        /// <summary>
        /// SET (1): indicates the presence of the handle area in the response
        /// </summary>
        [EnumMember]
        RHandle = 0x10000000,
        /// <summary>
        /// SET (1): indicates that the command is vendor-specific
        /// CLEAR (0): indicates that the command is defined in a version of this specification
        /// </summary>
        [EnumMember]
        V = 0x20000000,
        /// <summary>
        /// allocated for software; shall be zero
        /// </summary>
        [EnumMember]
        ResBitMask = 0xC0000000,
        [EnumMember]
        ResBitOffset = 30,
        [EnumMember]
        ResBitLength = 2,
        [EnumMember]
        ResBit0 = 0x40000000,
        [EnumMember]
        ResBit1 = 0x80000000
    }
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_MODES")]
    /// <summary>
    /// This structure of this attribute is used to report that the TPM is designed for these modes. This structure may be read using TPM2_GetCapability(capability = TPM_CAP_TPM_PROPERTIES, property = TPM_PT_MODES).
    /// </summary>
    public enum ModesAttr : uint
    {
        None = 0,
        /// <summary>
        /// SET (1): indicates that the TPM is designed to comply with all of the FIPS 140-2 requirements at Level 1 or higher.
        /// </summary>
        [EnumMember]
        Fips1402 = 0x1,
    }
    [Flags]
    [DataContract]
    [SpecTypeName("TPM_NV_INDEX")]
    /// <summary>
    /// A TPM_NV_INDEX is used to reference a defined location in NV memory. The format of the Index is changed from TPM 1.2 in order to include the Index in the reserved handle space. Handles in this range use the digest of the public area of the Index as the Name of the entity in authorization computations
    /// </summary>
    public enum NvIndex : uint
    {
        None = 0,
        /// <summary>
        /// The Index of the NV location
        /// </summary>
        [EnumMember]
        indexBitMask = 0x00FFFFFF,
        [EnumMember]
        indexBitOffset = 0,
        [EnumMember]
        indexBitLength = 24,
        [EnumMember]
        indexBit0 = 0x00000001,
        [EnumMember]
        indexBit1 = 0x00000002,
        [EnumMember]
        indexBit2 = 0x00000004,
        [EnumMember]
        indexBit3 = 0x00000008,
        [EnumMember]
        indexBit4 = 0x00000010,
        [EnumMember]
        indexBit5 = 0x00000020,
        [EnumMember]
        indexBit6 = 0x00000040,
        [EnumMember]
        indexBit7 = 0x00000080,
        [EnumMember]
        indexBit8 = 0x00000100,
        [EnumMember]
        indexBit9 = 0x00000200,
        [EnumMember]
        indexBit10 = 0x00000400,
        [EnumMember]
        indexBit11 = 0x00000800,
        [EnumMember]
        indexBit12 = 0x00001000,
        [EnumMember]
        indexBit13 = 0x00002000,
        [EnumMember]
        indexBit14 = 0x00004000,
        [EnumMember]
        indexBit15 = 0x00008000,
        [EnumMember]
        indexBit16 = 0x00010000,
        [EnumMember]
        indexBit17 = 0x00020000,
        [EnumMember]
        indexBit18 = 0x00040000,
        [EnumMember]
        indexBit19 = 0x00080000,
        [EnumMember]
        indexBit20 = 0x00100000,
        [EnumMember]
        indexBit21 = 0x00200000,
        [EnumMember]
        indexBit22 = 0x00400000,
        [EnumMember]
        indexBit23 = 0x00800000,
        /// <summary>
        /// constant value of TPM_HT_NV_INDEX indicating the NV Index range
        /// </summary>
        [EnumMember]
        RhNvBitMask = 0xFF000000,
        [EnumMember]
        RhNvBitOffset = 24,
        [EnumMember]
        RhNvBitLength = 8,
        [EnumMember]
        RhNvBit0 = 0x01000000,
        [EnumMember]
        RhNvBit1 = 0x02000000,
        [EnumMember]
        RhNvBit2 = 0x04000000,
        [EnumMember]
        RhNvBit3 = 0x08000000,
        [EnumMember]
        RhNvBit4 = 0x10000000,
        [EnumMember]
        RhNvBit5 = 0x20000000,
        [EnumMember]
        RhNvBit6 = 0x40000000,
        [EnumMember]
        RhNvBit7 = 0x80000000
    }
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_NV")]
    /// <summary>
    /// This structure allows the TPM to keep track of the data and permissions to manipulate an NV Index.
    /// </summary>
    public enum NvAttr : uint
    {
        None = 0,
        /// <summary>
        /// SET (1): The Index data can be written if Platform Authorization is provided.
        /// CLEAR (0): Writing of the Index data cannot be authorized with Platform Authorization.
        /// </summary>
        [EnumMember]
        Ppwrite = 0x1,
        [ObsoleteAttribute]
        TpmaNvPpwrite = 0x1,
        /// <summary>
        /// SET (1): The Index data can be written if Owner Authorization is provided.
        /// CLEAR (0): Writing of the Index data cannot be authorized with Owner Authorization.
        /// </summary>
        [EnumMember]
        Ownerwrite = 0x2,
        [ObsoleteAttribute]
        TpmaNvOwnerwrite = 0x2,
        /// <summary>
        /// SET (1): Authorizations to change the Index contents that require USER role may be provided with an HMAC session or password.
        /// CLEAR (0): Authorizations to change the Index contents that require USER role may not be provided with an HMAC session or password.
        /// </summary>
        [EnumMember]
        Authwrite = 0x4,
        [ObsoleteAttribute]
        TpmaNvAuthwrite = 0x4,
        /// <summary>
        /// SET (1): Authorizations to change the Index contents that require USER role may be provided with a policy session.
        /// CLEAR (0): Authorizations to change the Index contents that require USER role may not be provided with a policy session.
        /// NOTE	TPM2_NV_ChangeAuth() always requires that authorization be provided in a policy session.
        /// </summary>
        [EnumMember]
        Policywrite = 0x8,
        [ObsoleteAttribute]
        TpmaNvPolicywrite = 0x8,
        /// <summary>
        /// Ordinary  contains data that is opaque to the TPM that can only be modified using TPM2_NV_Write().
        /// </summary>
        [EnumMember]
        Ordinary = 0x0,
        [ObsoleteAttribute]
        TpmaNvOrdinary = 0x0,
        /// <summary>
        /// Counter  contains an 8-octet value that is to be used as a counter and can only be modified with TPM2_NV_Increment()
        /// </summary>
        [EnumMember]
        Counter = 0x10,
        [ObsoleteAttribute]
        TpmaNvCounter = 0x10,
        /// <summary>
        /// Bit Field  contains an 8-octet value to be used as a bit field and can only be modified with TPM2_NV_SetBits().
        /// </summary>
        [EnumMember]
        Bits = 0x20,
        [ObsoleteAttribute]
        TpmaNvBits = 0x20,
        /// <summary>
        /// Extend  contains a digest-sized value used like a PCR. The Index can only be modified using TPM2_NV_Extend(). The extend will use the nameAlg of the Index.
        /// </summary>
        [EnumMember]
        Extend = 0x40,
        [ObsoleteAttribute]
        TpmaNvExtend = 0x40,
        /// <summary>
        /// PIN Fail - contains pinCount that increments on a PIN authorization failure and a pinLimit
        /// </summary>
        [EnumMember]
        PinFail = 0x80,
        [ObsoleteAttribute]
        TpmaNvPinFail = 0x80,
        /// <summary>
        /// PIN Pass - contains pinCount that increments on a PIN authorization success and a pinLimit
        /// </summary>
        [EnumMember]
        PinPass = 0x90,
        [ObsoleteAttribute]
        TpmaNvPinPass = 0x90,
        /// <summary>
        /// The type of the index. NOTE A TPM is not required to support all TPM_NT values
        /// </summary>
        [EnumMember]
        TpmNtBitMask = 0x000000F0,
        [EnumMember]
        TpmNtBitOffset = 4,
        [EnumMember]
        TpmNtBitLength = 4,
        [EnumMember]
        TpmNtBit0 = 0x00000010,
        [EnumMember]
        TpmNtBit1 = 0x00000020,
        [EnumMember]
        TpmNtBit2 = 0x00000040,
        [EnumMember]
        TpmNtBit3 = 0x00000080,
        /// <summary>
        /// SET (1): Index may not be deleted unless the authPolicy is satisfied using TPM2_NV_UndefineSpaceSpecial().
        /// CLEAR (0): Index may be deleted with proper platform or owner authorization using TPM2_NV_UndefineSpace().
        /// </summary>
        [EnumMember]
        PolicyDelete = 0x400,
        [ObsoleteAttribute]
        TpmaNvPolicyDelete = 0x400,
        /// <summary>
        /// SET (1): Index cannot be written.
        /// CLEAR (0): Index can be written.
        /// </summary>
        [EnumMember]
        Writelocked = 0x800,
        [ObsoleteAttribute]
        TpmaNvWritelocked = 0x800,
        /// <summary>
        /// SET (1): A partial write of the Index data is not allowed. The write size shall match the defined space size.
        /// CLEAR (0): Partial writes are allowed. This setting is required if the .dataSize of the Index is larger than NV_MAX_BUFFER_SIZE for the implementation.
        /// </summary>
        [EnumMember]
        Writeall = 0x1000,
        [ObsoleteAttribute]
        TpmaNvWriteall = 0x1000,
        /// <summary>
        /// SET (1): TPM2_NV_WriteLock() may be used to prevent further writes to this location.
        /// CLEAR (0): TPM2_NV_WriteLock() does not block subsequent writes if TPMA_NV_WRITE_STCLEAR is also CLEAR.
        /// </summary>
        [EnumMember]
        Writedefine = 0x2000,
        [ObsoleteAttribute]
        TpmaNvWritedefine = 0x2000,
        /// <summary>
        /// SET (1): TPM2_NV_WriteLock() may be used to prevent further writes to this location until the next TPM Reset or TPM Restart.
        /// CLEAR (0): TPM2_NV_WriteLock() does not block subsequent writes if TPMA_NV_WRITEDEFINE is also CLEAR.
        /// </summary>
        [EnumMember]
        WriteStclear = 0x4000,
        [ObsoleteAttribute]
        TpmaNvWriteStclear = 0x4000,
        /// <summary>
        /// SET (1): If TPM2_NV_GlobalWriteLock() is successful, then further writes to this location are not permitted until the next TPM Reset or TPM Restart.
        /// CLEAR (0): TPM2_NV_GlobalWriteLock() has no effect on the writing of the data at this Index.
        /// </summary>
        [EnumMember]
        Globallock = 0x8000,
        [ObsoleteAttribute]
        TpmaNvGloballock = 0x8000,
        /// <summary>
        /// SET (1): The Index data can be read if Platform Authorization is provided.
        /// CLEAR (0): Reading of the Index data cannot be authorized with Platform Authorization.
        /// </summary>
        [EnumMember]
        Ppread = 0x10000,
        [ObsoleteAttribute]
        TpmaNvPpread = 0x10000,
        /// <summary>
        /// SET (1): The Index data can be read if Owner Authorization is provided.
        /// CLEAR (0): Reading of the Index data cannot be authorized with Owner Authorization.
        /// </summary>
        [EnumMember]
        Ownerread = 0x20000,
        [ObsoleteAttribute]
        TpmaNvOwnerread = 0x20000,
        /// <summary>
        /// SET (1): The Index data may be read if the authValue is provided.
        /// CLEAR (0): Reading of the Index data cannot be authorized with the Index authValue.
        /// </summary>
        [EnumMember]
        Authread = 0x40000,
        [ObsoleteAttribute]
        TpmaNvAuthread = 0x40000,
        /// <summary>
        /// SET (1): The Index data may be read if the authPolicy is satisfied.
        /// CLEAR (0): Reading of the Index data cannot be authorized with the Index authPolicy.
        /// </summary>
        [EnumMember]
        Policyread = 0x80000,
        [ObsoleteAttribute]
        TpmaNvPolicyread = 0x80000,
        /// <summary>
        /// SET (1): Authorization failures of the Index do not affect the DA logic and authorization of the Index is not blocked when the TPM is in Lockout mode.
        /// CLEAR (0): Authorization failures of the Index will increment the authorization failure counter and authorizations of this Index are not allowed when the TPM is in Lockout mode.
        /// </summary>
        [EnumMember]
        NoDa = 0x2000000,
        [ObsoleteAttribute]
        TpmaNvNoDa = 0x2000000,
        /// <summary>
        /// SET (1): NV Index state is only required to be saved when the TPM performs an orderly shutdown (TPM2_Shutdown()).
        /// CLEAR (0): NV Index state is required to be persistent after the command to update the Index completes successfully (that is, the NV update is synchronous with the update command).
        /// </summary>
        [EnumMember]
        Orderly = 0x4000000,
        [ObsoleteAttribute]
        TpmaNvOrderly = 0x4000000,
        /// <summary>
        /// SET (1): TPMA_NV_WRITTEN for the Index is CLEAR by TPM Reset or TPM Restart.
        /// CLEAR (0): TPMA_NV_WRITTEN is not changed by TPM Restart.
        /// NOTE 1	This attribute may only be SET if TPM_NT is not TPM_NT_COUNTER.
        /// NOTE 2	If the TPMA_NV_ORDERLY is SET, TPMA_NV_WRITTEN will be CLEAR by TPM Reset.
        /// </summary>
        [EnumMember]
        ClearStclear = 0x8000000,
        [ObsoleteAttribute]
        TpmaNvClearStclear = 0x8000000,
        /// <summary>
        /// SET (1): Reads of the Index are blocked until the next TPM Reset or TPM Restart.
        /// CLEAR (0): Reads of the Index are allowed if proper authorization is provided.
        /// </summary>
        [EnumMember]
        Readlocked = 0x10000000,
        [ObsoleteAttribute]
        TpmaNvReadlocked = 0x10000000,
        /// <summary>
        /// SET (1): Index has been written.
        /// CLEAR (0): Index has not been written.
        /// </summary>
        [EnumMember]
        Written = 0x20000000,
        [ObsoleteAttribute]
        TpmaNvWritten = 0x20000000,
        /// <summary>
        /// SET (1): This Index may be undefined with Platform Authorization but not with Owner Authorization.
        /// CLEAR (0): This Index may be undefined using Owner Authorization but not with Platform Authorization. The TPM will validate that this attribute is SET when the Index is defined using Platform Authorization and will validate that this attribute is CLEAR when the Index is defined using Owner Authorization.
        /// </summary>
        [EnumMember]
        Platformcreate = 0x40000000,
        [ObsoleteAttribute]
        TpmaNvPlatformcreate = 0x40000000,
        /// <summary>
        /// SET (1): TPM2_NV_ReadLock() may be used to SET TPMA_NV_READLOCKED for this Index.
        /// CLEAR (0): TPM2_NV_ReadLock() has no effect on this Index.
        /// </summary>
        [EnumMember]
        ReadStclear = 0x80000000,
        [ObsoleteAttribute]
        TpmaNvReadStclear = 0x80000000
    }
    //-----------------------------------------------------------------------------
    //------------------------- UNIONS -----------------------------------------
    //-----------------------------------------------------------------------------
    /// <summary>
    /// Table 83  Definition of TPMU_NAME Union <>
    /// (One of [TpmHash, TpmHandle])
    /// </summary>
    public interface INameUnion
    {
        NameUnionTagValues GetUnionSelector();
    }
    /// <summary>
    /// Table 108  Definition of TPMU_CAPABILITIES Union <OUT>
    /// (One of [AlgPropertyArray, HandleArray, CcaArray, CcArray, CcArray, PcrSelectionArray, TaggedTpmPropertyArray, TaggedPcrPropertyArray, EccCurveArray])
    /// </summary>
    public interface ICapabilitiesUnion
    {
        Cap GetUnionSelector();
    }
    /// <summary>
    /// Table 120  Definition of TPMU_ATTEST Union <OUT>
    /// (One of [CertifyInfo, CreationInfo, QuoteInfo, CommandAuditInfo, SessionAuditInfo, TimeAttestInfo, NvCertifyInfo])
    /// </summary>
    public interface IAttestUnion
    {
        TpmSt GetUnionSelector();
    }
    /// <summary>
    /// This union is used to collect the symmetric encryption key sizes.
    /// (One of [TpmiTdesKeyBits, TpmiAesKeyBits, TpmiSm4KeyBits, TpmiCamelliaKeyBits, KeyBits, TpmiAlgHash, NullSymKeyBits])
    /// </summary>
    public interface ISymKeyBitsUnion
    {
        TpmAlgId GetUnionSelector();
    }
    /// <summary>
    /// This union allows the mode value in a TPMT_SYM_DEF or TPMT_SYM_DEF_OBJECT to be empty.
    /// (One of [TpmiAlgSymMode, TpmiAlgSymMode, TpmiAlgSymMode, TpmiAlgSymMode, TpmiAlgSymMode, XorSymMode, NullSymMode])
    /// </summary>
    public interface ISymModeUnion
    {
        TpmAlgId GetUnionSelector();
    }
    /// <summary>
    /// This union allows additional parameters to be added for a symmetric cipher. Currently, no additional parameters are required for any of the symmetric algorithms.
    /// (One of [TdesSymDetails, AesSymDetails, Sm4SymDetails, CamelliaSymDetails, AnySymDetails, XorSymDetails, NullSymDetails])
    /// </summary>
    public interface ISymDetailsUnion
    {
        TpmAlgId GetUnionSelector();
    }
    /// <summary>
    /// This structure allows a TPM2B_SENSITIVE_CREATE structure to carry either a TPM2B_SENSITVE_DATA or a TPM2B_DERIVE structure. The contents of the union are determined by context. When an object is being derived, the derivation values are present.
    /// (One of [Byte, TpmDerive])
    /// </summary>
    public interface ISensitiveCreateUnion
    {
        TpmAlgId GetUnionSelector();
    }
    /// <summary>
    /// Table 145  Definition of TPMU_SCHEME_KEYEDHASH Union <IN/OUT, S>
    /// (One of [SchemeHmac, SchemeXor, NullSchemeKeyedhash])
    /// </summary>
    public interface ISchemeKeyedhashUnion
    {
        TpmAlgId GetUnionSelector();
    }
    /// <summary>
    /// The union of all of the signature schemes.
    /// (One of [SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme])
    /// </summary>
    public interface ISigSchemeUnion
    {
        TpmAlgId GetUnionSelector();
    }
    /// <summary>
    /// Table 154  Definition of TPMU_KDF_SCHEME Union <IN/OUT, S>
    /// (One of [SchemeMgf1, SchemeKdf1Sp80056a, SchemeKdf2, SchemeKdf1Sp800108, NullKdfScheme])
    /// </summary>
    public interface IKdfSchemeUnion
    {
        TpmAlgId GetUnionSelector();
    }
    /// <summary>
    /// This union of all asymmetric schemes is used in each of the asymmetric scheme structures. The actual scheme structure is defined by the interface type used for the selector (TPMI_ALG_ASYM_SCHEME).
    /// (One of [KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme])
    /// </summary>
    public interface IAsymSchemeUnion
    {
        TpmAlgId GetUnionSelector();
    }
    /// <summary>
    /// A TPMU_SIGNATURE_COMPOSITE is a union of the various signatures that are supported by a particular TPM implementation. The union allows substitution of any signature algorithm wherever a signature is required in a structure.
    /// (One of [SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature])
    /// </summary>
    public interface ISignatureUnion
    {
        TpmAlgId GetUnionSelector();
    }
    /// <summary>
    /// This structure is used to hold either an ephemeral public point for ECDH, an OAEP-encrypted block for RSA, or a symmetrically encrypted value. This structure is defined for the limited purpose of determining the size of a TPM2B_ENCRYPTED_SECRET.
    /// (One of [Byte, Byte, Byte, Byte])
    /// </summary>
    public interface IEncryptedSecretUnion
    {
        TpmAlgId GetUnionSelector();
    }
    /// <summary>
    /// This is the union of all values allowed in in the unique field of a TPMT_PUBLIC.
    /// (One of [Tpm2bDigestKeyedhash, Tpm2bDigestSymcipher, Tpm2bPublicKeyRsa, EccPoint, TpmDerive])
    /// </summary>
    public interface IPublicIdUnion
    {
        TpmAlgId GetUnionSelector();
    }
    /// <summary>
    /// Table 187 defines the possible parameter definition structures that may be contained in the public portion of a key. If the Object can be a parent, the first field must be a TPMT_SYM_DEF_OBJECT. See 11.1.7.
    /// (One of [KeyedhashParms, SymcipherParms, RsaParms, EccParms, AsymParms])
    /// </summary>
    public interface IPublicParmsUnion
    {
        TpmAlgId GetUnionSelector();
    }
    /// <summary>
    /// Table 193  Definition of TPMU_SENSITIVE_COMPOSITE Union <IN/OUT, S>
    /// (One of [Tpm2bPrivateKeyRsa, Tpm2bEccParameter, Tpm2bSensitiveData, Tpm2bSymKey, Tpm2bPrivateVendorSpecific])
    /// </summary>
    public interface ISensitiveCompositeUnion
    {
        TpmAlgId GetUnionSelector();
    }

    public abstract partial class TpmStructureBase
    {
        Type UnionElementFromSelector(Type unionInterface, object selector)
        {
            if (unionInterface == typeof(INameUnion))
            {
                switch((NameUnionTagValues)selector)
                {
                    case NameUnionTagValues.TagTpmuNameTpmtHa: return typeof(TpmHash);
                    case NameUnionTagValues.TagTpmuNameTpmHandle: return typeof(TpmHandle);
                }
            }
            else if (unionInterface == typeof(ICapabilitiesUnion))
            {
                switch((Cap)selector)
                {
                    case Cap.Algs: return typeof(AlgPropertyArray);
                    case Cap.Handles: return typeof(HandleArray);
                    case Cap.Commands: return typeof(CcaArray);
                    case Cap.PpCommands: return typeof(CcArray);
                    case Cap.AuditCommands: return typeof(CcArray);
                    case Cap.Pcrs: return typeof(PcrSelectionArray);
                    case Cap.TpmProperties: return typeof(TaggedTpmPropertyArray);
                    case Cap.PcrProperties: return typeof(TaggedPcrPropertyArray);
                    case Cap.EccCurves: return typeof(EccCurveArray);
                }
            }
            else if (unionInterface == typeof(IAttestUnion))
            {
                switch((TpmSt)selector)
                {
                    case TpmSt.AttestCertify: return typeof(CertifyInfo);
                    case TpmSt.AttestCreation: return typeof(CreationInfo);
                    case TpmSt.AttestQuote: return typeof(QuoteInfo);
                    case TpmSt.AttestCommandAudit: return typeof(CommandAuditInfo);
                    case TpmSt.AttestSessionAudit: return typeof(SessionAuditInfo);
                    case TpmSt.AttestTime: return typeof(TimeAttestInfo);
                    case TpmSt.AttestNv: return typeof(NvCertifyInfo);
                }
            }
            else if (unionInterface == typeof(ISymDetailsUnion))
            {
                switch((TpmAlgId)selector)
                {
                    case TpmAlgId.Tdes: return typeof(TdesSymDetails);
                    case TpmAlgId.Aes: return typeof(AesSymDetails);
                    case TpmAlgId.Sm4: return typeof(Sm4SymDetails);
                    case TpmAlgId.Camellia: return typeof(CamelliaSymDetails);
                    case TpmAlgId.Any: return typeof(AnySymDetails);
                    case TpmAlgId.Xor: return typeof(XorSymDetails);
                    case TpmAlgId.Null: return typeof(NullSymDetails);
                }
            }
            else if (unionInterface == typeof(ISensitiveCreateUnion))
            {
                switch((TpmAlgId)selector)
                {
                    case TpmAlgId.Any: return typeof(Byte);
                    case TpmAlgId.Any2: return typeof(TpmDerive);
                }
            }
            else if (unionInterface == typeof(ISchemeKeyedhashUnion))
            {
                switch((TpmAlgId)selector)
                {
                    case TpmAlgId.Hmac: return typeof(SchemeHmac);
                    case TpmAlgId.Xor: return typeof(SchemeXor);
                    case TpmAlgId.Null: return typeof(NullSchemeKeyedhash);
                }
            }
            else if (unionInterface == typeof(ISigSchemeUnion))
            {
                switch((TpmAlgId)selector)
                {
                    case TpmAlgId.Rsassa: return typeof(SigSchemeRsassa);
                    case TpmAlgId.Rsapss: return typeof(SigSchemeRsapss);
                    case TpmAlgId.Ecdsa: return typeof(SigSchemeEcdsa);
                    case TpmAlgId.Ecdaa: return typeof(SigSchemeEcdaa);
                    case TpmAlgId.Sm2: return typeof(SigSchemeSm2);
                    case TpmAlgId.Ecschnorr: return typeof(SigSchemeEcschnorr);
                    case TpmAlgId.Hmac: return typeof(SchemeHmac);
                    case TpmAlgId.Any: return typeof(SchemeHash);
                    case TpmAlgId.Null: return typeof(NullSigScheme);
                }
            }
            else if (unionInterface == typeof(IKdfSchemeUnion))
            {
                switch((TpmAlgId)selector)
                {
                    case TpmAlgId.Mgf1: return typeof(SchemeMgf1);
                    case TpmAlgId.Kdf1Sp80056a: return typeof(SchemeKdf1Sp80056a);
                    case TpmAlgId.Kdf2: return typeof(SchemeKdf2);
                    case TpmAlgId.Kdf1Sp800108: return typeof(SchemeKdf1Sp800108);
                    case TpmAlgId.Null: return typeof(NullKdfScheme);
                }
            }
            else if (unionInterface == typeof(IAsymSchemeUnion))
            {
                switch((TpmAlgId)selector)
                {
                    case TpmAlgId.Ecdh: return typeof(KeySchemeEcdh);
                    case TpmAlgId.Ecmqv: return typeof(KeySchemeEcmqv);
                    case TpmAlgId.Rsassa: return typeof(SigSchemeRsassa);
                    case TpmAlgId.Rsapss: return typeof(SigSchemeRsapss);
                    case TpmAlgId.Ecdsa: return typeof(SigSchemeEcdsa);
                    case TpmAlgId.Ecdaa: return typeof(SigSchemeEcdaa);
                    case TpmAlgId.Sm2: return typeof(SigSchemeSm2);
                    case TpmAlgId.Ecschnorr: return typeof(SigSchemeEcschnorr);
                    case TpmAlgId.Rsaes: return typeof(EncSchemeRsaes);
                    case TpmAlgId.Oaep: return typeof(EncSchemeOaep);
                    case TpmAlgId.Any: return typeof(SchemeHash);
                    case TpmAlgId.Null: return typeof(NullAsymScheme);
                }
            }
            else if (unionInterface == typeof(ISignatureUnion))
            {
                switch((TpmAlgId)selector)
                {
                    case TpmAlgId.Rsassa: return typeof(SignatureRsassa);
                    case TpmAlgId.Rsapss: return typeof(SignatureRsapss);
                    case TpmAlgId.Ecdsa: return typeof(SignatureEcdsa);
                    case TpmAlgId.Ecdaa: return typeof(SignatureEcdaa);
                    case TpmAlgId.Sm2: return typeof(SignatureSm2);
                    case TpmAlgId.Ecschnorr: return typeof(SignatureEcschnorr);
                    case TpmAlgId.Hmac: return typeof(TpmHash);
                    case TpmAlgId.Any: return typeof(SchemeHash);
                    case TpmAlgId.Null: return typeof(NullSignature);
                }
            }
            else if (unionInterface == typeof(IEncryptedSecretUnion))
            {
                switch((TpmAlgId)selector)
                {
                    case TpmAlgId.Ecc: return typeof(Byte);
                    case TpmAlgId.Rsa: return typeof(Byte);
                    case TpmAlgId.Symcipher: return typeof(Byte);
                    case TpmAlgId.Keyedhash: return typeof(Byte);
                }
            }
            else if (unionInterface == typeof(IPublicIdUnion))
            {
                switch((TpmAlgId)selector)
                {
                    case TpmAlgId.Keyedhash: return typeof(Tpm2bDigestKeyedhash);
                    case TpmAlgId.Symcipher: return typeof(Tpm2bDigestSymcipher);
                    case TpmAlgId.Rsa: return typeof(Tpm2bPublicKeyRsa);
                    case TpmAlgId.Ecc: return typeof(EccPoint);
                    case TpmAlgId.Any: return typeof(TpmDerive);
                }
            }
            else if (unionInterface == typeof(IPublicParmsUnion))
            {
                switch((TpmAlgId)selector)
                {
                    case TpmAlgId.Keyedhash: return typeof(KeyedhashParms);
                    case TpmAlgId.Symcipher: return typeof(SymcipherParms);
                    case TpmAlgId.Rsa: return typeof(RsaParms);
                    case TpmAlgId.Ecc: return typeof(EccParms);
                    case TpmAlgId.Any: return typeof(AsymParms);
                }
            }
            else if (unionInterface == typeof(ISensitiveCompositeUnion))
            {
                switch((TpmAlgId)selector)
                {
                    case TpmAlgId.Rsa: return typeof(Tpm2bPrivateKeyRsa);
                    case TpmAlgId.Ecc: return typeof(Tpm2bEccParameter);
                    case TpmAlgId.Keyedhash: return typeof(Tpm2bSensitiveData);
                    case TpmAlgId.Symcipher: return typeof(Tpm2bSymKey);
                    case TpmAlgId.Any: return typeof(Tpm2bPrivateVendorSpecific);
                }
            }
            else
            {
                throw new Exception("Unknown union interface type " + unionInterface.Name);
            }
            throw new Exception("Unknown selector value" + selector + " for " + unionInterface.Name +  " union");
        }
    }
    //-----------------------------------------------------------------------------
    //------------------------- STRUCTURES-----------------------------------------
    //-----------------------------------------------------------------------------
    /// <summary>
    /// Handle of a loaded TPM key or other object [TSS]
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM_HANDLE")]
    public partial class TpmHandle: TpmStructureBase, INameUnion
    {
        /// <summary>
        /// Handle value
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public uint handle { get; set; }
        public TpmHandle()
        {
            handle = 0;
        }
        public TpmHandle(TpmHandle the_TpmHandle)
        {
            if((Object) the_TpmHandle == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            handle = the_TpmHandle.handle;
            Auth = the_TpmHandle.Auth;
            if (the_TpmHandle.Name != null)
                Name = Globs.CopyData(the_TpmHandle.Name);
        }
        ///<param name = "the_handle">Handle value</param>
        public TpmHandle(
        uint the_handle
        )
        {
            this.handle = the_handle;
        }
        public virtual NameUnionTagValues GetUnionSelector()
        {
            return NameUnionTagValues.TagTpmuNameTpmHandle;
        }
        new public TpmHandle Copy()
        {
            return Marshaller.FromTpmRepresentation<TpmHandle>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Base class for empty union elements.
    /// An empty union element does not contain any data to marshal.
    /// This data structure can be used in place of any other union
    /// initialized with its own empty element.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_NULL_UNION")]
    public partial class NullUnion: TpmStructureBase, ISymKeyBitsUnion, ISymModeUnion, ISymDetailsUnion, ISchemeKeyedhashUnion, ISigSchemeUnion, IKdfSchemeUnion, IAsymSchemeUnion, ISignatureUnion
    {
        public NullUnion()
        {
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Null;
        }
        new public NullUnion Copy()
        {
            return Marshaller.FromTpmRepresentation<NullUnion>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used as a placeholder. In some cases, a union will have a selector value with no data to unmarshal when that type is selected. Rather than leave the entry empty, TPMS_EMPTY may be selected.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_EMPTY")]
    public partial class Empty: TpmStructureBase, IAsymSchemeUnion
    {
        public Empty()
        {
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Rsaes;
        }
        new public Empty Copy()
        {
            return Marshaller.FromTpmRepresentation<Empty>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is a return value for a TPM2_GetCapability() that reads the installed algorithms.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(AlgorithmAttr))]
    [SpecTypeName("TPMS_ALGORITHM_DESCRIPTION")]
    public partial class AlgorithmDescription: TpmStructureBase
    {
        /// <summary>
        /// an algorithm
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId alg { get; set; }
        /// <summary>
        /// the attributes of the algorithm
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public AlgorithmAttr attributes { get; set; }
        public AlgorithmDescription()
        {
            alg = TpmAlgId.Null;
            attributes = new AlgorithmAttr();
        }
        public AlgorithmDescription(AlgorithmDescription the_AlgorithmDescription)
        {
            if((Object) the_AlgorithmDescription == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            alg = the_AlgorithmDescription.alg;
            attributes = the_AlgorithmDescription.attributes;
        }
        ///<param name = "the_alg">an algorithm</param>
        ///<param name = "the_attributes">the attributes of the algorithm</param>
        public AlgorithmDescription(
        TpmAlgId the_alg,
        AlgorithmAttr the_attributes
        )
        {
            this.alg = the_alg;
            this.attributes = the_attributes;
        }
        new public AlgorithmDescription Copy()
        {
            return Marshaller.FromTpmRepresentation<AlgorithmDescription>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used for a sized buffer that cannot be larger than the largest digest produced by any hash algorithm implemented on the TPM.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_DIGEST")]
    public partial class Tpm2bDigest: TpmStructureBase, IPublicIdUnion
    {
        /// <summary>
        /// the buffer area that can be no larger than a digest
        /// </summary>
        [Range(MaxVal = 50u /*sizeof(TpmHash)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bDigest()
        {
            buffer = null;
        }
        public Tpm2bDigest(Tpm2bDigest the_Tpm2bDigest)
        {
            if((Object) the_Tpm2bDigest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bDigest.buffer;
        }
        ///<param name = "the_buffer">the buffer area that can be no larger than a digest</param>
        public Tpm2bDigest(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Keyedhash;
        }
        new public Tpm2bDigest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bDigest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used for a data buffer that is required to be no larger than the size of the Name of an object.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_DATA")]
    public partial class Tpm2bData: TpmStructureBase
    {
        [Range(MaxVal = 50u /*sizeof(TpmHash)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bData()
        {
            buffer = null;
        }
        public Tpm2bData(Tpm2bData the_Tpm2bData)
        {
            if((Object) the_Tpm2bData == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bData.buffer;
        }
        ///<param name = "the_buffer"></param>
        public Tpm2bData(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        new public Tpm2bData Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bData>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Table 75  Definition of Types for TPM2B_NONCE
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_NONCE")]
    public partial class Tpm2bNonce: Tpm2bDigest
    {
        public Tpm2bNonce()
        {
        }
        public Tpm2bNonce(Tpm2bNonce the_Tpm2bNonce)
        : base(the_Tpm2bNonce)
        {
        }
        ///<param name = "the_buffer">the buffer area that can be no larger than a digest</param>
        public Tpm2bNonce(
        byte[] the_buffer
        )
        : base(the_buffer)
        {
        }
    }
    /// <summary>
    /// This structure is used for an authorization value and limits an authValue to being no larger than the largest digest produced by a TPM. In order to ensure consistency within an object, the authValue may be no larger than the size of the digest produced by the objects nameAlg. This ensures that any TPM that can load the object will be able to handle the authValue of the object.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_AUTH")]
    public partial class Tpm2bAuth: Tpm2bDigest
    {
        public Tpm2bAuth()
        {
        }
        public Tpm2bAuth(Tpm2bAuth the_Tpm2bAuth)
        : base(the_Tpm2bAuth)
        {
        }
        ///<param name = "the_buffer">the buffer area that can be no larger than a digest</param>
        public Tpm2bAuth(
        byte[] the_buffer
        )
        : base(the_buffer)
        {
        }
    }
    /// <summary>
    /// This type is a sized buffer that can hold an operand for a comparison with an NV Index location. The maximum size of the operand is implementation dependent but a TPM is required to support an operand size that is at least as big as the digest produced by any of the hash algorithms implemented on the TPM.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_OPERAND")]
    public partial class Tpm2bOperand: Tpm2bDigest
    {
        public Tpm2bOperand()
        {
        }
        public Tpm2bOperand(Tpm2bOperand the_Tpm2bOperand)
        : base(the_Tpm2bOperand)
        {
        }
        ///<param name = "the_buffer">the buffer area that can be no larger than a digest</param>
        public Tpm2bOperand(
        byte[] the_buffer
        )
        : base(the_buffer)
        {
        }
    }
    /// <summary>
    /// This type is a sized buffer that can hold event data.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_EVENT")]
    public partial class Tpm2bEvent: TpmStructureBase
    {
        /// <summary>
        /// the operand
        /// </summary>
        [Range(MaxVal = 1024u /*1024*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bEvent()
        {
            buffer = null;
        }
        public Tpm2bEvent(Tpm2bEvent the_Tpm2bEvent)
        {
            if((Object) the_Tpm2bEvent == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bEvent.buffer;
        }
        ///<param name = "the_buffer">the operand</param>
        public Tpm2bEvent(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        new public Tpm2bEvent Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bEvent>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This type is a sized buffer that can hold a maximally sized buffer for commands that use a large data buffer such as TPM2_PCR_Event(), TPM2_Hash(), TPM2_SequenceUpdate(), or TPM2_FieldUpgradeData().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_MAX_BUFFER")]
    public partial class Tpm2bMaxBuffer: TpmStructureBase
    {
        /// <summary>
        /// the operand NOTE	MAX_DIGEST_BUFFER is TPM-dependent but is required to be at least 1,024.
        /// </summary>
        [Range(MaxVal = 1024u /*MAX_DIGEST_BUFFER*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bMaxBuffer()
        {
            buffer = null;
        }
        public Tpm2bMaxBuffer(Tpm2bMaxBuffer the_Tpm2bMaxBuffer)
        {
            if((Object) the_Tpm2bMaxBuffer == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bMaxBuffer.buffer;
        }
        ///<param name = "the_buffer">the operand NOTE	MAX_DIGEST_BUFFER is TPM-dependent but is required to be at least 1,024.</param>
        public Tpm2bMaxBuffer(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        new public Tpm2bMaxBuffer Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bMaxBuffer>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This type is a sized buffer that can hold a maximally sized buffer for NV data commands such as TPM2_NV_Read(), TPM2_NV_Write(), and TPM2_NV_Certify().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_MAX_NV_BUFFER")]
    public partial class Tpm2bMaxNvBuffer: TpmStructureBase
    {
        /// <summary>
        /// the operand NOTE	MAX_NV_BUFFER_SIZE is TPM-dependent
        /// </summary>
        [Range(MaxVal = 1024u /*MAX_NV_BUFFER_SIZE*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bMaxNvBuffer()
        {
            buffer = null;
        }
        public Tpm2bMaxNvBuffer(Tpm2bMaxNvBuffer the_Tpm2bMaxNvBuffer)
        {
            if((Object) the_Tpm2bMaxNvBuffer == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bMaxNvBuffer.buffer;
        }
        ///<param name = "the_buffer">the operand NOTE	MAX_NV_BUFFER_SIZE is TPM-dependent</param>
        public Tpm2bMaxNvBuffer(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        new public Tpm2bMaxNvBuffer Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bMaxNvBuffer>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This TPM-dependent structure is used to provide the timeout value for an authorization.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_TIMEOUT")]
    public partial class Tpm2bTimeout: Tpm2bDigest
    {
        public Tpm2bTimeout()
        {
        }
        public Tpm2bTimeout(Tpm2bTimeout the_Tpm2bTimeout)
        : base(the_Tpm2bTimeout)
        {
        }
        ///<param name = "the_buffer">the buffer area that can be no larger than a digest</param>
        public Tpm2bTimeout(
        byte[] the_buffer
        )
        : base(the_buffer)
        {
        }
    }
    /// <summary>
    /// This structure is used for passing an initial value for a symmetric block cipher to or from the TPM. The size is set to be the largest block size of any implemented symmetric cipher implemented on the TPM.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_IV")]
    public partial class Tpm2bIv: TpmStructureBase
    {
        /// <summary>
        /// the IV value
        /// </summary>
        [Range(MaxVal = 16u /*MAX_SYM_BLOCK_SIZE*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bIv()
        {
            buffer = null;
        }
        public Tpm2bIv(Tpm2bIv the_Tpm2bIv)
        {
            if((Object) the_Tpm2bIv == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bIv.buffer;
        }
        ///<param name = "the_buffer">the IV value</param>
        public Tpm2bIv(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        new public Tpm2bIv Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bIv>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This buffer holds a Name for any entity type.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_NAME")]
    public partial class Tpm2bName: TpmStructureBase
    {
        /// <summary>
        /// the Name structure
        /// </summary>
        [Range(MaxVal = 50u /*sizeof(TPMU_NAME)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] name;
        public Tpm2bName()
        {
            name = null;
        }
        public Tpm2bName(Tpm2bName the_Tpm2bName)
        {
            if((Object) the_Tpm2bName == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            name = the_Tpm2bName.name;
        }
        ///<param name = "the_name">the Name structure</param>
        public Tpm2bName(
        byte[] the_name
        )
        {
            this.name = the_name;
        }
        new public Tpm2bName Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bName>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure provides a standard method of specifying a list of PCR.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_PCR_SELECT")]
    public partial class PcrSelect: TpmStructureBase
    {
        /// <summary>
        /// the bit map of selected PCR
        /// </summary>
        [Range(MinVal = 3u /*PCR_SELECT_MIN*/, MaxVal = 3u /*PCR_SELECT_MAX*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "sizeofSelect", 1)]
        [DataMember()]
        public byte[] pcrSelect;
        public PcrSelect()
        {
            pcrSelect = null;
        }
        public PcrSelect(PcrSelect the_PcrSelect)
        {
            if((Object) the_PcrSelect == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            pcrSelect = the_PcrSelect.pcrSelect;
        }
        ///<param name = "the_pcrSelect">the bit map of selected PCR</param>
        public PcrSelect(
        byte[] the_pcrSelect
        )
        {
            this.pcrSelect = the_pcrSelect;
        }
        new public PcrSelect Copy()
        {
            return Marshaller.FromTpmRepresentation<PcrSelect>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Table 86  Definition of TPMS_PCR_SELECTION Structure
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMS_PCR_SELECTION")]
    public partial class PcrSelection: TpmStructureBase
    {
        /// <summary>
        /// the hash algorithm associated with the selection
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId hash { get; set; }
        /// <summary>
        /// the bit map of selected PCR
        /// </summary>
        [Range(MinVal = 3u /*PCR_SELECT_MIN*/, MaxVal = 3u /*PCR_SELECT_MAX*/)]
        [MarshalAs(1, MarshalType.VariableLengthArray, "sizeofSelect", 1)]
        [DataMember()]
        public byte[] pcrSelect;
        public PcrSelection()
        {
            hash = TpmAlgId.Null;
            pcrSelect = null;
        }
        public PcrSelection(PcrSelection the_PcrSelection)
        {
            if((Object) the_PcrSelection == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            hash = the_PcrSelection.hash;
            pcrSelect = the_PcrSelection.pcrSelect;
        }
        ///<param name = "the_hash">the hash algorithm associated with the selection</param>
        ///<param name = "the_pcrSelect">the bit map of selected PCR</param>
        public PcrSelection(
        TpmAlgId the_hash,
        byte[] the_pcrSelect
        )
        {
            this.hash = the_hash;
            this.pcrSelect = the_pcrSelect;
        }
        new public PcrSelection Copy()
        {
            return Marshaller.FromTpmRepresentation<PcrSelection>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This ticket is produced by TPM2_Create() or TPM2_CreatePrimary(). It is used to bind the creation data to the object to which it applies. The ticket is computed by
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPMT_TK_CREATION")]
    public partial class TkCreation: TpmStructureBase
    {
        /// <summary>
        /// ticket structure tag
        /// </summary>
        [Range(OnlyVal = 32801u /*TPM_ST_CREATION*/)]
        [MarshalAs(0)]
        [DataMember()]
        public TpmSt tag = TpmSt.Creation;
        /// <summary>
        /// the hierarchy containing name
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle hierarchy { get; set; }
        /// <summary>
        /// This shall be the HMAC produced using a proof value of hierarchy.
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "digestSize", 2)]
        [DataMember()]
        public byte[] digest;
        public TkCreation()
        {
            hierarchy = new TpmHandle();
            digest = null;
        }
        public TkCreation(TkCreation the_TkCreation)
        {
            if((Object) the_TkCreation == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            hierarchy = the_TkCreation.hierarchy;
            digest = the_TkCreation.digest;
        }
        ///<param name = "the_hierarchy">the hierarchy containing name</param>
        ///<param name = "the_digest">This shall be the HMAC produced using a proof value of hierarchy.</param>
        public TkCreation(
        TpmHandle the_hierarchy,
        byte[] the_digest
        )
        {
            this.hierarchy = the_hierarchy;
            this.digest = the_digest;
        }
        new public TkCreation Copy()
        {
            return Marshaller.FromTpmRepresentation<TkCreation>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This ticket is produced by TPM2_VerifySignature(). This formulation is used for multiple ticket uses. The ticket provides evidence that the TPM has validated that a digest was signed by a key with the Name of keyName. The ticket is computed by
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPMT_TK_VERIFIED")]
    public partial class TkVerified: TpmStructureBase
    {
        /// <summary>
        /// ticket structure tag
        /// </summary>
        [Range(OnlyVal = 32802u /*TPM_ST_VERIFIED*/)]
        [MarshalAs(0)]
        [DataMember()]
        public TpmSt tag = TpmSt.Verified;
        /// <summary>
        /// the hierarchy containing keyName
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle hierarchy { get; set; }
        /// <summary>
        /// This shall be the HMAC produced using a proof value of hierarchy.
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "digestSize", 2)]
        [DataMember()]
        public byte[] digest;
        public TkVerified()
        {
            hierarchy = new TpmHandle();
            digest = null;
        }
        public TkVerified(TkVerified the_TkVerified)
        {
            if((Object) the_TkVerified == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            hierarchy = the_TkVerified.hierarchy;
            digest = the_TkVerified.digest;
        }
        ///<param name = "the_hierarchy">the hierarchy containing keyName</param>
        ///<param name = "the_digest">This shall be the HMAC produced using a proof value of hierarchy.</param>
        public TkVerified(
        TpmHandle the_hierarchy,
        byte[] the_digest
        )
        {
            this.hierarchy = the_hierarchy;
            this.digest = the_digest;
        }
        new public TkVerified Copy()
        {
            return Marshaller.FromTpmRepresentation<TkVerified>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This ticket is produced by TPM2_PolicySigned() and TPM2_PolicySecret() when the authorization has an expiration time. The ticket is computed by
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmSt))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPMT_TK_AUTH")]
    public partial class TkAuth: TpmStructureBase
    {
        /// <summary>
        /// ticket structure tag
        /// </summary>
        [Range(Values = new[] {32805u /*TPM_ST_AUTH_SIGNED*/, 32803u /*TPM_ST_AUTH_SECRET*/})]
        [MarshalAs(0)]
        [DataMember()]
        public TpmSt tag { get; set; }
        /// <summary>
        /// the hierarchy of the object used to produce the ticket
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle hierarchy { get; set; }
        /// <summary>
        /// This shall be the HMAC produced using a proof value of hierarchy.
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "digestSize", 2)]
        [DataMember()]
        public byte[] digest;
        public TkAuth()
        {
            tag = new TpmSt();
            hierarchy = new TpmHandle();
            digest = null;
        }
        public TkAuth(TkAuth the_TkAuth)
        {
            if((Object) the_TkAuth == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            tag = the_TkAuth.tag;
            hierarchy = the_TkAuth.hierarchy;
            digest = the_TkAuth.digest;
        }
        ///<param name = "the_tag">ticket structure tag</param>
        ///<param name = "the_hierarchy">the hierarchy of the object used to produce the ticket</param>
        ///<param name = "the_digest">This shall be the HMAC produced using a proof value of hierarchy.</param>
        public TkAuth(
        TpmSt the_tag,
        TpmHandle the_hierarchy,
        byte[] the_digest
        )
        {
            this.tag = the_tag;
            this.hierarchy = the_hierarchy;
            this.digest = the_digest;
        }
        new public TkAuth Copy()
        {
            return Marshaller.FromTpmRepresentation<TkAuth>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This ticket is produced by TPM2_SequenceComplete() when the message that was digested did not start with TPM_GENERATED_VALUE. The ticket is computed by
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPMT_TK_HASHCHECK")]
    public partial class TkHashcheck: TpmStructureBase
    {
        /// <summary>
        /// ticket structure tag
        /// </summary>
        [Range(OnlyVal = 32804u /*TPM_ST_HASHCHECK*/)]
        [MarshalAs(0)]
        [DataMember()]
        public TpmSt tag = TpmSt.Hashcheck;
        /// <summary>
        /// the hierarchy
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle hierarchy { get; set; }
        /// <summary>
        /// This shall be the HMAC produced using a proof value of hierarchy.
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "digestSize", 2)]
        [DataMember()]
        public byte[] digest;
        public TkHashcheck()
        {
            hierarchy = new TpmHandle();
            digest = null;
        }
        public TkHashcheck(TkHashcheck the_TkHashcheck)
        {
            if((Object) the_TkHashcheck == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            hierarchy = the_TkHashcheck.hierarchy;
            digest = the_TkHashcheck.digest;
        }
        ///<param name = "the_hierarchy">the hierarchy</param>
        ///<param name = "the_digest">This shall be the HMAC produced using a proof value of hierarchy.</param>
        public TkHashcheck(
        TpmHandle the_hierarchy,
        byte[] the_digest
        )
        {
            this.hierarchy = the_hierarchy;
            this.digest = the_digest;
        }
        new public TkHashcheck Copy()
        {
            return Marshaller.FromTpmRepresentation<TkHashcheck>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used to report the properties of an algorithm identifier. It is returned in response to a TPM2_GetCapability() with capability = TPM_CAP_ALG.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(AlgorithmAttr))]
    [SpecTypeName("TPMS_ALG_PROPERTY")]
    public partial class AlgProperty: TpmStructureBase
    {
        /// <summary>
        /// an algorithm identifier
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId alg { get; set; }
        /// <summary>
        /// the attributes of the algorithm
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public AlgorithmAttr algProperties { get; set; }
        public AlgProperty()
        {
            alg = TpmAlgId.Null;
            algProperties = new AlgorithmAttr();
        }
        public AlgProperty(AlgProperty the_AlgProperty)
        {
            if((Object) the_AlgProperty == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            alg = the_AlgProperty.alg;
            algProperties = the_AlgProperty.algProperties;
        }
        ///<param name = "the_alg">an algorithm identifier</param>
        ///<param name = "the_algProperties">the attributes of the algorithm</param>
        public AlgProperty(
        TpmAlgId the_alg,
        AlgorithmAttr the_algProperties
        )
        {
            this.alg = the_alg;
            this.algProperties = the_algProperties;
        }
        new public AlgProperty Copy()
        {
            return Marshaller.FromTpmRepresentation<AlgProperty>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used to report the properties that are UINT32 values. It is returned in response to a TPM2_GetCapability().
    /// </summary>
    [DataContract]
    [KnownType(typeof(Pt))]
    [SpecTypeName("TPMS_TAGGED_PROPERTY")]
    public partial class TaggedProperty: TpmStructureBase
    {
        /// <summary>
        /// a property identifier
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public Pt property { get; set; }
        /// <summary>
        /// the value of the property
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint value { get; set; }
        public TaggedProperty()
        {
            property = new Pt();
            value = 0;
        }
        public TaggedProperty(TaggedProperty the_TaggedProperty)
        {
            if((Object) the_TaggedProperty == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            property = the_TaggedProperty.property;
            value = the_TaggedProperty.value;
        }
        ///<param name = "the_property">a property identifier</param>
        ///<param name = "the_value">the value of the property</param>
        public TaggedProperty(
        Pt the_property,
        uint the_value
        )
        {
            this.property = the_property;
            this.value = the_value;
        }
        new public TaggedProperty Copy()
        {
            return Marshaller.FromTpmRepresentation<TaggedProperty>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used in TPM2_GetCapability() to return the attributes of the PCR.
    /// </summary>
    [DataContract]
    [KnownType(typeof(PtPcr))]
    [SpecTypeName("TPMS_TAGGED_PCR_SELECT")]
    public partial class TaggedPcrSelect: TpmStructureBase
    {
        /// <summary>
        /// the property identifier
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public PtPcr tag { get; set; }
        /// <summary>
        /// the bit map of PCR with the identified property
        /// </summary>
        [Range(MinVal = 3u /*PCR_SELECT_MIN*/, MaxVal = 3u /*PCR_SELECT_MAX*/)]
        [MarshalAs(1, MarshalType.VariableLengthArray, "sizeofSelect", 1)]
        [DataMember()]
        public byte[] pcrSelect;
        public TaggedPcrSelect()
        {
            tag = new PtPcr();
            pcrSelect = null;
        }
        public TaggedPcrSelect(TaggedPcrSelect the_TaggedPcrSelect)
        {
            if((Object) the_TaggedPcrSelect == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            tag = the_TaggedPcrSelect.tag;
            pcrSelect = the_TaggedPcrSelect.pcrSelect;
        }
        ///<param name = "the_tag">the property identifier</param>
        ///<param name = "the_pcrSelect">the bit map of PCR with the identified property</param>
        public TaggedPcrSelect(
        PtPcr the_tag,
        byte[] the_pcrSelect
        )
        {
            this.tag = the_tag;
            this.pcrSelect = the_pcrSelect;
        }
        new public TaggedPcrSelect Copy()
        {
            return Marshaller.FromTpmRepresentation<TaggedPcrSelect>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// A list of command codes may be input to the TPM or returned by the TPM depending on the command.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPML_CC")]
    public partial class CcArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary>
        /// a list of command codes
        /// The maximum only applies to a command code list in a command. The response size is limited only by the size of the parameter buffer.
        /// </summary>
        [Range(MaxVal = 402u /*MAX_CAP_CC*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public TpmCc[] commandCodes;
        public CcArray()
        {
            commandCodes = null;
        }
        public CcArray(CcArray the_CcArray)
        {
            if((Object) the_CcArray == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            commandCodes = the_CcArray.commandCodes;
        }
        ///<param name = "the_commandCodes">a list of command codes The maximum only applies to a command code list in a command. The response size is limited only by the size of the parameter buffer.</param>
        public CcArray(
        TpmCc[] the_commandCodes
        )
        {
            this.commandCodes = the_commandCodes;
        }
        public virtual Cap GetUnionSelector()
        {
            return Cap.PpCommands;
        }
        new public CcArray Copy()
        {
            return Marshaller.FromTpmRepresentation<CcArray>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This list is only used in TPM2_GetCapability(capability = TPM_CAP_COMMANDS).
    /// </summary>
    [DataContract]
    [SpecTypeName("TPML_CCA")]
    public partial class CcaArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary>
        /// a list of command codes attributes
        /// </summary>
        [Range(MaxVal = 402u /*MAX_CAP_CC*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public CcAttr[] commandAttributes;
        public CcaArray()
        {
            commandAttributes = null;
        }
        public CcaArray(CcaArray the_CcaArray)
        {
            if((Object) the_CcaArray == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            commandAttributes = the_CcaArray.commandAttributes;
        }
        ///<param name = "the_commandAttributes">a list of command codes attributes</param>
        public CcaArray(
        CcAttr[] the_commandAttributes
        )
        {
            this.commandAttributes = the_commandAttributes;
        }
        public virtual Cap GetUnionSelector()
        {
            return Cap.Commands;
        }
        new public CcaArray Copy()
        {
            return Marshaller.FromTpmRepresentation<CcaArray>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This list is returned by TPM2_IncrementalSelfTest().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPML_ALG")]
    public partial class AlgArray: TpmStructureBase
    {
        /// <summary>
        /// a list of algorithm IDs
        /// The maximum only applies to an algorithm list in a command. The response size is limited only by the size of the parameter buffer.
        /// </summary>
        [Range(MaxVal = 64u /*MAX_ALG_LIST_SIZE*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public TpmAlgId[] algorithms;
        public AlgArray()
        {
            algorithms = null;
        }
        public AlgArray(AlgArray the_AlgArray)
        {
            if((Object) the_AlgArray == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            algorithms = the_AlgArray.algorithms;
        }
        ///<param name = "the_algorithms">a list of algorithm IDs The maximum only applies to an algorithm list in a command. The response size is limited only by the size of the parameter buffer.</param>
        public AlgArray(
        TpmAlgId[] the_algorithms
        )
        {
            this.algorithms = the_algorithms;
        }
        new public AlgArray Copy()
        {
            return Marshaller.FromTpmRepresentation<AlgArray>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used when the TPM returns a list of loaded handles when the capability in TPM2_GetCapability() is TPM_CAP_HANDLE.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPML_HANDLE")]
    public partial class HandleArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary>
        /// an array of handles
        /// </summary>
        [Range(MaxVal = 254u /*MAX_CAP_HANDLES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public TpmHandle[] handle;
        public HandleArray()
        {
            handle = null;
        }
        public HandleArray(HandleArray the_HandleArray)
        {
            if((Object) the_HandleArray == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            handle = the_HandleArray.handle;
        }
        ///<param name = "the_handle">an array of handles</param>
        public HandleArray(
        TpmHandle[] the_handle
        )
        {
            this.handle = the_handle;
        }
        public virtual Cap GetUnionSelector()
        {
            return Cap.Handles;
        }
        new public HandleArray Copy()
        {
            return Marshaller.FromTpmRepresentation<HandleArray>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This list is used to convey a list of digest values. This type is used in TPM2_PolicyOR() and in TPM2_PCR_Read().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPML_DIGEST")]
    public partial class DigestArray: TpmStructureBase
    {
        /// <summary>
        /// a list of digests
        /// For TPM2_PolicyOR(), all digests will have been computed using the digest of the policy session. For TPM2_PCR_Read(), each digest will be the size of the digest for the bank containing the PCR.
        /// </summary>
        [Range(MinVal = 2u /*2*/, MaxVal = 8u /*8*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public Tpm2bDigest[] digests;
        public DigestArray()
        {
            digests = null;
        }
        public DigestArray(DigestArray the_DigestArray)
        {
            if((Object) the_DigestArray == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            digests = the_DigestArray.digests;
        }
        ///<param name = "the_digests">a list of digests For TPM2_PolicyOR(), all digests will have been computed using the digest of the policy session. For TPM2_PCR_Read(), each digest will be the size of the digest for the bank containing the PCR.</param>
        public DigestArray(
        Tpm2bDigest[] the_digests
        )
        {
            this.digests = the_digests;
        }
        new public DigestArray Copy()
        {
            return Marshaller.FromTpmRepresentation<DigestArray>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This list is used to convey a list of digest values. This type is returned by TPM2_Event() and TPM2_SequenceComplete() and is an input for TPM2_PCR_Extend().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPML_DIGEST_VALUES")]
    public partial class DigestValuesArray: TpmStructureBase
    {
        /// <summary>
        /// a list of tagged digests
        /// </summary>
        [Range(MaxVal = 3u /*HASH_COUNT*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public TpmHash[] digests;
        public DigestValuesArray()
        {
            digests = null;
        }
        public DigestValuesArray(DigestValuesArray the_DigestValuesArray)
        {
            if((Object) the_DigestValuesArray == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            digests = the_DigestValuesArray.digests;
        }
        ///<param name = "the_digests">a list of tagged digests</param>
        public DigestValuesArray(
        TpmHash[] the_digests
        )
        {
            this.digests = the_digests;
        }
        new public DigestValuesArray Copy()
        {
            return Marshaller.FromTpmRepresentation<DigestValuesArray>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Digest list in a sized buffer. This list is returned by TPM2_PCR_SequenceComplete().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_DIGEST_VALUES")]
    public partial class Tpm2bDigestValues: TpmStructureBase
    {
        /// <summary>
        /// the operand
        /// </summary>
        [Range(MaxVal = 154u /*sizeof(TPML_DIGEST_VALUES)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bDigestValues()
        {
            buffer = null;
        }
        public Tpm2bDigestValues(Tpm2bDigestValues the_Tpm2bDigestValues)
        {
            if((Object) the_Tpm2bDigestValues == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bDigestValues.buffer;
        }
        ///<param name = "the_buffer">the operand</param>
        public Tpm2bDigestValues(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        new public Tpm2bDigestValues Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bDigestValues>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This list is used to indicate the PCR that are included in a selection when more than one PCR value may be selected.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPML_PCR_SELECTION")]
    public partial class PcrSelectionArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary>
        /// list of selections
        /// </summary>
        [Range(MaxVal = 3u /*HASH_COUNT*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public PcrSelection[] pcrSelections;
        public PcrSelectionArray()
        {
            pcrSelections = null;
        }
        public PcrSelectionArray(PcrSelectionArray the_PcrSelectionArray)
        {
            if((Object) the_PcrSelectionArray == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            pcrSelections = the_PcrSelectionArray.pcrSelections;
        }
        ///<param name = "the_pcrSelections">list of selections</param>
        public PcrSelectionArray(
        PcrSelection[] the_pcrSelections
        )
        {
            this.pcrSelections = the_pcrSelections;
        }
        public virtual Cap GetUnionSelector()
        {
            return Cap.Pcrs;
        }
        new public PcrSelectionArray Copy()
        {
            return Marshaller.FromTpmRepresentation<PcrSelectionArray>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This list is used to report on a list of algorithm attributes. It is returned in a TPM2_GetCapability().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPML_ALG_PROPERTY")]
    public partial class AlgPropertyArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary>
        /// list of properties
        /// </summary>
        [Range(MaxVal = 68u /*MAX_CAP_ALGS*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public AlgProperty[] algProperties;
        public AlgPropertyArray()
        {
            algProperties = null;
        }
        public AlgPropertyArray(AlgPropertyArray the_AlgPropertyArray)
        {
            if((Object) the_AlgPropertyArray == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            algProperties = the_AlgPropertyArray.algProperties;
        }
        ///<param name = "the_algProperties">list of properties</param>
        public AlgPropertyArray(
        AlgProperty[] the_algProperties
        )
        {
            this.algProperties = the_algProperties;
        }
        public virtual Cap GetUnionSelector()
        {
            return Cap.Algs;
        }
        new public AlgPropertyArray Copy()
        {
            return Marshaller.FromTpmRepresentation<AlgPropertyArray>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This list is used to report on a list of properties that are TPMS_TAGGED_PROPERTY values. It is returned by a TPM2_GetCapability().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPML_TAGGED_TPM_PROPERTY")]
    public partial class TaggedTpmPropertyArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary>
        /// an array of tagged properties
        /// </summary>
        [Range(MaxVal = 127u /*MAX_TPM_PROPERTIES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public TaggedProperty[] tpmProperty;
        public TaggedTpmPropertyArray()
        {
            tpmProperty = null;
        }
        public TaggedTpmPropertyArray(TaggedTpmPropertyArray the_TaggedTpmPropertyArray)
        {
            if((Object) the_TaggedTpmPropertyArray == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            tpmProperty = the_TaggedTpmPropertyArray.tpmProperty;
        }
        ///<param name = "the_tpmProperty">an array of tagged properties</param>
        public TaggedTpmPropertyArray(
        TaggedProperty[] the_tpmProperty
        )
        {
            this.tpmProperty = the_tpmProperty;
        }
        public virtual Cap GetUnionSelector()
        {
            return Cap.TpmProperties;
        }
        new public TaggedTpmPropertyArray Copy()
        {
            return Marshaller.FromTpmRepresentation<TaggedTpmPropertyArray>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This list is used to report on a list of properties that are TPMS_PCR_SELECT values. It is returned by a TPM2_GetCapability().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPML_TAGGED_PCR_PROPERTY")]
    public partial class TaggedPcrPropertyArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary>
        /// a tagged PCR selection
        /// </summary>
        [Range(MaxVal = 127u /*MAX_PCR_PROPERTIES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public TaggedPcrSelect[] pcrProperty;
        public TaggedPcrPropertyArray()
        {
            pcrProperty = null;
        }
        public TaggedPcrPropertyArray(TaggedPcrPropertyArray the_TaggedPcrPropertyArray)
        {
            if((Object) the_TaggedPcrPropertyArray == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            pcrProperty = the_TaggedPcrPropertyArray.pcrProperty;
        }
        ///<param name = "the_pcrProperty">a tagged PCR selection</param>
        public TaggedPcrPropertyArray(
        TaggedPcrSelect[] the_pcrProperty
        )
        {
            this.pcrProperty = the_pcrProperty;
        }
        public virtual Cap GetUnionSelector()
        {
            return Cap.PcrProperties;
        }
        new public TaggedPcrPropertyArray Copy()
        {
            return Marshaller.FromTpmRepresentation<TaggedPcrPropertyArray>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This list is used to report the ECC curve ID values supported by the TPM. It is returned by a TPM2_GetCapability().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPML_ECC_CURVE")]
    public partial class EccCurveArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary>
        /// array of ECC curve identifiers
        /// </summary>
        [Range(MaxVal = 508u /*MAX_ECC_CURVES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public EccCurve[] eccCurves;
        public EccCurveArray()
        {
            eccCurves = null;
        }
        public EccCurveArray(EccCurveArray the_EccCurveArray)
        {
            if((Object) the_EccCurveArray == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            eccCurves = the_EccCurveArray.eccCurves;
        }
        ///<param name = "the_eccCurves">array of ECC curve identifiers</param>
        public EccCurveArray(
        EccCurve[] the_eccCurves
        )
        {
            this.eccCurves = the_eccCurves;
        }
        public virtual Cap GetUnionSelector()
        {
            return Cap.EccCurves;
        }
        new public EccCurveArray Copy()
        {
            return Marshaller.FromTpmRepresentation<EccCurveArray>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This data area is returned in response to a TPM2_GetCapability().
    /// </summary>
    [DataContract]
    [KnownType(typeof(Cap))]
    [KnownType(typeof(CcArray))]
    [KnownType(typeof(CcaArray))]
    [KnownType(typeof(HandleArray))]
    [KnownType(typeof(PcrSelectionArray))]
    [KnownType(typeof(AlgPropertyArray))]
    [KnownType(typeof(TaggedTpmPropertyArray))]
    [KnownType(typeof(TaggedPcrPropertyArray))]
    [KnownType(typeof(EccCurveArray))]
    [SpecTypeName("TPMS_CAPABILITY_DATA")]
    public partial class CapabilityData: TpmStructureBase
    {
        /// <summary>
        /// the capability
        /// </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public Cap capability {
            get { return (Cap)data.GetUnionSelector(); }
        }
        /// <summary>
        /// the capability data
        /// (One of [AlgPropertyArray, HandleArray, CcaArray, CcArray, CcArray, PcrSelectionArray, TaggedTpmPropertyArray, TaggedPcrPropertyArray, EccCurveArray])
        /// </summary>
        [MarshalAs(1, MarshalType.Union, "capability")]
        [DataMember()]
        public ICapabilitiesUnion data { get; set; }
        public CapabilityData()
        {
        }
        public CapabilityData(CapabilityData the_CapabilityData)
        {
            if((Object) the_CapabilityData == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
        }
        ///<param name = "the_data">the capability data(One of AlgPropertyArray, HandleArray, CcaArray, CcArray, CcArray, PcrSelectionArray, TaggedTpmPropertyArray, TaggedPcrPropertyArray, EccCurveArray)</param>
        public CapabilityData(
        ICapabilitiesUnion the_data
        )
        {
            this.data = the_data;
        }
        new public CapabilityData Copy()
        {
            return Marshaller.FromTpmRepresentation<CapabilityData>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used in each of the attestation commands.
    /// </summary>
    [DataContract]
    [KnownType(typeof(ulong))]
    [KnownType(typeof(byte))]
    [SpecTypeName("TPMS_CLOCK_INFO")]
    public partial class ClockInfo: TpmStructureBase
    {
        /// <summary>
        /// time value in milliseconds that advances while the TPM is powered
        /// NOTE The interpretation of the time-origin (clock=0) is out of the scope of this specification, although Coordinated Universal Time (UTC) is expected to be a common convention. This structure element is used to report on the TPM's Clock value.
        /// The value of Clock shall be recorded in non-volatile memory no less often than once per 222 milliseconds (~69.9 minutes) of TPM operation. The reference for the millisecond timer is the TPM oscillator.
        /// This value is reset to zero when the Storage Primary Seed is changed (TPM2_Clear()).
        /// This value may be advanced by TPM2_ClockSet().
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public ulong clock { get; set; }
        /// <summary>
        /// number of occurrences of TPM Reset since the last TPM2_Clear()
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint resetCount { get; set; }
        /// <summary>
        /// number of times that TPM2_Shutdown() or _TPM_Hash_Start have occurred since the last TPM Reset or TPM2_Clear().
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public uint restartCount { get; set; }
        /// <summary>
        /// no value of Clock greater than the current value of Clock has been previously reported by the TPM. Set to YES on TPM2_Clear().
        /// </summary>
        [MarshalAs(3)]
        [DataMember()]
        public byte safe { get; set; }
        public ClockInfo()
        {
            clock = new ulong();
            resetCount = 0;
            restartCount = 0;
            safe = 0;
        }
        public ClockInfo(ClockInfo the_ClockInfo)
        {
            if((Object) the_ClockInfo == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            clock = the_ClockInfo.clock;
            resetCount = the_ClockInfo.resetCount;
            restartCount = the_ClockInfo.restartCount;
            safe = the_ClockInfo.safe;
        }
        ///<param name = "the_clock">time value in milliseconds that advances while the TPM is powered NOTE The interpretation of the time-origin (clock=0) is out of the scope of this specification, although Coordinated Universal Time (UTC) is expected to be a common convention. This structure element is used to report on the TPM's Clock value. The value of Clock shall be recorded in non-volatile memory no less often than once per 222 milliseconds (~69.9 minutes) of TPM operation. The reference for the millisecond timer is the TPM oscillator. This value is reset to zero when the Storage Primary Seed is changed (TPM2_Clear()). This value may be advanced by TPM2_ClockSet().</param>
        ///<param name = "the_resetCount">number of occurrences of TPM Reset since the last TPM2_Clear()</param>
        ///<param name = "the_restartCount">number of times that TPM2_Shutdown() or _TPM_Hash_Start have occurred since the last TPM Reset or TPM2_Clear().</param>
        ///<param name = "the_safe">no value of Clock greater than the current value of Clock has been previously reported by the TPM. Set to YES on TPM2_Clear().</param>
        public ClockInfo(
        ulong the_clock,
        uint the_resetCount,
        uint the_restartCount,
        byte the_safe
        )
        {
            this.clock = the_clock;
            this.resetCount = the_resetCount;
            this.restartCount = the_restartCount;
            this.safe = the_safe;
        }
        new public ClockInfo Copy()
        {
            return Marshaller.FromTpmRepresentation<ClockInfo>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used in the TPM2_GetTime() attestation.
    /// </summary>
    [DataContract]
    [KnownType(typeof(ulong))]
    [KnownType(typeof(ClockInfo))]
    [SpecTypeName("TPMS_TIME_INFO")]
    public partial class TimeInfo: TpmStructureBase
    {
        /// <summary>
        /// time in milliseconds since the last _TPM_Init() or TPM2_Startup()
        /// This structure element is used to report on the TPM's Time value.
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public ulong time { get; set; }
        /// <summary>
        /// a structure containing the clock information
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ClockInfo clockInfo { get; set; }
        public TimeInfo()
        {
            time = new ulong();
            clockInfo = new ClockInfo();
        }
        public TimeInfo(TimeInfo the_TimeInfo)
        {
            if((Object) the_TimeInfo == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            time = the_TimeInfo.time;
            clockInfo = the_TimeInfo.clockInfo;
        }
        ///<param name = "the_time">time in milliseconds since the last _TPM_Init() or TPM2_Startup() This structure element is used to report on the TPM's Time value.</param>
        ///<param name = "the_clockInfo">a structure containing the clock information</param>
        public TimeInfo(
        ulong the_time,
        ClockInfo the_clockInfo
        )
        {
            this.time = the_time;
            this.clockInfo = the_clockInfo;
        }
        new public TimeInfo Copy()
        {
            return Marshaller.FromTpmRepresentation<TimeInfo>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used when the TPM performs TPM2_GetTime.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TimeInfo))]
    [KnownType(typeof(ulong))]
    [SpecTypeName("TPMS_TIME_ATTEST_INFO")]
    public partial class TimeAttestInfo: TpmStructureBase, IAttestUnion
    {
        /// <summary>
        /// the Time, Clock, resetCount, restartCount, and Safe indicator
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TimeInfo time { get; set; }
        /// <summary>
        /// a TPM vendor-specific value indicating the version number of the firmware
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ulong firmwareVersion { get; set; }
        public TimeAttestInfo()
        {
            time = new TimeInfo();
            firmwareVersion = new ulong();
        }
        public TimeAttestInfo(TimeAttestInfo the_TimeAttestInfo)
        {
            if((Object) the_TimeAttestInfo == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            time = the_TimeAttestInfo.time;
            firmwareVersion = the_TimeAttestInfo.firmwareVersion;
        }
        ///<param name = "the_time">the Time, Clock, resetCount, restartCount, and Safe indicator</param>
        ///<param name = "the_firmwareVersion">a TPM vendor-specific value indicating the version number of the firmware</param>
        public TimeAttestInfo(
        TimeInfo the_time,
        ulong the_firmwareVersion
        )
        {
            this.time = the_time;
            this.firmwareVersion = the_firmwareVersion;
        }
        public virtual TpmSt GetUnionSelector()
        {
            return TpmSt.AttestTime;
        }
        new public TimeAttestInfo Copy()
        {
            return Marshaller.FromTpmRepresentation<TimeAttestInfo>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This is the attested data for TPM2_Certify().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_CERTIFY_INFO")]
    public partial class CertifyInfo: TpmStructureBase, IAttestUnion
    {
        /// <summary>
        /// Name of the certified object
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "nameSize", 2)]
        [DataMember()]
        public byte[] name;
        /// <summary>
        /// Qualified Name of the certified object
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "qualifiedNameSize", 2)]
        [DataMember()]
        public byte[] qualifiedName;
        public CertifyInfo()
        {
            name = null;
            qualifiedName = null;
        }
        public CertifyInfo(CertifyInfo the_CertifyInfo)
        {
            if((Object) the_CertifyInfo == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            name = the_CertifyInfo.name;
            qualifiedName = the_CertifyInfo.qualifiedName;
        }
        ///<param name = "the_name">Name of the certified object</param>
        ///<param name = "the_qualifiedName">Qualified Name of the certified object</param>
        public CertifyInfo(
        byte[] the_name,
        byte[] the_qualifiedName
        )
        {
            this.name = the_name;
            this.qualifiedName = the_qualifiedName;
        }
        public virtual TpmSt GetUnionSelector()
        {
            return TpmSt.AttestCertify;
        }
        new public CertifyInfo Copy()
        {
            return Marshaller.FromTpmRepresentation<CertifyInfo>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This is the attested data for TPM2_Quote().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_QUOTE_INFO")]
    public partial class QuoteInfo: TpmStructureBase, IAttestUnion
    {
        /// <summary>
        /// information on algID, PCR selected and digest
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "pcrSelectCount", 4)]
        [DataMember()]
        public PcrSelection[] pcrSelect;
        /// <summary>
        /// digest of the selected PCR using the hash of the signing key
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "pcrDigestSize", 2)]
        [DataMember()]
        public byte[] pcrDigest;
        public QuoteInfo()
        {
            pcrSelect = null;
            pcrDigest = null;
        }
        public QuoteInfo(QuoteInfo the_QuoteInfo)
        {
            if((Object) the_QuoteInfo == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            pcrSelect = the_QuoteInfo.pcrSelect;
            pcrDigest = the_QuoteInfo.pcrDigest;
        }
        ///<param name = "the_pcrSelect">information on algID, PCR selected and digest</param>
        ///<param name = "the_pcrDigest">digest of the selected PCR using the hash of the signing key</param>
        public QuoteInfo(
        PcrSelection[] the_pcrSelect,
        byte[] the_pcrDigest
        )
        {
            this.pcrSelect = the_pcrSelect;
            this.pcrDigest = the_pcrDigest;
        }
        public virtual TpmSt GetUnionSelector()
        {
            return TpmSt.AttestQuote;
        }
        new public QuoteInfo Copy()
        {
            return Marshaller.FromTpmRepresentation<QuoteInfo>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This is the attested data for TPM2_GetCommandAuditDigest().
    /// </summary>
    [DataContract]
    [KnownType(typeof(ulong))]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMS_COMMAND_AUDIT_INFO")]
    public partial class CommandAuditInfo: TpmStructureBase, IAttestUnion
    {
        /// <summary>
        /// the monotonic audit counter
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public ulong auditCounter { get; set; }
        /// <summary>
        /// hash algorithm used for the command audit
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmAlgId digestAlg { get; set; }
        /// <summary>
        /// the current value of the audit digest
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "auditDigestSize", 2)]
        [DataMember()]
        public byte[] auditDigest;
        /// <summary>
        /// digest of the command codes being audited using digestAlg
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "commandDigestSize", 2)]
        [DataMember()]
        public byte[] commandDigest;
        public CommandAuditInfo()
        {
            auditCounter = new ulong();
            digestAlg = TpmAlgId.Null;
            auditDigest = null;
            commandDigest = null;
        }
        public CommandAuditInfo(CommandAuditInfo the_CommandAuditInfo)
        {
            if((Object) the_CommandAuditInfo == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            auditCounter = the_CommandAuditInfo.auditCounter;
            digestAlg = the_CommandAuditInfo.digestAlg;
            auditDigest = the_CommandAuditInfo.auditDigest;
            commandDigest = the_CommandAuditInfo.commandDigest;
        }
        ///<param name = "the_auditCounter">the monotonic audit counter</param>
        ///<param name = "the_digestAlg">hash algorithm used for the command audit</param>
        ///<param name = "the_auditDigest">the current value of the audit digest</param>
        ///<param name = "the_commandDigest">digest of the command codes being audited using digestAlg</param>
        public CommandAuditInfo(
        ulong the_auditCounter,
        TpmAlgId the_digestAlg,
        byte[] the_auditDigest,
        byte[] the_commandDigest
        )
        {
            this.auditCounter = the_auditCounter;
            this.digestAlg = the_digestAlg;
            this.auditDigest = the_auditDigest;
            this.commandDigest = the_commandDigest;
        }
        public virtual TpmSt GetUnionSelector()
        {
            return TpmSt.AttestCommandAudit;
        }
        new public CommandAuditInfo Copy()
        {
            return Marshaller.FromTpmRepresentation<CommandAuditInfo>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This is the attested data for TPM2_GetSessionAuditDigest().
    /// </summary>
    [DataContract]
    [KnownType(typeof(byte))]
    [SpecTypeName("TPMS_SESSION_AUDIT_INFO")]
    public partial class SessionAuditInfo: TpmStructureBase, IAttestUnion
    {
        /// <summary>
        /// current exclusive status of the session TRUE if all of the commands recorded in the sessionDigest were executed without any intervening TPM command that did not use this audit session
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public byte exclusiveSession { get; set; }
        /// <summary>
        /// the current value of the session audit digest
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "sessionDigestSize", 2)]
        [DataMember()]
        public byte[] sessionDigest;
        public SessionAuditInfo()
        {
            exclusiveSession = 0;
            sessionDigest = null;
        }
        public SessionAuditInfo(SessionAuditInfo the_SessionAuditInfo)
        {
            if((Object) the_SessionAuditInfo == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            exclusiveSession = the_SessionAuditInfo.exclusiveSession;
            sessionDigest = the_SessionAuditInfo.sessionDigest;
        }
        ///<param name = "the_exclusiveSession">current exclusive status of the session TRUE if all of the commands recorded in the sessionDigest were executed without any intervening TPM command that did not use this audit session</param>
        ///<param name = "the_sessionDigest">the current value of the session audit digest</param>
        public SessionAuditInfo(
        byte the_exclusiveSession,
        byte[] the_sessionDigest
        )
        {
            this.exclusiveSession = the_exclusiveSession;
            this.sessionDigest = the_sessionDigest;
        }
        public virtual TpmSt GetUnionSelector()
        {
            return TpmSt.AttestSessionAudit;
        }
        new public SessionAuditInfo Copy()
        {
            return Marshaller.FromTpmRepresentation<SessionAuditInfo>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This is the attested data for TPM2_CertifyCreation().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_CREATION_INFO")]
    public partial class CreationInfo: TpmStructureBase, IAttestUnion
    {
        /// <summary>
        /// Name of the object
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "objectNameSize", 2)]
        [DataMember()]
        public byte[] objectName;
        /// <summary>
        /// creationHash
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "creationHashSize", 2)]
        [DataMember()]
        public byte[] creationHash;
        public CreationInfo()
        {
            objectName = null;
            creationHash = null;
        }
        public CreationInfo(CreationInfo the_CreationInfo)
        {
            if((Object) the_CreationInfo == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            objectName = the_CreationInfo.objectName;
            creationHash = the_CreationInfo.creationHash;
        }
        ///<param name = "the_objectName">Name of the object</param>
        ///<param name = "the_creationHash">creationHash</param>
        public CreationInfo(
        byte[] the_objectName,
        byte[] the_creationHash
        )
        {
            this.objectName = the_objectName;
            this.creationHash = the_creationHash;
        }
        public virtual TpmSt GetUnionSelector()
        {
            return TpmSt.AttestCreation;
        }
        new public CreationInfo Copy()
        {
            return Marshaller.FromTpmRepresentation<CreationInfo>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure contains the Name and contents of the selected NV Index that is certified by TPM2_NV_Certify().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_NV_CERTIFY_INFO")]
    public partial class NvCertifyInfo: TpmStructureBase, IAttestUnion
    {
        /// <summary>
        /// Name of the NV Index
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "indexNameSize", 2)]
        [DataMember()]
        public byte[] indexName;
        /// <summary>
        /// the offset parameter of TPM2_NV_Certify()
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ushort offset { get; set; }
        /// <summary>
        /// contents of the NV Index
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "nvContentsSize", 2)]
        [DataMember()]
        public byte[] nvContents;
        public NvCertifyInfo()
        {
            indexName = null;
            offset = 0;
            nvContents = null;
        }
        public NvCertifyInfo(NvCertifyInfo the_NvCertifyInfo)
        {
            if((Object) the_NvCertifyInfo == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            indexName = the_NvCertifyInfo.indexName;
            offset = the_NvCertifyInfo.offset;
            nvContents = the_NvCertifyInfo.nvContents;
        }
        ///<param name = "the_indexName">Name of the NV Index</param>
        ///<param name = "the_offset">the offset parameter of TPM2_NV_Certify()</param>
        ///<param name = "the_nvContents">contents of the NV Index</param>
        public NvCertifyInfo(
        byte[] the_indexName,
        ushort the_offset,
        byte[] the_nvContents
        )
        {
            this.indexName = the_indexName;
            this.offset = the_offset;
            this.nvContents = the_nvContents;
        }
        public virtual TpmSt GetUnionSelector()
        {
            return TpmSt.AttestNv;
        }
        new public NvCertifyInfo Copy()
        {
            return Marshaller.FromTpmRepresentation<NvCertifyInfo>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used on each TPM-generated signed structure. The signature is over this structure.
    /// </summary>
    [DataContract]
    [KnownType(typeof(Generated))]
    [KnownType(typeof(TpmSt))]
    [KnownType(typeof(ClockInfo))]
    [KnownType(typeof(ulong))]
    [KnownType(typeof(TimeAttestInfo))]
    [KnownType(typeof(CertifyInfo))]
    [KnownType(typeof(QuoteInfo))]
    [KnownType(typeof(CommandAuditInfo))]
    [KnownType(typeof(SessionAuditInfo))]
    [KnownType(typeof(CreationInfo))]
    [KnownType(typeof(NvCertifyInfo))]
    [SpecTypeName("TPMS_ATTEST")]
    public partial class Attest: TpmStructureBase
    {
        /// <summary>
        /// the indication that this structure was created by a TPM (always TPM_GENERATED_VALUE)
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public Generated magic { get; set; }
        /// <summary>
        /// type of the attestation structure
        /// </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmSt type {
            get { return (TpmSt)attested.GetUnionSelector(); }
        }
        /// <summary>
        /// Qualified Name of the signing key
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "qualifiedSignerSize", 2)]
        [DataMember()]
        public byte[] qualifiedSigner;
        /// <summary>
        /// external information supplied by caller
        /// NOTE	A TPM2B_DATA structure provides room for a digest and a method indicator to indicate the components of the digest. The definition of this method indicator is outside the scope of this specification.
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "extraDataSize", 2)]
        [DataMember()]
        public byte[] extraData;
        /// <summary>
        /// Clock, resetCount, restartCount, and Safe
        /// </summary>
        [MarshalAs(4)]
        [DataMember()]
        public ClockInfo clockInfo { get; set; }
        /// <summary>
        /// TPM-vendor-specific value identifying the version number of the firmware
        /// </summary>
        [MarshalAs(5)]
        [DataMember()]
        public ulong firmwareVersion { get; set; }
        /// <summary>
        /// the type-specific attestation information
        /// (One of [CertifyInfo, CreationInfo, QuoteInfo, CommandAuditInfo, SessionAuditInfo, TimeAttestInfo, NvCertifyInfo])
        /// </summary>
        [MarshalAs(6, MarshalType.Union, "type")]
        [DataMember()]
        public IAttestUnion attested { get; set; }
        public Attest()
        {
            magic = new Generated();
            qualifiedSigner = null;
            extraData = null;
            clockInfo = new ClockInfo();
            firmwareVersion = new ulong();
        }
        public Attest(Attest the_Attest)
        {
            if((Object) the_Attest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            magic = the_Attest.magic;
            qualifiedSigner = the_Attest.qualifiedSigner;
            extraData = the_Attest.extraData;
            clockInfo = the_Attest.clockInfo;
            firmwareVersion = the_Attest.firmwareVersion;
        }
        ///<param name = "the_magic">the indication that this structure was created by a TPM (always TPM_GENERATED_VALUE)</param>
        ///<param name = "the_qualifiedSigner">Qualified Name of the signing key</param>
        ///<param name = "the_extraData">external information supplied by caller NOTE	A TPM2B_DATA structure provides room for a digest and a method indicator to indicate the components of the digest. The definition of this method indicator is outside the scope of this specification.</param>
        ///<param name = "the_clockInfo">Clock, resetCount, restartCount, and Safe</param>
        ///<param name = "the_firmwareVersion">TPM-vendor-specific value identifying the version number of the firmware</param>
        ///<param name = "the_attested">the type-specific attestation information(One of CertifyInfo, CreationInfo, QuoteInfo, CommandAuditInfo, SessionAuditInfo, TimeAttestInfo, NvCertifyInfo)</param>
        public Attest(
        Generated the_magic,
        byte[] the_qualifiedSigner,
        byte[] the_extraData,
        ClockInfo the_clockInfo,
        ulong the_firmwareVersion,
        IAttestUnion the_attested
        )
        {
            this.magic = the_magic;
            this.qualifiedSigner = the_qualifiedSigner;
            this.extraData = the_extraData;
            this.clockInfo = the_clockInfo;
            this.firmwareVersion = the_firmwareVersion;
            this.attested = the_attested;
        }
        new public Attest Copy()
        {
            return Marshaller.FromTpmRepresentation<Attest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This sized buffer to contain the signed structure. The attestationData is the signed portion of the structure. The size parameter is not signed.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_ATTEST")]
    public partial class Tpm2bAttest: TpmStructureBase
    {
        /// <summary>
        /// the signed structure
        /// </summary>
        [Range(MaxVal = 1215u /*sizeof(TPMS_ATTEST)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] attestationData;
        public Tpm2bAttest()
        {
            attestationData = null;
        }
        public Tpm2bAttest(Tpm2bAttest the_Tpm2bAttest)
        {
            if((Object) the_Tpm2bAttest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            attestationData = the_Tpm2bAttest.attestationData;
        }
        ///<param name = "the_attestationData">the signed structure</param>
        public Tpm2bAttest(
        byte[] the_attestationData
        )
        {
            this.attestationData = the_attestationData;
        }
        new public Tpm2bAttest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bAttest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This is the format used for each of the authorizations in the session area of a command.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(SessionAttr))]
    [SpecTypeName("TPMS_AUTH_COMMAND")]
    public partial class AuthCommand: TpmStructureBase
    {
        /// <summary>
        /// the session handle
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle sessionHandle { get; set; }
        /// <summary>
        /// the session nonce, may be the Empty Buffer
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "nonceSize", 2)]
        [DataMember()]
        public byte[] nonce;
        /// <summary>
        /// the session attributes
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public SessionAttr sessionAttributes { get; set; }
        /// <summary>
        /// either an HMAC, a password, or an EmptyAuth
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "hmacSize", 2)]
        [DataMember()]
        public byte[] hmac;
        public AuthCommand()
        {
            sessionHandle = new TpmHandle();
            nonce = null;
            sessionAttributes = new SessionAttr();
            hmac = null;
        }
        public AuthCommand(AuthCommand the_AuthCommand)
        {
            if((Object) the_AuthCommand == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            sessionHandle = the_AuthCommand.sessionHandle;
            nonce = the_AuthCommand.nonce;
            sessionAttributes = the_AuthCommand.sessionAttributes;
            hmac = the_AuthCommand.hmac;
        }
        ///<param name = "the_sessionHandle">the session handle</param>
        ///<param name = "the_nonce">the session nonce, may be the Empty Buffer</param>
        ///<param name = "the_sessionAttributes">the session attributes</param>
        ///<param name = "the_hmac">either an HMAC, a password, or an EmptyAuth</param>
        public AuthCommand(
        TpmHandle the_sessionHandle,
        byte[] the_nonce,
        SessionAttr the_sessionAttributes,
        byte[] the_hmac
        )
        {
            this.sessionHandle = the_sessionHandle;
            this.nonce = the_nonce;
            this.sessionAttributes = the_sessionAttributes;
            this.hmac = the_hmac;
        }
        new public AuthCommand Copy()
        {
            return Marshaller.FromTpmRepresentation<AuthCommand>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This is the format for each of the authorizations in the session area of the response. If the TPM returns TPM_RC_SUCCESS, then the session area of the response contains the same number of authorizations as the command and the authorizations are in the same order.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_AUTH_RESPONSE")]
    public partial class AuthResponse: TpmStructureBase
    {
        public AuthResponse()
        {
        }
        new public AuthResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<AuthResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_NULL for the union TpmuSymKeyBits
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_NULL_SYM_KEY_BITS")]
    public partial class NullSymKeyBits: NullUnion
    {
        public NullSymKeyBits()
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Null;
        }
    }
    /// <summary>
    /// Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_XOR for the union TpmuSymMode
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_XOR_SYM_MODE")]
    public partial class XorSymMode: NullUnion
    {
        public XorSymMode()
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Xor;
        }
    }
    /// <summary>
    /// Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_NULL for the union TpmuSymMode
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_NULL_SYM_MODE")]
    public partial class NullSymMode: NullUnion
    {
        public NullSymMode()
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Null;
        }
    }
    /// <summary>
    /// Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_TDES for the union TpmuSymDetails
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_TDES_SYM_DETAILS")]
    public partial class TdesSymDetails: NullUnion
    {
        public TdesSymDetails()
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Tdes;
        }
    }
    /// <summary>
    /// Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_AES for the union TpmuSymDetails
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_AES_SYM_DETAILS")]
    public partial class AesSymDetails: NullUnion
    {
        public AesSymDetails()
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Aes;
        }
    }
    /// <summary>
    /// Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_SM4 for the union TpmuSymDetails
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SM4_SYM_DETAILS")]
    public partial class Sm4SymDetails: NullUnion
    {
        public Sm4SymDetails()
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Sm4;
        }
    }
    /// <summary>
    /// Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_CAMELLIA for the union TpmuSymDetails
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_CAMELLIA_SYM_DETAILS")]
    public partial class CamelliaSymDetails: NullUnion
    {
        public CamelliaSymDetails()
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Camellia;
        }
    }
    /// <summary>
    /// Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_ANY for the union TpmuSymDetails
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_ANY_SYM_DETAILS")]
    public partial class AnySymDetails: NullUnion
    {
        public AnySymDetails()
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Any;
        }
    }
    /// <summary>
    /// Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_XOR for the union TpmuSymDetails
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_XOR_SYM_DETAILS")]
    public partial class XorSymDetails: NullUnion
    {
        public XorSymDetails()
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Xor;
        }
    }
    /// <summary>
    /// Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_NULL for the union TpmuSymDetails
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_NULL_SYM_DETAILS")]
    public partial class NullSymDetails: NullUnion
    {
        public NullSymDetails()
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Null;
        }
    }
    /// <summary>
    /// The TPMT_SYM_DEF structure is used to select an algorithm to be used for parameter encryption in those cases when different symmetric algorithms may be selected.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(ushort))]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMT_SYM_DEF")]
    public partial class SymDef: TpmStructureBase
    {
        /// <summary>
        /// symmetric algorithm
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId Algorithm { get; set; }
        /// <summary>
        /// key size in bits
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ushort KeyBits { get; set; }
        /// <summary>
        /// encryption mode
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmAlgId Mode { get; set; }
        public SymDef()
        {
            Algorithm = TpmAlgId.Null;
            KeyBits = 0;
            Mode = TpmAlgId.Null;
        }
        public SymDef(SymDef the_SymDef)
        {
            if((Object) the_SymDef == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            Algorithm = the_SymDef.Algorithm;
            KeyBits = the_SymDef.KeyBits;
            Mode = the_SymDef.Mode;
        }
        ///<param name = "the_Algorithm">symmetric algorithm</param>
        ///<param name = "the_KeyBits">key size in bits</param>
        ///<param name = "the_Mode">encryption mode</param>
        public SymDef(
        TpmAlgId the_Algorithm,
        ushort the_KeyBits,
        TpmAlgId the_Mode
        )
        {
            this.Algorithm = the_Algorithm;
            this.KeyBits = the_KeyBits;
            this.Mode = the_Mode;
        }
        new public SymDef Copy()
        {
            return Marshaller.FromTpmRepresentation<SymDef>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used when different symmetric block cipher (not XOR) algorithms may be selected. If the Object can be an ordinary parent (not a derivation parent), this must be the first field in the Object's parameter (see 12.2.3.7) field.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(ushort))]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMT_SYM_DEF_OBJECT")]
    public partial class SymDefObject: TpmStructureBase
    {
        /// <summary>
        /// symmetric algorithm
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId Algorithm { get; set; }
        /// <summary>
        /// key size in bits
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ushort KeyBits { get; set; }
        /// <summary>
        /// encryption mode
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmAlgId Mode { get; set; }
        public SymDefObject()
        {
            Algorithm = TpmAlgId.Null;
            KeyBits = 0;
            Mode = TpmAlgId.Null;
        }
        public SymDefObject(SymDefObject the_SymDefObject)
        {
            if((Object) the_SymDefObject == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            Algorithm = the_SymDefObject.Algorithm;
            KeyBits = the_SymDefObject.KeyBits;
            Mode = the_SymDefObject.Mode;
        }
        ///<param name = "the_Algorithm">symmetric algorithm</param>
        ///<param name = "the_KeyBits">key size in bits</param>
        ///<param name = "the_Mode">encryption mode</param>
        public SymDefObject(
        TpmAlgId the_Algorithm,
        ushort the_KeyBits,
        TpmAlgId the_Mode
        )
        {
            this.Algorithm = the_Algorithm;
            this.KeyBits = the_KeyBits;
            this.Mode = the_Mode;
        }
        new public SymDefObject Copy()
        {
            return Marshaller.FromTpmRepresentation<SymDefObject>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used to hold a symmetric key in the sensitive area of an asymmetric object.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_SYM_KEY")]
    public partial class Tpm2bSymKey: TpmStructureBase, ISensitiveCompositeUnion
    {
        /// <summary>
        /// the key
        /// </summary>
        [Range(MaxVal = 32u /*MAX_SYM_KEY_BYTES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bSymKey()
        {
            buffer = null;
        }
        public Tpm2bSymKey(Tpm2bSymKey the_Tpm2bSymKey)
        {
            if((Object) the_Tpm2bSymKey == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bSymKey.buffer;
        }
        ///<param name = "the_buffer">the key</param>
        public Tpm2bSymKey(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Symcipher;
        }
        new public Tpm2bSymKey Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bSymKey>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure contains the parameters for a symmetric block cipher object.
    /// </summary>
    [DataContract]
    [KnownType(typeof(SymDefObject))]
    [SpecTypeName("TPMS_SYMCIPHER_PARMS")]
    public partial class SymcipherParms: TpmStructureBase, IPublicParmsUnion
    {
        /// <summary>
        /// a symmetric block cipher
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public SymDefObject sym { get; set; }
        public SymcipherParms()
        {
            sym = new SymDefObject();
        }
        public SymcipherParms(SymcipherParms the_SymcipherParms)
        {
            if((Object) the_SymcipherParms == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            sym = the_SymcipherParms.sym;
        }
        ///<param name = "the_sym">a symmetric block cipher</param>
        public SymcipherParms(
        SymDefObject the_sym
        )
        {
            this.sym = the_sym;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Symcipher;
        }
        new public SymcipherParms Copy()
        {
            return Marshaller.FromTpmRepresentation<SymcipherParms>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This buffer holds a label or context value. For interoperability and backwards compatibility, LABEL_MAX_BUFFER is the minimum of the largest digest on the device and the largest ECC parameter (MAX_ECC_KEY_BYTES) but no more than 32 bytes.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_LABEL")]
    public partial class Tpm2bLabel: TpmStructureBase
    {
        /// <summary>
        /// symmetic data for a created object or the label and context for a derived object
        /// </summary>
        [Range(MaxVal = 32u /*LABEL_MAX_BUFFER*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bLabel()
        {
            buffer = null;
        }
        public Tpm2bLabel(Tpm2bLabel the_Tpm2bLabel)
        {
            if((Object) the_Tpm2bLabel == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bLabel.buffer;
        }
        ///<param name = "the_buffer">symmetic data for a created object or the label and context for a derived object</param>
        public Tpm2bLabel(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        new public Tpm2bLabel Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bLabel>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure contains the label and context fields for a derived object. These values are used in the derivation KDF. The values in the unique field of inPublic area template take precedence over the values in the inSensitive parameter.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_DERIVE")]
    public partial class TpmDerive: TpmStructureBase, ISensitiveCreateUnion, IPublicIdUnion
    {
        [MarshalAs(0, MarshalType.VariableLengthArray, "labelSize", 2)]
        [DataMember()]
        public byte[] label;
        [MarshalAs(1, MarshalType.VariableLengthArray, "contextSize", 2)]
        [DataMember()]
        public byte[] context;
        public TpmDerive()
        {
            label = null;
            context = null;
        }
        public TpmDerive(TpmDerive the_TpmDerive)
        {
            if((Object) the_TpmDerive == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            label = the_TpmDerive.label;
            context = the_TpmDerive.context;
        }
        ///<param name = "the_label"></param>
        ///<param name = "the_context"></param>
        public TpmDerive(
        byte[] the_label,
        byte[] the_context
        )
        {
            this.label = the_label;
            this.context = the_context;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Any2;
        }
        new public TpmDerive Copy()
        {
            return Marshaller.FromTpmRepresentation<TpmDerive>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Table 135  Definition of TPM2B_DERIVE Structure
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_DERIVE")]
    public partial class Tpm2bDerive: TpmStructureBase
    {
        /// <summary>
        /// symmetic data for a created object or the label and context for a derived object
        /// </summary>
        [Range(MaxVal = 68u /*sizeof(TPMS_DERIVE)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bDerive()
        {
            buffer = null;
        }
        public Tpm2bDerive(Tpm2bDerive the_Tpm2bDerive)
        {
            if((Object) the_Tpm2bDerive == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bDerive.buffer;
        }
        ///<param name = "the_buffer">symmetic data for a created object or the label and context for a derived object</param>
        public Tpm2bDerive(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        new public Tpm2bDerive Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bDerive>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This buffer wraps the TPMU_SENSITIVE_CREATE structure.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_SENSITIVE_DATA")]
    public partial class Tpm2bSensitiveData: TpmStructureBase, ISensitiveCompositeUnion
    {
        /// <summary>
        /// symmetic data for a created object or the label and context for a derived object
        /// </summary>
        [Range(MaxVal = 128u /*sizeof(TPMU_SENSITIVE_CREATE)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bSensitiveData()
        {
            buffer = null;
        }
        public Tpm2bSensitiveData(Tpm2bSensitiveData the_Tpm2bSensitiveData)
        {
            if((Object) the_Tpm2bSensitiveData == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bSensitiveData.buffer;
        }
        ///<param name = "the_buffer">symmetic data for a created object or the label and context for a derived object</param>
        public Tpm2bSensitiveData(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Keyedhash;
        }
        new public Tpm2bSensitiveData Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bSensitiveData>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure defines the values to be placed in the sensitive area of a created object. This structure is only used within a TPM2B_SENSITIVE_CREATE structure.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SENSITIVE_CREATE")]
    public partial class SensitiveCreate: TpmStructureBase
    {
        /// <summary>
        /// the USER auth secret value
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "userAuthSize", 2)]
        [DataMember()]
        public byte[] userAuth;
        /// <summary>
        /// data to be sealed, a key, or derivation values
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "dataSize", 2)]
        [DataMember()]
        public byte[] data;
        public SensitiveCreate()
        {
            userAuth = null;
            data = null;
        }
        public SensitiveCreate(SensitiveCreate the_SensitiveCreate)
        {
            if((Object) the_SensitiveCreate == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            userAuth = the_SensitiveCreate.userAuth;
            data = the_SensitiveCreate.data;
        }
        ///<param name = "the_userAuth">the USER auth secret value</param>
        ///<param name = "the_data">data to be sealed, a key, or derivation values</param>
        public SensitiveCreate(
        byte[] the_userAuth,
        byte[] the_data
        )
        {
            this.userAuth = the_userAuth;
            this.data = the_data;
        }
        new public SensitiveCreate Copy()
        {
            return Marshaller.FromTpmRepresentation<SensitiveCreate>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure contains the sensitive creation data in a sized buffer. This structure is defined so that both the userAuth and data values of the TPMS_SENSITIVE_CREATE may be passed as a single parameter for parameter encryption purposes.
    /// </summary>
    [DataContract]
    [KnownType(typeof(SensitiveCreate))]
    [SpecTypeName("TPM2B_SENSITIVE_CREATE")]
    public partial class Tpm2bSensitiveCreate: TpmStructureBase
    {
        /// <summary>
        /// data to be sealed or a symmetric key value.
        /// </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "size", 2)]
        [DataMember()]
        public SensitiveCreate sensitive { get; set; }
        public Tpm2bSensitiveCreate()
        {
            sensitive = new SensitiveCreate();
        }
        public Tpm2bSensitiveCreate(Tpm2bSensitiveCreate the_Tpm2bSensitiveCreate)
        {
            if((Object) the_Tpm2bSensitiveCreate == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            sensitive = the_Tpm2bSensitiveCreate.sensitive;
        }
        ///<param name = "the_sensitive">data to be sealed or a symmetric key value.</param>
        public Tpm2bSensitiveCreate(
        SensitiveCreate the_sensitive
        )
        {
            this.sensitive = the_sensitive;
        }
        new public Tpm2bSensitiveCreate Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bSensitiveCreate>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is the scheme data for schemes that only require a hash to complete their definition.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMS_SCHEME_HASH")]
    public partial class SchemeHash: TpmStructureBase, ISchemeKeyedhashUnion, ISigSchemeUnion, IKdfSchemeUnion, IAsymSchemeUnion, ISignatureUnion
    {
        /// <summary>
        /// the hash algorithm used to digest the message
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }
        public SchemeHash()
        {
            hashAlg = TpmAlgId.Null;
        }
        public SchemeHash(SchemeHash the_SchemeHash)
        {
            if((Object) the_SchemeHash == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            hashAlg = the_SchemeHash.hashAlg;
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SchemeHash(
        TpmAlgId the_hashAlg
        )
        {
            this.hashAlg = the_hashAlg;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Hmac;
        }
        new public SchemeHash Copy()
        {
            return Marshaller.FromTpmRepresentation<SchemeHash>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This definition is for split signing schemes that require a commit count.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMS_SCHEME_ECDAA")]
    public partial class SchemeEcdaa: TpmStructureBase, ISigSchemeUnion, IAsymSchemeUnion
    {
        /// <summary>
        /// the hash algorithm used to digest the message
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }
        /// <summary>
        /// the counter value that is used between TPM2_Commit() and the sign operation
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ushort count { get; set; }
        public SchemeEcdaa()
        {
            hashAlg = TpmAlgId.Null;
            count = 0;
        }
        public SchemeEcdaa(SchemeEcdaa the_SchemeEcdaa)
        {
            if((Object) the_SchemeEcdaa == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            hashAlg = the_SchemeEcdaa.hashAlg;
            count = the_SchemeEcdaa.count;
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        ///<param name = "the_count">the counter value that is used between TPM2_Commit() and the sign operation</param>
        public SchemeEcdaa(
        TpmAlgId the_hashAlg,
        ushort the_count
        )
        {
            this.hashAlg = the_hashAlg;
            this.count = the_count;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Ecdaa;
        }
        new public SchemeEcdaa Copy()
        {
            return Marshaller.FromTpmRepresentation<SchemeEcdaa>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Table 143  Definition of Types for HMAC_SIG_SCHEME
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_HMAC")]
    public partial class SchemeHmac: SchemeHash
    {
        public SchemeHmac()
        {
        }
        public SchemeHmac(SchemeHmac the_SchemeHmac)
        : base(the_SchemeHmac)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SchemeHmac(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Hmac;
        }
    }
    /// <summary>
    /// This structure is for the XOR encryption scheme.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMS_SCHEME_XOR")]
    public partial class SchemeXor: TpmStructureBase, ISchemeKeyedhashUnion
    {
        /// <summary>
        /// the hash algorithm used to digest the message
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }
        /// <summary>
        /// the key derivation function
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmAlgId kdf { get; set; }
        public SchemeXor()
        {
            hashAlg = TpmAlgId.Null;
            kdf = TpmAlgId.Null;
        }
        public SchemeXor(SchemeXor the_SchemeXor)
        {
            if((Object) the_SchemeXor == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            hashAlg = the_SchemeXor.hashAlg;
            kdf = the_SchemeXor.kdf;
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        ///<param name = "the_kdf">the key derivation function</param>
        public SchemeXor(
        TpmAlgId the_hashAlg,
        TpmAlgId the_kdf
        )
        {
            this.hashAlg = the_hashAlg;
            this.kdf = the_kdf;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Xor;
        }
        new public SchemeXor Copy()
        {
            return Marshaller.FromTpmRepresentation<SchemeXor>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_NULL for the union TpmuSchemeKeyedhash
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_NULL_SCHEME_KEYEDHASH")]
    public partial class NullSchemeKeyedhash: NullUnion
    {
        public NullSchemeKeyedhash()
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Null;
        }
    }
    /// <summary>
    /// This structure is used for a hash signing object.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SchemeXor))]
    [KnownType(typeof(NullSchemeKeyedhash))]
    [SpecTypeName("TPMT_KEYEDHASH_SCHEME")]
    public partial class KeyedhashScheme: TpmStructureBase
    {
        /// <summary>
        /// selects the scheme
        /// </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId scheme {
            get {
                if(details != null) {
                    return (TpmAlgId)details.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// the scheme parameters
        /// (One of [SchemeHmac, SchemeXor, NullSchemeKeyedhash])
        /// </summary>
        [MarshalAs(1, MarshalType.Union, "scheme")]
        [DataMember()]
        public ISchemeKeyedhashUnion details { get; set; }
        public KeyedhashScheme()
        {
        }
        public KeyedhashScheme(KeyedhashScheme the_KeyedhashScheme)
        {
            if((Object) the_KeyedhashScheme == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
        }
        ///<param name = "the_details">the scheme parameters(One of SchemeHmac, SchemeXor, NullSchemeKeyedhash)</param>
        public KeyedhashScheme(
        ISchemeKeyedhashUnion the_details
        )
        {
            this.details = the_details;
        }
        new public KeyedhashScheme Copy()
        {
            return Marshaller.FromTpmRepresentation<KeyedhashScheme>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// These are the RSA schemes that only need a hash algorithm as a scheme parameter.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIG_SCHEME_RSASSA")]
    public partial class SigSchemeRsassa: SchemeHash
    {
        public SigSchemeRsassa()
        {
        }
        public SigSchemeRsassa(SigSchemeRsassa the_SigSchemeRsassa)
        : base(the_SigSchemeRsassa)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SigSchemeRsassa(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Rsassa;
        }
    }
    /// <summary>
    /// These are the RSA schemes that only need a hash algorithm as a scheme parameter.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIG_SCHEME_RSAPSS")]
    public partial class SigSchemeRsapss: SchemeHash
    {
        public SigSchemeRsapss()
        {
        }
        public SigSchemeRsapss(SigSchemeRsapss the_SigSchemeRsapss)
        : base(the_SigSchemeRsapss)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SigSchemeRsapss(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Rsapss;
        }
    }
    /// <summary>
    /// Most of the ECC signature schemes only require a hash algorithm to complete the definition and can be typed as TPMS_SCHEME_HASH. Anonymous algorithms also require a count value so they are typed to be TPMS_SCHEME_ECDAA.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIG_SCHEME_ECDSA")]
    public partial class SigSchemeEcdsa: SchemeHash
    {
        public SigSchemeEcdsa()
        {
        }
        public SigSchemeEcdsa(SigSchemeEcdsa the_SigSchemeEcdsa)
        : base(the_SigSchemeEcdsa)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SigSchemeEcdsa(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Ecdsa;
        }
    }
    /// <summary>
    /// Most of the ECC signature schemes only require a hash algorithm to complete the definition and can be typed as TPMS_SCHEME_HASH. Anonymous algorithms also require a count value so they are typed to be TPMS_SCHEME_ECDAA.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIG_SCHEME_SM2")]
    public partial class SigSchemeSm2: SchemeHash
    {
        public SigSchemeSm2()
        {
        }
        public SigSchemeSm2(SigSchemeSm2 the_SigSchemeSm2)
        : base(the_SigSchemeSm2)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SigSchemeSm2(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Sm2;
        }
    }
    /// <summary>
    /// Most of the ECC signature schemes only require a hash algorithm to complete the definition and can be typed as TPMS_SCHEME_HASH. Anonymous algorithms also require a count value so they are typed to be TPMS_SCHEME_ECDAA.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIG_SCHEME_ECSCHNORR")]
    public partial class SigSchemeEcschnorr: SchemeHash
    {
        public SigSchemeEcschnorr()
        {
        }
        public SigSchemeEcschnorr(SigSchemeEcschnorr the_SigSchemeEcschnorr)
        : base(the_SigSchemeEcschnorr)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SigSchemeEcschnorr(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Ecschnorr;
        }
    }
    /// <summary>
    /// Most of the ECC signature schemes only require a hash algorithm to complete the definition and can be typed as TPMS_SCHEME_HASH. Anonymous algorithms also require a count value so they are typed to be TPMS_SCHEME_ECDAA.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIG_SCHEME_ECDAA")]
    public partial class SigSchemeEcdaa: SchemeEcdaa
    {
        public SigSchemeEcdaa()
        {
        }
        public SigSchemeEcdaa(SigSchemeEcdaa the_SigSchemeEcdaa)
        : base(the_SigSchemeEcdaa)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        ///<param name = "the_count">the counter value that is used between TPM2_Commit() and the sign operation</param>
        public SigSchemeEcdaa(
        TpmAlgId the_hashAlg,
        ushort the_count
        )
        : base(the_hashAlg, the_count)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Ecdaa;
        }
    }
    /// <summary>
    /// Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_NULL for the union TpmuSigScheme
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_NULL_SIG_SCHEME")]
    public partial class NullSigScheme: NullUnion
    {
        public NullSigScheme()
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Null;
        }
    }
    /// <summary>
    /// Table 150  Definition of TPMT_SIG_SCHEME Structure
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(NullSigScheme))]
    [SpecTypeName("TPMT_SIG_SCHEME")]
    public partial class SigScheme: TpmStructureBase
    {
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId scheme {
            get {
                if(details != null) {
                    return (TpmAlgId)details.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// scheme parameters
        /// (One of [SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme])
        /// </summary>
        [MarshalAs(1, MarshalType.Union, "scheme")]
        [DataMember()]
        public ISigSchemeUnion details { get; set; }
        public SigScheme()
        {
        }
        public SigScheme(SigScheme the_SigScheme)
        {
            if((Object) the_SigScheme == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
        }
        ///<param name = "the_details">scheme parameters(One of SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme)</param>
        public SigScheme(
        ISigSchemeUnion the_details
        )
        {
            this.details = the_details;
        }
        new public SigScheme Copy()
        {
            return Marshaller.FromTpmRepresentation<SigScheme>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// These are the RSA encryption schemes that only need a hash algorithm as a controlling parameter.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_ENC_SCHEME_OAEP")]
    public partial class EncSchemeOaep: SchemeHash
    {
        public EncSchemeOaep()
        {
        }
        public EncSchemeOaep(EncSchemeOaep the_EncSchemeOaep)
        : base(the_EncSchemeOaep)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public EncSchemeOaep(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Oaep;
        }
    }
    /// <summary>
    /// These are the RSA encryption schemes that only need a hash algorithm as a controlling parameter.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_ENC_SCHEME_RSAES")]
    public partial class EncSchemeRsaes: Empty
    {
        public EncSchemeRsaes()
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Rsaes;
        }
    }
    /// <summary>
    /// These are the ECC schemes that only need a hash algorithm as a controlling parameter.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_KEY_SCHEME_ECDH")]
    public partial class KeySchemeEcdh: SchemeHash
    {
        public KeySchemeEcdh()
        {
        }
        public KeySchemeEcdh(KeySchemeEcdh the_KeySchemeEcdh)
        : base(the_KeySchemeEcdh)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public KeySchemeEcdh(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Ecdh;
        }
    }
    /// <summary>
    /// These are the ECC schemes that only need a hash algorithm as a controlling parameter.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_KEY_SCHEME_ECMQV")]
    public partial class KeySchemeEcmqv: SchemeHash
    {
        public KeySchemeEcmqv()
        {
        }
        public KeySchemeEcmqv(KeySchemeEcmqv the_KeySchemeEcmqv)
        : base(the_KeySchemeEcmqv)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public KeySchemeEcmqv(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Ecmqv;
        }
    }
    /// <summary>
    /// These structures are used to define the key derivation for symmetric secret sharing using asymmetric methods. A secret sharing scheme is required in any asymmetric key with the decrypt attribute SET.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_MGF1")]
    public partial class SchemeMgf1: SchemeHash
    {
        public SchemeMgf1()
        {
        }
        public SchemeMgf1(SchemeMgf1 the_SchemeMgf1)
        : base(the_SchemeMgf1)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SchemeMgf1(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Mgf1;
        }
    }
    /// <summary>
    /// These structures are used to define the key derivation for symmetric secret sharing using asymmetric methods. A secret sharing scheme is required in any asymmetric key with the decrypt attribute SET.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_KDF1_SP800_56A")]
    public partial class SchemeKdf1Sp80056a: SchemeHash
    {
        public SchemeKdf1Sp80056a()
        {
        }
        public SchemeKdf1Sp80056a(SchemeKdf1Sp80056a the_SchemeKdf1Sp80056a)
        : base(the_SchemeKdf1Sp80056a)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SchemeKdf1Sp80056a(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Kdf1Sp80056a;
        }
    }
    /// <summary>
    /// These structures are used to define the key derivation for symmetric secret sharing using asymmetric methods. A secret sharing scheme is required in any asymmetric key with the decrypt attribute SET.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_KDF2")]
    public partial class SchemeKdf2: SchemeHash
    {
        public SchemeKdf2()
        {
        }
        public SchemeKdf2(SchemeKdf2 the_SchemeKdf2)
        : base(the_SchemeKdf2)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SchemeKdf2(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Kdf2;
        }
    }
    /// <summary>
    /// These structures are used to define the key derivation for symmetric secret sharing using asymmetric methods. A secret sharing scheme is required in any asymmetric key with the decrypt attribute SET.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_KDF1_SP800_108")]
    public partial class SchemeKdf1Sp800108: SchemeHash
    {
        public SchemeKdf1Sp800108()
        {
        }
        public SchemeKdf1Sp800108(SchemeKdf1Sp800108 the_SchemeKdf1Sp800108)
        : base(the_SchemeKdf1Sp800108)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SchemeKdf1Sp800108(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Kdf1Sp800108;
        }
    }
    /// <summary>
    /// Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_NULL for the union TpmuKdfScheme
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_NULL_KDF_SCHEME")]
    public partial class NullKdfScheme: NullUnion
    {
        public NullKdfScheme()
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Null;
        }
    }
    /// <summary>
    /// Table 155  Definition of TPMT_KDF_SCHEME Structure
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeMgf1))]
    [KnownType(typeof(SchemeKdf1Sp80056a))]
    [KnownType(typeof(SchemeKdf2))]
    [KnownType(typeof(SchemeKdf1Sp800108))]
    [KnownType(typeof(NullKdfScheme))]
    [SpecTypeName("TPMT_KDF_SCHEME")]
    public partial class KdfScheme: TpmStructureBase
    {
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId scheme {
            get {
                if(details != null) {
                    return (TpmAlgId)details.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// scheme parameters
        /// (One of [SchemeMgf1, SchemeKdf1Sp80056a, SchemeKdf2, SchemeKdf1Sp800108, NullKdfScheme])
        /// </summary>
        [MarshalAs(1, MarshalType.Union, "scheme")]
        [DataMember()]
        public IKdfSchemeUnion details { get; set; }
        public KdfScheme()
        {
        }
        public KdfScheme(KdfScheme the_KdfScheme)
        {
            if((Object) the_KdfScheme == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
        }
        ///<param name = "the_details">scheme parameters(One of SchemeMgf1, SchemeKdf1Sp80056a, SchemeKdf2, SchemeKdf1Sp800108, NullKdfScheme)</param>
        public KdfScheme(
        IKdfSchemeUnion the_details
        )
        {
            this.details = the_details;
        }
        new public KdfScheme Copy()
        {
            return Marshaller.FromTpmRepresentation<KdfScheme>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_NULL for the union TpmuAsymScheme
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_NULL_ASYM_SCHEME")]
    public partial class NullAsymScheme: NullUnion
    {
        public NullAsymScheme()
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Null;
        }
    }
    /// <summary>
    /// This structure is defined to allow overlay of all of the schemes for any asymmetric object. This structure is not sent on the interface. It is defined so that common functions may operate on any similar scheme structure.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(Empty))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [SpecTypeName("TPMT_ASYM_SCHEME")]
    public partial class AsymScheme: TpmStructureBase
    {
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId scheme {
            get {
                if(details != null) {
                    return (TpmAlgId)details.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// scheme parameters
        /// (One of [KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme])
        /// </summary>
        [MarshalAs(1, MarshalType.Union, "scheme")]
        [DataMember()]
        public IAsymSchemeUnion details { get; set; }
        public AsymScheme()
        {
        }
        public AsymScheme(AsymScheme the_AsymScheme)
        {
            if((Object) the_AsymScheme == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
        }
        ///<param name = "the_details">scheme parameters(One of KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme)</param>
        public AsymScheme(
        IAsymSchemeUnion the_details
        )
        {
            this.details = the_details;
        }
        new public AsymScheme Copy()
        {
            return Marshaller.FromTpmRepresentation<AsymScheme>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Table 160  Definition of {RSA} TPMT_RSA_SCHEME Structure
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(Empty))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [SpecTypeName("TPMT_RSA_SCHEME")]
    public partial class RsaScheme: TpmStructureBase
    {
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId scheme {
            get {
                if(details != null) {
                    return (TpmAlgId)details.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// scheme parameters
        /// (One of [KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme])
        /// </summary>
        [MarshalAs(1, MarshalType.Union, "scheme")]
        [DataMember()]
        public IAsymSchemeUnion details { get; set; }
        public RsaScheme()
        {
        }
        public RsaScheme(RsaScheme the_RsaScheme)
        {
            if((Object) the_RsaScheme == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
        }
        ///<param name = "the_details">scheme parameters(One of KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme)</param>
        public RsaScheme(
        IAsymSchemeUnion the_details
        )
        {
            this.details = the_details;
        }
        new public RsaScheme Copy()
        {
            return Marshaller.FromTpmRepresentation<RsaScheme>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Table 162  Definition of {RSA} TPMT_RSA_DECRYPT Structure
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(Empty))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [SpecTypeName("TPMT_RSA_DECRYPT")]
    public partial class RsaDecrypt: TpmStructureBase
    {
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId scheme {
            get {
                if(details != null) {
                    return (TpmAlgId)details.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// scheme parameters
        /// (One of [KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme])
        /// </summary>
        [MarshalAs(1, MarshalType.Union, "scheme")]
        [DataMember()]
        public IAsymSchemeUnion details { get; set; }
        public RsaDecrypt()
        {
        }
        public RsaDecrypt(RsaDecrypt the_RsaDecrypt)
        {
            if((Object) the_RsaDecrypt == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
        }
        ///<param name = "the_details">scheme parameters(One of KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme)</param>
        public RsaDecrypt(
        IAsymSchemeUnion the_details
        )
        {
            this.details = the_details;
        }
        new public RsaDecrypt Copy()
        {
            return Marshaller.FromTpmRepresentation<RsaDecrypt>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This sized buffer holds the largest RSA public key supported by the TPM.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_PUBLIC_KEY_RSA")]
    public partial class Tpm2bPublicKeyRsa: TpmStructureBase, IPublicIdUnion
    {
        /// <summary>
        /// Value
        /// </summary>
        [Range(MaxVal = 256u /*MAX_RSA_KEY_BYTES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bPublicKeyRsa()
        {
            buffer = null;
        }
        public Tpm2bPublicKeyRsa(Tpm2bPublicKeyRsa the_Tpm2bPublicKeyRsa)
        {
            if((Object) the_Tpm2bPublicKeyRsa == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bPublicKeyRsa.buffer;
        }
        ///<param name = "the_buffer">Value</param>
        public Tpm2bPublicKeyRsa(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Rsa;
        }
        new public Tpm2bPublicKeyRsa Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bPublicKeyRsa>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This sized buffer holds the largest RSA prime number supported by the TPM.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_PRIVATE_KEY_RSA")]
    public partial class Tpm2bPrivateKeyRsa: TpmStructureBase, ISensitiveCompositeUnion
    {
        [Range(MaxVal = 128u /*MAX_RSA_KEY_BYTES/2*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bPrivateKeyRsa()
        {
            buffer = null;
        }
        public Tpm2bPrivateKeyRsa(Tpm2bPrivateKeyRsa the_Tpm2bPrivateKeyRsa)
        {
            if((Object) the_Tpm2bPrivateKeyRsa == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bPrivateKeyRsa.buffer;
        }
        ///<param name = "the_buffer"></param>
        public Tpm2bPrivateKeyRsa(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Rsa;
        }
        new public Tpm2bPrivateKeyRsa Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bPrivateKeyRsa>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This sized buffer holds the largest ECC parameter (coordinate) supported by the TPM.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_ECC_PARAMETER")]
    public partial class Tpm2bEccParameter: TpmStructureBase, ISensitiveCompositeUnion
    {
        /// <summary>
        /// the parameter data
        /// </summary>
        [Range(MaxVal = 48u /*MAX_ECC_KEY_BYTES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bEccParameter()
        {
            buffer = null;
        }
        public Tpm2bEccParameter(Tpm2bEccParameter the_Tpm2bEccParameter)
        {
            if((Object) the_Tpm2bEccParameter == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bEccParameter.buffer;
        }
        ///<param name = "the_buffer">the parameter data</param>
        public Tpm2bEccParameter(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Ecc;
        }
        new public Tpm2bEccParameter Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bEccParameter>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure holds two ECC coordinates that, together, make up an ECC point.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_ECC_POINT")]
    public partial class EccPoint: TpmStructureBase, IPublicIdUnion
    {
        /// <summary>
        /// X coordinate
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "xSize", 2)]
        [DataMember()]
        public byte[] x;
        /// <summary>
        /// Y coordinate
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "ySize", 2)]
        [DataMember()]
        public byte[] y;
        public EccPoint()
        {
            x = null;
            y = null;
        }
        public EccPoint(EccPoint the_EccPoint)
        {
            if((Object) the_EccPoint == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            x = the_EccPoint.x;
            y = the_EccPoint.y;
        }
        ///<param name = "the_x">X coordinate</param>
        ///<param name = "the_y">Y coordinate</param>
        public EccPoint(
        byte[] the_x,
        byte[] the_y
        )
        {
            this.x = the_x;
            this.y = the_y;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Ecc;
        }
        new public EccPoint Copy()
        {
            return Marshaller.FromTpmRepresentation<EccPoint>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is defined to allow a point to be a single sized parameter so that it may be encrypted.
    /// </summary>
    [DataContract]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("TPM2B_ECC_POINT")]
    public partial class Tpm2bEccPoint: TpmStructureBase
    {
        /// <summary>
        /// coordinates
        /// </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "size", 2)]
        [DataMember()]
        public EccPoint point { get; set; }
        public Tpm2bEccPoint()
        {
            point = new EccPoint();
        }
        public Tpm2bEccPoint(Tpm2bEccPoint the_Tpm2bEccPoint)
        {
            if((Object) the_Tpm2bEccPoint == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            point = the_Tpm2bEccPoint.point;
        }
        ///<param name = "the_point">coordinates</param>
        public Tpm2bEccPoint(
        EccPoint the_point
        )
        {
            this.point = the_point;
        }
        new public Tpm2bEccPoint Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bEccPoint>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Table 171  Definition of (TPMT_SIG_SCHEME) {ECC} TPMT_ECC_SCHEME Structure
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(Empty))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [SpecTypeName("TPMT_ECC_SCHEME")]
    public partial class EccScheme: TpmStructureBase
    {
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId scheme {
            get {
                if(details != null) {
                    return (TpmAlgId)details.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// scheme parameters
        /// (One of [KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme])
        /// </summary>
        [MarshalAs(1, MarshalType.Union, "scheme")]
        [DataMember()]
        public IAsymSchemeUnion details { get; set; }
        public EccScheme()
        {
        }
        public EccScheme(EccScheme the_EccScheme)
        {
            if((Object) the_EccScheme == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
        }
        ///<param name = "the_details">scheme parameters(One of KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme)</param>
        public EccScheme(
        IAsymSchemeUnion the_details
        )
        {
            this.details = the_details;
        }
        new public EccScheme Copy()
        {
            return Marshaller.FromTpmRepresentation<EccScheme>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used to report on the curve parameters of an ECC curve. It is returned by TPM2_ECC_Parameters().
    /// </summary>
    [DataContract]
    [KnownType(typeof(EccCurve))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeMgf1))]
    [KnownType(typeof(SchemeKdf1Sp80056a))]
    [KnownType(typeof(SchemeKdf2))]
    [KnownType(typeof(SchemeKdf1Sp800108))]
    [KnownType(typeof(NullKdfScheme))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(Empty))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [SpecTypeName("TPMS_ALGORITHM_DETAIL_ECC")]
    public partial class AlgorithmDetailEcc: TpmStructureBase
    {
        /// <summary>
        /// identifier for the curve
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public EccCurve curveID { get; set; }
        /// <summary>
        /// Size in bits of the key
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ushort keySize { get; set; }
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(2, MarshalType.UnionSelector)]
        public TpmAlgId kdfScheme {
            get {
                if(kdf != null) {
                    return (TpmAlgId)kdf.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// if not TPM_ALG_NULL, the required KDF and hash algorithm used in secret sharing operations
        /// (One of [SchemeMgf1, SchemeKdf1Sp80056a, SchemeKdf2, SchemeKdf1Sp800108, NullKdfScheme])
        /// </summary>
        [MarshalAs(3, MarshalType.Union, "kdfScheme")]
        [DataMember()]
        public IKdfSchemeUnion kdf { get; set; }
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(4, MarshalType.UnionSelector)]
        public TpmAlgId signScheme {
            get {
                if(sign != null) {
                    return (TpmAlgId)sign.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// If not TPM_ALG_NULL, this is the mandatory signature scheme that is required to be used with this curve.
        /// (One of [KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme])
        /// </summary>
        [MarshalAs(5, MarshalType.Union, "signScheme")]
        [DataMember()]
        public IAsymSchemeUnion sign { get; set; }
        /// <summary>
        /// Fp (the modulus)
        /// </summary>
        [MarshalAs(6, MarshalType.VariableLengthArray, "pSize", 2)]
        [DataMember()]
        public byte[] p;
        /// <summary>
        /// coefficient of the linear term in the curve equation
        /// </summary>
        [MarshalAs(7, MarshalType.VariableLengthArray, "aSize", 2)]
        [DataMember()]
        public byte[] a;
        /// <summary>
        /// constant term for curve equation
        /// </summary>
        [MarshalAs(8, MarshalType.VariableLengthArray, "bSize", 2)]
        [DataMember()]
        public byte[] b;
        /// <summary>
        /// x coordinate of base point G
        /// </summary>
        [MarshalAs(9, MarshalType.VariableLengthArray, "gXSize", 2)]
        [DataMember()]
        public byte[] gX;
        /// <summary>
        /// y coordinate of base point G
        /// </summary>
        [MarshalAs(10, MarshalType.VariableLengthArray, "gYSize", 2)]
        [DataMember()]
        public byte[] gY;
        /// <summary>
        /// order of G
        /// </summary>
        [MarshalAs(11, MarshalType.VariableLengthArray, "nSize", 2)]
        [DataMember()]
        public byte[] n;
        /// <summary>
        /// cofactor (a size of zero indicates a cofactor of 1)
        /// </summary>
        [MarshalAs(12, MarshalType.VariableLengthArray, "hSize", 2)]
        [DataMember()]
        public byte[] h;
        public AlgorithmDetailEcc()
        {
            curveID = new EccCurve();
            keySize = 0;
            p = null;
            a = null;
            b = null;
            gX = null;
            gY = null;
            n = null;
            h = null;
        }
        public AlgorithmDetailEcc(AlgorithmDetailEcc the_AlgorithmDetailEcc)
        {
            if((Object) the_AlgorithmDetailEcc == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            curveID = the_AlgorithmDetailEcc.curveID;
            keySize = the_AlgorithmDetailEcc.keySize;
            p = the_AlgorithmDetailEcc.p;
            a = the_AlgorithmDetailEcc.a;
            b = the_AlgorithmDetailEcc.b;
            gX = the_AlgorithmDetailEcc.gX;
            gY = the_AlgorithmDetailEcc.gY;
            n = the_AlgorithmDetailEcc.n;
            h = the_AlgorithmDetailEcc.h;
        }
        ///<param name = "the_curveID">identifier for the curve</param>
        ///<param name = "the_keySize">Size in bits of the key</param>
        ///<param name = "the_kdf">if not TPM_ALG_NULL, the required KDF and hash algorithm used in secret sharing operations(One of SchemeMgf1, SchemeKdf1Sp80056a, SchemeKdf2, SchemeKdf1Sp800108, NullKdfScheme)</param>
        ///<param name = "the_sign">If not TPM_ALG_NULL, this is the mandatory signature scheme that is required to be used with this curve.(One of KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme)</param>
        ///<param name = "the_p">Fp (the modulus)</param>
        ///<param name = "the_a">coefficient of the linear term in the curve equation</param>
        ///<param name = "the_b">constant term for curve equation</param>
        ///<param name = "the_gX">x coordinate of base point G</param>
        ///<param name = "the_gY">y coordinate of base point G</param>
        ///<param name = "the_n">order of G</param>
        ///<param name = "the_h">cofactor (a size of zero indicates a cofactor of 1)</param>
        public AlgorithmDetailEcc(
        EccCurve the_curveID,
        ushort the_keySize,
        IKdfSchemeUnion the_kdf,
        IAsymSchemeUnion the_sign,
        byte[] the_p,
        byte[] the_a,
        byte[] the_b,
        byte[] the_gX,
        byte[] the_gY,
        byte[] the_n,
        byte[] the_h
        )
        {
            this.curveID = the_curveID;
            this.keySize = the_keySize;
            this.kdf = the_kdf;
            this.sign = the_sign;
            this.p = the_p;
            this.a = the_a;
            this.b = the_b;
            this.gX = the_gX;
            this.gY = the_gY;
            this.n = the_n;
            this.h = the_h;
        }
        new public AlgorithmDetailEcc Copy()
        {
            return Marshaller.FromTpmRepresentation<AlgorithmDetailEcc>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Table 173  Definition of {RSA} TPMS_SIGNATURE_RSA Structure
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMS_SIGNATURE_RSA")]
    public partial class SignatureRsa: TpmStructureBase, ISignatureUnion
    {
        /// <summary>
        /// the hash algorithm used to digest the message
        /// TPM_ALG_NULL is not allowed.
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId hash { get; set; }
        /// <summary>
        /// The signature is the size of a public key.
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "sigSize", 2)]
        [DataMember()]
        public byte[] sig;
        public SignatureRsa()
        {
            hash = TpmAlgId.Null;
            sig = null;
        }
        public SignatureRsa(SignatureRsa the_SignatureRsa)
        {
            if((Object) the_SignatureRsa == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            hash = the_SignatureRsa.hash;
            sig = the_SignatureRsa.sig;
        }
        ///<param name = "the_hash">the hash algorithm used to digest the message TPM_ALG_NULL is not allowed.</param>
        ///<param name = "the_sig">The signature is the size of a public key.</param>
        public SignatureRsa(
        TpmAlgId the_hash,
        byte[] the_sig
        )
        {
            this.hash = the_hash;
            this.sig = the_sig;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Rsassa;
        }
        new public SignatureRsa Copy()
        {
            return Marshaller.FromTpmRepresentation<SignatureRsa>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Table 173  Definition of {RSA} TPMS_SIGNATURE_RSA Structure
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIGNATURE_RSASSA")]
    public partial class SignatureRsassa: SignatureRsa
    {
        public SignatureRsassa()
        {
        }
        public SignatureRsassa(SignatureRsassa the_SignatureRsassa)
        : base(the_SignatureRsassa)
        {
        }
        ///<param name = "the_hash">the hash algorithm used to digest the message TPM_ALG_NULL is not allowed.</param>
        ///<param name = "the_sig">The signature is the size of a public key.</param>
        public SignatureRsassa(
        TpmAlgId the_hash,
        byte[] the_sig
        )
        : base(the_hash, the_sig)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Rsassa;
        }
    }
    /// <summary>
    /// Table 173  Definition of {RSA} TPMS_SIGNATURE_RSA Structure
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIGNATURE_RSAPSS")]
    public partial class SignatureRsapss: SignatureRsa
    {
        public SignatureRsapss()
        {
        }
        public SignatureRsapss(SignatureRsapss the_SignatureRsapss)
        : base(the_SignatureRsapss)
        {
        }
        ///<param name = "the_hash">the hash algorithm used to digest the message TPM_ALG_NULL is not allowed.</param>
        ///<param name = "the_sig">The signature is the size of a public key.</param>
        public SignatureRsapss(
        TpmAlgId the_hash,
        byte[] the_sig
        )
        : base(the_hash, the_sig)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Rsapss;
        }
    }
    /// <summary>
    /// Table 175  Definition of {ECC} TPMS_SIGNATURE_ECC Structure
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMS_SIGNATURE_ECC")]
    public partial class SignatureEcc: TpmStructureBase, ISignatureUnion
    {
        /// <summary>
        /// the hash algorithm used in the signature process
        /// TPM_ALG_NULL is not allowed.
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId hash { get; set; }
        [MarshalAs(1, MarshalType.VariableLengthArray, "signatureRSize", 2)]
        [DataMember()]
        public byte[] signatureR;
        [MarshalAs(2, MarshalType.VariableLengthArray, "signatureSSize", 2)]
        [DataMember()]
        public byte[] signatureS;
        public SignatureEcc()
        {
            hash = TpmAlgId.Null;
            signatureR = null;
            signatureS = null;
        }
        public SignatureEcc(SignatureEcc the_SignatureEcc)
        {
            if((Object) the_SignatureEcc == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            hash = the_SignatureEcc.hash;
            signatureR = the_SignatureEcc.signatureR;
            signatureS = the_SignatureEcc.signatureS;
        }
        ///<param name = "the_hash">the hash algorithm used in the signature process TPM_ALG_NULL is not allowed.</param>
        ///<param name = "the_signatureR"></param>
        ///<param name = "the_signatureS"></param>
        public SignatureEcc(
        TpmAlgId the_hash,
        byte[] the_signatureR,
        byte[] the_signatureS
        )
        {
            this.hash = the_hash;
            this.signatureR = the_signatureR;
            this.signatureS = the_signatureS;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Ecdsa;
        }
        new public SignatureEcc Copy()
        {
            return Marshaller.FromTpmRepresentation<SignatureEcc>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Table 175  Definition of {ECC} TPMS_SIGNATURE_ECC Structure
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIGNATURE_ECDSA")]
    public partial class SignatureEcdsa: SignatureEcc
    {
        public SignatureEcdsa()
        {
        }
        public SignatureEcdsa(SignatureEcdsa the_SignatureEcdsa)
        : base(the_SignatureEcdsa)
        {
        }
        ///<param name = "the_hash">the hash algorithm used in the signature process TPM_ALG_NULL is not allowed.</param>
        ///<param name = "the_signatureR"></param>
        ///<param name = "the_signatureS"></param>
        public SignatureEcdsa(
        TpmAlgId the_hash,
        byte[] the_signatureR,
        byte[] the_signatureS
        )
        : base(the_hash, the_signatureR, the_signatureS)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Ecdsa;
        }
    }
    /// <summary>
    /// Table 175  Definition of {ECC} TPMS_SIGNATURE_ECC Structure
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIGNATURE_ECDAA")]
    public partial class SignatureEcdaa: SignatureEcc
    {
        public SignatureEcdaa()
        {
        }
        public SignatureEcdaa(SignatureEcdaa the_SignatureEcdaa)
        : base(the_SignatureEcdaa)
        {
        }
        ///<param name = "the_hash">the hash algorithm used in the signature process TPM_ALG_NULL is not allowed.</param>
        ///<param name = "the_signatureR"></param>
        ///<param name = "the_signatureS"></param>
        public SignatureEcdaa(
        TpmAlgId the_hash,
        byte[] the_signatureR,
        byte[] the_signatureS
        )
        : base(the_hash, the_signatureR, the_signatureS)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Ecdaa;
        }
    }
    /// <summary>
    /// Table 175  Definition of {ECC} TPMS_SIGNATURE_ECC Structure
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIGNATURE_SM2")]
    public partial class SignatureSm2: SignatureEcc
    {
        public SignatureSm2()
        {
        }
        public SignatureSm2(SignatureSm2 the_SignatureSm2)
        : base(the_SignatureSm2)
        {
        }
        ///<param name = "the_hash">the hash algorithm used in the signature process TPM_ALG_NULL is not allowed.</param>
        ///<param name = "the_signatureR"></param>
        ///<param name = "the_signatureS"></param>
        public SignatureSm2(
        TpmAlgId the_hash,
        byte[] the_signatureR,
        byte[] the_signatureS
        )
        : base(the_hash, the_signatureR, the_signatureS)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Sm2;
        }
    }
    /// <summary>
    /// Table 175  Definition of {ECC} TPMS_SIGNATURE_ECC Structure
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIGNATURE_ECSCHNORR")]
    public partial class SignatureEcschnorr: SignatureEcc
    {
        public SignatureEcschnorr()
        {
        }
        public SignatureEcschnorr(SignatureEcschnorr the_SignatureEcschnorr)
        : base(the_SignatureEcschnorr)
        {
        }
        ///<param name = "the_hash">the hash algorithm used in the signature process TPM_ALG_NULL is not allowed.</param>
        ///<param name = "the_signatureR"></param>
        ///<param name = "the_signatureS"></param>
        public SignatureEcschnorr(
        TpmAlgId the_hash,
        byte[] the_signatureR,
        byte[] the_signatureS
        )
        : base(the_hash, the_signatureR, the_signatureS)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Ecschnorr;
        }
    }
    /// <summary>
    /// Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_NULL for the union TpmuSignature
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_NULL_SIGNATURE")]
    public partial class NullSignature: NullUnion
    {
        public NullSignature()
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Null;
        }
    }
    /// <summary>
    /// Table 178 shows the basic algorithm-agile structure when a symmetric or asymmetric signature is indicated. The sigAlg parameter indicates the algorithm used for the signature. This structure is output from the attestation commands and is an input to TPM2_VerifySignature(), TPM2_PolicySigned(), and TPM2_FieldUpgradeStart().
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureRsa))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureEcc))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(NullSignature))]
    [SpecTypeName("TPMT_SIGNATURE")]
    public partial class Signature: TpmStructureBase
    {
        /// <summary>
        /// selector of the algorithm used to construct the signature
        /// </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId sigAlg {
            get {
                if(signature != null) {
                    return (TpmAlgId)signature.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// This shall be the actual signature information.
        /// (One of [SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature])
        /// </summary>
        [MarshalAs(1, MarshalType.Union, "sigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }
        public Signature()
        {
        }
        public Signature(Signature the_Signature)
        {
            if((Object) the_Signature == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
        }
        ///<param name = "the_signature">This shall be the actual signature information.(One of SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature)</param>
        public Signature(
        ISignatureUnion the_signature
        )
        {
            this.signature = the_signature;
        }
        new public Signature Copy()
        {
            return Marshaller.FromTpmRepresentation<Signature>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Table 180  Definition of TPM2B_ENCRYPTED_SECRET Structure
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_ENCRYPTED_SECRET")]
    public partial class Tpm2bEncryptedSecret: TpmStructureBase
    {
        /// <summary>
        /// secret
        /// </summary>
        [Range(MaxVal = 256u /*sizeof(TPMU_ENCRYPTED_SECRET)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] secret;
        public Tpm2bEncryptedSecret()
        {
            secret = null;
        }
        public Tpm2bEncryptedSecret(Tpm2bEncryptedSecret the_Tpm2bEncryptedSecret)
        {
            if((Object) the_Tpm2bEncryptedSecret == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            secret = the_Tpm2bEncryptedSecret.secret;
        }
        ///<param name = "the_secret">secret</param>
        public Tpm2bEncryptedSecret(
        byte[] the_secret
        )
        {
            this.secret = the_secret;
        }
        new public Tpm2bEncryptedSecret Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bEncryptedSecret>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure describes the parameters that would appear in the public area of a KEYEDHASH object.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SchemeXor))]
    [KnownType(typeof(NullSchemeKeyedhash))]
    [SpecTypeName("TPMS_KEYEDHASH_PARMS")]
    public partial class KeyedhashParms: TpmStructureBase, IPublicParmsUnion
    {
        /// <summary>
        /// selects the scheme
        /// </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId schemeScheme {
            get {
                if(scheme != null) {
                    return (TpmAlgId)scheme.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// Indicates the signing method used for a keyedHash signing object. This field also determines the size of the data field for a data object created with TPM2_Create() or TPM2_CreatePrimary().
        /// (One of [SchemeHmac, SchemeXor, NullSchemeKeyedhash])
        /// </summary>
        [MarshalAs(1, MarshalType.Union, "schemeScheme")]
        [DataMember()]
        public ISchemeKeyedhashUnion scheme { get; set; }
        public KeyedhashParms()
        {
        }
        public KeyedhashParms(KeyedhashParms the_KeyedhashParms)
        {
            if((Object) the_KeyedhashParms == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
        }
        ///<param name = "the_scheme">Indicates the signing method used for a keyedHash signing object. This field also determines the size of the data field for a data object created with TPM2_Create() or TPM2_CreatePrimary().(One of SchemeHmac, SchemeXor, NullSchemeKeyedhash)</param>
        public KeyedhashParms(
        ISchemeKeyedhashUnion the_scheme
        )
        {
            this.scheme = the_scheme;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Keyedhash;
        }
        new public KeyedhashParms Copy()
        {
            return Marshaller.FromTpmRepresentation<KeyedhashParms>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure contains the common public area parameters for an asymmetric key. The first two parameters of the parameter definition structures of an asymmetric key shall have the same two first components.
    /// </summary>
    [DataContract]
    [KnownType(typeof(SymDefObject))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(Empty))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [SpecTypeName("TPMS_ASYM_PARMS")]
    public partial class AsymParms: TpmStructureBase, IPublicParmsUnion
    {
        /// <summary>
        /// the companion symmetric algorithm for a restricted decryption key and shall be set to a supported symmetric algorithm
        /// This field is optional for keys that are not decryption keys and shall be set to TPM_ALG_NULL if not used.
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public SymDefObject symmetric { get; set; }
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId schemeScheme {
            get {
                if(scheme != null) {
                    return (TpmAlgId)scheme.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// for a key with the sign attribute SET, a valid signing scheme for the key type
        /// for a key with the decrypt attribute SET, a valid key exchange protocol
        /// for a key with sign and decrypt attributes, shall be TPM_ALG_NULL
        /// (One of [KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme])
        /// </summary>
        [MarshalAs(2, MarshalType.Union, "schemeScheme")]
        [DataMember()]
        public IAsymSchemeUnion scheme { get; set; }
        public AsymParms()
        {
            symmetric = new SymDefObject();
        }
        public AsymParms(AsymParms the_AsymParms)
        {
            if((Object) the_AsymParms == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            symmetric = the_AsymParms.symmetric;
        }
        ///<param name = "the_symmetric">the companion symmetric algorithm for a restricted decryption key and shall be set to a supported symmetric algorithm This field is optional for keys that are not decryption keys and shall be set to TPM_ALG_NULL if not used.</param>
        ///<param name = "the_scheme">for a key with the sign attribute SET, a valid signing scheme for the key type for a key with the decrypt attribute SET, a valid key exchange protocol for a key with sign and decrypt attributes, shall be TPM_ALG_NULL(One of KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme)</param>
        public AsymParms(
        SymDefObject the_symmetric,
        IAsymSchemeUnion the_scheme
        )
        {
            this.symmetric = the_symmetric;
            this.scheme = the_scheme;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Any;
        }
        new public AsymParms Copy()
        {
            return Marshaller.FromTpmRepresentation<AsymParms>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// A TPM compatible with this specification and supporting RSA shall support two primes and an exponent of zero. Support for other values is optional. Use of other exponents in duplicated keys is not recommended because the resulting keys would not be interoperable with other TPMs.
    /// </summary>
    [DataContract]
    [KnownType(typeof(SymDefObject))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(Empty))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [SpecTypeName("TPMS_RSA_PARMS")]
    public partial class RsaParms: TpmStructureBase, IPublicParmsUnion
    {
        /// <summary>
        /// for a restricted decryption key, shall be set to a supported symmetric algorithm, key size, and mode.
        /// if the key is not a restricted decryption key, this field shall be set to TPM_ALG_NULL.
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public SymDefObject symmetric { get; set; }
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId schemeScheme {
            get {
                if(scheme != null) {
                    return (TpmAlgId)scheme.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// scheme.scheme shall be:
        /// for an unrestricted signing key, either TPM_ALG_RSAPSS TPM_ALG_RSASSA or TPM_ALG_NULL
        /// for a restricted signing key, either TPM_ALG_RSAPSS or TPM_ALG_RSASSA
        /// for an unrestricted decryption key, TPM_ALG_RSAES, TPM_ALG_OAEP, or TPM_ALG_NULL unless the object also has the sign attribute
        /// for a restricted decryption key, TPM_ALG_NULL
        /// NOTE	When both sign and decrypt are SET, restricted shall be CLEAR and scheme shall be TPM_ALG_NULL.
        /// (One of [KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme])
        /// </summary>
        [MarshalAs(2, MarshalType.Union, "schemeScheme")]
        [DataMember()]
        public IAsymSchemeUnion scheme { get; set; }
        /// <summary>
        /// number of bits in the public modulus
        /// </summary>
        [MarshalAs(3)]
        [DataMember()]
        public ushort keyBits { get; set; }
        /// <summary>
        /// the public exponent A prime number greater than 2.
        /// When zero, indicates that the exponent is the default of 216 + 1
        /// </summary>
        [MarshalAs(4)]
        [DataMember()]
        public uint exponent { get; set; }
        public RsaParms()
        {
            symmetric = new SymDefObject();
            keyBits = 0;
            exponent = 0;
        }
        public RsaParms(RsaParms the_RsaParms)
        {
            if((Object) the_RsaParms == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            symmetric = the_RsaParms.symmetric;
            keyBits = the_RsaParms.keyBits;
            exponent = the_RsaParms.exponent;
        }
        ///<param name = "the_symmetric">for a restricted decryption key, shall be set to a supported symmetric algorithm, key size, and mode. if the key is not a restricted decryption key, this field shall be set to TPM_ALG_NULL.</param>
        ///<param name = "the_scheme">scheme.scheme shall be: for an unrestricted signing key, either TPM_ALG_RSAPSS TPM_ALG_RSASSA or TPM_ALG_NULL for a restricted signing key, either TPM_ALG_RSAPSS or TPM_ALG_RSASSA for an unrestricted decryption key, TPM_ALG_RSAES, TPM_ALG_OAEP, or TPM_ALG_NULL unless the object also has the sign attribute for a restricted decryption key, TPM_ALG_NULL NOTE	When both sign and decrypt are SET, restricted shall be CLEAR and scheme shall be TPM_ALG_NULL.(One of KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme)</param>
        ///<param name = "the_keyBits">number of bits in the public modulus</param>
        ///<param name = "the_exponent">the public exponent A prime number greater than 2. When zero, indicates that the exponent is the default of 216 + 1</param>
        public RsaParms(
        SymDefObject the_symmetric,
        IAsymSchemeUnion the_scheme,
        ushort the_keyBits,
        uint the_exponent
        )
        {
            this.symmetric = the_symmetric;
            this.scheme = the_scheme;
            this.keyBits = the_keyBits;
            this.exponent = the_exponent;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Rsa;
        }
        new public RsaParms Copy()
        {
            return Marshaller.FromTpmRepresentation<RsaParms>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure contains the parameters for prime modulus ECC.
    /// </summary>
    [DataContract]
    [KnownType(typeof(SymDefObject))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(Empty))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [KnownType(typeof(EccCurve))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeMgf1))]
    [KnownType(typeof(SchemeKdf1Sp80056a))]
    [KnownType(typeof(SchemeKdf2))]
    [KnownType(typeof(SchemeKdf1Sp800108))]
    [KnownType(typeof(NullKdfScheme))]
    [SpecTypeName("TPMS_ECC_PARMS")]
    public partial class EccParms: TpmStructureBase, IPublicParmsUnion
    {
        /// <summary>
        /// for a restricted decryption key, shall be set to a supported symmetric algorithm, key size. and mode.
        /// if the key is not a restricted decryption key, this field shall be set to TPM_ALG_NULL.
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public SymDefObject symmetric { get; set; }
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId schemeScheme {
            get {
                if(scheme != null) {
                    return (TpmAlgId)scheme.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// If the sign attribute of the key is SET, then this shall be a valid signing scheme.
        /// NOTE	If the sign parameter in curveID indicates a mandatory scheme, then this field shall have the same value.
        /// If the decrypt attribute of the key is SET, then this shall be a valid key exchange scheme or TPM_ALG_NULL.
        /// If the key is a Storage Key, then this field shall be TPM_ALG_NULL.
        /// (One of [KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme])
        /// </summary>
        [MarshalAs(2, MarshalType.Union, "schemeScheme")]
        [DataMember()]
        public IAsymSchemeUnion scheme { get; set; }
        /// <summary>
        /// ECC curve ID
        /// </summary>
        [MarshalAs(3)]
        [DataMember()]
        public EccCurve curveID { get; set; }
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(4, MarshalType.UnionSelector)]
        public TpmAlgId kdfScheme {
            get {
                if(kdf != null) {
                    return (TpmAlgId)kdf.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// an optional key derivation scheme for generating a symmetric key from a Z value
        /// If the kdf parameter associated with curveID is not TPM_ALG_NULL then this is required to be NULL.
        /// NOTE	There are currently no commands where this parameter has effect and, in the reference code, this field needs to be set to TPM_ALG_NULL.
        /// (One of [SchemeMgf1, SchemeKdf1Sp80056a, SchemeKdf2, SchemeKdf1Sp800108, NullKdfScheme])
        /// </summary>
        [MarshalAs(5, MarshalType.Union, "kdfScheme")]
        [DataMember()]
        public IKdfSchemeUnion kdf { get; set; }
        public EccParms()
        {
            symmetric = new SymDefObject();
            curveID = new EccCurve();
        }
        public EccParms(EccParms the_EccParms)
        {
            if((Object) the_EccParms == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            symmetric = the_EccParms.symmetric;
            curveID = the_EccParms.curveID;
        }
        ///<param name = "the_symmetric">for a restricted decryption key, shall be set to a supported symmetric algorithm, key size. and mode. if the key is not a restricted decryption key, this field shall be set to TPM_ALG_NULL.</param>
        ///<param name = "the_scheme">If the sign attribute of the key is SET, then this shall be a valid signing scheme. NOTE	If the sign parameter in curveID indicates a mandatory scheme, then this field shall have the same value. If the decrypt attribute of the key is SET, then this shall be a valid key exchange scheme or TPM_ALG_NULL. If the key is a Storage Key, then this field shall be TPM_ALG_NULL.(One of KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme)</param>
        ///<param name = "the_curveID">ECC curve ID</param>
        ///<param name = "the_kdf">an optional key derivation scheme for generating a symmetric key from a Z value If the kdf parameter associated with curveID is not TPM_ALG_NULL then this is required to be NULL. NOTE	There are currently no commands where this parameter has effect and, in the reference code, this field needs to be set to TPM_ALG_NULL.(One of SchemeMgf1, SchemeKdf1Sp80056a, SchemeKdf2, SchemeKdf1Sp800108, NullKdfScheme)</param>
        public EccParms(
        SymDefObject the_symmetric,
        IAsymSchemeUnion the_scheme,
        EccCurve the_curveID,
        IKdfSchemeUnion the_kdf
        )
        {
            this.symmetric = the_symmetric;
            this.scheme = the_scheme;
            this.curveID = the_curveID;
            this.kdf = the_kdf;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Ecc;
        }
        new public EccParms Copy()
        {
            return Marshaller.FromTpmRepresentation<EccParms>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used in TPM2_TestParms() to validate that a set of algorithm parameters is supported by the TPM.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(SymcipherParms))]
    [KnownType(typeof(KeyedhashParms))]
    [KnownType(typeof(AsymParms))]
    [KnownType(typeof(RsaParms))]
    [KnownType(typeof(EccParms))]
    [SpecTypeName("TPMT_PUBLIC_PARMS")]
    public partial class PublicParms: TpmStructureBase
    {
        /// <summary>
        /// the algorithm to be tested
        /// </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId type {
            get { return (TpmAlgId)parameters.GetUnionSelector(); }
        }
        /// <summary>
        /// the algorithm details
        /// (One of [KeyedhashParms, SymcipherParms, RsaParms, EccParms, AsymParms])
        /// </summary>
        [MarshalAs(1, MarshalType.Union, "type")]
        [DataMember()]
        public IPublicParmsUnion parameters { get; set; }
        public PublicParms()
        {
        }
        public PublicParms(PublicParms the_PublicParms)
        {
            if((Object) the_PublicParms == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
        }
        ///<param name = "the_parameters">the algorithm details(One of KeyedhashParms, SymcipherParms, RsaParms, EccParms, AsymParms)</param>
        public PublicParms(
        IPublicParmsUnion the_parameters
        )
        {
            this.parameters = the_parameters;
        }
        new public PublicParms Copy()
        {
            return Marshaller.FromTpmRepresentation<PublicParms>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Table 189 defines the public area structure. The Name of the object is nameAlg concatenated with the digest of this structure using nameAlg.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(ObjectAttr))]
    [KnownType(typeof(SymcipherParms))]
    [KnownType(typeof(KeyedhashParms))]
    [KnownType(typeof(AsymParms))]
    [KnownType(typeof(RsaParms))]
    [KnownType(typeof(EccParms))]
    [KnownType(typeof(Tpm2bDigest))]
    [KnownType(typeof(TpmDerive))]
    [KnownType(typeof(Tpm2bPublicKeyRsa))]
    [KnownType(typeof(EccPoint))]
    [KnownType(typeof(Tpm2bDigestSymcipher))]
    [KnownType(typeof(Tpm2bDigestKeyedhash))]
    [SpecTypeName("TPMT_PUBLIC")]
    public partial class TpmPublic: TpmStructureBase
    {
        /// <summary>
        /// algorithm associated with this object
        /// </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId type {
            get { return (TpmAlgId)parameters.GetUnionSelector(); }
        }
        /// <summary>
        /// algorithm used for computing the Name of the object
        /// NOTE	The "+" indicates that the instance of a TPMT_PUBLIC may have a "+" to indicate that the nameAlg may be TPM_ALG_NULL.
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmAlgId nameAlg { get; set; }
        /// <summary>
        /// attributes that, along with type, determine the manipulations of this object
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public ObjectAttr objectAttributes { get; set; }
        /// <summary>
        /// optional policy for using this key
        /// The policy is computed using the nameAlg of the object.
        /// NOTE Shall be the Empty Policy if no authorization policy is present.
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "authPolicySize", 2)]
        [DataMember()]
        public byte[] authPolicy;
        /// <summary>
        /// the algorithm or structure details
        /// (One of [KeyedhashParms, SymcipherParms, RsaParms, EccParms, AsymParms])
        /// </summary>
        [MarshalAs(4, MarshalType.Union, "type")]
        [DataMember()]
        public IPublicParmsUnion parameters { get; set; }
        /// <summary>
        /// the unique identifier of the structure
        /// For an asymmetric key, this would be the public key.
        /// (One of [Tpm2bDigestKeyedhash, Tpm2bDigestSymcipher, Tpm2bPublicKeyRsa, EccPoint, TpmDerive])
        /// </summary>
        [MarshalAs(5, MarshalType.Union, "type")]
        [DataMember()]
        public IPublicIdUnion unique { get; set; }
        public TpmPublic()
        {
            nameAlg = TpmAlgId.Null;
            objectAttributes = new ObjectAttr();
            authPolicy = null;
        }
        public TpmPublic(TpmPublic the_TpmPublic)
        {
            if((Object) the_TpmPublic == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            nameAlg = the_TpmPublic.nameAlg;
            objectAttributes = the_TpmPublic.objectAttributes;
            authPolicy = the_TpmPublic.authPolicy;
        }
        ///<param name = "the_nameAlg">algorithm used for computing the Name of the object NOTE	The "+" indicates that the instance of a TPMT_PUBLIC may have a "+" to indicate that the nameAlg may be TPM_ALG_NULL.</param>
        ///<param name = "the_objectAttributes">attributes that, along with type, determine the manipulations of this object</param>
        ///<param name = "the_authPolicy">optional policy for using this key The policy is computed using the nameAlg of the object. NOTE Shall be the Empty Policy if no authorization policy is present.</param>
        ///<param name = "the_parameters">the algorithm or structure details(One of KeyedhashParms, SymcipherParms, RsaParms, EccParms, AsymParms)</param>
        ///<param name = "the_unique">the unique identifier of the structure For an asymmetric key, this would be the public key.(One of Tpm2bDigestKeyedhash, Tpm2bDigestSymcipher, Tpm2bPublicKeyRsa, EccPoint, TpmDerive)</param>
        public TpmPublic(
        TpmAlgId the_nameAlg,
        ObjectAttr the_objectAttributes,
        byte[] the_authPolicy,
        IPublicParmsUnion the_parameters,
        IPublicIdUnion the_unique
        )
        {
            this.nameAlg = the_nameAlg;
            this.objectAttributes = the_objectAttributes;
            this.authPolicy = the_authPolicy;
            this.parameters = the_parameters;
            this.unique = the_unique;
        }
        new public TpmPublic Copy()
        {
            return Marshaller.FromTpmRepresentation<TpmPublic>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This sized buffer is used to embed a TPMT_PUBLIC in a load command and in any response that returns a public area.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmPublic))]
    [SpecTypeName("TPM2B_PUBLIC")]
    public partial class Tpm2bPublic: TpmStructureBase
    {
        /// <summary>
        /// the public area NOTE	The + indicates that the caller may specify that use of TPM_ALG_NULL is allowed for nameAlg.
        /// </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "size", 2)]
        [DataMember()]
        public TpmPublic publicArea { get; set; }
        public Tpm2bPublic()
        {
            publicArea = new TpmPublic();
        }
        public Tpm2bPublic(Tpm2bPublic the_Tpm2bPublic)
        {
            if((Object) the_Tpm2bPublic == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            publicArea = the_Tpm2bPublic.publicArea;
        }
        ///<param name = "the_publicArea">the public area NOTE	The + indicates that the caller may specify that use of TPM_ALG_NULL is allowed for nameAlg.</param>
        public Tpm2bPublic(
        TpmPublic the_publicArea
        )
        {
            this.publicArea = the_publicArea;
        }
        new public Tpm2bPublic Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bPublic>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This sized buffer is used to embed a TPMT_TEMPLATE for TPM2_CreateLoaded().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_TEMPLATE")]
    public partial class Tpm2bTemplate: TpmStructureBase
    {
        /// <summary>
        /// the public area
        /// </summary>
        [Range(MaxVal = 334u /*sizeof(TPMT_PUBLIC)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bTemplate()
        {
            buffer = null;
        }
        public Tpm2bTemplate(Tpm2bTemplate the_Tpm2bTemplate)
        {
            if((Object) the_Tpm2bTemplate == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bTemplate.buffer;
        }
        ///<param name = "the_buffer">the public area</param>
        public Tpm2bTemplate(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        new public Tpm2bTemplate Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bTemplate>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is defined for coding purposes. For IO to the TPM, the sensitive portion of the key will be in a canonical form. For an RSA key, this will be one of the prime factors of the public modulus. After loading, it is typical that other values will be computed so that computations using the private key will not need to start with just one prime factor. This structure can be used to store the results of such vendor-specific calculations.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_PRIVATE_VENDOR_SPECIFIC")]
    public partial class Tpm2bPrivateVendorSpecific: TpmStructureBase, ISensitiveCompositeUnion
    {
        [Range(MaxVal = 640u /*PRIVATE_VENDOR_SPECIFIC_BYTES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bPrivateVendorSpecific()
        {
            buffer = null;
        }
        public Tpm2bPrivateVendorSpecific(Tpm2bPrivateVendorSpecific the_Tpm2bPrivateVendorSpecific)
        {
            if((Object) the_Tpm2bPrivateVendorSpecific == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bPrivateVendorSpecific.buffer;
        }
        ///<param name = "the_buffer"></param>
        public Tpm2bPrivateVendorSpecific(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        public virtual TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Any;
        }
        new public Tpm2bPrivateVendorSpecific Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bPrivateVendorSpecific>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Table 194  Definition of TPMT_SENSITIVE Structure
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(Tpm2bSymKey))]
    [KnownType(typeof(Tpm2bSensitiveData))]
    [KnownType(typeof(Tpm2bPrivateKeyRsa))]
    [KnownType(typeof(Tpm2bEccParameter))]
    [KnownType(typeof(Tpm2bPrivateVendorSpecific))]
    [SpecTypeName("TPMT_SENSITIVE")]
    public partial class Sensitive: TpmStructureBase
    {
        /// <summary>
        /// identifier for the sensitive area This shall be the same as the type parameter of the associated public area.
        /// </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId sensitiveType {
            get { return (TpmAlgId)sensitive.GetUnionSelector(); }
        }
        /// <summary>
        /// user authorization data
        /// The authValue may be a zero-length string.
        /// This value shall not be larger than the size of the digest produced by the nameAlg of the object.
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "authValueSize", 2)]
        [DataMember()]
        public byte[] authValue;
        /// <summary>
        /// for a parent object, the optional protection seed; for other objects, the obfuscation value
        /// This value shall not be larger than the size of the digest produced by nameAlg of the object.
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "seedValueSize", 2)]
        [DataMember()]
        public byte[] seedValue;
        /// <summary>
        /// the type-specific private data
        /// (One of [Tpm2bPrivateKeyRsa, Tpm2bEccParameter, Tpm2bSensitiveData, Tpm2bSymKey, Tpm2bPrivateVendorSpecific])
        /// </summary>
        [MarshalAs(3, MarshalType.Union, "sensitiveType")]
        [DataMember()]
        public ISensitiveCompositeUnion sensitive { get; set; }
        public Sensitive()
        {
            authValue = null;
            seedValue = null;
        }
        public Sensitive(Sensitive the_Sensitive)
        {
            if((Object) the_Sensitive == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authValue = the_Sensitive.authValue;
            seedValue = the_Sensitive.seedValue;
        }
        ///<param name = "the_authValue">user authorization data The authValue may be a zero-length string. This value shall not be larger than the size of the digest produced by the nameAlg of the object.</param>
        ///<param name = "the_seedValue">for a parent object, the optional protection seed; for other objects, the obfuscation value This value shall not be larger than the size of the digest produced by nameAlg of the object.</param>
        ///<param name = "the_sensitive">the type-specific private data(One of Tpm2bPrivateKeyRsa, Tpm2bEccParameter, Tpm2bSensitiveData, Tpm2bSymKey, Tpm2bPrivateVendorSpecific)</param>
        public Sensitive(
        byte[] the_authValue,
        byte[] the_seedValue,
        ISensitiveCompositeUnion the_sensitive
        )
        {
            this.authValue = the_authValue;
            this.seedValue = the_seedValue;
            this.sensitive = the_sensitive;
        }
        new public Sensitive Copy()
        {
            return Marshaller.FromTpmRepresentation<Sensitive>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// The TPM2B_SENSITIVE structure is used as a parameter in TPM2_LoadExternal(). It is an unencrypted sensitive area but it may be encrypted using parameter encryption.
    /// </summary>
    [DataContract]
    [KnownType(typeof(Sensitive))]
    [SpecTypeName("TPM2B_SENSITIVE")]
    public partial class Tpm2bSensitive: TpmStructureBase
    {
        /// <summary>
        /// an unencrypted sensitive area
        /// </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "size", 2)]
        [DataMember()]
        public Sensitive sensitiveArea { get; set; }
        public Tpm2bSensitive()
        {
            sensitiveArea = new Sensitive();
        }
        public Tpm2bSensitive(Tpm2bSensitive the_Tpm2bSensitive)
        {
            if((Object) the_Tpm2bSensitive == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            sensitiveArea = the_Tpm2bSensitive.sensitiveArea;
        }
        ///<param name = "the_sensitiveArea">an unencrypted sensitive area</param>
        public Tpm2bSensitive(
        Sensitive the_sensitiveArea
        )
        {
            this.sensitiveArea = the_sensitiveArea;
        }
        new public Tpm2bSensitive Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bSensitive>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is defined to size the contents of a TPM2B_PRIVATE. This structure is not directly marshaled or unmarshaled.
    /// </summary>
    [DataContract]
    [KnownType(typeof(Sensitive))]
    [SpecTypeName("_PRIVATE")]
    public partial class Private: TpmStructureBase
    {
        [MarshalAs(0, MarshalType.VariableLengthArray, "integrityOuterSize", 2)]
        [DataMember()]
        public byte[] integrityOuter;
        /// <summary>
        /// could also be a TPM2B_IV
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "integrityInnerSize", 2)]
        [DataMember()]
        public byte[] integrityInner;
        /// <summary>
        /// the sensitive area
        /// </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "sensitiveSize", 2)]
        [DataMember()]
        public Sensitive sensitive { get; set; }
        public Private()
        {
            integrityOuter = null;
            integrityInner = null;
            sensitive = new Sensitive();
        }
        public Private(Private the_Private)
        {
            if((Object) the_Private == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            integrityOuter = the_Private.integrityOuter;
            integrityInner = the_Private.integrityInner;
            sensitive = the_Private.sensitive;
        }
        ///<param name = "the_integrityOuter"></param>
        ///<param name = "the_integrityInner">could also be a TPM2B_IV</param>
        ///<param name = "the_sensitive">the sensitive area</param>
        public Private(
        byte[] the_integrityOuter,
        byte[] the_integrityInner,
        Sensitive the_sensitive
        )
        {
            this.integrityOuter = the_integrityOuter;
            this.integrityInner = the_integrityInner;
            this.sensitive = the_sensitive;
        }
        new public Private Copy()
        {
            return Marshaller.FromTpmRepresentation<Private>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// The TPM2B_PRIVATE structure is used as a parameter in multiple commands that create, load, and modify the sensitive area of an object.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_PRIVATE")]
    public partial class TpmPrivate: TpmStructureBase
    {
        /// <summary>
        /// an encrypted private area
        /// </summary>
        [Range(MaxVal = 1024u /*sizeof(_PRIVATE)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public TpmPrivate()
        {
            buffer = null;
        }
        public TpmPrivate(TpmPrivate the_TpmPrivate)
        {
            if((Object) the_TpmPrivate == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_TpmPrivate.buffer;
        }
        ///<param name = "the_buffer">an encrypted private area</param>
        public TpmPrivate(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        new public TpmPrivate Copy()
        {
            return Marshaller.FromTpmRepresentation<TpmPrivate>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used for sizing the TPM2B_ID_OBJECT.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_ID_OBJECT")]
    public partial class IdObject: TpmStructureBase
    {
        /// <summary>
        /// HMAC using the nameAlg of the storage key on the target TPM
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "integrityHMACSize", 2)]
        [DataMember()]
        public byte[] integrityHMAC;
        /// <summary>
        /// credential protector information returned if name matches the referenced object
        /// All of the encIdentity is encrypted, including the size field.
        /// NOTE	The TPM is not required to check that the size is not larger than the digest of the nameAlg. However, if the size is larger, the ID object may not be usable on a TPM that has no digest larger than produced by nameAlg.
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "encIdentitySize", 2)]
        [DataMember()]
        public byte[] encIdentity;
        public IdObject()
        {
            integrityHMAC = null;
            encIdentity = null;
        }
        public IdObject(IdObject the_IdObject)
        {
            if((Object) the_IdObject == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            integrityHMAC = the_IdObject.integrityHMAC;
            encIdentity = the_IdObject.encIdentity;
        }
        ///<param name = "the_integrityHMAC">HMAC using the nameAlg of the storage key on the target TPM</param>
        ///<param name = "the_encIdentity">credential protector information returned if name matches the referenced object All of the encIdentity is encrypted, including the size field. NOTE	The TPM is not required to check that the size is not larger than the digest of the nameAlg. However, if the size is larger, the ID object may not be usable on a TPM that has no digest larger than produced by nameAlg.</param>
        public IdObject(
        byte[] the_integrityHMAC,
        byte[] the_encIdentity
        )
        {
            this.integrityHMAC = the_integrityHMAC;
            this.encIdentity = the_encIdentity;
        }
        new public IdObject Copy()
        {
            return Marshaller.FromTpmRepresentation<IdObject>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is an output from TPM2_MakeCredential() and is an input to TPM2_ActivateCredential().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_ID_OBJECT")]
    public partial class Tpm2bIdObject: TpmStructureBase
    {
        /// <summary>
        /// an encrypted credential area
        /// </summary>
        [Range(MaxVal = 104u /*sizeof(TPMS_ID_OBJECT)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] credential;
        public Tpm2bIdObject()
        {
            credential = null;
        }
        public Tpm2bIdObject(Tpm2bIdObject the_Tpm2bIdObject)
        {
            if((Object) the_Tpm2bIdObject == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            credential = the_Tpm2bIdObject.credential;
        }
        ///<param name = "the_credential">an encrypted credential area</param>
        public Tpm2bIdObject(
        byte[] the_credential
        )
        {
            this.credential = the_credential;
        }
        new public Tpm2bIdObject Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bIdObject>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This is the data that can be written to and read from a TPM_NT_PIN_PASS or TPM_NT_PIN_FAIL non-volatile index. pinCount is the most significant octets. pinLimit is the least significant octets.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_NV_PIN_COUNTER_PARAMETERS")]
    public partial class NvPinCounterParameters: TpmStructureBase
    {
        /// <summary>
        /// This counter shows the current number of successful authValue authorization attempts to access a TPM_NT_PIN_PASS index or the current number of unsuccessful authValue authorization attempts to access a TPM_NT_PIN_FAIL index.
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public uint pinCount { get; set; }
        /// <summary>
        /// This threshold is the value of pinCount at which the authValue authorization of the host TPM_NT_PIN_PASS or TPM_NT_PIN_FAIL index is locked out.
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint pinLimit { get; set; }
        public NvPinCounterParameters()
        {
            pinCount = 0;
            pinLimit = 0;
        }
        public NvPinCounterParameters(NvPinCounterParameters the_NvPinCounterParameters)
        {
            if((Object) the_NvPinCounterParameters == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            pinCount = the_NvPinCounterParameters.pinCount;
            pinLimit = the_NvPinCounterParameters.pinLimit;
        }
        ///<param name = "the_pinCount">This counter shows the current number of successful authValue authorization attempts to access a TPM_NT_PIN_PASS index or the current number of unsuccessful authValue authorization attempts to access a TPM_NT_PIN_FAIL index.</param>
        ///<param name = "the_pinLimit">This threshold is the value of pinCount at which the authValue authorization of the host TPM_NT_PIN_PASS or TPM_NT_PIN_FAIL index is locked out.</param>
        public NvPinCounterParameters(
        uint the_pinCount,
        uint the_pinLimit
        )
        {
            this.pinCount = the_pinCount;
            this.pinLimit = the_pinLimit;
        }
        new public NvPinCounterParameters Copy()
        {
            return Marshaller.FromTpmRepresentation<NvPinCounterParameters>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure describes an NV Index.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NvAttr))]
    [SpecTypeName("TPMS_NV_PUBLIC")]
    public partial class NvPublic: TpmStructureBase
    {
        /// <summary>
        /// the handle of the data area
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }
        /// <summary>
        /// hash algorithm used to compute the name of the Index and used for the authPolicy. For an extend index, the hash algorithm used for the extend.
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmAlgId nameAlg { get; set; }
        /// <summary>
        /// the Index attributes
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public NvAttr attributes { get; set; }
        /// <summary>
        /// optional access policy for the Index The policy is computed using the nameAlg NOTE Shall be the Empty Policy if no authorization policy is present.
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "authPolicySize", 2)]
        [DataMember()]
        public byte[] authPolicy;
        /// <summary>
        /// the size of the data area
        /// The maximum size is implementation-dependent. The minimum maximum size is platform-specific.
        /// </summary>
        [Range(MaxVal = 2048u /*MAX_NV_INDEX_SIZE*/)]
        [MarshalAs(4)]
        [DataMember()]
        public ushort dataSize { get; set; }
        public NvPublic()
        {
            nvIndex = new TpmHandle();
            nameAlg = TpmAlgId.Null;
            attributes = new NvAttr();
            authPolicy = null;
            dataSize = 0;
        }
        public NvPublic(NvPublic the_NvPublic)
        {
            if((Object) the_NvPublic == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            nvIndex = the_NvPublic.nvIndex;
            nameAlg = the_NvPublic.nameAlg;
            attributes = the_NvPublic.attributes;
            authPolicy = the_NvPublic.authPolicy;
            dataSize = the_NvPublic.dataSize;
        }
        ///<param name = "the_nvIndex">the handle of the data area</param>
        ///<param name = "the_nameAlg">hash algorithm used to compute the name of the Index and used for the authPolicy. For an extend index, the hash algorithm used for the extend.</param>
        ///<param name = "the_attributes">the Index attributes</param>
        ///<param name = "the_authPolicy">optional access policy for the Index The policy is computed using the nameAlg NOTE Shall be the Empty Policy if no authorization policy is present.</param>
        ///<param name = "the_dataSize">the size of the data area The maximum size is implementation-dependent. The minimum maximum size is platform-specific.</param>
        public NvPublic(
        TpmHandle the_nvIndex,
        TpmAlgId the_nameAlg,
        NvAttr the_attributes,
        byte[] the_authPolicy,
        ushort the_dataSize
        )
        {
            this.nvIndex = the_nvIndex;
            this.nameAlg = the_nameAlg;
            this.attributes = the_attributes;
            this.authPolicy = the_authPolicy;
            this.dataSize = the_dataSize;
        }
        new public NvPublic Copy()
        {
            return Marshaller.FromTpmRepresentation<NvPublic>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used when a TPMS_NV_PUBLIC is sent on the TPM interface.
    /// </summary>
    [DataContract]
    [KnownType(typeof(NvPublic))]
    [SpecTypeName("TPM2B_NV_PUBLIC")]
    public partial class Tpm2bNvPublic: TpmStructureBase
    {
        /// <summary>
        /// the public area
        /// </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "size", 2)]
        [DataMember()]
        public NvPublic nvPublic { get; set; }
        public Tpm2bNvPublic()
        {
            nvPublic = new NvPublic();
        }
        public Tpm2bNvPublic(Tpm2bNvPublic the_Tpm2bNvPublic)
        {
            if((Object) the_Tpm2bNvPublic == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            nvPublic = the_Tpm2bNvPublic.nvPublic;
        }
        ///<param name = "the_nvPublic">the public area</param>
        public Tpm2bNvPublic(
        NvPublic the_nvPublic
        )
        {
            this.nvPublic = the_nvPublic;
        }
        new public Tpm2bNvPublic Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bNvPublic>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure holds the object or session context data. When saved, the full structure is encrypted.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_CONTEXT_SENSITIVE")]
    public partial class Tpm2bContextSensitive: TpmStructureBase
    {
        /// <summary>
        /// the sensitive data
        /// </summary>
        [Range(MaxVal = 2048u /*MAX_CONTEXT_SIZE*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bContextSensitive()
        {
            buffer = null;
        }
        public Tpm2bContextSensitive(Tpm2bContextSensitive the_Tpm2bContextSensitive)
        {
            if((Object) the_Tpm2bContextSensitive == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bContextSensitive.buffer;
        }
        ///<param name = "the_buffer">the sensitive data</param>
        public Tpm2bContextSensitive(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        new public Tpm2bContextSensitive Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bContextSensitive>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure holds the integrity value and the encrypted data for a context.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_CONTEXT_DATA")]
    public partial class ContextData: TpmStructureBase
    {
        /// <summary>
        /// the integrity value
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "integritySize", 2)]
        [DataMember()]
        public byte[] integrity;
        /// <summary>
        /// the sensitive area
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "encryptedSize", 2)]
        [DataMember()]
        public byte[] encrypted;
        public ContextData()
        {
            integrity = null;
            encrypted = null;
        }
        public ContextData(ContextData the_ContextData)
        {
            if((Object) the_ContextData == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            integrity = the_ContextData.integrity;
            encrypted = the_ContextData.encrypted;
        }
        ///<param name = "the_integrity">the integrity value</param>
        ///<param name = "the_encrypted">the sensitive area</param>
        public ContextData(
        byte[] the_integrity,
        byte[] the_encrypted
        )
        {
            this.integrity = the_integrity;
            this.encrypted = the_encrypted;
        }
        new public ContextData Copy()
        {
            return Marshaller.FromTpmRepresentation<ContextData>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used in a TPMS_CONTEXT.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_CONTEXT_DATA")]
    public partial class Tpm2bContextData: TpmStructureBase
    {
        [Range(MaxVal = 2102u /*sizeof(TPMS_CONTEXT_DATA)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2bContextData()
        {
            buffer = null;
        }
        public Tpm2bContextData(Tpm2bContextData the_Tpm2bContextData)
        {
            if((Object) the_Tpm2bContextData == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            buffer = the_Tpm2bContextData.buffer;
        }
        ///<param name = "the_buffer"></param>
        public Tpm2bContextData(
        byte[] the_buffer
        )
        {
            this.buffer = the_buffer;
        }
        new public Tpm2bContextData Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bContextData>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is used in TPM2_ContextLoad() and TPM2_ContextSave(). If the values of the TPMS_CONTEXT structure in TPM2_ContextLoad() are not the same as the values when the context was saved (TPM2_ContextSave()), then the TPM shall not load the context.
    /// </summary>
    [DataContract]
    [KnownType(typeof(ulong))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPMS_CONTEXT")]
    public partial class Context: TpmStructureBase
    {
        /// <summary>
        /// the sequence number of the context
        /// NOTE	Transient object contexts and session contexts used different counters.
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public ulong sequence { get; set; }
        /// <summary>
        /// a handle indicating if the context is a session, object, or sequence object
        /// See Table 210  Context Handle Values
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle savedHandle { get; set; }
        /// <summary>
        /// the hierarchy of the context
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle hierarchy { get; set; }
        /// <summary>
        /// the context data and integrity HMAC
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "contextBlobSize", 2)]
        [DataMember()]
        public byte[] contextBlob;
        public Context()
        {
            sequence = new ulong();
            savedHandle = new TpmHandle();
            hierarchy = new TpmHandle();
            contextBlob = null;
        }
        public Context(Context the_Context)
        {
            if((Object) the_Context == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            sequence = the_Context.sequence;
            savedHandle = the_Context.savedHandle;
            hierarchy = the_Context.hierarchy;
            contextBlob = the_Context.contextBlob;
        }
        ///<param name = "the_sequence">the sequence number of the context NOTE	Transient object contexts and session contexts used different counters.</param>
        ///<param name = "the_savedHandle">a handle indicating if the context is a session, object, or sequence object See Table 210  Context Handle Values</param>
        ///<param name = "the_hierarchy">the hierarchy of the context</param>
        ///<param name = "the_contextBlob">the context data and integrity HMAC</param>
        public Context(
        ulong the_sequence,
        TpmHandle the_savedHandle,
        TpmHandle the_hierarchy,
        byte[] the_contextBlob
        )
        {
            this.sequence = the_sequence;
            this.savedHandle = the_savedHandle;
            this.hierarchy = the_hierarchy;
            this.contextBlob = the_contextBlob;
        }
        new public Context Copy()
        {
            return Marshaller.FromTpmRepresentation<Context>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure provides information relating to the creation environment for the object. The creation data includes the parent Name, parent Qualified Name, and the digest of selected PCR. These values represent the environment in which the object was created. Creation data allows a relying party to determine if an object was created when some appropriate protections were present.
    /// </summary>
    [DataContract]
    [KnownType(typeof(LocalityAttr))]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMS_CREATION_DATA")]
    public partial class CreationData: TpmStructureBase
    {
        /// <summary>
        /// list indicating the PCR included in pcrDigest
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "pcrSelectCount", 4)]
        [DataMember()]
        public PcrSelection[] pcrSelect;
        /// <summary>
        /// digest of the selected PCR using nameAlg of the object for which this structure is being created
        /// pcrDigest.size shall be zero if the pcrSelect list is empty.
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "pcrDigestSize", 2)]
        [DataMember()]
        public byte[] pcrDigest;
        /// <summary>
        /// the locality at which the object was created
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public LocalityAttr locality { get; set; }
        /// <summary>
        /// nameAlg of the parent
        /// </summary>
        [MarshalAs(3)]
        [DataMember()]
        public TpmAlgId parentNameAlg { get; set; }
        /// <summary>
        /// Name of the parent at time of creation
        /// The size will match digest size associated with parentNameAlg unless it is TPM_ALG_NULL, in which case the size will be 4 and parentName will be the hierarchy handle.
        /// </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "parentNameSize", 2)]
        [DataMember()]
        public byte[] parentName;
        /// <summary>
        /// Qualified Name of the parent at the time of creation
        /// Size is the same as parentName.
        /// </summary>
        [MarshalAs(5, MarshalType.VariableLengthArray, "parentQualifiedNameSize", 2)]
        [DataMember()]
        public byte[] parentQualifiedName;
        /// <summary>
        /// association with additional information added by the key creator
        /// This will be the contents of the outsideInfo parameter in TPM2_Create() or TPM2_CreatePrimary().
        /// </summary>
        [MarshalAs(6, MarshalType.VariableLengthArray, "outsideInfoSize", 2)]
        [DataMember()]
        public byte[] outsideInfo;
        public CreationData()
        {
            pcrSelect = null;
            pcrDigest = null;
            locality = new LocalityAttr();
            parentNameAlg = TpmAlgId.Null;
            parentName = null;
            parentQualifiedName = null;
            outsideInfo = null;
        }
        public CreationData(CreationData the_CreationData)
        {
            if((Object) the_CreationData == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            pcrSelect = the_CreationData.pcrSelect;
            pcrDigest = the_CreationData.pcrDigest;
            locality = the_CreationData.locality;
            parentNameAlg = the_CreationData.parentNameAlg;
            parentName = the_CreationData.parentName;
            parentQualifiedName = the_CreationData.parentQualifiedName;
            outsideInfo = the_CreationData.outsideInfo;
        }
        ///<param name = "the_pcrSelect">list indicating the PCR included in pcrDigest</param>
        ///<param name = "the_pcrDigest">digest of the selected PCR using nameAlg of the object for which this structure is being created pcrDigest.size shall be zero if the pcrSelect list is empty.</param>
        ///<param name = "the_locality">the locality at which the object was created</param>
        ///<param name = "the_parentNameAlg">nameAlg of the parent</param>
        ///<param name = "the_parentName">Name of the parent at time of creation The size will match digest size associated with parentNameAlg unless it is TPM_ALG_NULL, in which case the size will be 4 and parentName will be the hierarchy handle.</param>
        ///<param name = "the_parentQualifiedName">Qualified Name of the parent at the time of creation Size is the same as parentName.</param>
        ///<param name = "the_outsideInfo">association with additional information added by the key creator This will be the contents of the outsideInfo parameter in TPM2_Create() or TPM2_CreatePrimary().</param>
        public CreationData(
        PcrSelection[] the_pcrSelect,
        byte[] the_pcrDigest,
        LocalityAttr the_locality,
        TpmAlgId the_parentNameAlg,
        byte[] the_parentName,
        byte[] the_parentQualifiedName,
        byte[] the_outsideInfo
        )
        {
            this.pcrSelect = the_pcrSelect;
            this.pcrDigest = the_pcrDigest;
            this.locality = the_locality;
            this.parentNameAlg = the_parentNameAlg;
            this.parentName = the_parentName;
            this.parentQualifiedName = the_parentQualifiedName;
            this.outsideInfo = the_outsideInfo;
        }
        new public CreationData Copy()
        {
            return Marshaller.FromTpmRepresentation<CreationData>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This structure is created by TPM2_Create() and TPM2_CreatePrimary(). It is never entered into the TPM and never has a size of zero.
    /// </summary>
    [DataContract]
    [KnownType(typeof(CreationData))]
    [SpecTypeName("TPM2B_CREATION_DATA")]
    public partial class Tpm2bCreationData: TpmStructureBase
    {
        [MarshalAs(0, MarshalType.SizedStruct, "size", 2)]
        [DataMember()]
        public CreationData creationData { get; set; }
        public Tpm2bCreationData()
        {
            creationData = new CreationData();
        }
        public Tpm2bCreationData(Tpm2bCreationData the_Tpm2bCreationData)
        {
            if((Object) the_Tpm2bCreationData == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            creationData = the_Tpm2bCreationData.creationData;
        }
        ///<param name = "the_creationData"></param>
        public Tpm2bCreationData(
        CreationData the_creationData
        )
        {
            this.creationData = the_creationData;
        }
        new public Tpm2bCreationData Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2bCreationData>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// TPM2_Startup() is always preceded by _TPM_Init, which is the physical indication that TPM initialization is necessary because of a system-wide reset. TPM2_Startup() is only valid after _TPM_Init. Additional TPM2_Startup() commands are not allowed after it has completed successfully. If a TPM requires TPM2_Startup() and another command is received, or if the TPM receives TPM2_Startup() when it is not required, the TPM shall return TPM_RC_INITIALIZE.
    /// </summary>
    [DataContract]
    [KnownType(typeof(Su))]
    [SpecTypeName("TPM2_Startup_REQUEST")]
    public partial class Tpm2StartupRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_SU_CLEAR or TPM_SU_STATE
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public Su startupType { get; set; }
        public Tpm2StartupRequest()
        {
            startupType = new Su();
        }
        public Tpm2StartupRequest(Tpm2StartupRequest the_Tpm2StartupRequest)
        {
            if((Object) the_Tpm2StartupRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            startupType = the_Tpm2StartupRequest.startupType;
        }
        ///<param name = "the_startupType">TPM_SU_CLEAR or TPM_SU_STATE</param>
        public Tpm2StartupRequest(
        Su the_startupType
        )
        {
            this.startupType = the_startupType;
        }
        new public Tpm2StartupRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2StartupRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// TPM2_Startup() is always preceded by _TPM_Init, which is the physical indication that TPM initialization is necessary because of a system-wide reset. TPM2_Startup() is only valid after _TPM_Init. Additional TPM2_Startup() commands are not allowed after it has completed successfully. If a TPM requires TPM2_Startup() and another command is received, or if the TPM receives TPM2_Startup() when it is not required, the TPM shall return TPM_RC_INITIALIZE.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_Startup_RESPONSE")]
    public partial class Tpm2StartupResponse: TpmStructureBase
    {
        public Tpm2StartupResponse()
        {
        }
        new public Tpm2StartupResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2StartupResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to prepare the TPM for a power cycle. The shutdownType parameter indicates how the subsequent TPM2_Startup() will be processed.
    /// </summary>
    [DataContract]
    [KnownType(typeof(Su))]
    [SpecTypeName("TPM2_Shutdown_REQUEST")]
    public partial class Tpm2ShutdownRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_SU_CLEAR or TPM_SU_STATE
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public Su shutdownType { get; set; }
        public Tpm2ShutdownRequest()
        {
            shutdownType = new Su();
        }
        public Tpm2ShutdownRequest(Tpm2ShutdownRequest the_Tpm2ShutdownRequest)
        {
            if((Object) the_Tpm2ShutdownRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            shutdownType = the_Tpm2ShutdownRequest.shutdownType;
        }
        ///<param name = "the_shutdownType">TPM_SU_CLEAR or TPM_SU_STATE</param>
        public Tpm2ShutdownRequest(
        Su the_shutdownType
        )
        {
            this.shutdownType = the_shutdownType;
        }
        new public Tpm2ShutdownRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ShutdownRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to prepare the TPM for a power cycle. The shutdownType parameter indicates how the subsequent TPM2_Startup() will be processed.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_Shutdown_RESPONSE")]
    public partial class Tpm2ShutdownResponse: TpmStructureBase
    {
        public Tpm2ShutdownResponse()
        {
        }
        new public Tpm2ShutdownResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ShutdownResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command causes the TPM to perform a test of its capabilities. If the fullTest is YES, the TPM will test all functions. If fullTest = NO, the TPM will only test those functions that have not previously been tested.
    /// </summary>
    [DataContract]
    [KnownType(typeof(byte))]
    [SpecTypeName("TPM2_SelfTest_REQUEST")]
    public partial class Tpm2SelfTestRequest: TpmStructureBase
    {
        /// <summary>
        /// YES if full test to be performed
        /// NO if only test of untested functions required
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public byte fullTest { get; set; }
        public Tpm2SelfTestRequest()
        {
            fullTest = 0;
        }
        public Tpm2SelfTestRequest(Tpm2SelfTestRequest the_Tpm2SelfTestRequest)
        {
            if((Object) the_Tpm2SelfTestRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            fullTest = the_Tpm2SelfTestRequest.fullTest;
        }
        ///<param name = "the_fullTest">YES if full test to be performed NO if only test of untested functions required</param>
        public Tpm2SelfTestRequest(
        byte the_fullTest
        )
        {
            this.fullTest = the_fullTest;
        }
        new public Tpm2SelfTestRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2SelfTestRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command causes the TPM to perform a test of its capabilities. If the fullTest is YES, the TPM will test all functions. If fullTest = NO, the TPM will only test those functions that have not previously been tested.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_SelfTest_RESPONSE")]
    public partial class Tpm2SelfTestResponse: TpmStructureBase
    {
        public Tpm2SelfTestResponse()
        {
        }
        new public Tpm2SelfTestResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2SelfTestResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command causes the TPM to perform a test of the selected algorithms.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_IncrementalSelfTest_REQUEST")]
    public partial class Tpm2IncrementalSelfTestRequest: TpmStructureBase
    {
        /// <summary>
        /// list of algorithms that should be tested
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "toTestCount", 4)]
        [DataMember()]
        public TpmAlgId[] toTest;
        public Tpm2IncrementalSelfTestRequest()
        {
            toTest = null;
        }
        public Tpm2IncrementalSelfTestRequest(Tpm2IncrementalSelfTestRequest the_Tpm2IncrementalSelfTestRequest)
        {
            if((Object) the_Tpm2IncrementalSelfTestRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            toTest = the_Tpm2IncrementalSelfTestRequest.toTest;
        }
        ///<param name = "the_toTest">list of algorithms that should be tested</param>
        public Tpm2IncrementalSelfTestRequest(
        TpmAlgId[] the_toTest
        )
        {
            this.toTest = the_toTest;
        }
        new public Tpm2IncrementalSelfTestRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2IncrementalSelfTestRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command causes the TPM to perform a test of the selected algorithms.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_IncrementalSelfTest_RESPONSE")]
    public partial class Tpm2IncrementalSelfTestResponse: TpmStructureBase
    {
        /// <summary>
        /// list of algorithms that need testing
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "toDoListCount", 4)]
        [DataMember()]
        public TpmAlgId[] toDoList;
        public Tpm2IncrementalSelfTestResponse()
        {
            toDoList = null;
        }
        public Tpm2IncrementalSelfTestResponse(Tpm2IncrementalSelfTestResponse the_Tpm2IncrementalSelfTestResponse)
        {
            if((Object) the_Tpm2IncrementalSelfTestResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            toDoList = the_Tpm2IncrementalSelfTestResponse.toDoList;
        }
        ///<param name = "the_toDoList">list of algorithms that need testing</param>
        public Tpm2IncrementalSelfTestResponse(
        TpmAlgId[] the_toDoList
        )
        {
            this.toDoList = the_toDoList;
        }
        new public Tpm2IncrementalSelfTestResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2IncrementalSelfTestResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns manufacturer-specific information regarding the results of a self-test and an indication of the test status.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_GetTestResult_REQUEST")]
    public partial class Tpm2GetTestResultRequest: TpmStructureBase
    {
        public Tpm2GetTestResultRequest()
        {
        }
        new public Tpm2GetTestResultRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2GetTestResultRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns manufacturer-specific information regarding the results of a self-test and an indication of the test status.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmRc))]
    [SpecTypeName("TPM2_GetTestResult_RESPONSE")]
    public partial class Tpm2GetTestResultResponse: TpmStructureBase
    {
        /// <summary>
        /// test result data
        /// contains manufacturer-specific information
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "outDataSize", 2)]
        [DataMember()]
        public byte[] outData;
        [MarshalAs(1)]
        [DataMember()]
        public TpmRc testResult { get; set; }
        public Tpm2GetTestResultResponse()
        {
            outData = null;
            testResult = new TpmRc();
        }
        public Tpm2GetTestResultResponse(Tpm2GetTestResultResponse the_Tpm2GetTestResultResponse)
        {
            if((Object) the_Tpm2GetTestResultResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            outData = the_Tpm2GetTestResultResponse.outData;
            testResult = the_Tpm2GetTestResultResponse.testResult;
        }
        ///<param name = "the_outData">test result data contains manufacturer-specific information</param>
        ///<param name = "the_testResult"></param>
        public Tpm2GetTestResultResponse(
        byte[] the_outData,
        TpmRc the_testResult
        )
        {
            this.outData = the_outData;
            this.testResult = the_testResult;
        }
        new public Tpm2GetTestResultResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2GetTestResultResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to start an authorization session using alternative methods of establishing the session key (sessionKey). The session key is then used to derive values used for authorization and for encrypting parameters.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmSe))]
    [KnownType(typeof(SymDef))]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPM2_StartAuthSession_REQUEST")]
    public partial class Tpm2StartAuthSessionRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of a loaded decrypt key used to encrypt salt
        /// may be TPM_RH_NULL
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle tpmKey { get; set; }
        /// <summary>
        /// entity providing the authValue
        /// may be TPM_RH_NULL
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle bind { get; set; }
        /// <summary>
        /// initial nonceCaller, sets nonceTPM size for the session
        /// shall be at least 16 octets
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "nonceCallerSize", 2)]
        [DataMember()]
        public byte[] nonceCaller;
        /// <summary>
        /// value encrypted according to the type of tpmKey
        /// If tpmKey is TPM_RH_NULL, this shall be the Empty Buffer.
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "encryptedSaltSize", 2)]
        [DataMember()]
        public byte[] encryptedSalt;
        /// <summary>
        /// indicates the type of the session; simple HMAC or policy (including a trial policy)
        /// </summary>
        [MarshalAs(4)]
        [DataMember()]
        public TpmSe sessionType { get; set; }
        /// <summary>
        /// the algorithm and key size for parameter encryption
        /// may select TPM_ALG_NULL
        /// </summary>
        [MarshalAs(5)]
        [DataMember()]
        public SymDef symmetric { get; set; }
        /// <summary>
        /// hash algorithm to use for the session
        /// Shall be a hash algorithm supported by the TPM and not TPM_ALG_NULL
        /// </summary>
        [MarshalAs(6)]
        [DataMember()]
        public TpmAlgId authHash { get; set; }
        public Tpm2StartAuthSessionRequest()
        {
            tpmKey = new TpmHandle();
            bind = new TpmHandle();
            nonceCaller = null;
            encryptedSalt = null;
            sessionType = new TpmSe();
            symmetric = new SymDef();
            authHash = TpmAlgId.Null;
        }
        public Tpm2StartAuthSessionRequest(Tpm2StartAuthSessionRequest the_Tpm2StartAuthSessionRequest)
        {
            if((Object) the_Tpm2StartAuthSessionRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            tpmKey = the_Tpm2StartAuthSessionRequest.tpmKey;
            bind = the_Tpm2StartAuthSessionRequest.bind;
            nonceCaller = the_Tpm2StartAuthSessionRequest.nonceCaller;
            encryptedSalt = the_Tpm2StartAuthSessionRequest.encryptedSalt;
            sessionType = the_Tpm2StartAuthSessionRequest.sessionType;
            symmetric = the_Tpm2StartAuthSessionRequest.symmetric;
            authHash = the_Tpm2StartAuthSessionRequest.authHash;
        }
        ///<param name = "the_tpmKey">handle of a loaded decrypt key used to encrypt salt may be TPM_RH_NULL Auth Index: None</param>
        ///<param name = "the_bind">entity providing the authValue may be TPM_RH_NULL Auth Index: None</param>
        ///<param name = "the_nonceCaller">initial nonceCaller, sets nonceTPM size for the session shall be at least 16 octets</param>
        ///<param name = "the_encryptedSalt">value encrypted according to the type of tpmKey If tpmKey is TPM_RH_NULL, this shall be the Empty Buffer.</param>
        ///<param name = "the_sessionType">indicates the type of the session; simple HMAC or policy (including a trial policy)</param>
        ///<param name = "the_symmetric">the algorithm and key size for parameter encryption may select TPM_ALG_NULL</param>
        ///<param name = "the_authHash">hash algorithm to use for the session Shall be a hash algorithm supported by the TPM and not TPM_ALG_NULL</param>
        public Tpm2StartAuthSessionRequest(
        TpmHandle the_tpmKey,
        TpmHandle the_bind,
        byte[] the_nonceCaller,
        byte[] the_encryptedSalt,
        TpmSe the_sessionType,
        SymDef the_symmetric,
        TpmAlgId the_authHash
        )
        {
            this.tpmKey = the_tpmKey;
            this.bind = the_bind;
            this.nonceCaller = the_nonceCaller;
            this.encryptedSalt = the_encryptedSalt;
            this.sessionType = the_sessionType;
            this.symmetric = the_symmetric;
            this.authHash = the_authHash;
        }
        new public Tpm2StartAuthSessionRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2StartAuthSessionRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to start an authorization session using alternative methods of establishing the session key (sessionKey). The session key is then used to derive values used for authorization and for encrypting parameters.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_StartAuthSession_RESPONSE")]
    public partial class Tpm2StartAuthSessionResponse: TpmStructureBase
    {
        /// <summary>
        /// handle for the newly created session
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle sessionHandle { get; set; }
        /// <summary>
        /// the initial nonce from the TPM, used in the computation of the sessionKey
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "nonceTPMSize", 2)]
        [DataMember()]
        public byte[] nonceTPM;
        public Tpm2StartAuthSessionResponse()
        {
            sessionHandle = new TpmHandle();
            nonceTPM = null;
        }
        public Tpm2StartAuthSessionResponse(Tpm2StartAuthSessionResponse the_Tpm2StartAuthSessionResponse)
        {
            if((Object) the_Tpm2StartAuthSessionResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            sessionHandle = the_Tpm2StartAuthSessionResponse.sessionHandle;
            nonceTPM = the_Tpm2StartAuthSessionResponse.nonceTPM;
        }
        ///<param name = "the_sessionHandle">handle for the newly created session</param>
        ///<param name = "the_nonceTPM">the initial nonce from the TPM, used in the computation of the sessionKey</param>
        public Tpm2StartAuthSessionResponse(
        TpmHandle the_sessionHandle,
        byte[] the_nonceTPM
        )
        {
            this.sessionHandle = the_sessionHandle;
            this.nonceTPM = the_nonceTPM;
        }
        new public Tpm2StartAuthSessionResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2StartAuthSessionResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows a policy authorization session to be returned to its initial state. This command is used after the TPM returns TPM_RC_PCR_CHANGED. That response code indicates that a policy will fail because the PCR have changed after TPM2_PolicyPCR() was executed. Restarting the session allows the authorizations to be replayed because the session restarts with the same nonceTPM. If the PCR are valid for the policy, the policy may then succeed.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PolicyRestart_REQUEST")]
    public partial class Tpm2PolicyRestartRequest: TpmStructureBase
    {
        /// <summary>
        /// the handle for the policy session
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle sessionHandle { get; set; }
        public Tpm2PolicyRestartRequest()
        {
            sessionHandle = new TpmHandle();
        }
        public Tpm2PolicyRestartRequest(Tpm2PolicyRestartRequest the_Tpm2PolicyRestartRequest)
        {
            if((Object) the_Tpm2PolicyRestartRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            sessionHandle = the_Tpm2PolicyRestartRequest.sessionHandle;
        }
        ///<param name = "the_sessionHandle">the handle for the policy session</param>
        public Tpm2PolicyRestartRequest(
        TpmHandle the_sessionHandle
        )
        {
            this.sessionHandle = the_sessionHandle;
        }
        new public Tpm2PolicyRestartRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyRestartRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows a policy authorization session to be returned to its initial state. This command is used after the TPM returns TPM_RC_PCR_CHANGED. That response code indicates that a policy will fail because the PCR have changed after TPM2_PolicyPCR() was executed. Restarting the session allows the authorizations to be replayed because the session restarts with the same nonceTPM. If the PCR are valid for the policy, the policy may then succeed.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyRestart_RESPONSE")]
    public partial class Tpm2PolicyRestartResponse: TpmStructureBase
    {
        public Tpm2PolicyRestartResponse()
        {
        }
        new public Tpm2PolicyRestartResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyRestartResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to create an object that can be loaded into a TPM using TPM2_Load(). If the command completes successfully, the TPM will create the new object and return the objects creation data (creationData), its public area (outPublic), and its encrypted sensitive area (outPrivate). Preservation of the returned data is the responsibility of the caller. The object will need to be loaded (TPM2_Load()) before it may be used. The only difference between the inPublic TPMT_PUBLIC template and the outPublic TPMT_PUBLIC object is in the unique field.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(SensitiveCreate))]
    [SpecTypeName("TPM2_Create_REQUEST")]
    public partial class Tpm2CreateRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of parent for new object
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle parentHandle { get; set; }
        /// <summary>
        /// the sensitive data
        /// </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "inSensitiveSize", 2)]
        [DataMember()]
        public SensitiveCreate inSensitive { get; set; }
        /// <summary>
        /// the public template
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "inPublicSize", 2)]
        [DataMember()]
        public byte[] inPublic;
        /// <summary>
        /// data that will be included in the creation data for this object to provide permanent, verifiable linkage between this object and some object owner data
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "outsideInfoSize", 2)]
        [DataMember()]
        public byte[] outsideInfo;
        /// <summary>
        /// PCR that will be used in creation data
        /// </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "creationPCRCount", 4)]
        [DataMember()]
        public PcrSelection[] creationPCR;
        public Tpm2CreateRequest()
        {
            parentHandle = new TpmHandle();
            inSensitive = new SensitiveCreate();
            inPublic = null;
            outsideInfo = null;
            creationPCR = null;
        }
        public Tpm2CreateRequest(Tpm2CreateRequest the_Tpm2CreateRequest)
        {
            if((Object) the_Tpm2CreateRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            parentHandle = the_Tpm2CreateRequest.parentHandle;
            inSensitive = the_Tpm2CreateRequest.inSensitive;
            inPublic = the_Tpm2CreateRequest.inPublic;
            outsideInfo = the_Tpm2CreateRequest.outsideInfo;
            creationPCR = the_Tpm2CreateRequest.creationPCR;
        }
        ///<param name = "the_parentHandle">handle of parent for new object Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_inSensitive">the sensitive data</param>
        ///<param name = "the_inPublic">the public template</param>
        ///<param name = "the_outsideInfo">data that will be included in the creation data for this object to provide permanent, verifiable linkage between this object and some object owner data</param>
        ///<param name = "the_creationPCR">PCR that will be used in creation data</param>
        public Tpm2CreateRequest(
        TpmHandle the_parentHandle,
        SensitiveCreate the_inSensitive,
        byte[] the_inPublic,
        byte[] the_outsideInfo,
        PcrSelection[] the_creationPCR
        )
        {
            this.parentHandle = the_parentHandle;
            this.inSensitive = the_inSensitive;
            this.inPublic = the_inPublic;
            this.outsideInfo = the_outsideInfo;
            this.creationPCR = the_creationPCR;
        }
        new public Tpm2CreateRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2CreateRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to create an object that can be loaded into a TPM using TPM2_Load(). If the command completes successfully, the TPM will create the new object and return the objects creation data (creationData), its public area (outPublic), and its encrypted sensitive area (outPrivate). Preservation of the returned data is the responsibility of the caller. The object will need to be loaded (TPM2_Load()) before it may be used. The only difference between the inPublic TPMT_PUBLIC template and the outPublic TPMT_PUBLIC object is in the unique field.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmPrivate))]
    [KnownType(typeof(TpmPublic))]
    [KnownType(typeof(CreationData))]
    [KnownType(typeof(TkCreation))]
    [SpecTypeName("TPM2_Create_RESPONSE")]
    public partial class Tpm2CreateResponse: TpmStructureBase
    {
        /// <summary>
        /// the private portion of the object
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmPrivate outPrivate { get; set; }
        /// <summary>
        /// the public portion of the created object
        /// </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "outPublicSize", 2)]
        [DataMember()]
        public TpmPublic outPublic { get; set; }
        /// <summary>
        /// contains a TPMS_CREATION_DATA
        /// </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "creationDataSize", 2)]
        [DataMember()]
        public CreationData creationData { get; set; }
        /// <summary>
        /// digest of creationData using nameAlg of outPublic
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "creationHashSize", 2)]
        [DataMember()]
        public byte[] creationHash;
        /// <summary>
        /// ticket used by TPM2_CertifyCreation() to validate that the creation data was produced by the TPM
        /// </summary>
        [MarshalAs(4)]
        [DataMember()]
        public TkCreation creationTicket { get; set; }
        public Tpm2CreateResponse()
        {
            outPrivate = new TpmPrivate();
            outPublic = new TpmPublic();
            creationData = new CreationData();
            creationHash = null;
            creationTicket = new TkCreation();
        }
        public Tpm2CreateResponse(Tpm2CreateResponse the_Tpm2CreateResponse)
        {
            if((Object) the_Tpm2CreateResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            outPrivate = the_Tpm2CreateResponse.outPrivate;
            outPublic = the_Tpm2CreateResponse.outPublic;
            creationData = the_Tpm2CreateResponse.creationData;
            creationHash = the_Tpm2CreateResponse.creationHash;
            creationTicket = the_Tpm2CreateResponse.creationTicket;
        }
        ///<param name = "the_outPrivate">the private portion of the object</param>
        ///<param name = "the_outPublic">the public portion of the created object</param>
        ///<param name = "the_creationData">contains a TPMS_CREATION_DATA</param>
        ///<param name = "the_creationHash">digest of creationData using nameAlg of outPublic</param>
        ///<param name = "the_creationTicket">ticket used by TPM2_CertifyCreation() to validate that the creation data was produced by the TPM</param>
        public Tpm2CreateResponse(
        TpmPrivate the_outPrivate,
        TpmPublic the_outPublic,
        CreationData the_creationData,
        byte[] the_creationHash,
        TkCreation the_creationTicket
        )
        {
            this.outPrivate = the_outPrivate;
            this.outPublic = the_outPublic;
            this.creationData = the_creationData;
            this.creationHash = the_creationHash;
            this.creationTicket = the_creationTicket;
        }
        new public Tpm2CreateResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2CreateResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to load objects into the TPM. This command is used when both a TPM2B_PUBLIC and TPM2B_PRIVATE are to be loaded. If only a TPM2B_PUBLIC is to be loaded, the TPM2_LoadExternal command is used.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmPrivate))]
    [KnownType(typeof(TpmPublic))]
    [SpecTypeName("TPM2_Load_REQUEST")]
    public partial class Tpm2LoadRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM handle of parent key; shall not be a reserved handle
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle parentHandle { get; set; }
        /// <summary>
        /// the private portion of the object
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmPrivate inPrivate { get; set; }
        /// <summary>
        /// the public portion of the object
        /// </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "inPublicSize", 2)]
        [DataMember()]
        public TpmPublic inPublic { get; set; }
        public Tpm2LoadRequest()
        {
            parentHandle = new TpmHandle();
            inPrivate = new TpmPrivate();
            inPublic = new TpmPublic();
        }
        public Tpm2LoadRequest(Tpm2LoadRequest the_Tpm2LoadRequest)
        {
            if((Object) the_Tpm2LoadRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            parentHandle = the_Tpm2LoadRequest.parentHandle;
            inPrivate = the_Tpm2LoadRequest.inPrivate;
            inPublic = the_Tpm2LoadRequest.inPublic;
        }
        ///<param name = "the_parentHandle">TPM handle of parent key; shall not be a reserved handle Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_inPrivate">the private portion of the object</param>
        ///<param name = "the_inPublic">the public portion of the object</param>
        public Tpm2LoadRequest(
        TpmHandle the_parentHandle,
        TpmPrivate the_inPrivate,
        TpmPublic the_inPublic
        )
        {
            this.parentHandle = the_parentHandle;
            this.inPrivate = the_inPrivate;
            this.inPublic = the_inPublic;
        }
        new public Tpm2LoadRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2LoadRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to load objects into the TPM. This command is used when both a TPM2B_PUBLIC and TPM2B_PRIVATE are to be loaded. If only a TPM2B_PUBLIC is to be loaded, the TPM2_LoadExternal command is used.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_Load_RESPONSE")]
    public partial class Tpm2LoadResponse: TpmStructureBase
    {
        /// <summary>
        /// handle of type TPM_HT_TRANSIENT for the loaded object
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle objectHandle { get; set; }
        /// <summary>
        /// Name of the loaded object
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "nameSize", 2)]
        [DataMember()]
        public byte[] name;
        public Tpm2LoadResponse()
        {
            objectHandle = new TpmHandle();
            name = null;
        }
        public Tpm2LoadResponse(Tpm2LoadResponse the_Tpm2LoadResponse)
        {
            if((Object) the_Tpm2LoadResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            objectHandle = the_Tpm2LoadResponse.objectHandle;
            name = the_Tpm2LoadResponse.name;
        }
        ///<param name = "the_objectHandle">handle of type TPM_HT_TRANSIENT for the loaded object</param>
        ///<param name = "the_name">Name of the loaded object</param>
        public Tpm2LoadResponse(
        TpmHandle the_objectHandle,
        byte[] the_name
        )
        {
            this.objectHandle = the_objectHandle;
            this.name = the_name;
        }
        new public Tpm2LoadResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2LoadResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to load an object that is not a Protected Object into the TPM. The command allows loading of a public area or both a public and sensitive area.
    /// </summary>
    [DataContract]
    [KnownType(typeof(Sensitive))]
    [KnownType(typeof(TpmPublic))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_LoadExternal_REQUEST")]
    public partial class Tpm2LoadExternalRequest: TpmStructureBase
    {
        /// <summary>
        /// the sensitive portion of the object (optional)
        /// </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "inPrivateSize", 2)]
        [DataMember()]
        public Sensitive inPrivate { get; set; }
        /// <summary>
        /// the public portion of the object
        /// </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "inPublicSize", 2)]
        [DataMember()]
        public TpmPublic inPublic { get; set; }
        /// <summary>
        /// hierarchy with which the object area is associated
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle hierarchy { get; set; }
        public Tpm2LoadExternalRequest()
        {
            inPrivate = new Sensitive();
            inPublic = new TpmPublic();
            hierarchy = new TpmHandle();
        }
        public Tpm2LoadExternalRequest(Tpm2LoadExternalRequest the_Tpm2LoadExternalRequest)
        {
            if((Object) the_Tpm2LoadExternalRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            inPrivate = the_Tpm2LoadExternalRequest.inPrivate;
            inPublic = the_Tpm2LoadExternalRequest.inPublic;
            hierarchy = the_Tpm2LoadExternalRequest.hierarchy;
        }
        ///<param name = "the_inPrivate">the sensitive portion of the object (optional)</param>
        ///<param name = "the_inPublic">the public portion of the object</param>
        ///<param name = "the_hierarchy">hierarchy with which the object area is associated</param>
        public Tpm2LoadExternalRequest(
        Sensitive the_inPrivate,
        TpmPublic the_inPublic,
        TpmHandle the_hierarchy
        )
        {
            this.inPrivate = the_inPrivate;
            this.inPublic = the_inPublic;
            this.hierarchy = the_hierarchy;
        }
        new public Tpm2LoadExternalRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2LoadExternalRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to load an object that is not a Protected Object into the TPM. The command allows loading of a public area or both a public and sensitive area.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_LoadExternal_RESPONSE")]
    public partial class Tpm2LoadExternalResponse: TpmStructureBase
    {
        /// <summary>
        /// handle of type TPM_HT_TRANSIENT for the loaded object
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle objectHandle { get; set; }
        /// <summary>
        /// name of the loaded object
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "nameSize", 2)]
        [DataMember()]
        public byte[] name;
        public Tpm2LoadExternalResponse()
        {
            objectHandle = new TpmHandle();
            name = null;
        }
        public Tpm2LoadExternalResponse(Tpm2LoadExternalResponse the_Tpm2LoadExternalResponse)
        {
            if((Object) the_Tpm2LoadExternalResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            objectHandle = the_Tpm2LoadExternalResponse.objectHandle;
            name = the_Tpm2LoadExternalResponse.name;
        }
        ///<param name = "the_objectHandle">handle of type TPM_HT_TRANSIENT for the loaded object</param>
        ///<param name = "the_name">name of the loaded object</param>
        public Tpm2LoadExternalResponse(
        TpmHandle the_objectHandle,
        byte[] the_name
        )
        {
            this.objectHandle = the_objectHandle;
            this.name = the_name;
        }
        new public Tpm2LoadExternalResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2LoadExternalResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows access to the public area of a loaded object.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_ReadPublic_REQUEST")]
    public partial class Tpm2ReadPublicRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM handle of an object
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle objectHandle { get; set; }
        public Tpm2ReadPublicRequest()
        {
            objectHandle = new TpmHandle();
        }
        public Tpm2ReadPublicRequest(Tpm2ReadPublicRequest the_Tpm2ReadPublicRequest)
        {
            if((Object) the_Tpm2ReadPublicRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            objectHandle = the_Tpm2ReadPublicRequest.objectHandle;
        }
        ///<param name = "the_objectHandle">TPM handle of an object Auth Index: None</param>
        public Tpm2ReadPublicRequest(
        TpmHandle the_objectHandle
        )
        {
            this.objectHandle = the_objectHandle;
        }
        new public Tpm2ReadPublicRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ReadPublicRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows access to the public area of a loaded object.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmPublic))]
    [SpecTypeName("TPM2_ReadPublic_RESPONSE")]
    public partial class Tpm2ReadPublicResponse: TpmStructureBase
    {
        /// <summary>
        /// structure containing the public area of an object
        /// </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "outPublicSize", 2)]
        [DataMember()]
        public TpmPublic outPublic { get; set; }
        /// <summary>
        /// name of the object
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "nameSize", 2)]
        [DataMember()]
        public byte[] name;
        /// <summary>
        /// the Qualified Name of the object
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "qualifiedNameSize", 2)]
        [DataMember()]
        public byte[] qualifiedName;
        public Tpm2ReadPublicResponse()
        {
            outPublic = new TpmPublic();
            name = null;
            qualifiedName = null;
        }
        public Tpm2ReadPublicResponse(Tpm2ReadPublicResponse the_Tpm2ReadPublicResponse)
        {
            if((Object) the_Tpm2ReadPublicResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            outPublic = the_Tpm2ReadPublicResponse.outPublic;
            name = the_Tpm2ReadPublicResponse.name;
            qualifiedName = the_Tpm2ReadPublicResponse.qualifiedName;
        }
        ///<param name = "the_outPublic">structure containing the public area of an object</param>
        ///<param name = "the_name">name of the object</param>
        ///<param name = "the_qualifiedName">the Qualified Name of the object</param>
        public Tpm2ReadPublicResponse(
        TpmPublic the_outPublic,
        byte[] the_name,
        byte[] the_qualifiedName
        )
        {
            this.outPublic = the_outPublic;
            this.name = the_name;
            this.qualifiedName = the_qualifiedName;
        }
        new public Tpm2ReadPublicResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ReadPublicResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command enables the association of a credential with an object in a way that ensures that the TPM has validated the parameters of the credentialed object.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_ActivateCredential_REQUEST")]
    public partial class Tpm2ActivateCredentialRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of the object associated with certificate in credentialBlob
        /// Auth Index: 1
        /// Auth Role: ADMIN
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle activateHandle { get; set; }
        /// <summary>
        /// loaded key used to decrypt the TPMS_SENSITIVE in credentialBlob
        /// Auth Index: 2
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }
        /// <summary>
        /// the credential
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "credentialBlobSize", 2)]
        [DataMember()]
        public byte[] credentialBlob;
        /// <summary>
        /// keyHandle algorithm-dependent encrypted seed that protects credentialBlob
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "secretSize", 2)]
        [DataMember()]
        public byte[] secret;
        public Tpm2ActivateCredentialRequest()
        {
            activateHandle = new TpmHandle();
            keyHandle = new TpmHandle();
            credentialBlob = null;
            secret = null;
        }
        public Tpm2ActivateCredentialRequest(Tpm2ActivateCredentialRequest the_Tpm2ActivateCredentialRequest)
        {
            if((Object) the_Tpm2ActivateCredentialRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            activateHandle = the_Tpm2ActivateCredentialRequest.activateHandle;
            keyHandle = the_Tpm2ActivateCredentialRequest.keyHandle;
            credentialBlob = the_Tpm2ActivateCredentialRequest.credentialBlob;
            secret = the_Tpm2ActivateCredentialRequest.secret;
        }
        ///<param name = "the_activateHandle">handle of the object associated with certificate in credentialBlob Auth Index: 1 Auth Role: ADMIN</param>
        ///<param name = "the_keyHandle">loaded key used to decrypt the TPMS_SENSITIVE in credentialBlob Auth Index: 2 Auth Role: USER</param>
        ///<param name = "the_credentialBlob">the credential</param>
        ///<param name = "the_secret">keyHandle algorithm-dependent encrypted seed that protects credentialBlob</param>
        public Tpm2ActivateCredentialRequest(
        TpmHandle the_activateHandle,
        TpmHandle the_keyHandle,
        byte[] the_credentialBlob,
        byte[] the_secret
        )
        {
            this.activateHandle = the_activateHandle;
            this.keyHandle = the_keyHandle;
            this.credentialBlob = the_credentialBlob;
            this.secret = the_secret;
        }
        new public Tpm2ActivateCredentialRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ActivateCredentialRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command enables the association of a credential with an object in a way that ensures that the TPM has validated the parameters of the credentialed object.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_ActivateCredential_RESPONSE")]
    public partial class Tpm2ActivateCredentialResponse: TpmStructureBase
    {
        /// <summary>
        /// the decrypted certificate information
        /// the data should be no larger than the size of the digest of the nameAlg associated with keyHandle
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "certInfoSize", 2)]
        [DataMember()]
        public byte[] certInfo;
        public Tpm2ActivateCredentialResponse()
        {
            certInfo = null;
        }
        public Tpm2ActivateCredentialResponse(Tpm2ActivateCredentialResponse the_Tpm2ActivateCredentialResponse)
        {
            if((Object) the_Tpm2ActivateCredentialResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            certInfo = the_Tpm2ActivateCredentialResponse.certInfo;
        }
        ///<param name = "the_certInfo">the decrypted certificate information the data should be no larger than the size of the digest of the nameAlg associated with keyHandle</param>
        public Tpm2ActivateCredentialResponse(
        byte[] the_certInfo
        )
        {
            this.certInfo = the_certInfo;
        }
        new public Tpm2ActivateCredentialResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ActivateCredentialResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows the TPM to perform the actions required of a Certificate Authority (CA) in creating a TPM2B_ID_OBJECT containing an activation credential.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_MakeCredential_REQUEST")]
    public partial class Tpm2MakeCredentialRequest: TpmStructureBase
    {
        /// <summary>
        /// loaded public area, used to encrypt the sensitive area containing the credential key
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }
        /// <summary>
        /// the credential information
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "credentialSize", 2)]
        [DataMember()]
        public byte[] credential;
        /// <summary>
        /// Name of the object to which the credential applies
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "objectNameSize", 2)]
        [DataMember()]
        public byte[] objectName;
        public Tpm2MakeCredentialRequest()
        {
            handle = new TpmHandle();
            credential = null;
            objectName = null;
        }
        public Tpm2MakeCredentialRequest(Tpm2MakeCredentialRequest the_Tpm2MakeCredentialRequest)
        {
            if((Object) the_Tpm2MakeCredentialRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            handle = the_Tpm2MakeCredentialRequest.handle;
            credential = the_Tpm2MakeCredentialRequest.credential;
            objectName = the_Tpm2MakeCredentialRequest.objectName;
        }
        ///<param name = "the_handle">loaded public area, used to encrypt the sensitive area containing the credential key Auth Index: None</param>
        ///<param name = "the_credential">the credential information</param>
        ///<param name = "the_objectName">Name of the object to which the credential applies</param>
        public Tpm2MakeCredentialRequest(
        TpmHandle the_handle,
        byte[] the_credential,
        byte[] the_objectName
        )
        {
            this.handle = the_handle;
            this.credential = the_credential;
            this.objectName = the_objectName;
        }
        new public Tpm2MakeCredentialRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2MakeCredentialRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows the TPM to perform the actions required of a Certificate Authority (CA) in creating a TPM2B_ID_OBJECT containing an activation credential.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_MakeCredential_RESPONSE")]
    public partial class Tpm2MakeCredentialResponse: TpmStructureBase
    {
        /// <summary>
        /// the credential
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "credentialBlobSize", 2)]
        [DataMember()]
        public byte[] credentialBlob;
        /// <summary>
        /// handle algorithm-dependent data that wraps the key that encrypts credentialBlob
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "secretSize", 2)]
        [DataMember()]
        public byte[] secret;
        public Tpm2MakeCredentialResponse()
        {
            credentialBlob = null;
            secret = null;
        }
        public Tpm2MakeCredentialResponse(Tpm2MakeCredentialResponse the_Tpm2MakeCredentialResponse)
        {
            if((Object) the_Tpm2MakeCredentialResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            credentialBlob = the_Tpm2MakeCredentialResponse.credentialBlob;
            secret = the_Tpm2MakeCredentialResponse.secret;
        }
        ///<param name = "the_credentialBlob">the credential</param>
        ///<param name = "the_secret">handle algorithm-dependent data that wraps the key that encrypts credentialBlob</param>
        public Tpm2MakeCredentialResponse(
        byte[] the_credentialBlob,
        byte[] the_secret
        )
        {
            this.credentialBlob = the_credentialBlob;
            this.secret = the_secret;
        }
        new public Tpm2MakeCredentialResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2MakeCredentialResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns the data in a loaded Sealed Data Object.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_Unseal_REQUEST")]
    public partial class Tpm2UnsealRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of a loaded data object
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle itemHandle { get; set; }
        public Tpm2UnsealRequest()
        {
            itemHandle = new TpmHandle();
        }
        public Tpm2UnsealRequest(Tpm2UnsealRequest the_Tpm2UnsealRequest)
        {
            if((Object) the_Tpm2UnsealRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            itemHandle = the_Tpm2UnsealRequest.itemHandle;
        }
        ///<param name = "the_itemHandle">handle of a loaded data object Auth Index: 1 Auth Role: USER</param>
        public Tpm2UnsealRequest(
        TpmHandle the_itemHandle
        )
        {
            this.itemHandle = the_itemHandle;
        }
        new public Tpm2UnsealRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2UnsealRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns the data in a loaded Sealed Data Object.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_Unseal_RESPONSE")]
    public partial class Tpm2UnsealResponse: TpmStructureBase
    {
        /// <summary>
        /// unsealed data
        /// Size of outData is limited to be no more than 128 octets.
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "outDataSize", 2)]
        [DataMember()]
        public byte[] outData;
        public Tpm2UnsealResponse()
        {
            outData = null;
        }
        public Tpm2UnsealResponse(Tpm2UnsealResponse the_Tpm2UnsealResponse)
        {
            if((Object) the_Tpm2UnsealResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            outData = the_Tpm2UnsealResponse.outData;
        }
        ///<param name = "the_outData">unsealed data Size of outData is limited to be no more than 128 octets.</param>
        public Tpm2UnsealResponse(
        byte[] the_outData
        )
        {
            this.outData = the_outData;
        }
        new public Tpm2UnsealResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2UnsealResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to change the authorization secret for a TPM-resident object.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_ObjectChangeAuth_REQUEST")]
    public partial class Tpm2ObjectChangeAuthRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of the object
        /// Auth Index: 1
        /// Auth Role: ADMIN
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle objectHandle { get; set; }
        /// <summary>
        /// handle of the parent
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle parentHandle { get; set; }
        /// <summary>
        /// new authorization value
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "newAuthSize", 2)]
        [DataMember()]
        public byte[] newAuth;
        public Tpm2ObjectChangeAuthRequest()
        {
            objectHandle = new TpmHandle();
            parentHandle = new TpmHandle();
            newAuth = null;
        }
        public Tpm2ObjectChangeAuthRequest(Tpm2ObjectChangeAuthRequest the_Tpm2ObjectChangeAuthRequest)
        {
            if((Object) the_Tpm2ObjectChangeAuthRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            objectHandle = the_Tpm2ObjectChangeAuthRequest.objectHandle;
            parentHandle = the_Tpm2ObjectChangeAuthRequest.parentHandle;
            newAuth = the_Tpm2ObjectChangeAuthRequest.newAuth;
        }
        ///<param name = "the_objectHandle">handle of the object Auth Index: 1 Auth Role: ADMIN</param>
        ///<param name = "the_parentHandle">handle of the parent Auth Index: None</param>
        ///<param name = "the_newAuth">new authorization value</param>
        public Tpm2ObjectChangeAuthRequest(
        TpmHandle the_objectHandle,
        TpmHandle the_parentHandle,
        byte[] the_newAuth
        )
        {
            this.objectHandle = the_objectHandle;
            this.parentHandle = the_parentHandle;
            this.newAuth = the_newAuth;
        }
        new public Tpm2ObjectChangeAuthRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ObjectChangeAuthRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to change the authorization secret for a TPM-resident object.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmPrivate))]
    [SpecTypeName("TPM2_ObjectChangeAuth_RESPONSE")]
    public partial class Tpm2ObjectChangeAuthResponse: TpmStructureBase
    {
        /// <summary>
        /// private area containing the new authorization value
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmPrivate outPrivate { get; set; }
        public Tpm2ObjectChangeAuthResponse()
        {
            outPrivate = new TpmPrivate();
        }
        public Tpm2ObjectChangeAuthResponse(Tpm2ObjectChangeAuthResponse the_Tpm2ObjectChangeAuthResponse)
        {
            if((Object) the_Tpm2ObjectChangeAuthResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            outPrivate = the_Tpm2ObjectChangeAuthResponse.outPrivate;
        }
        ///<param name = "the_outPrivate">private area containing the new authorization value</param>
        public Tpm2ObjectChangeAuthResponse(
        TpmPrivate the_outPrivate
        )
        {
            this.outPrivate = the_outPrivate;
        }
        new public Tpm2ObjectChangeAuthResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ObjectChangeAuthResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command creates an object and loads it in the TPM. This command allows creation of any type of object (Primary, Ordinary, or Derived) depending on the type of parentHandle. If parentHandle references a Primary Seed, then a Primary Object is created; if parentHandle references a Storage Parent, then an Ordinary Object is created; and if parentHandle references a Derivation Parent, then a Derived Object is generated.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(SensitiveCreate))]
    [SpecTypeName("TPM2_CreateLoaded_REQUEST")]
    public partial class Tpm2CreateLoadedRequest: TpmStructureBase
    {
        /// <summary>
        /// Handle of a transient storage key, a persistent storage key, TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP}, or TPM_RH_NULL
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle parentHandle { get; set; }
        /// <summary>
        /// the sensitive data, see TPM 2.0 Part 1 Sensitive Values
        /// </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "inSensitiveSize", 2)]
        [DataMember()]
        public SensitiveCreate inSensitive { get; set; }
        /// <summary>
        /// the public template
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "inPublicSize", 2)]
        [DataMember()]
        public byte[] inPublic;
        public Tpm2CreateLoadedRequest()
        {
            parentHandle = new TpmHandle();
            inSensitive = new SensitiveCreate();
            inPublic = null;
        }
        public Tpm2CreateLoadedRequest(Tpm2CreateLoadedRequest the_Tpm2CreateLoadedRequest)
        {
            if((Object) the_Tpm2CreateLoadedRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            parentHandle = the_Tpm2CreateLoadedRequest.parentHandle;
            inSensitive = the_Tpm2CreateLoadedRequest.inSensitive;
            inPublic = the_Tpm2CreateLoadedRequest.inPublic;
        }
        ///<param name = "the_parentHandle">Handle of a transient storage key, a persistent storage key, TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP}, or TPM_RH_NULL Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_inSensitive">the sensitive data, see TPM 2.0 Part 1 Sensitive Values</param>
        ///<param name = "the_inPublic">the public template</param>
        public Tpm2CreateLoadedRequest(
        TpmHandle the_parentHandle,
        SensitiveCreate the_inSensitive,
        byte[] the_inPublic
        )
        {
            this.parentHandle = the_parentHandle;
            this.inSensitive = the_inSensitive;
            this.inPublic = the_inPublic;
        }
        new public Tpm2CreateLoadedRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2CreateLoadedRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command creates an object and loads it in the TPM. This command allows creation of any type of object (Primary, Ordinary, or Derived) depending on the type of parentHandle. If parentHandle references a Primary Seed, then a Primary Object is created; if parentHandle references a Storage Parent, then an Ordinary Object is created; and if parentHandle references a Derivation Parent, then a Derived Object is generated.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmPrivate))]
    [KnownType(typeof(TpmPublic))]
    [SpecTypeName("TPM2_CreateLoaded_RESPONSE")]
    public partial class Tpm2CreateLoadedResponse: TpmStructureBase
    {
        /// <summary>
        /// handle of type TPM_HT_TRANSIENT for created object
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle objectHandle { get; set; }
        /// <summary>
        /// the sensitive area of the object (optional)
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmPrivate outPrivate { get; set; }
        /// <summary>
        /// the public portion of the created object
        /// </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "outPublicSize", 2)]
        [DataMember()]
        public TpmPublic outPublic { get; set; }
        /// <summary>
        /// the name of the created object
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "nameSize", 2)]
        [DataMember()]
        public byte[] name;
        public Tpm2CreateLoadedResponse()
        {
            objectHandle = new TpmHandle();
            outPrivate = new TpmPrivate();
            outPublic = new TpmPublic();
            name = null;
        }
        public Tpm2CreateLoadedResponse(Tpm2CreateLoadedResponse the_Tpm2CreateLoadedResponse)
        {
            if((Object) the_Tpm2CreateLoadedResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            objectHandle = the_Tpm2CreateLoadedResponse.objectHandle;
            outPrivate = the_Tpm2CreateLoadedResponse.outPrivate;
            outPublic = the_Tpm2CreateLoadedResponse.outPublic;
            name = the_Tpm2CreateLoadedResponse.name;
        }
        ///<param name = "the_objectHandle">handle of type TPM_HT_TRANSIENT for created object</param>
        ///<param name = "the_outPrivate">the sensitive area of the object (optional)</param>
        ///<param name = "the_outPublic">the public portion of the created object</param>
        ///<param name = "the_name">the name of the created object</param>
        public Tpm2CreateLoadedResponse(
        TpmHandle the_objectHandle,
        TpmPrivate the_outPrivate,
        TpmPublic the_outPublic,
        byte[] the_name
        )
        {
            this.objectHandle = the_objectHandle;
            this.outPrivate = the_outPrivate;
            this.outPublic = the_outPublic;
            this.name = the_name;
        }
        new public Tpm2CreateLoadedResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2CreateLoadedResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command duplicates a loaded object so that it may be used in a different hierarchy. The new parent key for the duplicate may be on the same or different TPM or TPM_RH_NULL. Only the public area of newParentHandle is required to be loaded.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(SymDefObject))]
    [SpecTypeName("TPM2_Duplicate_REQUEST")]
    public partial class Tpm2DuplicateRequest: TpmStructureBase
    {
        /// <summary>
        /// loaded object to duplicate
        /// Auth Index: 1
        /// Auth Role: DUP
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle objectHandle { get; set; }
        /// <summary>
        /// shall reference the public area of an asymmetric key
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle newParentHandle { get; set; }
        /// <summary>
        /// optional symmetric encryption key
        /// The size for this key is set to zero when the TPM is to generate the key. This parameter may be encrypted.
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "encryptionKeyInSize", 2)]
        [DataMember()]
        public byte[] encryptionKeyIn;
        /// <summary>
        /// definition for the symmetric algorithm to be used for the inner wrapper
        /// may be TPM_ALG_NULL if no inner wrapper is applied
        /// </summary>
        [MarshalAs(3)]
        [DataMember()]
        public SymDefObject symmetricAlg { get; set; }
        public Tpm2DuplicateRequest()
        {
            objectHandle = new TpmHandle();
            newParentHandle = new TpmHandle();
            encryptionKeyIn = null;
            symmetricAlg = new SymDefObject();
        }
        public Tpm2DuplicateRequest(Tpm2DuplicateRequest the_Tpm2DuplicateRequest)
        {
            if((Object) the_Tpm2DuplicateRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            objectHandle = the_Tpm2DuplicateRequest.objectHandle;
            newParentHandle = the_Tpm2DuplicateRequest.newParentHandle;
            encryptionKeyIn = the_Tpm2DuplicateRequest.encryptionKeyIn;
            symmetricAlg = the_Tpm2DuplicateRequest.symmetricAlg;
        }
        ///<param name = "the_objectHandle">loaded object to duplicate Auth Index: 1 Auth Role: DUP</param>
        ///<param name = "the_newParentHandle">shall reference the public area of an asymmetric key Auth Index: None</param>
        ///<param name = "the_encryptionKeyIn">optional symmetric encryption key The size for this key is set to zero when the TPM is to generate the key. This parameter may be encrypted.</param>
        ///<param name = "the_symmetricAlg">definition for the symmetric algorithm to be used for the inner wrapper may be TPM_ALG_NULL if no inner wrapper is applied</param>
        public Tpm2DuplicateRequest(
        TpmHandle the_objectHandle,
        TpmHandle the_newParentHandle,
        byte[] the_encryptionKeyIn,
        SymDefObject the_symmetricAlg
        )
        {
            this.objectHandle = the_objectHandle;
            this.newParentHandle = the_newParentHandle;
            this.encryptionKeyIn = the_encryptionKeyIn;
            this.symmetricAlg = the_symmetricAlg;
        }
        new public Tpm2DuplicateRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2DuplicateRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command duplicates a loaded object so that it may be used in a different hierarchy. The new parent key for the duplicate may be on the same or different TPM or TPM_RH_NULL. Only the public area of newParentHandle is required to be loaded.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmPrivate))]
    [SpecTypeName("TPM2_Duplicate_RESPONSE")]
    public partial class Tpm2DuplicateResponse: TpmStructureBase
    {
        /// <summary>
        /// If the caller provided an encryption key or if symmetricAlg was TPM_ALG_NULL, then this will be the Empty Buffer; otherwise, it shall contain the TPM-generated, symmetric encryption key for the inner wrapper.
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "encryptionKeyOutSize", 2)]
        [DataMember()]
        public byte[] encryptionKeyOut;
        /// <summary>
        /// private area that may be encrypted by encryptionKeyIn; and may be doubly encrypted
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmPrivate duplicate { get; set; }
        /// <summary>
        /// seed protected by the asymmetric algorithms of new parent (NP)
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "outSymSeedSize", 2)]
        [DataMember()]
        public byte[] outSymSeed;
        public Tpm2DuplicateResponse()
        {
            encryptionKeyOut = null;
            duplicate = new TpmPrivate();
            outSymSeed = null;
        }
        public Tpm2DuplicateResponse(Tpm2DuplicateResponse the_Tpm2DuplicateResponse)
        {
            if((Object) the_Tpm2DuplicateResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            encryptionKeyOut = the_Tpm2DuplicateResponse.encryptionKeyOut;
            duplicate = the_Tpm2DuplicateResponse.duplicate;
            outSymSeed = the_Tpm2DuplicateResponse.outSymSeed;
        }
        ///<param name = "the_encryptionKeyOut">If the caller provided an encryption key or if symmetricAlg was TPM_ALG_NULL, then this will be the Empty Buffer; otherwise, it shall contain the TPM-generated, symmetric encryption key for the inner wrapper.</param>
        ///<param name = "the_duplicate">private area that may be encrypted by encryptionKeyIn; and may be doubly encrypted</param>
        ///<param name = "the_outSymSeed">seed protected by the asymmetric algorithms of new parent (NP)</param>
        public Tpm2DuplicateResponse(
        byte[] the_encryptionKeyOut,
        TpmPrivate the_duplicate,
        byte[] the_outSymSeed
        )
        {
            this.encryptionKeyOut = the_encryptionKeyOut;
            this.duplicate = the_duplicate;
            this.outSymSeed = the_outSymSeed;
        }
        new public Tpm2DuplicateResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2DuplicateResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows the TPM to serve in the role as a Duplication Authority. If proper authorization for use of the oldParent is provided, then an HMAC key and a symmetric key are recovered from inSymSeed and used to integrity check and decrypt inDuplicate. A new protection seed value is generated according to the methods appropriate for newParent and the blob is re-encrypted and a new integrity value is computed. The re-encrypted blob is returned in outDuplicate and the symmetric key returned in outSymKey.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmPrivate))]
    [SpecTypeName("TPM2_Rewrap_REQUEST")]
    public partial class Tpm2RewrapRequest: TpmStructureBase
    {
        /// <summary>
        /// parent of object
        /// Auth Index: 1
        /// Auth Role: User
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle oldParent { get; set; }
        /// <summary>
        /// new parent of the object
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle newParent { get; set; }
        /// <summary>
        /// an object encrypted using symmetric key derived from inSymSeed
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmPrivate inDuplicate { get; set; }
        /// <summary>
        /// the Name of the object being rewrapped
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "nameSize", 2)]
        [DataMember()]
        public byte[] name;
        /// <summary>
        /// the seed for the symmetric key and HMAC key
        /// needs oldParent private key to recover the seed and generate the symmetric key
        /// </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "inSymSeedSize", 2)]
        [DataMember()]
        public byte[] inSymSeed;
        public Tpm2RewrapRequest()
        {
            oldParent = new TpmHandle();
            newParent = new TpmHandle();
            inDuplicate = new TpmPrivate();
            name = null;
            inSymSeed = null;
        }
        public Tpm2RewrapRequest(Tpm2RewrapRequest the_Tpm2RewrapRequest)
        {
            if((Object) the_Tpm2RewrapRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            oldParent = the_Tpm2RewrapRequest.oldParent;
            newParent = the_Tpm2RewrapRequest.newParent;
            inDuplicate = the_Tpm2RewrapRequest.inDuplicate;
            name = the_Tpm2RewrapRequest.name;
            inSymSeed = the_Tpm2RewrapRequest.inSymSeed;
        }
        ///<param name = "the_oldParent">parent of object Auth Index: 1 Auth Role: User</param>
        ///<param name = "the_newParent">new parent of the object Auth Index: None</param>
        ///<param name = "the_inDuplicate">an object encrypted using symmetric key derived from inSymSeed</param>
        ///<param name = "the_name">the Name of the object being rewrapped</param>
        ///<param name = "the_inSymSeed">the seed for the symmetric key and HMAC key needs oldParent private key to recover the seed and generate the symmetric key</param>
        public Tpm2RewrapRequest(
        TpmHandle the_oldParent,
        TpmHandle the_newParent,
        TpmPrivate the_inDuplicate,
        byte[] the_name,
        byte[] the_inSymSeed
        )
        {
            this.oldParent = the_oldParent;
            this.newParent = the_newParent;
            this.inDuplicate = the_inDuplicate;
            this.name = the_name;
            this.inSymSeed = the_inSymSeed;
        }
        new public Tpm2RewrapRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2RewrapRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows the TPM to serve in the role as a Duplication Authority. If proper authorization for use of the oldParent is provided, then an HMAC key and a symmetric key are recovered from inSymSeed and used to integrity check and decrypt inDuplicate. A new protection seed value is generated according to the methods appropriate for newParent and the blob is re-encrypted and a new integrity value is computed. The re-encrypted blob is returned in outDuplicate and the symmetric key returned in outSymKey.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmPrivate))]
    [SpecTypeName("TPM2_Rewrap_RESPONSE")]
    public partial class Tpm2RewrapResponse: TpmStructureBase
    {
        /// <summary>
        /// an object encrypted using symmetric key derived from outSymSeed
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmPrivate outDuplicate { get; set; }
        /// <summary>
        /// seed for a symmetric key protected by newParent asymmetric key
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "outSymSeedSize", 2)]
        [DataMember()]
        public byte[] outSymSeed;
        public Tpm2RewrapResponse()
        {
            outDuplicate = new TpmPrivate();
            outSymSeed = null;
        }
        public Tpm2RewrapResponse(Tpm2RewrapResponse the_Tpm2RewrapResponse)
        {
            if((Object) the_Tpm2RewrapResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            outDuplicate = the_Tpm2RewrapResponse.outDuplicate;
            outSymSeed = the_Tpm2RewrapResponse.outSymSeed;
        }
        ///<param name = "the_outDuplicate">an object encrypted using symmetric key derived from outSymSeed</param>
        ///<param name = "the_outSymSeed">seed for a symmetric key protected by newParent asymmetric key</param>
        public Tpm2RewrapResponse(
        TpmPrivate the_outDuplicate,
        byte[] the_outSymSeed
        )
        {
            this.outDuplicate = the_outDuplicate;
            this.outSymSeed = the_outSymSeed;
        }
        new public Tpm2RewrapResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2RewrapResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows an object to be encrypted using the symmetric encryption values of a Storage Key. After encryption, the object may be loaded and used in the new hierarchy. The imported object (duplicate) may be singly encrypted, multiply encrypted, or unencrypted.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmPublic))]
    [KnownType(typeof(TpmPrivate))]
    [KnownType(typeof(SymDefObject))]
    [SpecTypeName("TPM2_Import_REQUEST")]
    public partial class Tpm2ImportRequest: TpmStructureBase
    {
        /// <summary>
        /// the handle of the new parent for the object
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle parentHandle { get; set; }
        /// <summary>
        /// the optional symmetric encryption key used as the inner wrapper for duplicate
        /// If symmetricAlg is TPM_ALG_NULL, then this parameter shall be the Empty Buffer.
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "encryptionKeySize", 2)]
        [DataMember()]
        public byte[] encryptionKey;
        /// <summary>
        /// the public area of the object to be imported
        /// This is provided so that the integrity value for duplicate and the object attributes can be checked.
        /// NOTE	Even if the integrity value of the object is not checked on input, the object Name is required to create the integrity value for the imported object.
        /// </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "objectPublicSize", 2)]
        [DataMember()]
        public TpmPublic objectPublic { get; set; }
        /// <summary>
        /// the symmetrically encrypted duplicate object that may contain an inner symmetric wrapper
        /// </summary>
        [MarshalAs(3)]
        [DataMember()]
        public TpmPrivate duplicate { get; set; }
        /// <summary>
        /// the seed for the symmetric key and HMAC key
        /// inSymSeed is encrypted/encoded using the algorithms of newParent.
        /// </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "inSymSeedSize", 2)]
        [DataMember()]
        public byte[] inSymSeed;
        /// <summary>
        /// definition for the symmetric algorithm to use for the inner wrapper
        /// If this algorithm is TPM_ALG_NULL, no inner wrapper is present and encryptionKey shall be the Empty Buffer.
        /// </summary>
        [MarshalAs(5)]
        [DataMember()]
        public SymDefObject symmetricAlg { get; set; }
        public Tpm2ImportRequest()
        {
            parentHandle = new TpmHandle();
            encryptionKey = null;
            objectPublic = new TpmPublic();
            duplicate = new TpmPrivate();
            inSymSeed = null;
            symmetricAlg = new SymDefObject();
        }
        public Tpm2ImportRequest(Tpm2ImportRequest the_Tpm2ImportRequest)
        {
            if((Object) the_Tpm2ImportRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            parentHandle = the_Tpm2ImportRequest.parentHandle;
            encryptionKey = the_Tpm2ImportRequest.encryptionKey;
            objectPublic = the_Tpm2ImportRequest.objectPublic;
            duplicate = the_Tpm2ImportRequest.duplicate;
            inSymSeed = the_Tpm2ImportRequest.inSymSeed;
            symmetricAlg = the_Tpm2ImportRequest.symmetricAlg;
        }
        ///<param name = "the_parentHandle">the handle of the new parent for the object Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_encryptionKey">the optional symmetric encryption key used as the inner wrapper for duplicate If symmetricAlg is TPM_ALG_NULL, then this parameter shall be the Empty Buffer.</param>
        ///<param name = "the_objectPublic">the public area of the object to be imported This is provided so that the integrity value for duplicate and the object attributes can be checked. NOTE	Even if the integrity value of the object is not checked on input, the object Name is required to create the integrity value for the imported object.</param>
        ///<param name = "the_duplicate">the symmetrically encrypted duplicate object that may contain an inner symmetric wrapper</param>
        ///<param name = "the_inSymSeed">the seed for the symmetric key and HMAC key inSymSeed is encrypted/encoded using the algorithms of newParent.</param>
        ///<param name = "the_symmetricAlg">definition for the symmetric algorithm to use for the inner wrapper If this algorithm is TPM_ALG_NULL, no inner wrapper is present and encryptionKey shall be the Empty Buffer.</param>
        public Tpm2ImportRequest(
        TpmHandle the_parentHandle,
        byte[] the_encryptionKey,
        TpmPublic the_objectPublic,
        TpmPrivate the_duplicate,
        byte[] the_inSymSeed,
        SymDefObject the_symmetricAlg
        )
        {
            this.parentHandle = the_parentHandle;
            this.encryptionKey = the_encryptionKey;
            this.objectPublic = the_objectPublic;
            this.duplicate = the_duplicate;
            this.inSymSeed = the_inSymSeed;
            this.symmetricAlg = the_symmetricAlg;
        }
        new public Tpm2ImportRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ImportRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows an object to be encrypted using the symmetric encryption values of a Storage Key. After encryption, the object may be loaded and used in the new hierarchy. The imported object (duplicate) may be singly encrypted, multiply encrypted, or unencrypted.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmPrivate))]
    [SpecTypeName("TPM2_Import_RESPONSE")]
    public partial class Tpm2ImportResponse: TpmStructureBase
    {
        /// <summary>
        /// the sensitive area encrypted with the symmetric key of parentHandle
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmPrivate outPrivate { get; set; }
        public Tpm2ImportResponse()
        {
            outPrivate = new TpmPrivate();
        }
        public Tpm2ImportResponse(Tpm2ImportResponse the_Tpm2ImportResponse)
        {
            if((Object) the_Tpm2ImportResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            outPrivate = the_Tpm2ImportResponse.outPrivate;
        }
        ///<param name = "the_outPrivate">the sensitive area encrypted with the symmetric key of parentHandle</param>
        public Tpm2ImportResponse(
        TpmPrivate the_outPrivate
        )
        {
            this.outPrivate = the_outPrivate;
        }
        new public Tpm2ImportResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ImportResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command performs RSA encryption using the indicated padding scheme according to IETF RFC 3447. If the scheme of keyHandle is TPM_ALG_NULL, then the caller may use inScheme to specify the padding scheme. If scheme of keyHandle is not TPM_ALG_NULL, then inScheme shall either be TPM_ALG_NULL or be the same as scheme (TPM_RC_SCHEME).
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(Empty))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [SpecTypeName("TPM2_RSA_Encrypt_REQUEST")]
    public partial class Tpm2RsaEncryptRequest: TpmStructureBase
    {
        /// <summary>
        /// reference to public portion of RSA key to use for encryption
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }
        /// <summary>
        /// message to be encrypted
        /// NOTE 1	The data type was chosen because it limits the overall size of the input to no greater than the size of the largest RSA public key. This may be larger than allowed for keyHandle.
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "messageSize", 2)]
        [DataMember()]
        public byte[] message;
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(2, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get {
                if(inScheme != null) {
                    return (TpmAlgId)inScheme.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// the padding scheme to use if scheme associated with keyHandle is TPM_ALG_NULL
        /// (One of [KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme])
        /// </summary>
        [MarshalAs(3, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public IAsymSchemeUnion inScheme { get; set; }
        /// <summary>
        /// optional label L to be associated with the message
        /// Size of the buffer is zero if no label is present
        /// NOTE 2	See description of label above.
        /// </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "labelSize", 2)]
        [DataMember()]
        public byte[] label;
        public Tpm2RsaEncryptRequest()
        {
            keyHandle = new TpmHandle();
            message = null;
            label = null;
        }
        public Tpm2RsaEncryptRequest(Tpm2RsaEncryptRequest the_Tpm2RsaEncryptRequest)
        {
            if((Object) the_Tpm2RsaEncryptRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            keyHandle = the_Tpm2RsaEncryptRequest.keyHandle;
            message = the_Tpm2RsaEncryptRequest.message;
            label = the_Tpm2RsaEncryptRequest.label;
        }
        ///<param name = "the_keyHandle">reference to public portion of RSA key to use for encryption Auth Index: None</param>
        ///<param name = "the_message">message to be encrypted NOTE 1	The data type was chosen because it limits the overall size of the input to no greater than the size of the largest RSA public key. This may be larger than allowed for keyHandle.</param>
        ///<param name = "the_inScheme">the padding scheme to use if scheme associated with keyHandle is TPM_ALG_NULL(One of KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme)</param>
        ///<param name = "the_label">optional label L to be associated with the message Size of the buffer is zero if no label is present NOTE 2	See description of label above.</param>
        public Tpm2RsaEncryptRequest(
        TpmHandle the_keyHandle,
        byte[] the_message,
        IAsymSchemeUnion the_inScheme,
        byte[] the_label
        )
        {
            this.keyHandle = the_keyHandle;
            this.message = the_message;
            this.inScheme = the_inScheme;
            this.label = the_label;
        }
        new public Tpm2RsaEncryptRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2RsaEncryptRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command performs RSA encryption using the indicated padding scheme according to IETF RFC 3447. If the scheme of keyHandle is TPM_ALG_NULL, then the caller may use inScheme to specify the padding scheme. If scheme of keyHandle is not TPM_ALG_NULL, then inScheme shall either be TPM_ALG_NULL or be the same as scheme (TPM_RC_SCHEME).
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_RSA_Encrypt_RESPONSE")]
    public partial class Tpm2RsaEncryptResponse: TpmStructureBase
    {
        /// <summary>
        /// encrypted output
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "outDataSize", 2)]
        [DataMember()]
        public byte[] outData;
        public Tpm2RsaEncryptResponse()
        {
            outData = null;
        }
        public Tpm2RsaEncryptResponse(Tpm2RsaEncryptResponse the_Tpm2RsaEncryptResponse)
        {
            if((Object) the_Tpm2RsaEncryptResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            outData = the_Tpm2RsaEncryptResponse.outData;
        }
        ///<param name = "the_outData">encrypted output</param>
        public Tpm2RsaEncryptResponse(
        byte[] the_outData
        )
        {
            this.outData = the_outData;
        }
        new public Tpm2RsaEncryptResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2RsaEncryptResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command performs RSA decryption using the indicated padding scheme according to IETF RFC 3447 ((PKCS#1).
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(Empty))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [SpecTypeName("TPM2_RSA_Decrypt_REQUEST")]
    public partial class Tpm2RsaDecryptRequest: TpmStructureBase
    {
        /// <summary>
        /// RSA key to use for decryption
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }
        /// <summary>
        /// cipher text to be decrypted
        /// NOTE	An encrypted RSA data block is the size of the public modulus.
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "cipherTextSize", 2)]
        [DataMember()]
        public byte[] cipherText;
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(2, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get {
                if(inScheme != null) {
                    return (TpmAlgId)inScheme.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// the padding scheme to use if scheme associated with keyHandle is TPM_ALG_NULL
        /// (One of [KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme])
        /// </summary>
        [MarshalAs(3, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public IAsymSchemeUnion inScheme { get; set; }
        /// <summary>
        /// label whose association with the message is to be verified
        /// </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "labelSize", 2)]
        [DataMember()]
        public byte[] label;
        public Tpm2RsaDecryptRequest()
        {
            keyHandle = new TpmHandle();
            cipherText = null;
            label = null;
        }
        public Tpm2RsaDecryptRequest(Tpm2RsaDecryptRequest the_Tpm2RsaDecryptRequest)
        {
            if((Object) the_Tpm2RsaDecryptRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            keyHandle = the_Tpm2RsaDecryptRequest.keyHandle;
            cipherText = the_Tpm2RsaDecryptRequest.cipherText;
            label = the_Tpm2RsaDecryptRequest.label;
        }
        ///<param name = "the_keyHandle">RSA key to use for decryption Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_cipherText">cipher text to be decrypted NOTE	An encrypted RSA data block is the size of the public modulus.</param>
        ///<param name = "the_inScheme">the padding scheme to use if scheme associated with keyHandle is TPM_ALG_NULL(One of KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes, EncSchemeOaep, SchemeHash, NullAsymScheme)</param>
        ///<param name = "the_label">label whose association with the message is to be verified</param>
        public Tpm2RsaDecryptRequest(
        TpmHandle the_keyHandle,
        byte[] the_cipherText,
        IAsymSchemeUnion the_inScheme,
        byte[] the_label
        )
        {
            this.keyHandle = the_keyHandle;
            this.cipherText = the_cipherText;
            this.inScheme = the_inScheme;
            this.label = the_label;
        }
        new public Tpm2RsaDecryptRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2RsaDecryptRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command performs RSA decryption using the indicated padding scheme according to IETF RFC 3447 ((PKCS#1).
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_RSA_Decrypt_RESPONSE")]
    public partial class Tpm2RsaDecryptResponse: TpmStructureBase
    {
        /// <summary>
        /// decrypted output
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "messageSize", 2)]
        [DataMember()]
        public byte[] message;
        public Tpm2RsaDecryptResponse()
        {
            message = null;
        }
        public Tpm2RsaDecryptResponse(Tpm2RsaDecryptResponse the_Tpm2RsaDecryptResponse)
        {
            if((Object) the_Tpm2RsaDecryptResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            message = the_Tpm2RsaDecryptResponse.message;
        }
        ///<param name = "the_message">decrypted output</param>
        public Tpm2RsaDecryptResponse(
        byte[] the_message
        )
        {
            this.message = the_message;
        }
        new public Tpm2RsaDecryptResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2RsaDecryptResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command uses the TPM to generate an ephemeral key pair (de, Qe where Qe  [de]G). It uses the private ephemeral key and a loaded public key (QS) to compute the shared secret value (P  [hde]QS).
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_ECDH_KeyGen_REQUEST")]
    public partial class Tpm2EcdhKeyGenRequest: TpmStructureBase
    {
        /// <summary>
        /// Handle of a loaded ECC key public area.
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }
        public Tpm2EcdhKeyGenRequest()
        {
            keyHandle = new TpmHandle();
        }
        public Tpm2EcdhKeyGenRequest(Tpm2EcdhKeyGenRequest the_Tpm2EcdhKeyGenRequest)
        {
            if((Object) the_Tpm2EcdhKeyGenRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            keyHandle = the_Tpm2EcdhKeyGenRequest.keyHandle;
        }
        ///<param name = "the_keyHandle">Handle of a loaded ECC key public area. Auth Index: None</param>
        public Tpm2EcdhKeyGenRequest(
        TpmHandle the_keyHandle
        )
        {
            this.keyHandle = the_keyHandle;
        }
        new public Tpm2EcdhKeyGenRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2EcdhKeyGenRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command uses the TPM to generate an ephemeral key pair (de, Qe where Qe  [de]G). It uses the private ephemeral key and a loaded public key (QS) to compute the shared secret value (P  [hde]QS).
    /// </summary>
    [DataContract]
    [KnownType(typeof(EccPoint))]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("TPM2_ECDH_KeyGen_RESPONSE")]
    public partial class Tpm2EcdhKeyGenResponse: TpmStructureBase
    {
        /// <summary>
        /// results of P  h[de]Qs
        /// </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "zPointSize", 2)]
        [DataMember()]
        public EccPoint zPoint { get; set; }
        /// <summary>
        /// generated ephemeral public point (Qe)
        /// </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "pubPointSize", 2)]
        [DataMember()]
        public EccPoint pubPoint { get; set; }
        public Tpm2EcdhKeyGenResponse()
        {
            zPoint = new EccPoint();
            pubPoint = new EccPoint();
        }
        public Tpm2EcdhKeyGenResponse(Tpm2EcdhKeyGenResponse the_Tpm2EcdhKeyGenResponse)
        {
            if((Object) the_Tpm2EcdhKeyGenResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            zPoint = the_Tpm2EcdhKeyGenResponse.zPoint;
            pubPoint = the_Tpm2EcdhKeyGenResponse.pubPoint;
        }
        ///<param name = "the_zPoint">results of P  h[de]Qs</param>
        ///<param name = "the_pubPoint">generated ephemeral public point (Qe)</param>
        public Tpm2EcdhKeyGenResponse(
        EccPoint the_zPoint,
        EccPoint the_pubPoint
        )
        {
            this.zPoint = the_zPoint;
            this.pubPoint = the_pubPoint;
        }
        new public Tpm2EcdhKeyGenResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2EcdhKeyGenResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command uses the TPM to recover the Z value from a public point (QB) and a private key (ds). It will perform the multiplication of the provided inPoint (QB) with the private key (ds) and return the coordinates of the resultant point (Z = (xZ , yZ)  [hds]QB; where h is the cofactor of the curve).
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("TPM2_ECDH_ZGen_REQUEST")]
    public partial class Tpm2EcdhZGenRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of a loaded ECC key
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }
        /// <summary>
        /// a public key
        /// </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "inPointSize", 2)]
        [DataMember()]
        public EccPoint inPoint { get; set; }
        public Tpm2EcdhZGenRequest()
        {
            keyHandle = new TpmHandle();
            inPoint = new EccPoint();
        }
        public Tpm2EcdhZGenRequest(Tpm2EcdhZGenRequest the_Tpm2EcdhZGenRequest)
        {
            if((Object) the_Tpm2EcdhZGenRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            keyHandle = the_Tpm2EcdhZGenRequest.keyHandle;
            inPoint = the_Tpm2EcdhZGenRequest.inPoint;
        }
        ///<param name = "the_keyHandle">handle of a loaded ECC key Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_inPoint">a public key</param>
        public Tpm2EcdhZGenRequest(
        TpmHandle the_keyHandle,
        EccPoint the_inPoint
        )
        {
            this.keyHandle = the_keyHandle;
            this.inPoint = the_inPoint;
        }
        new public Tpm2EcdhZGenRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2EcdhZGenRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command uses the TPM to recover the Z value from a public point (QB) and a private key (ds). It will perform the multiplication of the provided inPoint (QB) with the private key (ds) and return the coordinates of the resultant point (Z = (xZ , yZ)  [hds]QB; where h is the cofactor of the curve).
    /// </summary>
    [DataContract]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("TPM2_ECDH_ZGen_RESPONSE")]
    public partial class Tpm2EcdhZGenResponse: TpmStructureBase
    {
        /// <summary>
        /// X and Y coordinates of the product of the multiplication Z = (xZ , yZ)  [hdS]QB
        /// </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "outPointSize", 2)]
        [DataMember()]
        public EccPoint outPoint { get; set; }
        public Tpm2EcdhZGenResponse()
        {
            outPoint = new EccPoint();
        }
        public Tpm2EcdhZGenResponse(Tpm2EcdhZGenResponse the_Tpm2EcdhZGenResponse)
        {
            if((Object) the_Tpm2EcdhZGenResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            outPoint = the_Tpm2EcdhZGenResponse.outPoint;
        }
        ///<param name = "the_outPoint">X and Y coordinates of the product of the multiplication Z = (xZ , yZ)  [hdS]QB</param>
        public Tpm2EcdhZGenResponse(
        EccPoint the_outPoint
        )
        {
            this.outPoint = the_outPoint;
        }
        new public Tpm2EcdhZGenResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2EcdhZGenResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns the parameters of an ECC curve identified by its TCG-assigned curveID.
    /// </summary>
    [DataContract]
    [KnownType(typeof(EccCurve))]
    [SpecTypeName("TPM2_ECC_Parameters_REQUEST")]
    public partial class Tpm2EccParametersRequest: TpmStructureBase
    {
        /// <summary>
        /// parameter set selector
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public EccCurve curveID { get; set; }
        public Tpm2EccParametersRequest()
        {
            curveID = new EccCurve();
        }
        public Tpm2EccParametersRequest(Tpm2EccParametersRequest the_Tpm2EccParametersRequest)
        {
            if((Object) the_Tpm2EccParametersRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            curveID = the_Tpm2EccParametersRequest.curveID;
        }
        ///<param name = "the_curveID">parameter set selector</param>
        public Tpm2EccParametersRequest(
        EccCurve the_curveID
        )
        {
            this.curveID = the_curveID;
        }
        new public Tpm2EccParametersRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2EccParametersRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns the parameters of an ECC curve identified by its TCG-assigned curveID.
    /// </summary>
    [DataContract]
    [KnownType(typeof(AlgorithmDetailEcc))]
    [SpecTypeName("TPM2_ECC_Parameters_RESPONSE")]
    public partial class Tpm2EccParametersResponse: TpmStructureBase
    {
        /// <summary>
        /// ECC parameters for the selected curve
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public AlgorithmDetailEcc parameters { get; set; }
        public Tpm2EccParametersResponse()
        {
            parameters = new AlgorithmDetailEcc();
        }
        public Tpm2EccParametersResponse(Tpm2EccParametersResponse the_Tpm2EccParametersResponse)
        {
            if((Object) the_Tpm2EccParametersResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            parameters = the_Tpm2EccParametersResponse.parameters;
        }
        ///<param name = "the_parameters">ECC parameters for the selected curve</param>
        public Tpm2EccParametersResponse(
        AlgorithmDetailEcc the_parameters
        )
        {
            this.parameters = the_parameters;
        }
        new public Tpm2EccParametersResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2EccParametersResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command supports two-phase key exchange protocols. The command is used in combination with TPM2_EC_Ephemeral(). TPM2_EC_Ephemeral() generates an ephemeral key and returns the public point of that ephemeral key along with a numeric value that allows the TPM to regenerate the associated private key.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(EccPoint))]
    [KnownType(typeof(EccPoint))]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPM2_ZGen_2Phase_REQUEST")]
    public partial class Tpm2ZGen2PhaseRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of an unrestricted decryption key ECC
        /// The private key referenced by this handle is used as dS,A
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyA { get; set; }
        /// <summary>
        /// other partys static public key (Qs,B = (Xs,B, Ys,B))
        /// </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "inQsBSize", 2)]
        [DataMember()]
        public EccPoint inQsB { get; set; }
        /// <summary>
        /// other party's ephemeral public key (Qe,B = (Xe,B, Ye,B))
        /// </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "inQeBSize", 2)]
        [DataMember()]
        public EccPoint inQeB { get; set; }
        /// <summary>
        /// the key exchange scheme
        /// </summary>
        [MarshalAs(3)]
        [DataMember()]
        public TpmAlgId inScheme { get; set; }
        /// <summary>
        /// value returned by TPM2_EC_Ephemeral()
        /// </summary>
        [MarshalAs(4)]
        [DataMember()]
        public ushort counter { get; set; }
        public Tpm2ZGen2PhaseRequest()
        {
            keyA = new TpmHandle();
            inQsB = new EccPoint();
            inQeB = new EccPoint();
            inScheme = TpmAlgId.Null;
            counter = 0;
        }
        public Tpm2ZGen2PhaseRequest(Tpm2ZGen2PhaseRequest the_Tpm2ZGen2PhaseRequest)
        {
            if((Object) the_Tpm2ZGen2PhaseRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            keyA = the_Tpm2ZGen2PhaseRequest.keyA;
            inQsB = the_Tpm2ZGen2PhaseRequest.inQsB;
            inQeB = the_Tpm2ZGen2PhaseRequest.inQeB;
            inScheme = the_Tpm2ZGen2PhaseRequest.inScheme;
            counter = the_Tpm2ZGen2PhaseRequest.counter;
        }
        ///<param name = "the_keyA">handle of an unrestricted decryption key ECC The private key referenced by this handle is used as dS,A Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_inQsB">other partys static public key (Qs,B = (Xs,B, Ys,B))</param>
        ///<param name = "the_inQeB">other party's ephemeral public key (Qe,B = (Xe,B, Ye,B))</param>
        ///<param name = "the_inScheme">the key exchange scheme</param>
        ///<param name = "the_counter">value returned by TPM2_EC_Ephemeral()</param>
        public Tpm2ZGen2PhaseRequest(
        TpmHandle the_keyA,
        EccPoint the_inQsB,
        EccPoint the_inQeB,
        TpmAlgId the_inScheme,
        ushort the_counter
        )
        {
            this.keyA = the_keyA;
            this.inQsB = the_inQsB;
            this.inQeB = the_inQeB;
            this.inScheme = the_inScheme;
            this.counter = the_counter;
        }
        new public Tpm2ZGen2PhaseRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ZGen2PhaseRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command supports two-phase key exchange protocols. The command is used in combination with TPM2_EC_Ephemeral(). TPM2_EC_Ephemeral() generates an ephemeral key and returns the public point of that ephemeral key along with a numeric value that allows the TPM to regenerate the associated private key.
    /// </summary>
    [DataContract]
    [KnownType(typeof(EccPoint))]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("TPM2_ZGen_2Phase_RESPONSE")]
    public partial class Tpm2ZGen2PhaseResponse: TpmStructureBase
    {
        /// <summary>
        /// X and Y coordinates of the computed value (scheme dependent)
        /// </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "outZ1Size", 2)]
        [DataMember()]
        public EccPoint outZ1 { get; set; }
        /// <summary>
        /// X and Y coordinates of the second computed value (scheme dependent)
        /// </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "outZ2Size", 2)]
        [DataMember()]
        public EccPoint outZ2 { get; set; }
        public Tpm2ZGen2PhaseResponse()
        {
            outZ1 = new EccPoint();
            outZ2 = new EccPoint();
        }
        public Tpm2ZGen2PhaseResponse(Tpm2ZGen2PhaseResponse the_Tpm2ZGen2PhaseResponse)
        {
            if((Object) the_Tpm2ZGen2PhaseResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            outZ1 = the_Tpm2ZGen2PhaseResponse.outZ1;
            outZ2 = the_Tpm2ZGen2PhaseResponse.outZ2;
        }
        ///<param name = "the_outZ1">X and Y coordinates of the computed value (scheme dependent)</param>
        ///<param name = "the_outZ2">X and Y coordinates of the second computed value (scheme dependent)</param>
        public Tpm2ZGen2PhaseResponse(
        EccPoint the_outZ1,
        EccPoint the_outZ2
        )
        {
            this.outZ1 = the_outZ1;
            this.outZ2 = the_outZ2;
        }
        new public Tpm2ZGen2PhaseResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ZGen2PhaseResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command performs symmetric encryption or decryption using the symmetric key referenced by keyHandle and the selected mode.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(byte))]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPM2_EncryptDecrypt_REQUEST")]
    public partial class Tpm2EncryptDecryptRequest: TpmStructureBase
    {
        /// <summary>
        /// the symmetric key used for the operation
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }
        /// <summary>
        /// if YES, then the operation is decryption; if NO, the operation is encryption
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public byte decrypt { get; set; }
        /// <summary>
        /// symmetric mode
        /// this field shall match the default mode of the key or be TPM_ALG_NULL.
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmAlgId mode { get; set; }
        /// <summary>
        /// an initial value as required by the algorithm
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "ivInSize", 2)]
        [DataMember()]
        public byte[] ivIn;
        /// <summary>
        /// the data to be encrypted/decrypted
        /// </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "inDataSize", 2)]
        [DataMember()]
        public byte[] inData;
        public Tpm2EncryptDecryptRequest()
        {
            keyHandle = new TpmHandle();
            decrypt = 0;
            mode = TpmAlgId.Null;
            ivIn = null;
            inData = null;
        }
        public Tpm2EncryptDecryptRequest(Tpm2EncryptDecryptRequest the_Tpm2EncryptDecryptRequest)
        {
            if((Object) the_Tpm2EncryptDecryptRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            keyHandle = the_Tpm2EncryptDecryptRequest.keyHandle;
            decrypt = the_Tpm2EncryptDecryptRequest.decrypt;
            mode = the_Tpm2EncryptDecryptRequest.mode;
            ivIn = the_Tpm2EncryptDecryptRequest.ivIn;
            inData = the_Tpm2EncryptDecryptRequest.inData;
        }
        ///<param name = "the_keyHandle">the symmetric key used for the operation Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_decrypt">if YES, then the operation is decryption; if NO, the operation is encryption</param>
        ///<param name = "the_mode">symmetric mode this field shall match the default mode of the key or be TPM_ALG_NULL.</param>
        ///<param name = "the_ivIn">an initial value as required by the algorithm</param>
        ///<param name = "the_inData">the data to be encrypted/decrypted</param>
        public Tpm2EncryptDecryptRequest(
        TpmHandle the_keyHandle,
        byte the_decrypt,
        TpmAlgId the_mode,
        byte[] the_ivIn,
        byte[] the_inData
        )
        {
            this.keyHandle = the_keyHandle;
            this.decrypt = the_decrypt;
            this.mode = the_mode;
            this.ivIn = the_ivIn;
            this.inData = the_inData;
        }
        new public Tpm2EncryptDecryptRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2EncryptDecryptRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command performs symmetric encryption or decryption using the symmetric key referenced by keyHandle and the selected mode.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_EncryptDecrypt_RESPONSE")]
    public partial class Tpm2EncryptDecryptResponse: TpmStructureBase
    {
        /// <summary>
        /// encrypted or decrypted output
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "outDataSize", 2)]
        [DataMember()]
        public byte[] outData;
        /// <summary>
        /// chaining value to use for IV in next round
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "ivOutSize", 2)]
        [DataMember()]
        public byte[] ivOut;
        public Tpm2EncryptDecryptResponse()
        {
            outData = null;
            ivOut = null;
        }
        public Tpm2EncryptDecryptResponse(Tpm2EncryptDecryptResponse the_Tpm2EncryptDecryptResponse)
        {
            if((Object) the_Tpm2EncryptDecryptResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            outData = the_Tpm2EncryptDecryptResponse.outData;
            ivOut = the_Tpm2EncryptDecryptResponse.ivOut;
        }
        ///<param name = "the_outData">encrypted or decrypted output</param>
        ///<param name = "the_ivOut">chaining value to use for IV in next round</param>
        public Tpm2EncryptDecryptResponse(
        byte[] the_outData,
        byte[] the_ivOut
        )
        {
            this.outData = the_outData;
            this.ivOut = the_ivOut;
        }
        new public Tpm2EncryptDecryptResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2EncryptDecryptResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command performs a hash operation on a data buffer and returns the results.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_Hash_REQUEST")]
    public partial class Tpm2HashRequest: TpmStructureBase
    {
        /// <summary>
        /// data to be hashed
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "dataSize", 2)]
        [DataMember()]
        public byte[] data;
        /// <summary>
        /// algorithm for the hash being computed  shall not be TPM_ALG_NULL
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }
        /// <summary>
        /// hierarchy to use for the ticket (TPM_RH_NULL allowed)
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle hierarchy { get; set; }
        public Tpm2HashRequest()
        {
            data = null;
            hashAlg = TpmAlgId.Null;
            hierarchy = new TpmHandle();
        }
        public Tpm2HashRequest(Tpm2HashRequest the_Tpm2HashRequest)
        {
            if((Object) the_Tpm2HashRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            data = the_Tpm2HashRequest.data;
            hashAlg = the_Tpm2HashRequest.hashAlg;
            hierarchy = the_Tpm2HashRequest.hierarchy;
        }
        ///<param name = "the_data">data to be hashed</param>
        ///<param name = "the_hashAlg">algorithm for the hash being computed  shall not be TPM_ALG_NULL</param>
        ///<param name = "the_hierarchy">hierarchy to use for the ticket (TPM_RH_NULL allowed)</param>
        public Tpm2HashRequest(
        byte[] the_data,
        TpmAlgId the_hashAlg,
        TpmHandle the_hierarchy
        )
        {
            this.data = the_data;
            this.hashAlg = the_hashAlg;
            this.hierarchy = the_hierarchy;
        }
        new public Tpm2HashRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2HashRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command performs a hash operation on a data buffer and returns the results.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TkHashcheck))]
    [SpecTypeName("TPM2_Hash_RESPONSE")]
    public partial class Tpm2HashResponse: TpmStructureBase
    {
        /// <summary>
        /// results
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "outHashSize", 2)]
        [DataMember()]
        public byte[] outHash;
        /// <summary>
        /// ticket indicating that the sequence of octets used to compute outDigest did not start with TPM_GENERATED_VALUE
        /// will be a NULL ticket if the digest may not be signed with a restricted key
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TkHashcheck validation { get; set; }
        public Tpm2HashResponse()
        {
            outHash = null;
            validation = new TkHashcheck();
        }
        public Tpm2HashResponse(Tpm2HashResponse the_Tpm2HashResponse)
        {
            if((Object) the_Tpm2HashResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            outHash = the_Tpm2HashResponse.outHash;
            validation = the_Tpm2HashResponse.validation;
        }
        ///<param name = "the_outHash">results</param>
        ///<param name = "the_validation">ticket indicating that the sequence of octets used to compute outDigest did not start with TPM_GENERATED_VALUE will be a NULL ticket if the digest may not be signed with a restricted key</param>
        public Tpm2HashResponse(
        byte[] the_outHash,
        TkHashcheck the_validation
        )
        {
            this.outHash = the_outHash;
            this.validation = the_validation;
        }
        new public Tpm2HashResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2HashResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command performs an HMAC on the supplied data using the indicated hash algorithm.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPM2_HMAC_REQUEST")]
    public partial class Tpm2HmacRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the symmetric signing key providing the HMAC key
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }
        /// <summary>
        /// HMAC data
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "bufferSize", 2)]
        [DataMember()]
        public byte[] buffer;
        /// <summary>
        /// algorithm to use for HMAC
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }
        public Tpm2HmacRequest()
        {
            handle = new TpmHandle();
            buffer = null;
            hashAlg = TpmAlgId.Null;
        }
        public Tpm2HmacRequest(Tpm2HmacRequest the_Tpm2HmacRequest)
        {
            if((Object) the_Tpm2HmacRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            handle = the_Tpm2HmacRequest.handle;
            buffer = the_Tpm2HmacRequest.buffer;
            hashAlg = the_Tpm2HmacRequest.hashAlg;
        }
        ///<param name = "the_handle">handle for the symmetric signing key providing the HMAC key Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_buffer">HMAC data</param>
        ///<param name = "the_hashAlg">algorithm to use for HMAC</param>
        public Tpm2HmacRequest(
        TpmHandle the_handle,
        byte[] the_buffer,
        TpmAlgId the_hashAlg
        )
        {
            this.handle = the_handle;
            this.buffer = the_buffer;
            this.hashAlg = the_hashAlg;
        }
        new public Tpm2HmacRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2HmacRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command performs an HMAC on the supplied data using the indicated hash algorithm.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_HMAC_RESPONSE")]
    public partial class Tpm2HmacResponse: TpmStructureBase
    {
        /// <summary>
        /// the returned HMAC in a sized buffer
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "outHMACSize", 2)]
        [DataMember()]
        public byte[] outHMAC;
        public Tpm2HmacResponse()
        {
            outHMAC = null;
        }
        public Tpm2HmacResponse(Tpm2HmacResponse the_Tpm2HmacResponse)
        {
            if((Object) the_Tpm2HmacResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            outHMAC = the_Tpm2HmacResponse.outHMAC;
        }
        ///<param name = "the_outHMAC">the returned HMAC in a sized buffer</param>
        public Tpm2HmacResponse(
        byte[] the_outHMAC
        )
        {
            this.outHMAC = the_outHMAC;
        }
        new public Tpm2HmacResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2HmacResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns the next bytesRequested octets from the random number generator (RNG).
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_GetRandom_REQUEST")]
    public partial class Tpm2GetRandomRequest: TpmStructureBase
    {
        /// <summary>
        /// number of octets to return
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public ushort bytesRequested { get; set; }
        public Tpm2GetRandomRequest()
        {
            bytesRequested = 0;
        }
        public Tpm2GetRandomRequest(Tpm2GetRandomRequest the_Tpm2GetRandomRequest)
        {
            if((Object) the_Tpm2GetRandomRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            bytesRequested = the_Tpm2GetRandomRequest.bytesRequested;
        }
        ///<param name = "the_bytesRequested">number of octets to return</param>
        public Tpm2GetRandomRequest(
        ushort the_bytesRequested
        )
        {
            this.bytesRequested = the_bytesRequested;
        }
        new public Tpm2GetRandomRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2GetRandomRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns the next bytesRequested octets from the random number generator (RNG).
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_GetRandom_RESPONSE")]
    public partial class Tpm2GetRandomResponse: TpmStructureBase
    {
        /// <summary>
        /// the random octets
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "randomBytesSize", 2)]
        [DataMember()]
        public byte[] randomBytes;
        public Tpm2GetRandomResponse()
        {
            randomBytes = null;
        }
        public Tpm2GetRandomResponse(Tpm2GetRandomResponse the_Tpm2GetRandomResponse)
        {
            if((Object) the_Tpm2GetRandomResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            randomBytes = the_Tpm2GetRandomResponse.randomBytes;
        }
        ///<param name = "the_randomBytes">the random octets</param>
        public Tpm2GetRandomResponse(
        byte[] the_randomBytes
        )
        {
            this.randomBytes = the_randomBytes;
        }
        new public Tpm2GetRandomResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2GetRandomResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to add "additional information" to the RNG state.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_StirRandom_REQUEST")]
    public partial class Tpm2StirRandomRequest: TpmStructureBase
    {
        /// <summary>
        /// additional information
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "inDataSize", 2)]
        [DataMember()]
        public byte[] inData;
        public Tpm2StirRandomRequest()
        {
            inData = null;
        }
        public Tpm2StirRandomRequest(Tpm2StirRandomRequest the_Tpm2StirRandomRequest)
        {
            if((Object) the_Tpm2StirRandomRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            inData = the_Tpm2StirRandomRequest.inData;
        }
        ///<param name = "the_inData">additional information</param>
        public Tpm2StirRandomRequest(
        byte[] the_inData
        )
        {
            this.inData = the_inData;
        }
        new public Tpm2StirRandomRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2StirRandomRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to add "additional information" to the RNG state.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_StirRandom_RESPONSE")]
    public partial class Tpm2StirRandomResponse: TpmStructureBase
    {
        public Tpm2StirRandomResponse()
        {
        }
        new public Tpm2StirRandomResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2StirRandomResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command starts an HMAC sequence. The TPM will create and initialize an HMAC sequence structure, assign a handle to the sequence, and set the authValue of the sequence object to the value in auth.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPM2_HMAC_Start_REQUEST")]
    public partial class Tpm2HmacStartRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of an HMAC key
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }
        /// <summary>
        /// authorization value for subsequent use of the sequence
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "authSize", 2)]
        [DataMember()]
        public byte[] auth;
        /// <summary>
        /// the hash algorithm to use for the HMAC
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }
        public Tpm2HmacStartRequest()
        {
            handle = new TpmHandle();
            auth = null;
            hashAlg = TpmAlgId.Null;
        }
        public Tpm2HmacStartRequest(Tpm2HmacStartRequest the_Tpm2HmacStartRequest)
        {
            if((Object) the_Tpm2HmacStartRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            handle = the_Tpm2HmacStartRequest.handle;
            auth = the_Tpm2HmacStartRequest.auth;
            hashAlg = the_Tpm2HmacStartRequest.hashAlg;
        }
        ///<param name = "the_handle">handle of an HMAC key Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_auth">authorization value for subsequent use of the sequence</param>
        ///<param name = "the_hashAlg">the hash algorithm to use for the HMAC</param>
        public Tpm2HmacStartRequest(
        TpmHandle the_handle,
        byte[] the_auth,
        TpmAlgId the_hashAlg
        )
        {
            this.handle = the_handle;
            this.auth = the_auth;
            this.hashAlg = the_hashAlg;
        }
        new public Tpm2HmacStartRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2HmacStartRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command starts an HMAC sequence. The TPM will create and initialize an HMAC sequence structure, assign a handle to the sequence, and set the authValue of the sequence object to the value in auth.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_HMAC_Start_RESPONSE")]
    public partial class Tpm2HmacStartResponse: TpmStructureBase
    {
        /// <summary>
        /// a handle to reference the sequence
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle sequenceHandle { get; set; }
        public Tpm2HmacStartResponse()
        {
            sequenceHandle = new TpmHandle();
        }
        public Tpm2HmacStartResponse(Tpm2HmacStartResponse the_Tpm2HmacStartResponse)
        {
            if((Object) the_Tpm2HmacStartResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            sequenceHandle = the_Tpm2HmacStartResponse.sequenceHandle;
        }
        ///<param name = "the_sequenceHandle">a handle to reference the sequence</param>
        public Tpm2HmacStartResponse(
        TpmHandle the_sequenceHandle
        )
        {
            this.sequenceHandle = the_sequenceHandle;
        }
        new public Tpm2HmacStartResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2HmacStartResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command starts a hash or an Event Sequence. If hashAlg is an implemented hash, then a hash sequence is started. If hashAlg is TPM_ALG_NULL, then an Event Sequence is started. If hashAlg is neither an implemented algorithm nor TPM_ALG_NULL, then the TPM shall return TPM_RC_HASH.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPM2_HashSequenceStart_REQUEST")]
    public partial class Tpm2HashSequenceStartRequest: TpmStructureBase
    {
        /// <summary>
        /// authorization value for subsequent use of the sequence
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "authSize", 2)]
        [DataMember()]
        public byte[] auth;
        /// <summary>
        /// the hash algorithm to use for the hash sequence
        /// An Event Sequence starts if this is TPM_ALG_NULL.
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }
        public Tpm2HashSequenceStartRequest()
        {
            auth = null;
            hashAlg = TpmAlgId.Null;
        }
        public Tpm2HashSequenceStartRequest(Tpm2HashSequenceStartRequest the_Tpm2HashSequenceStartRequest)
        {
            if((Object) the_Tpm2HashSequenceStartRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            auth = the_Tpm2HashSequenceStartRequest.auth;
            hashAlg = the_Tpm2HashSequenceStartRequest.hashAlg;
        }
        ///<param name = "the_auth">authorization value for subsequent use of the sequence</param>
        ///<param name = "the_hashAlg">the hash algorithm to use for the hash sequence An Event Sequence starts if this is TPM_ALG_NULL.</param>
        public Tpm2HashSequenceStartRequest(
        byte[] the_auth,
        TpmAlgId the_hashAlg
        )
        {
            this.auth = the_auth;
            this.hashAlg = the_hashAlg;
        }
        new public Tpm2HashSequenceStartRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2HashSequenceStartRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command starts a hash or an Event Sequence. If hashAlg is an implemented hash, then a hash sequence is started. If hashAlg is TPM_ALG_NULL, then an Event Sequence is started. If hashAlg is neither an implemented algorithm nor TPM_ALG_NULL, then the TPM shall return TPM_RC_HASH.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_HashSequenceStart_RESPONSE")]
    public partial class Tpm2HashSequenceStartResponse: TpmStructureBase
    {
        /// <summary>
        /// a handle to reference the sequence
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle sequenceHandle { get; set; }
        public Tpm2HashSequenceStartResponse()
        {
            sequenceHandle = new TpmHandle();
        }
        public Tpm2HashSequenceStartResponse(Tpm2HashSequenceStartResponse the_Tpm2HashSequenceStartResponse)
        {
            if((Object) the_Tpm2HashSequenceStartResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            sequenceHandle = the_Tpm2HashSequenceStartResponse.sequenceHandle;
        }
        ///<param name = "the_sequenceHandle">a handle to reference the sequence</param>
        public Tpm2HashSequenceStartResponse(
        TpmHandle the_sequenceHandle
        )
        {
            this.sequenceHandle = the_sequenceHandle;
        }
        new public Tpm2HashSequenceStartResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2HashSequenceStartResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to add data to a hash or HMAC sequence. The amount of data in buffer may be any size up to the limits of the TPM.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_SequenceUpdate_REQUEST")]
    public partial class Tpm2SequenceUpdateRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the sequence object
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle sequenceHandle { get; set; }
        /// <summary>
        /// data to be added to hash
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "bufferSize", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2SequenceUpdateRequest()
        {
            sequenceHandle = new TpmHandle();
            buffer = null;
        }
        public Tpm2SequenceUpdateRequest(Tpm2SequenceUpdateRequest the_Tpm2SequenceUpdateRequest)
        {
            if((Object) the_Tpm2SequenceUpdateRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            sequenceHandle = the_Tpm2SequenceUpdateRequest.sequenceHandle;
            buffer = the_Tpm2SequenceUpdateRequest.buffer;
        }
        ///<param name = "the_sequenceHandle">handle for the sequence object Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_buffer">data to be added to hash</param>
        public Tpm2SequenceUpdateRequest(
        TpmHandle the_sequenceHandle,
        byte[] the_buffer
        )
        {
            this.sequenceHandle = the_sequenceHandle;
            this.buffer = the_buffer;
        }
        new public Tpm2SequenceUpdateRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2SequenceUpdateRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to add data to a hash or HMAC sequence. The amount of data in buffer may be any size up to the limits of the TPM.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_SequenceUpdate_RESPONSE")]
    public partial class Tpm2SequenceUpdateResponse: TpmStructureBase
    {
        public Tpm2SequenceUpdateResponse()
        {
        }
        new public Tpm2SequenceUpdateResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2SequenceUpdateResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command adds the last part of data, if any, to a hash/HMAC sequence and returns the result.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_SequenceComplete_REQUEST")]
    public partial class Tpm2SequenceCompleteRequest: TpmStructureBase
    {
        /// <summary>
        /// authorization for the sequence
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle sequenceHandle { get; set; }
        /// <summary>
        /// data to be added to the hash/HMAC
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "bufferSize", 2)]
        [DataMember()]
        public byte[] buffer;
        /// <summary>
        /// hierarchy of the ticket for a hash
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle hierarchy { get; set; }
        public Tpm2SequenceCompleteRequest()
        {
            sequenceHandle = new TpmHandle();
            buffer = null;
            hierarchy = new TpmHandle();
        }
        public Tpm2SequenceCompleteRequest(Tpm2SequenceCompleteRequest the_Tpm2SequenceCompleteRequest)
        {
            if((Object) the_Tpm2SequenceCompleteRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            sequenceHandle = the_Tpm2SequenceCompleteRequest.sequenceHandle;
            buffer = the_Tpm2SequenceCompleteRequest.buffer;
            hierarchy = the_Tpm2SequenceCompleteRequest.hierarchy;
        }
        ///<param name = "the_sequenceHandle">authorization for the sequence Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_buffer">data to be added to the hash/HMAC</param>
        ///<param name = "the_hierarchy">hierarchy of the ticket for a hash</param>
        public Tpm2SequenceCompleteRequest(
        TpmHandle the_sequenceHandle,
        byte[] the_buffer,
        TpmHandle the_hierarchy
        )
        {
            this.sequenceHandle = the_sequenceHandle;
            this.buffer = the_buffer;
            this.hierarchy = the_hierarchy;
        }
        new public Tpm2SequenceCompleteRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2SequenceCompleteRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command adds the last part of data, if any, to a hash/HMAC sequence and returns the result.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TkHashcheck))]
    [SpecTypeName("TPM2_SequenceComplete_RESPONSE")]
    public partial class Tpm2SequenceCompleteResponse: TpmStructureBase
    {
        /// <summary>
        /// the returned HMAC or digest in a sized buffer
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "resultSize", 2)]
        [DataMember()]
        public byte[] result;
        /// <summary>
        /// ticket indicating that the sequence of octets used to compute outDigest did not start with TPM_GENERATED_VALUE
        /// This is a NULL Ticket when the sequence is HMAC.
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TkHashcheck validation { get; set; }
        public Tpm2SequenceCompleteResponse()
        {
            result = null;
            validation = new TkHashcheck();
        }
        public Tpm2SequenceCompleteResponse(Tpm2SequenceCompleteResponse the_Tpm2SequenceCompleteResponse)
        {
            if((Object) the_Tpm2SequenceCompleteResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            result = the_Tpm2SequenceCompleteResponse.result;
            validation = the_Tpm2SequenceCompleteResponse.validation;
        }
        ///<param name = "the_result">the returned HMAC or digest in a sized buffer</param>
        ///<param name = "the_validation">ticket indicating that the sequence of octets used to compute outDigest did not start with TPM_GENERATED_VALUE This is a NULL Ticket when the sequence is HMAC.</param>
        public Tpm2SequenceCompleteResponse(
        byte[] the_result,
        TkHashcheck the_validation
        )
        {
            this.result = the_result;
            this.validation = the_validation;
        }
        new public Tpm2SequenceCompleteResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2SequenceCompleteResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command adds the last part of data, if any, to an Event Sequence and returns the result in a digest list. If pcrHandle references a PCR and not TPM_RH_NULL, then the returned digest list is processed in the same manner as the digest list input parameter to TPM2_PCR_Extend() with the pcrHandle in each bank extended with the associated digest value.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_EventSequenceComplete_REQUEST")]
    public partial class Tpm2EventSequenceCompleteRequest: TpmStructureBase
    {
        /// <summary>
        /// PCR to be extended with the Event data
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle pcrHandle { get; set; }
        /// <summary>
        /// authorization for the sequence
        /// Auth Index: 2
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle sequenceHandle { get; set; }
        /// <summary>
        /// data to be added to the Event
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "bufferSize", 2)]
        [DataMember()]
        public byte[] buffer;
        public Tpm2EventSequenceCompleteRequest()
        {
            pcrHandle = new TpmHandle();
            sequenceHandle = new TpmHandle();
            buffer = null;
        }
        public Tpm2EventSequenceCompleteRequest(Tpm2EventSequenceCompleteRequest the_Tpm2EventSequenceCompleteRequest)
        {
            if((Object) the_Tpm2EventSequenceCompleteRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            pcrHandle = the_Tpm2EventSequenceCompleteRequest.pcrHandle;
            sequenceHandle = the_Tpm2EventSequenceCompleteRequest.sequenceHandle;
            buffer = the_Tpm2EventSequenceCompleteRequest.buffer;
        }
        ///<param name = "the_pcrHandle">PCR to be extended with the Event data Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_sequenceHandle">authorization for the sequence Auth Index: 2 Auth Role: USER</param>
        ///<param name = "the_buffer">data to be added to the Event</param>
        public Tpm2EventSequenceCompleteRequest(
        TpmHandle the_pcrHandle,
        TpmHandle the_sequenceHandle,
        byte[] the_buffer
        )
        {
            this.pcrHandle = the_pcrHandle;
            this.sequenceHandle = the_sequenceHandle;
            this.buffer = the_buffer;
        }
        new public Tpm2EventSequenceCompleteRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2EventSequenceCompleteRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command adds the last part of data, if any, to an Event Sequence and returns the result in a digest list. If pcrHandle references a PCR and not TPM_RH_NULL, then the returned digest list is processed in the same manner as the digest list input parameter to TPM2_PCR_Extend() with the pcrHandle in each bank extended with the associated digest value.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_EventSequenceComplete_RESPONSE")]
    public partial class Tpm2EventSequenceCompleteResponse: TpmStructureBase
    {
        /// <summary>
        /// list of digests computed for the PCR
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "resultsCount", 4)]
        [DataMember()]
        public TpmHash[] results;
        public Tpm2EventSequenceCompleteResponse()
        {
            results = null;
        }
        public Tpm2EventSequenceCompleteResponse(Tpm2EventSequenceCompleteResponse the_Tpm2EventSequenceCompleteResponse)
        {
            if((Object) the_Tpm2EventSequenceCompleteResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            results = the_Tpm2EventSequenceCompleteResponse.results;
        }
        ///<param name = "the_results">list of digests computed for the PCR</param>
        public Tpm2EventSequenceCompleteResponse(
        TpmHash[] the_results
        )
        {
            this.results = the_results;
        }
        new public Tpm2EventSequenceCompleteResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2EventSequenceCompleteResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// The purpose of this command is to prove that an object with a specific Name is loaded in the TPM. By certifying that the object is loaded, the TPM warrants that a public area with a given Name is self-consistent and associated with a valid sensitive area. If a relying party has a public area that has the same Name as a Name certified with this command, then the values in that public area are correct.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(NullSigScheme))]
    [SpecTypeName("TPM2_Certify_REQUEST")]
    public partial class Tpm2CertifyRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of the object to be certified
        /// Auth Index: 1
        /// Auth Role: ADMIN
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle objectHandle { get; set; }
        /// <summary>
        /// handle of the key used to sign the attestation structure
        /// Auth Index: 2
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle signHandle { get; set; }
        /// <summary>
        /// user provided qualifying data
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "qualifyingDataSize", 2)]
        [DataMember()]
        public byte[] qualifyingData;
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(3, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get {
                if(inScheme != null) {
                    return (TpmAlgId)inScheme.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        /// (One of [SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme])
        /// </summary>
        [MarshalAs(4, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public ISigSchemeUnion inScheme { get; set; }
        public Tpm2CertifyRequest()
        {
            objectHandle = new TpmHandle();
            signHandle = new TpmHandle();
            qualifyingData = null;
        }
        public Tpm2CertifyRequest(Tpm2CertifyRequest the_Tpm2CertifyRequest)
        {
            if((Object) the_Tpm2CertifyRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            objectHandle = the_Tpm2CertifyRequest.objectHandle;
            signHandle = the_Tpm2CertifyRequest.signHandle;
            qualifyingData = the_Tpm2CertifyRequest.qualifyingData;
        }
        ///<param name = "the_objectHandle">handle of the object to be certified Auth Index: 1 Auth Role: ADMIN</param>
        ///<param name = "the_signHandle">handle of the key used to sign the attestation structure Auth Index: 2 Auth Role: USER</param>
        ///<param name = "the_qualifyingData">user provided qualifying data</param>
        ///<param name = "the_inScheme">signing scheme to use if the scheme for signHandle is TPM_ALG_NULL(One of SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme)</param>
        public Tpm2CertifyRequest(
        TpmHandle the_objectHandle,
        TpmHandle the_signHandle,
        byte[] the_qualifyingData,
        ISigSchemeUnion the_inScheme
        )
        {
            this.objectHandle = the_objectHandle;
            this.signHandle = the_signHandle;
            this.qualifyingData = the_qualifyingData;
            this.inScheme = the_inScheme;
        }
        new public Tpm2CertifyRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2CertifyRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// The purpose of this command is to prove that an object with a specific Name is loaded in the TPM. By certifying that the object is loaded, the TPM warrants that a public area with a given Name is self-consistent and associated with a valid sensitive area. If a relying party has a public area that has the same Name as a Name certified with this command, then the values in that public area are correct.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureRsa))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureEcc))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(NullSignature))]
    [SpecTypeName("TPM2_Certify_RESPONSE")]
    public partial class Tpm2CertifyResponse: TpmStructureBase
    {
        /// <summary>
        /// the structure that was signed
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "certifyInfoSize", 2)]
        [DataMember()]
        public byte[] certifyInfo;
        /// <summary>
        /// selector of the algorithm used to construct the signature
        /// </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get {
                if(signature != null) {
                    return (TpmAlgId)signature.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// the asymmetric signature over certifyInfo using the key referenced by signHandle
        /// (One of [SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature])
        /// </summary>
        [MarshalAs(2, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }
        public Tpm2CertifyResponse()
        {
            certifyInfo = null;
        }
        public Tpm2CertifyResponse(Tpm2CertifyResponse the_Tpm2CertifyResponse)
        {
            if((Object) the_Tpm2CertifyResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            certifyInfo = the_Tpm2CertifyResponse.certifyInfo;
        }
        ///<param name = "the_certifyInfo">the structure that was signed</param>
        ///<param name = "the_signature">the asymmetric signature over certifyInfo using the key referenced by signHandle(One of SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature)</param>
        public Tpm2CertifyResponse(
        byte[] the_certifyInfo,
        ISignatureUnion the_signature
        )
        {
            this.certifyInfo = the_certifyInfo;
            this.signature = the_signature;
        }
        new public Tpm2CertifyResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2CertifyResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to prove the association between an object and its creation data. The TPM will validate that the ticket was produced by the TPM and that the ticket validates the association between a loaded public area and the provided hash of the creation data (creationHash).
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(NullSigScheme))]
    [KnownType(typeof(TkCreation))]
    [SpecTypeName("TPM2_CertifyCreation_REQUEST")]
    public partial class Tpm2CertifyCreationRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of the key that will sign the attestation block
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle signHandle { get; set; }
        /// <summary>
        /// the object associated with the creation data
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle objectHandle { get; set; }
        /// <summary>
        /// user-provided qualifying data
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "qualifyingDataSize", 2)]
        [DataMember()]
        public byte[] qualifyingData;
        /// <summary>
        /// hash of the creation data produced by TPM2_Create() or TPM2_CreatePrimary()
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "creationHashSize", 2)]
        [DataMember()]
        public byte[] creationHash;
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(4, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get {
                if(inScheme != null) {
                    return (TpmAlgId)inScheme.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        /// (One of [SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme])
        /// </summary>
        [MarshalAs(5, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public ISigSchemeUnion inScheme { get; set; }
        /// <summary>
        /// ticket produced by TPM2_Create() or TPM2_CreatePrimary()
        /// </summary>
        [MarshalAs(6)]
        [DataMember()]
        public TkCreation creationTicket { get; set; }
        public Tpm2CertifyCreationRequest()
        {
            signHandle = new TpmHandle();
            objectHandle = new TpmHandle();
            qualifyingData = null;
            creationHash = null;
            creationTicket = new TkCreation();
        }
        public Tpm2CertifyCreationRequest(Tpm2CertifyCreationRequest the_Tpm2CertifyCreationRequest)
        {
            if((Object) the_Tpm2CertifyCreationRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            signHandle = the_Tpm2CertifyCreationRequest.signHandle;
            objectHandle = the_Tpm2CertifyCreationRequest.objectHandle;
            qualifyingData = the_Tpm2CertifyCreationRequest.qualifyingData;
            creationHash = the_Tpm2CertifyCreationRequest.creationHash;
            creationTicket = the_Tpm2CertifyCreationRequest.creationTicket;
        }
        ///<param name = "the_signHandle">handle of the key that will sign the attestation block Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_objectHandle">the object associated with the creation data Auth Index: None</param>
        ///<param name = "the_qualifyingData">user-provided qualifying data</param>
        ///<param name = "the_creationHash">hash of the creation data produced by TPM2_Create() or TPM2_CreatePrimary()</param>
        ///<param name = "the_inScheme">signing scheme to use if the scheme for signHandle is TPM_ALG_NULL(One of SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme)</param>
        ///<param name = "the_creationTicket">ticket produced by TPM2_Create() or TPM2_CreatePrimary()</param>
        public Tpm2CertifyCreationRequest(
        TpmHandle the_signHandle,
        TpmHandle the_objectHandle,
        byte[] the_qualifyingData,
        byte[] the_creationHash,
        ISigSchemeUnion the_inScheme,
        TkCreation the_creationTicket
        )
        {
            this.signHandle = the_signHandle;
            this.objectHandle = the_objectHandle;
            this.qualifyingData = the_qualifyingData;
            this.creationHash = the_creationHash;
            this.inScheme = the_inScheme;
            this.creationTicket = the_creationTicket;
        }
        new public Tpm2CertifyCreationRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2CertifyCreationRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to prove the association between an object and its creation data. The TPM will validate that the ticket was produced by the TPM and that the ticket validates the association between a loaded public area and the provided hash of the creation data (creationHash).
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureRsa))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureEcc))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(NullSignature))]
    [SpecTypeName("TPM2_CertifyCreation_RESPONSE")]
    public partial class Tpm2CertifyCreationResponse: TpmStructureBase
    {
        /// <summary>
        /// the structure that was signed
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "certifyInfoSize", 2)]
        [DataMember()]
        public byte[] certifyInfo;
        /// <summary>
        /// selector of the algorithm used to construct the signature
        /// </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get {
                if(signature != null) {
                    return (TpmAlgId)signature.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// the signature over certifyInfo
        /// (One of [SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature])
        /// </summary>
        [MarshalAs(2, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }
        public Tpm2CertifyCreationResponse()
        {
            certifyInfo = null;
        }
        public Tpm2CertifyCreationResponse(Tpm2CertifyCreationResponse the_Tpm2CertifyCreationResponse)
        {
            if((Object) the_Tpm2CertifyCreationResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            certifyInfo = the_Tpm2CertifyCreationResponse.certifyInfo;
        }
        ///<param name = "the_certifyInfo">the structure that was signed</param>
        ///<param name = "the_signature">the signature over certifyInfo(One of SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature)</param>
        public Tpm2CertifyCreationResponse(
        byte[] the_certifyInfo,
        ISignatureUnion the_signature
        )
        {
            this.certifyInfo = the_certifyInfo;
            this.signature = the_signature;
        }
        new public Tpm2CertifyCreationResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2CertifyCreationResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to quote PCR values.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(NullSigScheme))]
    [SpecTypeName("TPM2_Quote_REQUEST")]
    public partial class Tpm2QuoteRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of key that will perform signature
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle signHandle { get; set; }
        /// <summary>
        /// data supplied by the caller
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "qualifyingDataSize", 2)]
        [DataMember()]
        public byte[] qualifyingData;
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(2, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get {
                if(inScheme != null) {
                    return (TpmAlgId)inScheme.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        /// (One of [SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme])
        /// </summary>
        [MarshalAs(3, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public ISigSchemeUnion inScheme { get; set; }
        /// <summary>
        /// PCR set to quote
        /// </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "PCRselectCount", 4)]
        [DataMember()]
        public PcrSelection[] PCRselect;
        public Tpm2QuoteRequest()
        {
            signHandle = new TpmHandle();
            qualifyingData = null;
            PCRselect = null;
        }
        public Tpm2QuoteRequest(Tpm2QuoteRequest the_Tpm2QuoteRequest)
        {
            if((Object) the_Tpm2QuoteRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            signHandle = the_Tpm2QuoteRequest.signHandle;
            qualifyingData = the_Tpm2QuoteRequest.qualifyingData;
            PCRselect = the_Tpm2QuoteRequest.PCRselect;
        }
        ///<param name = "the_signHandle">handle of key that will perform signature Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_qualifyingData">data supplied by the caller</param>
        ///<param name = "the_inScheme">signing scheme to use if the scheme for signHandle is TPM_ALG_NULL(One of SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme)</param>
        ///<param name = "the_PCRselect">PCR set to quote</param>
        public Tpm2QuoteRequest(
        TpmHandle the_signHandle,
        byte[] the_qualifyingData,
        ISigSchemeUnion the_inScheme,
        PcrSelection[] the_PCRselect
        )
        {
            this.signHandle = the_signHandle;
            this.qualifyingData = the_qualifyingData;
            this.inScheme = the_inScheme;
            this.PCRselect = the_PCRselect;
        }
        new public Tpm2QuoteRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2QuoteRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to quote PCR values.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureRsa))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureEcc))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(NullSignature))]
    [SpecTypeName("TPM2_Quote_RESPONSE")]
    public partial class Tpm2QuoteResponse: TpmStructureBase
    {
        /// <summary>
        /// the quoted information
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "quotedSize", 2)]
        [DataMember()]
        public byte[] quoted;
        /// <summary>
        /// selector of the algorithm used to construct the signature
        /// </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get {
                if(signature != null) {
                    return (TpmAlgId)signature.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// the signature over quoted
        /// (One of [SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature])
        /// </summary>
        [MarshalAs(2, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }
        public Tpm2QuoteResponse()
        {
            quoted = null;
        }
        public Tpm2QuoteResponse(Tpm2QuoteResponse the_Tpm2QuoteResponse)
        {
            if((Object) the_Tpm2QuoteResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            quoted = the_Tpm2QuoteResponse.quoted;
        }
        ///<param name = "the_quoted">the quoted information</param>
        ///<param name = "the_signature">the signature over quoted(One of SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature)</param>
        public Tpm2QuoteResponse(
        byte[] the_quoted,
        ISignatureUnion the_signature
        )
        {
            this.quoted = the_quoted;
            this.signature = the_signature;
        }
        new public Tpm2QuoteResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2QuoteResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns a digital signature of the audit session digest.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(NullSigScheme))]
    [SpecTypeName("TPM2_GetSessionAuditDigest_REQUEST")]
    public partial class Tpm2GetSessionAuditDigestRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of the privacy administrator (TPM_RH_ENDORSEMENT)
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle privacyAdminHandle { get; set; }
        /// <summary>
        /// handle of the signing key
        /// Auth Index: 2
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle signHandle { get; set; }
        /// <summary>
        /// handle of the audit session
        /// Auth Index: None
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle sessionHandle { get; set; }
        /// <summary>
        /// user-provided qualifying data  may be zero-length
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "qualifyingDataSize", 2)]
        [DataMember()]
        public byte[] qualifyingData;
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(4, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get {
                if(inScheme != null) {
                    return (TpmAlgId)inScheme.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        /// (One of [SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme])
        /// </summary>
        [MarshalAs(5, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public ISigSchemeUnion inScheme { get; set; }
        public Tpm2GetSessionAuditDigestRequest()
        {
            privacyAdminHandle = new TpmHandle();
            signHandle = new TpmHandle();
            sessionHandle = new TpmHandle();
            qualifyingData = null;
        }
        public Tpm2GetSessionAuditDigestRequest(Tpm2GetSessionAuditDigestRequest the_Tpm2GetSessionAuditDigestRequest)
        {
            if((Object) the_Tpm2GetSessionAuditDigestRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            privacyAdminHandle = the_Tpm2GetSessionAuditDigestRequest.privacyAdminHandle;
            signHandle = the_Tpm2GetSessionAuditDigestRequest.signHandle;
            sessionHandle = the_Tpm2GetSessionAuditDigestRequest.sessionHandle;
            qualifyingData = the_Tpm2GetSessionAuditDigestRequest.qualifyingData;
        }
        ///<param name = "the_privacyAdminHandle">handle of the privacy administrator (TPM_RH_ENDORSEMENT) Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_signHandle">handle of the signing key Auth Index: 2 Auth Role: USER</param>
        ///<param name = "the_sessionHandle">handle of the audit session Auth Index: None</param>
        ///<param name = "the_qualifyingData">user-provided qualifying data  may be zero-length</param>
        ///<param name = "the_inScheme">signing scheme to use if the scheme for signHandle is TPM_ALG_NULL(One of SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme)</param>
        public Tpm2GetSessionAuditDigestRequest(
        TpmHandle the_privacyAdminHandle,
        TpmHandle the_signHandle,
        TpmHandle the_sessionHandle,
        byte[] the_qualifyingData,
        ISigSchemeUnion the_inScheme
        )
        {
            this.privacyAdminHandle = the_privacyAdminHandle;
            this.signHandle = the_signHandle;
            this.sessionHandle = the_sessionHandle;
            this.qualifyingData = the_qualifyingData;
            this.inScheme = the_inScheme;
        }
        new public Tpm2GetSessionAuditDigestRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2GetSessionAuditDigestRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns a digital signature of the audit session digest.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureRsa))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureEcc))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(NullSignature))]
    [SpecTypeName("TPM2_GetSessionAuditDigest_RESPONSE")]
    public partial class Tpm2GetSessionAuditDigestResponse: TpmStructureBase
    {
        /// <summary>
        /// the audit information that was signed
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "auditInfoSize", 2)]
        [DataMember()]
        public byte[] auditInfo;
        /// <summary>
        /// selector of the algorithm used to construct the signature
        /// </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get {
                if(signature != null) {
                    return (TpmAlgId)signature.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// the signature over auditInfo
        /// (One of [SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature])
        /// </summary>
        [MarshalAs(2, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }
        public Tpm2GetSessionAuditDigestResponse()
        {
            auditInfo = null;
        }
        public Tpm2GetSessionAuditDigestResponse(Tpm2GetSessionAuditDigestResponse the_Tpm2GetSessionAuditDigestResponse)
        {
            if((Object) the_Tpm2GetSessionAuditDigestResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            auditInfo = the_Tpm2GetSessionAuditDigestResponse.auditInfo;
        }
        ///<param name = "the_auditInfo">the audit information that was signed</param>
        ///<param name = "the_signature">the signature over auditInfo(One of SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature)</param>
        public Tpm2GetSessionAuditDigestResponse(
        byte[] the_auditInfo,
        ISignatureUnion the_signature
        )
        {
            this.auditInfo = the_auditInfo;
            this.signature = the_signature;
        }
        new public Tpm2GetSessionAuditDigestResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2GetSessionAuditDigestResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns the current value of the command audit digest, a digest of the commands being audited, and the audit hash algorithm. These values are placed in an attestation structure and signed with the key referenced by signHandle.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(NullSigScheme))]
    [SpecTypeName("TPM2_GetCommandAuditDigest_REQUEST")]
    public partial class Tpm2GetCommandAuditDigestRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of the privacy administrator (TPM_RH_ENDORSEMENT)
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle privacyHandle { get; set; }
        /// <summary>
        /// the handle of the signing key
        /// Auth Index: 2
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle signHandle { get; set; }
        /// <summary>
        /// other data to associate with this audit digest
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "qualifyingDataSize", 2)]
        [DataMember()]
        public byte[] qualifyingData;
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(3, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get {
                if(inScheme != null) {
                    return (TpmAlgId)inScheme.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        /// (One of [SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme])
        /// </summary>
        [MarshalAs(4, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public ISigSchemeUnion inScheme { get; set; }
        public Tpm2GetCommandAuditDigestRequest()
        {
            privacyHandle = new TpmHandle();
            signHandle = new TpmHandle();
            qualifyingData = null;
        }
        public Tpm2GetCommandAuditDigestRequest(Tpm2GetCommandAuditDigestRequest the_Tpm2GetCommandAuditDigestRequest)
        {
            if((Object) the_Tpm2GetCommandAuditDigestRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            privacyHandle = the_Tpm2GetCommandAuditDigestRequest.privacyHandle;
            signHandle = the_Tpm2GetCommandAuditDigestRequest.signHandle;
            qualifyingData = the_Tpm2GetCommandAuditDigestRequest.qualifyingData;
        }
        ///<param name = "the_privacyHandle">handle of the privacy administrator (TPM_RH_ENDORSEMENT) Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_signHandle">the handle of the signing key Auth Index: 2 Auth Role: USER</param>
        ///<param name = "the_qualifyingData">other data to associate with this audit digest</param>
        ///<param name = "the_inScheme">signing scheme to use if the scheme for signHandle is TPM_ALG_NULL(One of SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme)</param>
        public Tpm2GetCommandAuditDigestRequest(
        TpmHandle the_privacyHandle,
        TpmHandle the_signHandle,
        byte[] the_qualifyingData,
        ISigSchemeUnion the_inScheme
        )
        {
            this.privacyHandle = the_privacyHandle;
            this.signHandle = the_signHandle;
            this.qualifyingData = the_qualifyingData;
            this.inScheme = the_inScheme;
        }
        new public Tpm2GetCommandAuditDigestRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2GetCommandAuditDigestRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns the current value of the command audit digest, a digest of the commands being audited, and the audit hash algorithm. These values are placed in an attestation structure and signed with the key referenced by signHandle.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureRsa))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureEcc))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(NullSignature))]
    [SpecTypeName("TPM2_GetCommandAuditDigest_RESPONSE")]
    public partial class Tpm2GetCommandAuditDigestResponse: TpmStructureBase
    {
        /// <summary>
        /// the auditInfo that was signed
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "auditInfoSize", 2)]
        [DataMember()]
        public byte[] auditInfo;
        /// <summary>
        /// selector of the algorithm used to construct the signature
        /// </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get {
                if(signature != null) {
                    return (TpmAlgId)signature.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// the signature over auditInfo
        /// (One of [SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature])
        /// </summary>
        [MarshalAs(2, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }
        public Tpm2GetCommandAuditDigestResponse()
        {
            auditInfo = null;
        }
        public Tpm2GetCommandAuditDigestResponse(Tpm2GetCommandAuditDigestResponse the_Tpm2GetCommandAuditDigestResponse)
        {
            if((Object) the_Tpm2GetCommandAuditDigestResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            auditInfo = the_Tpm2GetCommandAuditDigestResponse.auditInfo;
        }
        ///<param name = "the_auditInfo">the auditInfo that was signed</param>
        ///<param name = "the_signature">the signature over auditInfo(One of SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature)</param>
        public Tpm2GetCommandAuditDigestResponse(
        byte[] the_auditInfo,
        ISignatureUnion the_signature
        )
        {
            this.auditInfo = the_auditInfo;
            this.signature = the_signature;
        }
        new public Tpm2GetCommandAuditDigestResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2GetCommandAuditDigestResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns the current values of Time and Clock.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(NullSigScheme))]
    [SpecTypeName("TPM2_GetTime_REQUEST")]
    public partial class Tpm2GetTimeRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of the privacy administrator (TPM_RH_ENDORSEMENT)
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle privacyAdminHandle { get; set; }
        /// <summary>
        /// the keyHandle identifier of a loaded key that can perform digital signatures
        /// Auth Index: 2
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle signHandle { get; set; }
        /// <summary>
        /// data to tick stamp
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "qualifyingDataSize", 2)]
        [DataMember()]
        public byte[] qualifyingData;
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(3, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get {
                if(inScheme != null) {
                    return (TpmAlgId)inScheme.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        /// (One of [SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme])
        /// </summary>
        [MarshalAs(4, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public ISigSchemeUnion inScheme { get; set; }
        public Tpm2GetTimeRequest()
        {
            privacyAdminHandle = new TpmHandle();
            signHandle = new TpmHandle();
            qualifyingData = null;
        }
        public Tpm2GetTimeRequest(Tpm2GetTimeRequest the_Tpm2GetTimeRequest)
        {
            if((Object) the_Tpm2GetTimeRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            privacyAdminHandle = the_Tpm2GetTimeRequest.privacyAdminHandle;
            signHandle = the_Tpm2GetTimeRequest.signHandle;
            qualifyingData = the_Tpm2GetTimeRequest.qualifyingData;
        }
        ///<param name = "the_privacyAdminHandle">handle of the privacy administrator (TPM_RH_ENDORSEMENT) Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_signHandle">the keyHandle identifier of a loaded key that can perform digital signatures Auth Index: 2 Auth Role: USER</param>
        ///<param name = "the_qualifyingData">data to tick stamp</param>
        ///<param name = "the_inScheme">signing scheme to use if the scheme for signHandle is TPM_ALG_NULL(One of SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme)</param>
        public Tpm2GetTimeRequest(
        TpmHandle the_privacyAdminHandle,
        TpmHandle the_signHandle,
        byte[] the_qualifyingData,
        ISigSchemeUnion the_inScheme
        )
        {
            this.privacyAdminHandle = the_privacyAdminHandle;
            this.signHandle = the_signHandle;
            this.qualifyingData = the_qualifyingData;
            this.inScheme = the_inScheme;
        }
        new public Tpm2GetTimeRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2GetTimeRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns the current values of Time and Clock.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureRsa))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureEcc))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(NullSignature))]
    [SpecTypeName("TPM2_GetTime_RESPONSE")]
    public partial class Tpm2GetTimeResponse: TpmStructureBase
    {
        /// <summary>
        /// standard TPM-generated attestation block
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "timeInfoSize", 2)]
        [DataMember()]
        public byte[] timeInfo;
        /// <summary>
        /// selector of the algorithm used to construct the signature
        /// </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get {
                if(signature != null) {
                    return (TpmAlgId)signature.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// the signature over timeInfo
        /// (One of [SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature])
        /// </summary>
        [MarshalAs(2, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }
        public Tpm2GetTimeResponse()
        {
            timeInfo = null;
        }
        public Tpm2GetTimeResponse(Tpm2GetTimeResponse the_Tpm2GetTimeResponse)
        {
            if((Object) the_Tpm2GetTimeResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            timeInfo = the_Tpm2GetTimeResponse.timeInfo;
        }
        ///<param name = "the_timeInfo">standard TPM-generated attestation block</param>
        ///<param name = "the_signature">the signature over timeInfo(One of SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature)</param>
        public Tpm2GetTimeResponse(
        byte[] the_timeInfo,
        ISignatureUnion the_signature
        )
        {
            this.timeInfo = the_timeInfo;
            this.signature = the_signature;
        }
        new public Tpm2GetTimeResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2GetTimeResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// TPM2_Commit() performs the first part of an ECC anonymous signing operation. The TPM will perform the point multiplications on the provided points and return intermediate signing values. The signHandle parameter shall refer to an ECC key and the signing scheme must be anonymous (TPM_RC_SCHEME).
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("TPM2_Commit_REQUEST")]
    public partial class Tpm2CommitRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of the key that will be used in the signing operation
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle signHandle { get; set; }
        /// <summary>
        /// a point (M) on the curve used by signHandle
        /// </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "P1Size", 2)]
        [DataMember()]
        public EccPoint P1 { get; set; }
        /// <summary>
        /// octet array used to derive x-coordinate of a base point
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "s2Size", 2)]
        [DataMember()]
        public byte[] s2;
        /// <summary>
        /// y coordinate of the point associated with s2
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "y2Size", 2)]
        [DataMember()]
        public byte[] y2;
        public Tpm2CommitRequest()
        {
            signHandle = new TpmHandle();
            P1 = new EccPoint();
            s2 = null;
            y2 = null;
        }
        public Tpm2CommitRequest(Tpm2CommitRequest the_Tpm2CommitRequest)
        {
            if((Object) the_Tpm2CommitRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            signHandle = the_Tpm2CommitRequest.signHandle;
            P1 = the_Tpm2CommitRequest.P1;
            s2 = the_Tpm2CommitRequest.s2;
            y2 = the_Tpm2CommitRequest.y2;
        }
        ///<param name = "the_signHandle">handle of the key that will be used in the signing operation Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_P1">a point (M) on the curve used by signHandle</param>
        ///<param name = "the_s2">octet array used to derive x-coordinate of a base point</param>
        ///<param name = "the_y2">y coordinate of the point associated with s2</param>
        public Tpm2CommitRequest(
        TpmHandle the_signHandle,
        EccPoint the_P1,
        byte[] the_s2,
        byte[] the_y2
        )
        {
            this.signHandle = the_signHandle;
            this.P1 = the_P1;
            this.s2 = the_s2;
            this.y2 = the_y2;
        }
        new public Tpm2CommitRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2CommitRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// TPM2_Commit() performs the first part of an ECC anonymous signing operation. The TPM will perform the point multiplications on the provided points and return intermediate signing values. The signHandle parameter shall refer to an ECC key and the signing scheme must be anonymous (TPM_RC_SCHEME).
    /// </summary>
    [DataContract]
    [KnownType(typeof(EccPoint))]
    [KnownType(typeof(EccPoint))]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("TPM2_Commit_RESPONSE")]
    public partial class Tpm2CommitResponse: TpmStructureBase
    {
        /// <summary>
        /// ECC point K  [ds](x2, y2)
        /// </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "KSize", 2)]
        [DataMember()]
        public EccPoint K { get; set; }
        /// <summary>
        /// ECC point L  [r](x2, y2)
        /// </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "LSize", 2)]
        [DataMember()]
        public EccPoint L { get; set; }
        /// <summary>
        /// ECC point E  [r]P1
        /// </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "ESize", 2)]
        [DataMember()]
        public EccPoint E { get; set; }
        /// <summary>
        /// least-significant 16 bits of commitCount
        /// </summary>
        [MarshalAs(3)]
        [DataMember()]
        public ushort counter { get; set; }
        public Tpm2CommitResponse()
        {
            K = new EccPoint();
            L = new EccPoint();
            E = new EccPoint();
            counter = 0;
        }
        public Tpm2CommitResponse(Tpm2CommitResponse the_Tpm2CommitResponse)
        {
            if((Object) the_Tpm2CommitResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            K = the_Tpm2CommitResponse.K;
            L = the_Tpm2CommitResponse.L;
            E = the_Tpm2CommitResponse.E;
            counter = the_Tpm2CommitResponse.counter;
        }
        ///<param name = "the_K">ECC point K  [ds](x2, y2)</param>
        ///<param name = "the_L">ECC point L  [r](x2, y2)</param>
        ///<param name = "the_E">ECC point E  [r]P1</param>
        ///<param name = "the_counter">least-significant 16 bits of commitCount</param>
        public Tpm2CommitResponse(
        EccPoint the_K,
        EccPoint the_L,
        EccPoint the_E,
        ushort the_counter
        )
        {
            this.K = the_K;
            this.L = the_L;
            this.E = the_E;
            this.counter = the_counter;
        }
        new public Tpm2CommitResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2CommitResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// TPM2_EC_Ephemeral() creates an ephemeral key for use in a two-phase key exchange protocol.
    /// </summary>
    [DataContract]
    [KnownType(typeof(EccCurve))]
    [SpecTypeName("TPM2_EC_Ephemeral_REQUEST")]
    public partial class Tpm2EcEphemeralRequest: TpmStructureBase
    {
        /// <summary>
        /// The curve for the computed ephemeral point
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public EccCurve curveID { get; set; }
        public Tpm2EcEphemeralRequest()
        {
            curveID = new EccCurve();
        }
        public Tpm2EcEphemeralRequest(Tpm2EcEphemeralRequest the_Tpm2EcEphemeralRequest)
        {
            if((Object) the_Tpm2EcEphemeralRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            curveID = the_Tpm2EcEphemeralRequest.curveID;
        }
        ///<param name = "the_curveID">The curve for the computed ephemeral point</param>
        public Tpm2EcEphemeralRequest(
        EccCurve the_curveID
        )
        {
            this.curveID = the_curveID;
        }
        new public Tpm2EcEphemeralRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2EcEphemeralRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// TPM2_EC_Ephemeral() creates an ephemeral key for use in a two-phase key exchange protocol.
    /// </summary>
    [DataContract]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("TPM2_EC_Ephemeral_RESPONSE")]
    public partial class Tpm2EcEphemeralResponse: TpmStructureBase
    {
        /// <summary>
        /// ephemeral public key Q  [r]G
        /// </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "QSize", 2)]
        [DataMember()]
        public EccPoint Q { get; set; }
        /// <summary>
        /// least-significant 16 bits of commitCount
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ushort counter { get; set; }
        public Tpm2EcEphemeralResponse()
        {
            Q = new EccPoint();
            counter = 0;
        }
        public Tpm2EcEphemeralResponse(Tpm2EcEphemeralResponse the_Tpm2EcEphemeralResponse)
        {
            if((Object) the_Tpm2EcEphemeralResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            Q = the_Tpm2EcEphemeralResponse.Q;
            counter = the_Tpm2EcEphemeralResponse.counter;
        }
        ///<param name = "the_Q">ephemeral public key Q  [r]G</param>
        ///<param name = "the_counter">least-significant 16 bits of commitCount</param>
        public Tpm2EcEphemeralResponse(
        EccPoint the_Q,
        ushort the_counter
        )
        {
            this.Q = the_Q;
            this.counter = the_counter;
        }
        new public Tpm2EcEphemeralResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2EcEphemeralResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command uses loaded keys to validate a signature on a message with the message digest passed to the TPM.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureRsa))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureEcc))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(NullSignature))]
    [SpecTypeName("TPM2_VerifySignature_REQUEST")]
    public partial class Tpm2VerifySignatureRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of public key that will be used in the validation
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }
        /// <summary>
        /// digest of the signed message
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "digestSize", 2)]
        [DataMember()]
        public byte[] digest;
        /// <summary>
        /// selector of the algorithm used to construct the signature
        /// </summary>
        [MarshalAs(2, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get {
                if(signature != null) {
                    return (TpmAlgId)signature.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// signature to be tested
        /// (One of [SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature])
        /// </summary>
        [MarshalAs(3, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }
        public Tpm2VerifySignatureRequest()
        {
            keyHandle = new TpmHandle();
            digest = null;
        }
        public Tpm2VerifySignatureRequest(Tpm2VerifySignatureRequest the_Tpm2VerifySignatureRequest)
        {
            if((Object) the_Tpm2VerifySignatureRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            keyHandle = the_Tpm2VerifySignatureRequest.keyHandle;
            digest = the_Tpm2VerifySignatureRequest.digest;
        }
        ///<param name = "the_keyHandle">handle of public key that will be used in the validation Auth Index: None</param>
        ///<param name = "the_digest">digest of the signed message</param>
        ///<param name = "the_signature">signature to be tested(One of SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature)</param>
        public Tpm2VerifySignatureRequest(
        TpmHandle the_keyHandle,
        byte[] the_digest,
        ISignatureUnion the_signature
        )
        {
            this.keyHandle = the_keyHandle;
            this.digest = the_digest;
            this.signature = the_signature;
        }
        new public Tpm2VerifySignatureRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2VerifySignatureRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command uses loaded keys to validate a signature on a message with the message digest passed to the TPM.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TkVerified))]
    [SpecTypeName("TPM2_VerifySignature_RESPONSE")]
    public partial class Tpm2VerifySignatureResponse: TpmStructureBase
    {
        [MarshalAs(0)]
        [DataMember()]
        public TkVerified validation { get; set; }
        public Tpm2VerifySignatureResponse()
        {
            validation = new TkVerified();
        }
        public Tpm2VerifySignatureResponse(Tpm2VerifySignatureResponse the_Tpm2VerifySignatureResponse)
        {
            if((Object) the_Tpm2VerifySignatureResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            validation = the_Tpm2VerifySignatureResponse.validation;
        }
        ///<param name = "the_validation"></param>
        public Tpm2VerifySignatureResponse(
        TkVerified the_validation
        )
        {
            this.validation = the_validation;
        }
        new public Tpm2VerifySignatureResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2VerifySignatureResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command causes the TPM to sign an externally provided hash with the specified symmetric or asymmetric signing key.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(NullSigScheme))]
    [KnownType(typeof(TkHashcheck))]
    [SpecTypeName("TPM2_Sign_REQUEST")]
    public partial class Tpm2SignRequest: TpmStructureBase
    {
        /// <summary>
        /// Handle of key that will perform signing
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }
        /// <summary>
        /// digest to be signed
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "digestSize", 2)]
        [DataMember()]
        public byte[] digest;
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(2, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get {
                if(inScheme != null) {
                    return (TpmAlgId)inScheme.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// signing scheme to use if the scheme for keyHandle is TPM_ALG_NULL
        /// (One of [SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme])
        /// </summary>
        [MarshalAs(3, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public ISigSchemeUnion inScheme { get; set; }
        /// <summary>
        /// proof that digest was created by the TPM
        /// If keyHandle is not a restricted signing key, then this may be a NULL Ticket with tag = TPM_ST_CHECKHASH.
        /// </summary>
        [MarshalAs(4)]
        [DataMember()]
        public TkHashcheck validation { get; set; }
        public Tpm2SignRequest()
        {
            keyHandle = new TpmHandle();
            digest = null;
            validation = new TkHashcheck();
        }
        public Tpm2SignRequest(Tpm2SignRequest the_Tpm2SignRequest)
        {
            if((Object) the_Tpm2SignRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            keyHandle = the_Tpm2SignRequest.keyHandle;
            digest = the_Tpm2SignRequest.digest;
            validation = the_Tpm2SignRequest.validation;
        }
        ///<param name = "the_keyHandle">Handle of key that will perform signing Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_digest">digest to be signed</param>
        ///<param name = "the_inScheme">signing scheme to use if the scheme for keyHandle is TPM_ALG_NULL(One of SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme)</param>
        ///<param name = "the_validation">proof that digest was created by the TPM If keyHandle is not a restricted signing key, then this may be a NULL Ticket with tag = TPM_ST_CHECKHASH.</param>
        public Tpm2SignRequest(
        TpmHandle the_keyHandle,
        byte[] the_digest,
        ISigSchemeUnion the_inScheme,
        TkHashcheck the_validation
        )
        {
            this.keyHandle = the_keyHandle;
            this.digest = the_digest;
            this.inScheme = the_inScheme;
            this.validation = the_validation;
        }
        new public Tpm2SignRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2SignRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command causes the TPM to sign an externally provided hash with the specified symmetric or asymmetric signing key.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureRsa))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureEcc))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(NullSignature))]
    [SpecTypeName("TPM2_Sign_RESPONSE")]
    public partial class Tpm2SignResponse: TpmStructureBase
    {
        /// <summary>
        /// selector of the algorithm used to construct the signature
        /// </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get {
                if(signature != null) {
                    return (TpmAlgId)signature.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// the signature
        /// (One of [SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature])
        /// </summary>
        [MarshalAs(1, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }
        public Tpm2SignResponse()
        {
        }
        public Tpm2SignResponse(Tpm2SignResponse the_Tpm2SignResponse)
        {
            if((Object) the_Tpm2SignResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
        }
        ///<param name = "the_signature">the signature(One of SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature)</param>
        public Tpm2SignResponse(
        ISignatureUnion the_signature
        )
        {
            this.signature = the_signature;
        }
        new public Tpm2SignResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2SignResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command may be used by the Privacy Administrator or platform to change the audit status of a command or to set the hash algorithm used for the audit digest, but not both at the same time.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPM2_SetCommandCodeAuditStatus_REQUEST")]
    public partial class Tpm2SetCommandCodeAuditStatusRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle auth { get; set; }
        /// <summary>
        /// hash algorithm for the audit digest; if TPM_ALG_NULL, then the hash is not changed
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmAlgId auditAlg { get; set; }
        /// <summary>
        /// list of commands that will be added to those that will be audited
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "setListCount", 4)]
        [DataMember()]
        public TpmCc[] setList;
        /// <summary>
        /// list of commands that will no longer be audited
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "clearListCount", 4)]
        [DataMember()]
        public TpmCc[] clearList;
        public Tpm2SetCommandCodeAuditStatusRequest()
        {
            auth = new TpmHandle();
            auditAlg = TpmAlgId.Null;
            setList = null;
            clearList = null;
        }
        public Tpm2SetCommandCodeAuditStatusRequest(Tpm2SetCommandCodeAuditStatusRequest the_Tpm2SetCommandCodeAuditStatusRequest)
        {
            if((Object) the_Tpm2SetCommandCodeAuditStatusRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            auth = the_Tpm2SetCommandCodeAuditStatusRequest.auth;
            auditAlg = the_Tpm2SetCommandCodeAuditStatusRequest.auditAlg;
            setList = the_Tpm2SetCommandCodeAuditStatusRequest.setList;
            clearList = the_Tpm2SetCommandCodeAuditStatusRequest.clearList;
        }
        ///<param name = "the_auth">TPM_RH_OWNER or TPM_RH_PLATFORM+{PP} Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_auditAlg">hash algorithm for the audit digest; if TPM_ALG_NULL, then the hash is not changed</param>
        ///<param name = "the_setList">list of commands that will be added to those that will be audited</param>
        ///<param name = "the_clearList">list of commands that will no longer be audited</param>
        public Tpm2SetCommandCodeAuditStatusRequest(
        TpmHandle the_auth,
        TpmAlgId the_auditAlg,
        TpmCc[] the_setList,
        TpmCc[] the_clearList
        )
        {
            this.auth = the_auth;
            this.auditAlg = the_auditAlg;
            this.setList = the_setList;
            this.clearList = the_clearList;
        }
        new public Tpm2SetCommandCodeAuditStatusRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2SetCommandCodeAuditStatusRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command may be used by the Privacy Administrator or platform to change the audit status of a command or to set the hash algorithm used for the audit digest, but not both at the same time.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_SetCommandCodeAuditStatus_RESPONSE")]
    public partial class Tpm2SetCommandCodeAuditStatusResponse: TpmStructureBase
    {
        public Tpm2SetCommandCodeAuditStatusResponse()
        {
        }
        new public Tpm2SetCommandCodeAuditStatusResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2SetCommandCodeAuditStatusResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to cause an update to the indicated PCR. The digests parameter contains one or more tagged digest values identified by an algorithm ID. For each digest, the PCR associated with pcrHandle is Extended into the bank identified by the tag (hashAlg).
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PCR_Extend_REQUEST")]
    public partial class Tpm2PcrExtendRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of the PCR
        /// Auth Handle: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle pcrHandle { get; set; }
        /// <summary>
        /// list of tagged digest values to be extended
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "digestsCount", 4)]
        [DataMember()]
        public TpmHash[] digests;
        public Tpm2PcrExtendRequest()
        {
            pcrHandle = new TpmHandle();
            digests = null;
        }
        public Tpm2PcrExtendRequest(Tpm2PcrExtendRequest the_Tpm2PcrExtendRequest)
        {
            if((Object) the_Tpm2PcrExtendRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            pcrHandle = the_Tpm2PcrExtendRequest.pcrHandle;
            digests = the_Tpm2PcrExtendRequest.digests;
        }
        ///<param name = "the_pcrHandle">handle of the PCR Auth Handle: 1 Auth Role: USER</param>
        ///<param name = "the_digests">list of tagged digest values to be extended</param>
        public Tpm2PcrExtendRequest(
        TpmHandle the_pcrHandle,
        TpmHash[] the_digests
        )
        {
            this.pcrHandle = the_pcrHandle;
            this.digests = the_digests;
        }
        new public Tpm2PcrExtendRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PcrExtendRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to cause an update to the indicated PCR. The digests parameter contains one or more tagged digest values identified by an algorithm ID. For each digest, the PCR associated with pcrHandle is Extended into the bank identified by the tag (hashAlg).
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PCR_Extend_RESPONSE")]
    public partial class Tpm2PcrExtendResponse: TpmStructureBase
    {
        public Tpm2PcrExtendResponse()
        {
        }
        new public Tpm2PcrExtendResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PcrExtendResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to cause an update to the indicated PCR.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PCR_Event_REQUEST")]
    public partial class Tpm2PcrEventRequest: TpmStructureBase
    {
        /// <summary>
        /// Handle of the PCR
        /// Auth Handle: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle pcrHandle { get; set; }
        /// <summary>
        /// Event data in sized buffer
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "eventDataSize", 2)]
        [DataMember()]
        public byte[] eventData;
        public Tpm2PcrEventRequest()
        {
            pcrHandle = new TpmHandle();
            eventData = null;
        }
        public Tpm2PcrEventRequest(Tpm2PcrEventRequest the_Tpm2PcrEventRequest)
        {
            if((Object) the_Tpm2PcrEventRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            pcrHandle = the_Tpm2PcrEventRequest.pcrHandle;
            eventData = the_Tpm2PcrEventRequest.eventData;
        }
        ///<param name = "the_pcrHandle">Handle of the PCR Auth Handle: 1 Auth Role: USER</param>
        ///<param name = "the_eventData">Event data in sized buffer</param>
        public Tpm2PcrEventRequest(
        TpmHandle the_pcrHandle,
        byte[] the_eventData
        )
        {
            this.pcrHandle = the_pcrHandle;
            this.eventData = the_eventData;
        }
        new public Tpm2PcrEventRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PcrEventRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to cause an update to the indicated PCR.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PCR_Event_RESPONSE")]
    public partial class Tpm2PcrEventResponse: TpmStructureBase
    {
        [MarshalAs(0, MarshalType.VariableLengthArray, "digestsCount", 4)]
        [DataMember()]
        public TpmHash[] digests;
        public Tpm2PcrEventResponse()
        {
            digests = null;
        }
        public Tpm2PcrEventResponse(Tpm2PcrEventResponse the_Tpm2PcrEventResponse)
        {
            if((Object) the_Tpm2PcrEventResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            digests = the_Tpm2PcrEventResponse.digests;
        }
        ///<param name = "the_digests"></param>
        public Tpm2PcrEventResponse(
        TpmHash[] the_digests
        )
        {
            this.digests = the_digests;
        }
        new public Tpm2PcrEventResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PcrEventResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns the values of all PCR specified in pcrSelectionIn.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PCR_Read_REQUEST")]
    public partial class Tpm2PcrReadRequest: TpmStructureBase
    {
        /// <summary>
        /// The selection of PCR to read
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "pcrSelectionInCount", 4)]
        [DataMember()]
        public PcrSelection[] pcrSelectionIn;
        public Tpm2PcrReadRequest()
        {
            pcrSelectionIn = null;
        }
        public Tpm2PcrReadRequest(Tpm2PcrReadRequest the_Tpm2PcrReadRequest)
        {
            if((Object) the_Tpm2PcrReadRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            pcrSelectionIn = the_Tpm2PcrReadRequest.pcrSelectionIn;
        }
        ///<param name = "the_pcrSelectionIn">The selection of PCR to read</param>
        public Tpm2PcrReadRequest(
        PcrSelection[] the_pcrSelectionIn
        )
        {
            this.pcrSelectionIn = the_pcrSelectionIn;
        }
        new public Tpm2PcrReadRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PcrReadRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns the values of all PCR specified in pcrSelectionIn.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PCR_Read_RESPONSE")]
    public partial class Tpm2PcrReadResponse: TpmStructureBase
    {
        /// <summary>
        /// the current value of the PCR update counter
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public uint pcrUpdateCounter { get; set; }
        /// <summary>
        /// the PCR in the returned list
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "pcrSelectionOutCount", 4)]
        [DataMember()]
        public PcrSelection[] pcrSelectionOut;
        /// <summary>
        /// the contents of the PCR indicated in pcrSelectOut-> pcrSelection[] as tagged digests
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "pcrValuesCount", 4)]
        [DataMember()]
        public Tpm2bDigest[] pcrValues;
        public Tpm2PcrReadResponse()
        {
            pcrUpdateCounter = 0;
            pcrSelectionOut = null;
            pcrValues = null;
        }
        public Tpm2PcrReadResponse(Tpm2PcrReadResponse the_Tpm2PcrReadResponse)
        {
            if((Object) the_Tpm2PcrReadResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            pcrUpdateCounter = the_Tpm2PcrReadResponse.pcrUpdateCounter;
            pcrSelectionOut = the_Tpm2PcrReadResponse.pcrSelectionOut;
            pcrValues = the_Tpm2PcrReadResponse.pcrValues;
        }
        ///<param name = "the_pcrUpdateCounter">the current value of the PCR update counter</param>
        ///<param name = "the_pcrSelectionOut">the PCR in the returned list</param>
        ///<param name = "the_pcrValues">the contents of the PCR indicated in pcrSelectOut-> pcrSelection[] as tagged digests</param>
        public Tpm2PcrReadResponse(
        uint the_pcrUpdateCounter,
        PcrSelection[] the_pcrSelectionOut,
        Tpm2bDigest[] the_pcrValues
        )
        {
            this.pcrUpdateCounter = the_pcrUpdateCounter;
            this.pcrSelectionOut = the_pcrSelectionOut;
            this.pcrValues = the_pcrValues;
        }
        new public Tpm2PcrReadResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PcrReadResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to set the desired PCR allocation of PCR and algorithms. This command requires Platform Authorization.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PCR_Allocate_REQUEST")]
    public partial class Tpm2PcrAllocateRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// the requested allocation
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "pcrAllocationCount", 4)]
        [DataMember()]
        public PcrSelection[] pcrAllocation;
        public Tpm2PcrAllocateRequest()
        {
            authHandle = new TpmHandle();
            pcrAllocation = null;
        }
        public Tpm2PcrAllocateRequest(Tpm2PcrAllocateRequest the_Tpm2PcrAllocateRequest)
        {
            if((Object) the_Tpm2PcrAllocateRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2PcrAllocateRequest.authHandle;
            pcrAllocation = the_Tpm2PcrAllocateRequest.pcrAllocation;
        }
        ///<param name = "the_authHandle">TPM_RH_PLATFORM+{PP} Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_pcrAllocation">the requested allocation</param>
        public Tpm2PcrAllocateRequest(
        TpmHandle the_authHandle,
        PcrSelection[] the_pcrAllocation
        )
        {
            this.authHandle = the_authHandle;
            this.pcrAllocation = the_pcrAllocation;
        }
        new public Tpm2PcrAllocateRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PcrAllocateRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to set the desired PCR allocation of PCR and algorithms. This command requires Platform Authorization.
    /// </summary>
    [DataContract]
    [KnownType(typeof(byte))]
    [SpecTypeName("TPM2_PCR_Allocate_RESPONSE")]
    public partial class Tpm2PcrAllocateResponse: TpmStructureBase
    {
        /// <summary>
        /// YES if the allocation succeeded
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public byte allocationSuccess { get; set; }
        /// <summary>
        /// maximum number of PCR that may be in a bank
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint maxPCR { get; set; }
        /// <summary>
        /// number of octets required to satisfy the request
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public uint sizeNeeded { get; set; }
        /// <summary>
        /// Number of octets available. Computed before the allocation.
        /// </summary>
        [MarshalAs(3)]
        [DataMember()]
        public uint sizeAvailable { get; set; }
        public Tpm2PcrAllocateResponse()
        {
            allocationSuccess = 0;
            maxPCR = 0;
            sizeNeeded = 0;
            sizeAvailable = 0;
        }
        public Tpm2PcrAllocateResponse(Tpm2PcrAllocateResponse the_Tpm2PcrAllocateResponse)
        {
            if((Object) the_Tpm2PcrAllocateResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            allocationSuccess = the_Tpm2PcrAllocateResponse.allocationSuccess;
            maxPCR = the_Tpm2PcrAllocateResponse.maxPCR;
            sizeNeeded = the_Tpm2PcrAllocateResponse.sizeNeeded;
            sizeAvailable = the_Tpm2PcrAllocateResponse.sizeAvailable;
        }
        ///<param name = "the_allocationSuccess">YES if the allocation succeeded</param>
        ///<param name = "the_maxPCR">maximum number of PCR that may be in a bank</param>
        ///<param name = "the_sizeNeeded">number of octets required to satisfy the request</param>
        ///<param name = "the_sizeAvailable">Number of octets available. Computed before the allocation.</param>
        public Tpm2PcrAllocateResponse(
        byte the_allocationSuccess,
        uint the_maxPCR,
        uint the_sizeNeeded,
        uint the_sizeAvailable
        )
        {
            this.allocationSuccess = the_allocationSuccess;
            this.maxPCR = the_maxPCR;
            this.sizeNeeded = the_sizeNeeded;
            this.sizeAvailable = the_sizeAvailable;
        }
        new public Tpm2PcrAllocateResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PcrAllocateResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to associate a policy with a PCR or group of PCR. The policy determines the conditions under which a PCR may be extended or reset.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PCR_SetAuthPolicy_REQUEST")]
    public partial class Tpm2PcrSetAuthPolicyRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// the desired authPolicy
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "authPolicySize", 2)]
        [DataMember()]
        public byte[] authPolicy;
        /// <summary>
        /// the hash algorithm of the policy
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }
        /// <summary>
        /// the PCR for which the policy is to be set
        /// </summary>
        [MarshalAs(3)]
        [DataMember()]
        public TpmHandle pcrNum { get; set; }
        public Tpm2PcrSetAuthPolicyRequest()
        {
            authHandle = new TpmHandle();
            authPolicy = null;
            hashAlg = TpmAlgId.Null;
            pcrNum = new TpmHandle();
        }
        public Tpm2PcrSetAuthPolicyRequest(Tpm2PcrSetAuthPolicyRequest the_Tpm2PcrSetAuthPolicyRequest)
        {
            if((Object) the_Tpm2PcrSetAuthPolicyRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2PcrSetAuthPolicyRequest.authHandle;
            authPolicy = the_Tpm2PcrSetAuthPolicyRequest.authPolicy;
            hashAlg = the_Tpm2PcrSetAuthPolicyRequest.hashAlg;
            pcrNum = the_Tpm2PcrSetAuthPolicyRequest.pcrNum;
        }
        ///<param name = "the_authHandle">TPM_RH_PLATFORM+{PP} Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_authPolicy">the desired authPolicy</param>
        ///<param name = "the_hashAlg">the hash algorithm of the policy</param>
        ///<param name = "the_pcrNum">the PCR for which the policy is to be set</param>
        public Tpm2PcrSetAuthPolicyRequest(
        TpmHandle the_authHandle,
        byte[] the_authPolicy,
        TpmAlgId the_hashAlg,
        TpmHandle the_pcrNum
        )
        {
            this.authHandle = the_authHandle;
            this.authPolicy = the_authPolicy;
            this.hashAlg = the_hashAlg;
            this.pcrNum = the_pcrNum;
        }
        new public Tpm2PcrSetAuthPolicyRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PcrSetAuthPolicyRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to associate a policy with a PCR or group of PCR. The policy determines the conditions under which a PCR may be extended or reset.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PCR_SetAuthPolicy_RESPONSE")]
    public partial class Tpm2PcrSetAuthPolicyResponse: TpmStructureBase
    {
        public Tpm2PcrSetAuthPolicyResponse()
        {
        }
        new public Tpm2PcrSetAuthPolicyResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PcrSetAuthPolicyResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command changes the authValue of a PCR or group of PCR.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PCR_SetAuthValue_REQUEST")]
    public partial class Tpm2PcrSetAuthValueRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for a PCR that may have an authorization value set
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle pcrHandle { get; set; }
        /// <summary>
        /// the desired authorization value
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "authSize", 2)]
        [DataMember()]
        public byte[] auth;
        public Tpm2PcrSetAuthValueRequest()
        {
            pcrHandle = new TpmHandle();
            auth = null;
        }
        public Tpm2PcrSetAuthValueRequest(Tpm2PcrSetAuthValueRequest the_Tpm2PcrSetAuthValueRequest)
        {
            if((Object) the_Tpm2PcrSetAuthValueRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            pcrHandle = the_Tpm2PcrSetAuthValueRequest.pcrHandle;
            auth = the_Tpm2PcrSetAuthValueRequest.auth;
        }
        ///<param name = "the_pcrHandle">handle for a PCR that may have an authorization value set Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_auth">the desired authorization value</param>
        public Tpm2PcrSetAuthValueRequest(
        TpmHandle the_pcrHandle,
        byte[] the_auth
        )
        {
            this.pcrHandle = the_pcrHandle;
            this.auth = the_auth;
        }
        new public Tpm2PcrSetAuthValueRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PcrSetAuthValueRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command changes the authValue of a PCR or group of PCR.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PCR_SetAuthValue_RESPONSE")]
    public partial class Tpm2PcrSetAuthValueResponse: TpmStructureBase
    {
        public Tpm2PcrSetAuthValueResponse()
        {
        }
        new public Tpm2PcrSetAuthValueResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PcrSetAuthValueResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// If the attribute of a PCR allows the PCR to be reset and proper authorization is provided, then this command may be used to set the PCR to zero. The attributes of the PCR may restrict the locality that can perform the reset operation.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PCR_Reset_REQUEST")]
    public partial class Tpm2PcrResetRequest: TpmStructureBase
    {
        /// <summary>
        /// the PCR to reset
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle pcrHandle { get; set; }
        public Tpm2PcrResetRequest()
        {
            pcrHandle = new TpmHandle();
        }
        public Tpm2PcrResetRequest(Tpm2PcrResetRequest the_Tpm2PcrResetRequest)
        {
            if((Object) the_Tpm2PcrResetRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            pcrHandle = the_Tpm2PcrResetRequest.pcrHandle;
        }
        ///<param name = "the_pcrHandle">the PCR to reset Auth Index: 1 Auth Role: USER</param>
        public Tpm2PcrResetRequest(
        TpmHandle the_pcrHandle
        )
        {
            this.pcrHandle = the_pcrHandle;
        }
        new public Tpm2PcrResetRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PcrResetRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// If the attribute of a PCR allows the PCR to be reset and proper authorization is provided, then this command may be used to set the PCR to zero. The attributes of the PCR may restrict the locality that can perform the reset operation.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PCR_Reset_RESPONSE")]
    public partial class Tpm2PcrResetResponse: TpmStructureBase
    {
        public Tpm2PcrResetResponse()
        {
        }
        new public Tpm2PcrResetResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PcrResetResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command includes a signed authorization in a policy. The command ties the policy to a signing key by including the Name of the signing key in the policyDigest
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(int))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureRsa))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureEcc))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(NullSignature))]
    [SpecTypeName("TPM2_PolicySigned_REQUEST")]
    public partial class Tpm2PolicySignedRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for a key that will validate the signature
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authObject { get; set; }
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        /// <summary>
        /// the policy nonce for the session
        /// This can be the Empty Buffer.
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "nonceTPMSize", 2)]
        [DataMember()]
        public byte[] nonceTPM;
        /// <summary>
        /// digest of the command parameters to which this authorization is limited
        /// This is not the cpHash for this command but the cpHash for the command to which this policy session will be applied. If it is not limited, the parameter will be the Empty Buffer.
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "cpHashASize", 2)]
        [DataMember()]
        public byte[] cpHashA;
        /// <summary>
        /// a reference to a policy relating to the authorization  may be the Empty Buffer
        /// Size is limited to be no larger than the nonce size supported on the TPM.
        /// </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "policyRefSize", 2)]
        [DataMember()]
        public byte[] policyRef;
        /// <summary>
        /// time when authorization will expire, measured in seconds from the time that nonceTPM was generated
        /// If expiration is non-negative, a NULL Ticket is returned. See 23.2.5.
        /// </summary>
        [MarshalAs(5)]
        [DataMember()]
        public int expiration { get; set; }
        /// <summary>
        /// selector of the algorithm used to construct the signature
        /// </summary>
        [MarshalAs(6, MarshalType.UnionSelector)]
        public TpmAlgId authSigAlg {
            get {
                if(auth != null) {
                    return (TpmAlgId)auth.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// signed authorization (not optional)
        /// (One of [SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature])
        /// </summary>
        [MarshalAs(7, MarshalType.Union, "authSigAlg")]
        [DataMember()]
        public ISignatureUnion auth { get; set; }
        public Tpm2PolicySignedRequest()
        {
            authObject = new TpmHandle();
            policySession = new TpmHandle();
            nonceTPM = null;
            cpHashA = null;
            policyRef = null;
            expiration = new int();
        }
        public Tpm2PolicySignedRequest(Tpm2PolicySignedRequest the_Tpm2PolicySignedRequest)
        {
            if((Object) the_Tpm2PolicySignedRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authObject = the_Tpm2PolicySignedRequest.authObject;
            policySession = the_Tpm2PolicySignedRequest.policySession;
            nonceTPM = the_Tpm2PolicySignedRequest.nonceTPM;
            cpHashA = the_Tpm2PolicySignedRequest.cpHashA;
            policyRef = the_Tpm2PolicySignedRequest.policyRef;
            expiration = the_Tpm2PolicySignedRequest.expiration;
        }
        ///<param name = "the_authObject">handle for a key that will validate the signature Auth Index: None</param>
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        ///<param name = "the_nonceTPM">the policy nonce for the session This can be the Empty Buffer.</param>
        ///<param name = "the_cpHashA">digest of the command parameters to which this authorization is limited This is not the cpHash for this command but the cpHash for the command to which this policy session will be applied. If it is not limited, the parameter will be the Empty Buffer.</param>
        ///<param name = "the_policyRef">a reference to a policy relating to the authorization  may be the Empty Buffer Size is limited to be no larger than the nonce size supported on the TPM.</param>
        ///<param name = "the_expiration">time when authorization will expire, measured in seconds from the time that nonceTPM was generated If expiration is non-negative, a NULL Ticket is returned. See 23.2.5.</param>
        ///<param name = "the_auth">signed authorization (not optional)(One of SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature)</param>
        public Tpm2PolicySignedRequest(
        TpmHandle the_authObject,
        TpmHandle the_policySession,
        byte[] the_nonceTPM,
        byte[] the_cpHashA,
        byte[] the_policyRef,
        int the_expiration,
        ISignatureUnion the_auth
        )
        {
            this.authObject = the_authObject;
            this.policySession = the_policySession;
            this.nonceTPM = the_nonceTPM;
            this.cpHashA = the_cpHashA;
            this.policyRef = the_policyRef;
            this.expiration = the_expiration;
            this.auth = the_auth;
        }
        new public Tpm2PolicySignedRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicySignedRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command includes a signed authorization in a policy. The command ties the policy to a signing key by including the Name of the signing key in the policyDigest
    /// </summary>
    [DataContract]
    [KnownType(typeof(TkAuth))]
    [SpecTypeName("TPM2_PolicySigned_RESPONSE")]
    public partial class Tpm2PolicySignedResponse: TpmStructureBase
    {
        /// <summary>
        /// implementation-specific time value, used to indicate to the TPM when the ticket expires
        /// NOTE	If policyTicket is a NULL Ticket, then this shall be the Empty Buffer.
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "timeoutSize", 2)]
        [DataMember()]
        public byte[] timeout;
        /// <summary>
        /// produced if the command succeeds and expiration in the command was non-zero; this ticket will use the TPMT_ST_AUTH_SIGNED structure tag. See 23.2.5
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TkAuth policyTicket { get; set; }
        public Tpm2PolicySignedResponse()
        {
            timeout = null;
            policyTicket = new TkAuth();
        }
        public Tpm2PolicySignedResponse(Tpm2PolicySignedResponse the_Tpm2PolicySignedResponse)
        {
            if((Object) the_Tpm2PolicySignedResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            timeout = the_Tpm2PolicySignedResponse.timeout;
            policyTicket = the_Tpm2PolicySignedResponse.policyTicket;
        }
        ///<param name = "the_timeout">implementation-specific time value, used to indicate to the TPM when the ticket expires NOTE	If policyTicket is a NULL Ticket, then this shall be the Empty Buffer.</param>
        ///<param name = "the_policyTicket">produced if the command succeeds and expiration in the command was non-zero; this ticket will use the TPMT_ST_AUTH_SIGNED structure tag. See 23.2.5</param>
        public Tpm2PolicySignedResponse(
        byte[] the_timeout,
        TkAuth the_policyTicket
        )
        {
            this.timeout = the_timeout;
            this.policyTicket = the_policyTicket;
        }
        new public Tpm2PolicySignedResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicySignedResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command includes a secret-based authorization to a policy. The caller proves knowledge of the secret value using an authorization session using the authValue associated with authHandle. A password session, an HMAC session, or a policy session containing TPM2_PolicyAuthValue() or TPM2_PolicyPassword() will satisfy this requirement.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(int))]
    [SpecTypeName("TPM2_PolicySecret_REQUEST")]
    public partial class Tpm2PolicySecretRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for an entity providing the authorization
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        /// <summary>
        /// the policy nonce for the session
        /// This can be the Empty Buffer.
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "nonceTPMSize", 2)]
        [DataMember()]
        public byte[] nonceTPM;
        /// <summary>
        /// digest of the command parameters to which this authorization is limited
        /// This not the cpHash for this command but the cpHash for the command to which this policy session will be applied. If it is not limited, the parameter will be the Empty Buffer.
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "cpHashASize", 2)]
        [DataMember()]
        public byte[] cpHashA;
        /// <summary>
        /// a reference to a policy relating to the authorization  may be the Empty Buffer
        /// Size is limited to be no larger than the nonce size supported on the TPM.
        /// </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "policyRefSize", 2)]
        [DataMember()]
        public byte[] policyRef;
        /// <summary>
        /// time when authorization will expire, measured in seconds from the time that nonceTPM was generated
        /// If expiration is non-negative, a NULL Ticket is returned. See 23.2.5.
        /// </summary>
        [MarshalAs(5)]
        [DataMember()]
        public int expiration { get; set; }
        public Tpm2PolicySecretRequest()
        {
            authHandle = new TpmHandle();
            policySession = new TpmHandle();
            nonceTPM = null;
            cpHashA = null;
            policyRef = null;
            expiration = new int();
        }
        public Tpm2PolicySecretRequest(Tpm2PolicySecretRequest the_Tpm2PolicySecretRequest)
        {
            if((Object) the_Tpm2PolicySecretRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2PolicySecretRequest.authHandle;
            policySession = the_Tpm2PolicySecretRequest.policySession;
            nonceTPM = the_Tpm2PolicySecretRequest.nonceTPM;
            cpHashA = the_Tpm2PolicySecretRequest.cpHashA;
            policyRef = the_Tpm2PolicySecretRequest.policyRef;
            expiration = the_Tpm2PolicySecretRequest.expiration;
        }
        ///<param name = "the_authHandle">handle for an entity providing the authorization Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        ///<param name = "the_nonceTPM">the policy nonce for the session This can be the Empty Buffer.</param>
        ///<param name = "the_cpHashA">digest of the command parameters to which this authorization is limited This not the cpHash for this command but the cpHash for the command to which this policy session will be applied. If it is not limited, the parameter will be the Empty Buffer.</param>
        ///<param name = "the_policyRef">a reference to a policy relating to the authorization  may be the Empty Buffer Size is limited to be no larger than the nonce size supported on the TPM.</param>
        ///<param name = "the_expiration">time when authorization will expire, measured in seconds from the time that nonceTPM was generated If expiration is non-negative, a NULL Ticket is returned. See 23.2.5.</param>
        public Tpm2PolicySecretRequest(
        TpmHandle the_authHandle,
        TpmHandle the_policySession,
        byte[] the_nonceTPM,
        byte[] the_cpHashA,
        byte[] the_policyRef,
        int the_expiration
        )
        {
            this.authHandle = the_authHandle;
            this.policySession = the_policySession;
            this.nonceTPM = the_nonceTPM;
            this.cpHashA = the_cpHashA;
            this.policyRef = the_policyRef;
            this.expiration = the_expiration;
        }
        new public Tpm2PolicySecretRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicySecretRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command includes a secret-based authorization to a policy. The caller proves knowledge of the secret value using an authorization session using the authValue associated with authHandle. A password session, an HMAC session, or a policy session containing TPM2_PolicyAuthValue() or TPM2_PolicyPassword() will satisfy this requirement.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TkAuth))]
    [SpecTypeName("TPM2_PolicySecret_RESPONSE")]
    public partial class Tpm2PolicySecretResponse: TpmStructureBase
    {
        /// <summary>
        /// implementation-specific time value used to indicate to the TPM when the ticket expires; this ticket will use the TPMT_ST_AUTH_SECRET structure tag
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "timeoutSize", 2)]
        [DataMember()]
        public byte[] timeout;
        /// <summary>
        /// produced if the command succeeds and expiration in the command was non-zero. See 23.2.5
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TkAuth policyTicket { get; set; }
        public Tpm2PolicySecretResponse()
        {
            timeout = null;
            policyTicket = new TkAuth();
        }
        public Tpm2PolicySecretResponse(Tpm2PolicySecretResponse the_Tpm2PolicySecretResponse)
        {
            if((Object) the_Tpm2PolicySecretResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            timeout = the_Tpm2PolicySecretResponse.timeout;
            policyTicket = the_Tpm2PolicySecretResponse.policyTicket;
        }
        ///<param name = "the_timeout">implementation-specific time value used to indicate to the TPM when the ticket expires; this ticket will use the TPMT_ST_AUTH_SECRET structure tag</param>
        ///<param name = "the_policyTicket">produced if the command succeeds and expiration in the command was non-zero. See 23.2.5</param>
        public Tpm2PolicySecretResponse(
        byte[] the_timeout,
        TkAuth the_policyTicket
        )
        {
            this.timeout = the_timeout;
            this.policyTicket = the_policyTicket;
        }
        new public Tpm2PolicySecretResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicySecretResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is similar to TPM2_PolicySigned() except that it takes a ticket instead of a signed authorization. The ticket represents a validated authorization that had an expiration time associated with it.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TkAuth))]
    [SpecTypeName("TPM2_PolicyTicket_REQUEST")]
    public partial class Tpm2PolicyTicketRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        /// <summary>
        /// time when authorization will expire
        /// The contents are TPM specific. This shall be the value returned when ticket was produced.
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "timeoutSize", 2)]
        [DataMember()]
        public byte[] timeout;
        /// <summary>
        /// digest of the command parameters to which this authorization is limited
        /// If it is not limited, the parameter will be the Empty Buffer.
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "cpHashASize", 2)]
        [DataMember()]
        public byte[] cpHashA;
        /// <summary>
        /// reference to a qualifier for the policy  may be the Empty Buffer
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "policyRefSize", 2)]
        [DataMember()]
        public byte[] policyRef;
        /// <summary>
        /// name of the object that provided the authorization
        /// </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "authNameSize", 2)]
        [DataMember()]
        public byte[] authName;
        /// <summary>
        /// an authorization ticket returned by the TPM in response to a TPM2_PolicySigned() or TPM2_PolicySecret()
        /// </summary>
        [MarshalAs(5)]
        [DataMember()]
        public TkAuth ticket { get; set; }
        public Tpm2PolicyTicketRequest()
        {
            policySession = new TpmHandle();
            timeout = null;
            cpHashA = null;
            policyRef = null;
            authName = null;
            ticket = new TkAuth();
        }
        public Tpm2PolicyTicketRequest(Tpm2PolicyTicketRequest the_Tpm2PolicyTicketRequest)
        {
            if((Object) the_Tpm2PolicyTicketRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            policySession = the_Tpm2PolicyTicketRequest.policySession;
            timeout = the_Tpm2PolicyTicketRequest.timeout;
            cpHashA = the_Tpm2PolicyTicketRequest.cpHashA;
            policyRef = the_Tpm2PolicyTicketRequest.policyRef;
            authName = the_Tpm2PolicyTicketRequest.authName;
            ticket = the_Tpm2PolicyTicketRequest.ticket;
        }
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        ///<param name = "the_timeout">time when authorization will expire The contents are TPM specific. This shall be the value returned when ticket was produced.</param>
        ///<param name = "the_cpHashA">digest of the command parameters to which this authorization is limited If it is not limited, the parameter will be the Empty Buffer.</param>
        ///<param name = "the_policyRef">reference to a qualifier for the policy  may be the Empty Buffer</param>
        ///<param name = "the_authName">name of the object that provided the authorization</param>
        ///<param name = "the_ticket">an authorization ticket returned by the TPM in response to a TPM2_PolicySigned() or TPM2_PolicySecret()</param>
        public Tpm2PolicyTicketRequest(
        TpmHandle the_policySession,
        byte[] the_timeout,
        byte[] the_cpHashA,
        byte[] the_policyRef,
        byte[] the_authName,
        TkAuth the_ticket
        )
        {
            this.policySession = the_policySession;
            this.timeout = the_timeout;
            this.cpHashA = the_cpHashA;
            this.policyRef = the_policyRef;
            this.authName = the_authName;
            this.ticket = the_ticket;
        }
        new public Tpm2PolicyTicketRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyTicketRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is similar to TPM2_PolicySigned() except that it takes a ticket instead of a signed authorization. The ticket represents a validated authorization that had an expiration time associated with it.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyTicket_RESPONSE")]
    public partial class Tpm2PolicyTicketResponse: TpmStructureBase
    {
        public Tpm2PolicyTicketResponse()
        {
        }
        new public Tpm2PolicyTicketResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyTicketResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows options in authorizations without requiring that the TPM evaluate all of the options. If a policy may be satisfied by different sets of conditions, the TPM need only evaluate one set that satisfies the policy. This command will indicate that one of the required sets of conditions has been satisfied.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PolicyOR_REQUEST")]
    public partial class Tpm2PolicyORRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        /// <summary>
        /// the list of hashes to check for a match
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "pHashListCount", 4)]
        [DataMember()]
        public Tpm2bDigest[] pHashList;
        public Tpm2PolicyORRequest()
        {
            policySession = new TpmHandle();
            pHashList = null;
        }
        public Tpm2PolicyORRequest(Tpm2PolicyORRequest the_Tpm2PolicyORRequest)
        {
            if((Object) the_Tpm2PolicyORRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            policySession = the_Tpm2PolicyORRequest.policySession;
            pHashList = the_Tpm2PolicyORRequest.pHashList;
        }
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        ///<param name = "the_pHashList">the list of hashes to check for a match</param>
        public Tpm2PolicyORRequest(
        TpmHandle the_policySession,
        Tpm2bDigest[] the_pHashList
        )
        {
            this.policySession = the_policySession;
            this.pHashList = the_pHashList;
        }
        new public Tpm2PolicyORRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyORRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows options in authorizations without requiring that the TPM evaluate all of the options. If a policy may be satisfied by different sets of conditions, the TPM need only evaluate one set that satisfies the policy. This command will indicate that one of the required sets of conditions has been satisfied.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyOR_RESPONSE")]
    public partial class Tpm2PolicyORResponse: TpmStructureBase
    {
        public Tpm2PolicyORResponse()
        {
        }
        new public Tpm2PolicyORResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyORResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to cause conditional gating of a policy based on PCR. This command together with TPM2_PolicyOR() allows one group of authorizations to occur when PCR are in one state and a different set of authorizations when the PCR are in a different state.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PolicyPCR_REQUEST")]
    public partial class Tpm2PolicyPCRRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        /// <summary>
        /// expected digest value of the selected PCR using the hash algorithm of the session; may be zero length
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "pcrDigestSize", 2)]
        [DataMember()]
        public byte[] pcrDigest;
        /// <summary>
        /// the PCR to include in the check digest
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "pcrsCount", 4)]
        [DataMember()]
        public PcrSelection[] pcrs;
        public Tpm2PolicyPCRRequest()
        {
            policySession = new TpmHandle();
            pcrDigest = null;
            pcrs = null;
        }
        public Tpm2PolicyPCRRequest(Tpm2PolicyPCRRequest the_Tpm2PolicyPCRRequest)
        {
            if((Object) the_Tpm2PolicyPCRRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            policySession = the_Tpm2PolicyPCRRequest.policySession;
            pcrDigest = the_Tpm2PolicyPCRRequest.pcrDigest;
            pcrs = the_Tpm2PolicyPCRRequest.pcrs;
        }
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        ///<param name = "the_pcrDigest">expected digest value of the selected PCR using the hash algorithm of the session; may be zero length</param>
        ///<param name = "the_pcrs">the PCR to include in the check digest</param>
        public Tpm2PolicyPCRRequest(
        TpmHandle the_policySession,
        byte[] the_pcrDigest,
        PcrSelection[] the_pcrs
        )
        {
            this.policySession = the_policySession;
            this.pcrDigest = the_pcrDigest;
            this.pcrs = the_pcrs;
        }
        new public Tpm2PolicyPCRRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyPCRRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to cause conditional gating of a policy based on PCR. This command together with TPM2_PolicyOR() allows one group of authorizations to occur when PCR are in one state and a different set of authorizations when the PCR are in a different state.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyPCR_RESPONSE")]
    public partial class Tpm2PolicyPCRResponse: TpmStructureBase
    {
        public Tpm2PolicyPCRResponse()
        {
        }
        new public Tpm2PolicyPCRResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyPCRResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command indicates that the authorization will be limited to a specific locality.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(LocalityAttr))]
    [SpecTypeName("TPM2_PolicyLocality_REQUEST")]
    public partial class Tpm2PolicyLocalityRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        /// <summary>
        /// the allowed localities for the policy
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public LocalityAttr locality { get; set; }
        public Tpm2PolicyLocalityRequest()
        {
            policySession = new TpmHandle();
            locality = new LocalityAttr();
        }
        public Tpm2PolicyLocalityRequest(Tpm2PolicyLocalityRequest the_Tpm2PolicyLocalityRequest)
        {
            if((Object) the_Tpm2PolicyLocalityRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            policySession = the_Tpm2PolicyLocalityRequest.policySession;
            locality = the_Tpm2PolicyLocalityRequest.locality;
        }
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        ///<param name = "the_locality">the allowed localities for the policy</param>
        public Tpm2PolicyLocalityRequest(
        TpmHandle the_policySession,
        LocalityAttr the_locality
        )
        {
            this.policySession = the_policySession;
            this.locality = the_locality;
        }
        new public Tpm2PolicyLocalityRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyLocalityRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command indicates that the authorization will be limited to a specific locality.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyLocality_RESPONSE")]
    public partial class Tpm2PolicyLocalityResponse: TpmStructureBase
    {
        public Tpm2PolicyLocalityResponse()
        {
        }
        new public Tpm2PolicyLocalityResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyLocalityResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to cause conditional gating of a policy based on the contents of an NV Index. It is an immediate assertion. The NV index is validated during the TPM2_PolicyNV() command, not when the session is used for authorization.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(Eo))]
    [SpecTypeName("TPM2_PolicyNV_REQUEST")]
    public partial class Tpm2PolicyNVRequest: TpmStructureBase
    {
        /// <summary>
        /// handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// the NV Index of the area to read
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        /// <summary>
        /// the second operand
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "operandBSize", 2)]
        [DataMember()]
        public byte[] operandB;
        /// <summary>
        /// the offset in the NV Index for the start of operand A
        /// </summary>
        [MarshalAs(4)]
        [DataMember()]
        public ushort offset { get; set; }
        /// <summary>
        /// the comparison to make
        /// </summary>
        [MarshalAs(5)]
        [DataMember()]
        public Eo operation { get; set; }
        public Tpm2PolicyNVRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
            policySession = new TpmHandle();
            operandB = null;
            offset = 0;
            operation = new Eo();
        }
        public Tpm2PolicyNVRequest(Tpm2PolicyNVRequest the_Tpm2PolicyNVRequest)
        {
            if((Object) the_Tpm2PolicyNVRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2PolicyNVRequest.authHandle;
            nvIndex = the_Tpm2PolicyNVRequest.nvIndex;
            policySession = the_Tpm2PolicyNVRequest.policySession;
            operandB = the_Tpm2PolicyNVRequest.operandB;
            offset = the_Tpm2PolicyNVRequest.offset;
            operation = the_Tpm2PolicyNVRequest.operation;
        }
        ///<param name = "the_authHandle">handle indicating the source of the authorization value Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_nvIndex">the NV Index of the area to read Auth Index: None</param>
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        ///<param name = "the_operandB">the second operand</param>
        ///<param name = "the_offset">the offset in the NV Index for the start of operand A</param>
        ///<param name = "the_operation">the comparison to make</param>
        public Tpm2PolicyNVRequest(
        TpmHandle the_authHandle,
        TpmHandle the_nvIndex,
        TpmHandle the_policySession,
        byte[] the_operandB,
        ushort the_offset,
        Eo the_operation
        )
        {
            this.authHandle = the_authHandle;
            this.nvIndex = the_nvIndex;
            this.policySession = the_policySession;
            this.operandB = the_operandB;
            this.offset = the_offset;
            this.operation = the_operation;
        }
        new public Tpm2PolicyNVRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyNVRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to cause conditional gating of a policy based on the contents of an NV Index. It is an immediate assertion. The NV index is validated during the TPM2_PolicyNV() command, not when the session is used for authorization.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyNV_RESPONSE")]
    public partial class Tpm2PolicyNVResponse: TpmStructureBase
    {
        public Tpm2PolicyNVResponse()
        {
        }
        new public Tpm2PolicyNVResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyNVResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to cause conditional gating of a policy based on the contents of the TPMS_TIME_INFO structure.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(Eo))]
    [SpecTypeName("TPM2_PolicyCounterTimer_REQUEST")]
    public partial class Tpm2PolicyCounterTimerRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        /// <summary>
        /// the second operand
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "operandBSize", 2)]
        [DataMember()]
        public byte[] operandB;
        /// <summary>
        /// the offset in TPMS_TIME_INFO structure for the start of operand A
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public ushort offset { get; set; }
        /// <summary>
        /// the comparison to make
        /// </summary>
        [MarshalAs(3)]
        [DataMember()]
        public Eo operation { get; set; }
        public Tpm2PolicyCounterTimerRequest()
        {
            policySession = new TpmHandle();
            operandB = null;
            offset = 0;
            operation = new Eo();
        }
        public Tpm2PolicyCounterTimerRequest(Tpm2PolicyCounterTimerRequest the_Tpm2PolicyCounterTimerRequest)
        {
            if((Object) the_Tpm2PolicyCounterTimerRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            policySession = the_Tpm2PolicyCounterTimerRequest.policySession;
            operandB = the_Tpm2PolicyCounterTimerRequest.operandB;
            offset = the_Tpm2PolicyCounterTimerRequest.offset;
            operation = the_Tpm2PolicyCounterTimerRequest.operation;
        }
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        ///<param name = "the_operandB">the second operand</param>
        ///<param name = "the_offset">the offset in TPMS_TIME_INFO structure for the start of operand A</param>
        ///<param name = "the_operation">the comparison to make</param>
        public Tpm2PolicyCounterTimerRequest(
        TpmHandle the_policySession,
        byte[] the_operandB,
        ushort the_offset,
        Eo the_operation
        )
        {
            this.policySession = the_policySession;
            this.operandB = the_operandB;
            this.offset = the_offset;
            this.operation = the_operation;
        }
        new public Tpm2PolicyCounterTimerRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyCounterTimerRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to cause conditional gating of a policy based on the contents of the TPMS_TIME_INFO structure.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyCounterTimer_RESPONSE")]
    public partial class Tpm2PolicyCounterTimerResponse: TpmStructureBase
    {
        public Tpm2PolicyCounterTimerResponse()
        {
        }
        new public Tpm2PolicyCounterTimerResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyCounterTimerResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command indicates that the authorization will be limited to a specific command code.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmCc))]
    [SpecTypeName("TPM2_PolicyCommandCode_REQUEST")]
    public partial class Tpm2PolicyCommandCodeRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        /// <summary>
        /// the allowed commandCode
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmCc code { get; set; }
        public Tpm2PolicyCommandCodeRequest()
        {
            policySession = new TpmHandle();
            code = new TpmCc();
        }
        public Tpm2PolicyCommandCodeRequest(Tpm2PolicyCommandCodeRequest the_Tpm2PolicyCommandCodeRequest)
        {
            if((Object) the_Tpm2PolicyCommandCodeRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            policySession = the_Tpm2PolicyCommandCodeRequest.policySession;
            code = the_Tpm2PolicyCommandCodeRequest.code;
        }
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        ///<param name = "the_code">the allowed commandCode</param>
        public Tpm2PolicyCommandCodeRequest(
        TpmHandle the_policySession,
        TpmCc the_code
        )
        {
            this.policySession = the_policySession;
            this.code = the_code;
        }
        new public Tpm2PolicyCommandCodeRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyCommandCodeRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command indicates that the authorization will be limited to a specific command code.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyCommandCode_RESPONSE")]
    public partial class Tpm2PolicyCommandCodeResponse: TpmStructureBase
    {
        public Tpm2PolicyCommandCodeResponse()
        {
        }
        new public Tpm2PolicyCommandCodeResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyCommandCodeResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command indicates that physical presence will need to be asserted at the time the authorization is performed.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PolicyPhysicalPresence_REQUEST")]
    public partial class Tpm2PolicyPhysicalPresenceRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        public Tpm2PolicyPhysicalPresenceRequest()
        {
            policySession = new TpmHandle();
        }
        public Tpm2PolicyPhysicalPresenceRequest(Tpm2PolicyPhysicalPresenceRequest the_Tpm2PolicyPhysicalPresenceRequest)
        {
            if((Object) the_Tpm2PolicyPhysicalPresenceRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            policySession = the_Tpm2PolicyPhysicalPresenceRequest.policySession;
        }
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        public Tpm2PolicyPhysicalPresenceRequest(
        TpmHandle the_policySession
        )
        {
            this.policySession = the_policySession;
        }
        new public Tpm2PolicyPhysicalPresenceRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyPhysicalPresenceRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command indicates that physical presence will need to be asserted at the time the authorization is performed.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyPhysicalPresence_RESPONSE")]
    public partial class Tpm2PolicyPhysicalPresenceResponse: TpmStructureBase
    {
        public Tpm2PolicyPhysicalPresenceResponse()
        {
        }
        new public Tpm2PolicyPhysicalPresenceResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyPhysicalPresenceResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to allow a policy to be bound to a specific command and command parameters.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PolicyCpHash_REQUEST")]
    public partial class Tpm2PolicyCpHashRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        /// <summary>
        /// the cpHash added to the policy
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "cpHashASize", 2)]
        [DataMember()]
        public byte[] cpHashA;
        public Tpm2PolicyCpHashRequest()
        {
            policySession = new TpmHandle();
            cpHashA = null;
        }
        public Tpm2PolicyCpHashRequest(Tpm2PolicyCpHashRequest the_Tpm2PolicyCpHashRequest)
        {
            if((Object) the_Tpm2PolicyCpHashRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            policySession = the_Tpm2PolicyCpHashRequest.policySession;
            cpHashA = the_Tpm2PolicyCpHashRequest.cpHashA;
        }
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        ///<param name = "the_cpHashA">the cpHash added to the policy</param>
        public Tpm2PolicyCpHashRequest(
        TpmHandle the_policySession,
        byte[] the_cpHashA
        )
        {
            this.policySession = the_policySession;
            this.cpHashA = the_cpHashA;
        }
        new public Tpm2PolicyCpHashRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyCpHashRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to allow a policy to be bound to a specific command and command parameters.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyCpHash_RESPONSE")]
    public partial class Tpm2PolicyCpHashResponse: TpmStructureBase
    {
        public Tpm2PolicyCpHashResponse()
        {
        }
        new public Tpm2PolicyCpHashResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyCpHashResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows a policy to be bound to a specific set of TPM entities without being bound to the parameters of the command. This is most useful for commands such as TPM2_Duplicate() and for TPM2_PCR_Event() when the referenced PCR requires a policy.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PolicyNameHash_REQUEST")]
    public partial class Tpm2PolicyNameHashRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        /// <summary>
        /// the digest to be added to the policy
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "nameHashSize", 2)]
        [DataMember()]
        public byte[] nameHash;
        public Tpm2PolicyNameHashRequest()
        {
            policySession = new TpmHandle();
            nameHash = null;
        }
        public Tpm2PolicyNameHashRequest(Tpm2PolicyNameHashRequest the_Tpm2PolicyNameHashRequest)
        {
            if((Object) the_Tpm2PolicyNameHashRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            policySession = the_Tpm2PolicyNameHashRequest.policySession;
            nameHash = the_Tpm2PolicyNameHashRequest.nameHash;
        }
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        ///<param name = "the_nameHash">the digest to be added to the policy</param>
        public Tpm2PolicyNameHashRequest(
        TpmHandle the_policySession,
        byte[] the_nameHash
        )
        {
            this.policySession = the_policySession;
            this.nameHash = the_nameHash;
        }
        new public Tpm2PolicyNameHashRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyNameHashRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows a policy to be bound to a specific set of TPM entities without being bound to the parameters of the command. This is most useful for commands such as TPM2_Duplicate() and for TPM2_PCR_Event() when the referenced PCR requires a policy.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyNameHash_RESPONSE")]
    public partial class Tpm2PolicyNameHashResponse: TpmStructureBase
    {
        public Tpm2PolicyNameHashResponse()
        {
        }
        new public Tpm2PolicyNameHashResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyNameHashResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows qualification of duplication to allow duplication to a selected new parent.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(byte))]
    [SpecTypeName("TPM2_PolicyDuplicationSelect_REQUEST")]
    public partial class Tpm2PolicyDuplicationSelectRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        /// <summary>
        /// the Name of the object to be duplicated
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "objectNameSize", 2)]
        [DataMember()]
        public byte[] objectName;
        /// <summary>
        /// the Name of the new parent
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "newParentNameSize", 2)]
        [DataMember()]
        public byte[] newParentName;
        /// <summary>
        /// if YES, the objectName will be included in the value in policySessionpolicyDigest
        /// </summary>
        [MarshalAs(3)]
        [DataMember()]
        public byte includeObject { get; set; }
        public Tpm2PolicyDuplicationSelectRequest()
        {
            policySession = new TpmHandle();
            objectName = null;
            newParentName = null;
            includeObject = 0;
        }
        public Tpm2PolicyDuplicationSelectRequest(Tpm2PolicyDuplicationSelectRequest the_Tpm2PolicyDuplicationSelectRequest)
        {
            if((Object) the_Tpm2PolicyDuplicationSelectRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            policySession = the_Tpm2PolicyDuplicationSelectRequest.policySession;
            objectName = the_Tpm2PolicyDuplicationSelectRequest.objectName;
            newParentName = the_Tpm2PolicyDuplicationSelectRequest.newParentName;
            includeObject = the_Tpm2PolicyDuplicationSelectRequest.includeObject;
        }
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        ///<param name = "the_objectName">the Name of the object to be duplicated</param>
        ///<param name = "the_newParentName">the Name of the new parent</param>
        ///<param name = "the_includeObject">if YES, the objectName will be included in the value in policySessionpolicyDigest</param>
        public Tpm2PolicyDuplicationSelectRequest(
        TpmHandle the_policySession,
        byte[] the_objectName,
        byte[] the_newParentName,
        byte the_includeObject
        )
        {
            this.policySession = the_policySession;
            this.objectName = the_objectName;
            this.newParentName = the_newParentName;
            this.includeObject = the_includeObject;
        }
        new public Tpm2PolicyDuplicationSelectRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyDuplicationSelectRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows qualification of duplication to allow duplication to a selected new parent.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyDuplicationSelect_RESPONSE")]
    public partial class Tpm2PolicyDuplicationSelectResponse: TpmStructureBase
    {
        public Tpm2PolicyDuplicationSelectResponse()
        {
        }
        new public Tpm2PolicyDuplicationSelectResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyDuplicationSelectResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows policies to change. If a policy were static, then it would be difficult to add users to a policy. This command lets a policy authority sign a new policy so that it may be used in an existing policy.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TkVerified))]
    [SpecTypeName("TPM2_PolicyAuthorize_REQUEST")]
    public partial class Tpm2PolicyAuthorizeRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        /// <summary>
        /// digest of the policy being approved
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "approvedPolicySize", 2)]
        [DataMember()]
        public byte[] approvedPolicy;
        /// <summary>
        /// a policy qualifier
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "policyRefSize", 2)]
        [DataMember()]
        public byte[] policyRef;
        /// <summary>
        /// Name of a key that can sign a policy addition
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "keySignSize", 2)]
        [DataMember()]
        public byte[] keySign;
        /// <summary>
        /// ticket validating that approvedPolicy and policyRef were signed by keySign
        /// </summary>
        [MarshalAs(4)]
        [DataMember()]
        public TkVerified checkTicket { get; set; }
        public Tpm2PolicyAuthorizeRequest()
        {
            policySession = new TpmHandle();
            approvedPolicy = null;
            policyRef = null;
            keySign = null;
            checkTicket = new TkVerified();
        }
        public Tpm2PolicyAuthorizeRequest(Tpm2PolicyAuthorizeRequest the_Tpm2PolicyAuthorizeRequest)
        {
            if((Object) the_Tpm2PolicyAuthorizeRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            policySession = the_Tpm2PolicyAuthorizeRequest.policySession;
            approvedPolicy = the_Tpm2PolicyAuthorizeRequest.approvedPolicy;
            policyRef = the_Tpm2PolicyAuthorizeRequest.policyRef;
            keySign = the_Tpm2PolicyAuthorizeRequest.keySign;
            checkTicket = the_Tpm2PolicyAuthorizeRequest.checkTicket;
        }
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        ///<param name = "the_approvedPolicy">digest of the policy being approved</param>
        ///<param name = "the_policyRef">a policy qualifier</param>
        ///<param name = "the_keySign">Name of a key that can sign a policy addition</param>
        ///<param name = "the_checkTicket">ticket validating that approvedPolicy and policyRef were signed by keySign</param>
        public Tpm2PolicyAuthorizeRequest(
        TpmHandle the_policySession,
        byte[] the_approvedPolicy,
        byte[] the_policyRef,
        byte[] the_keySign,
        TkVerified the_checkTicket
        )
        {
            this.policySession = the_policySession;
            this.approvedPolicy = the_approvedPolicy;
            this.policyRef = the_policyRef;
            this.keySign = the_keySign;
            this.checkTicket = the_checkTicket;
        }
        new public Tpm2PolicyAuthorizeRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyAuthorizeRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows policies to change. If a policy were static, then it would be difficult to add users to a policy. This command lets a policy authority sign a new policy so that it may be used in an existing policy.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyAuthorize_RESPONSE")]
    public partial class Tpm2PolicyAuthorizeResponse: TpmStructureBase
    {
        public Tpm2PolicyAuthorizeResponse()
        {
        }
        new public Tpm2PolicyAuthorizeResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyAuthorizeResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows a policy to be bound to the authorization value of the authorized entity.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PolicyAuthValue_REQUEST")]
    public partial class Tpm2PolicyAuthValueRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        public Tpm2PolicyAuthValueRequest()
        {
            policySession = new TpmHandle();
        }
        public Tpm2PolicyAuthValueRequest(Tpm2PolicyAuthValueRequest the_Tpm2PolicyAuthValueRequest)
        {
            if((Object) the_Tpm2PolicyAuthValueRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            policySession = the_Tpm2PolicyAuthValueRequest.policySession;
        }
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        public Tpm2PolicyAuthValueRequest(
        TpmHandle the_policySession
        )
        {
            this.policySession = the_policySession;
        }
        new public Tpm2PolicyAuthValueRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyAuthValueRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows a policy to be bound to the authorization value of the authorized entity.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyAuthValue_RESPONSE")]
    public partial class Tpm2PolicyAuthValueResponse: TpmStructureBase
    {
        public Tpm2PolicyAuthValueResponse()
        {
        }
        new public Tpm2PolicyAuthValueResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyAuthValueResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows a policy to be bound to the authorization value of the authorized object.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PolicyPassword_REQUEST")]
    public partial class Tpm2PolicyPasswordRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        public Tpm2PolicyPasswordRequest()
        {
            policySession = new TpmHandle();
        }
        public Tpm2PolicyPasswordRequest(Tpm2PolicyPasswordRequest the_Tpm2PolicyPasswordRequest)
        {
            if((Object) the_Tpm2PolicyPasswordRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            policySession = the_Tpm2PolicyPasswordRequest.policySession;
        }
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        public Tpm2PolicyPasswordRequest(
        TpmHandle the_policySession
        )
        {
            this.policySession = the_policySession;
        }
        new public Tpm2PolicyPasswordRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyPasswordRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows a policy to be bound to the authorization value of the authorized object.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyPassword_RESPONSE")]
    public partial class Tpm2PolicyPasswordResponse: TpmStructureBase
    {
        public Tpm2PolicyPasswordResponse()
        {
        }
        new public Tpm2PolicyPasswordResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyPasswordResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns the current policyDigest of the session. This command allows the TPM to be used to perform the actions required to pre-compute the authPolicy for an object.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PolicyGetDigest_REQUEST")]
    public partial class Tpm2PolicyGetDigestRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the policy session
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        public Tpm2PolicyGetDigestRequest()
        {
            policySession = new TpmHandle();
        }
        public Tpm2PolicyGetDigestRequest(Tpm2PolicyGetDigestRequest the_Tpm2PolicyGetDigestRequest)
        {
            if((Object) the_Tpm2PolicyGetDigestRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            policySession = the_Tpm2PolicyGetDigestRequest.policySession;
        }
        ///<param name = "the_policySession">handle for the policy session Auth Index: None</param>
        public Tpm2PolicyGetDigestRequest(
        TpmHandle the_policySession
        )
        {
            this.policySession = the_policySession;
        }
        new public Tpm2PolicyGetDigestRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyGetDigestRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns the current policyDigest of the session. This command allows the TPM to be used to perform the actions required to pre-compute the authPolicy for an object.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyGetDigest_RESPONSE")]
    public partial class Tpm2PolicyGetDigestResponse: TpmStructureBase
    {
        /// <summary>
        /// the current value of the policySessionpolicyDigest
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "policyDigestSize", 2)]
        [DataMember()]
        public byte[] policyDigest;
        public Tpm2PolicyGetDigestResponse()
        {
            policyDigest = null;
        }
        public Tpm2PolicyGetDigestResponse(Tpm2PolicyGetDigestResponse the_Tpm2PolicyGetDigestResponse)
        {
            if((Object) the_Tpm2PolicyGetDigestResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            policyDigest = the_Tpm2PolicyGetDigestResponse.policyDigest;
        }
        ///<param name = "the_policyDigest">the current value of the policySessionpolicyDigest</param>
        public Tpm2PolicyGetDigestResponse(
        byte[] the_policyDigest
        )
        {
            this.policyDigest = the_policyDigest;
        }
        new public Tpm2PolicyGetDigestResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyGetDigestResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows a policy to be bound to the TPMA_NV_WRITTEN attributes. This is a deferred assertion. Values are stored in the policy session context and checked when the policy is used for authorization.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(byte))]
    [SpecTypeName("TPM2_PolicyNvWritten_REQUEST")]
    public partial class Tpm2PolicyNvWrittenRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        /// <summary>
        /// YES if NV Index is required to have been written
        /// NO if NV Index is required not to have been written
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public byte writtenSet { get; set; }
        public Tpm2PolicyNvWrittenRequest()
        {
            policySession = new TpmHandle();
            writtenSet = 0;
        }
        public Tpm2PolicyNvWrittenRequest(Tpm2PolicyNvWrittenRequest the_Tpm2PolicyNvWrittenRequest)
        {
            if((Object) the_Tpm2PolicyNvWrittenRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            policySession = the_Tpm2PolicyNvWrittenRequest.policySession;
            writtenSet = the_Tpm2PolicyNvWrittenRequest.writtenSet;
        }
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        ///<param name = "the_writtenSet">YES if NV Index is required to have been written NO if NV Index is required not to have been written</param>
        public Tpm2PolicyNvWrittenRequest(
        TpmHandle the_policySession,
        byte the_writtenSet
        )
        {
            this.policySession = the_policySession;
            this.writtenSet = the_writtenSet;
        }
        new public Tpm2PolicyNvWrittenRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyNvWrittenRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows a policy to be bound to the TPMA_NV_WRITTEN attributes. This is a deferred assertion. Values are stored in the policy session context and checked when the policy is used for authorization.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyNvWritten_RESPONSE")]
    public partial class Tpm2PolicyNvWrittenResponse: TpmStructureBase
    {
        public Tpm2PolicyNvWrittenResponse()
        {
        }
        new public Tpm2PolicyNvWrittenResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyNvWrittenResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows a policy to be bound to a specific creation template. This is most useful for an object creation command such as TPM2_Create(), TPM2_CreatePrimary(), or TPM2_Derive().
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PolicyTemplate_REQUEST")]
    public partial class Tpm2PolicyTemplateRequest: TpmStructureBase
    {
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        /// <summary>
        /// the digest to be added to the policy
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "templateHashSize", 2)]
        [DataMember()]
        public byte[] templateHash;
        public Tpm2PolicyTemplateRequest()
        {
            policySession = new TpmHandle();
            templateHash = null;
        }
        public Tpm2PolicyTemplateRequest(Tpm2PolicyTemplateRequest the_Tpm2PolicyTemplateRequest)
        {
            if((Object) the_Tpm2PolicyTemplateRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            policySession = the_Tpm2PolicyTemplateRequest.policySession;
            templateHash = the_Tpm2PolicyTemplateRequest.templateHash;
        }
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        ///<param name = "the_templateHash">the digest to be added to the policy</param>
        public Tpm2PolicyTemplateRequest(
        TpmHandle the_policySession,
        byte[] the_templateHash
        )
        {
            this.policySession = the_policySession;
            this.templateHash = the_templateHash;
        }
        new public Tpm2PolicyTemplateRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyTemplateRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows a policy to be bound to a specific creation template. This is most useful for an object creation command such as TPM2_Create(), TPM2_CreatePrimary(), or TPM2_Derive().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyTemplate_RESPONSE")]
    public partial class Tpm2PolicyTemplateResponse: TpmStructureBase
    {
        public Tpm2PolicyTemplateResponse()
        {
        }
        new public Tpm2PolicyTemplateResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyTemplateResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows policies to change by indirection. It allows creation of a policy that refers to a policy that exists in a specified NV location. When executed, the hash algorithm ID of the policy buffer and the policyBuffer are compared to an algorithm ID and policyBuffer that reside in the specified NV location. If they match, the TPM will reset policySessionpolicyDigest to a Zero Digest. Then it will update policySessionpolicyDigest with
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PolicyAuthorizeNV_REQUEST")]
    public partial class Tpm2PolicyAuthorizeNVRequest: TpmStructureBase
    {
        /// <summary>
        /// handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// the NV Index of the area to read
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }
        /// <summary>
        /// handle for the policy session being extended
        /// Auth Index: None
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle policySession { get; set; }
        public Tpm2PolicyAuthorizeNVRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
            policySession = new TpmHandle();
        }
        public Tpm2PolicyAuthorizeNVRequest(Tpm2PolicyAuthorizeNVRequest the_Tpm2PolicyAuthorizeNVRequest)
        {
            if((Object) the_Tpm2PolicyAuthorizeNVRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2PolicyAuthorizeNVRequest.authHandle;
            nvIndex = the_Tpm2PolicyAuthorizeNVRequest.nvIndex;
            policySession = the_Tpm2PolicyAuthorizeNVRequest.policySession;
        }
        ///<param name = "the_authHandle">handle indicating the source of the authorization value Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_nvIndex">the NV Index of the area to read Auth Index: None</param>
        ///<param name = "the_policySession">handle for the policy session being extended Auth Index: None</param>
        public Tpm2PolicyAuthorizeNVRequest(
        TpmHandle the_authHandle,
        TpmHandle the_nvIndex,
        TpmHandle the_policySession
        )
        {
            this.authHandle = the_authHandle;
            this.nvIndex = the_nvIndex;
            this.policySession = the_policySession;
        }
        new public Tpm2PolicyAuthorizeNVRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyAuthorizeNVRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows policies to change by indirection. It allows creation of a policy that refers to a policy that exists in a specified NV location. When executed, the hash algorithm ID of the policy buffer and the policyBuffer are compared to an algorithm ID and policyBuffer that reside in the specified NV location. If they match, the TPM will reset policySessionpolicyDigest to a Zero Digest. Then it will update policySessionpolicyDigest with
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PolicyAuthorizeNV_RESPONSE")]
    public partial class Tpm2PolicyAuthorizeNVResponse: TpmStructureBase
    {
        public Tpm2PolicyAuthorizeNVResponse()
        {
        }
        new public Tpm2PolicyAuthorizeNVResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PolicyAuthorizeNVResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to create a Primary Object under one of the Primary Seeds or a Temporary Object under TPM_RH_NULL. The command uses a TPM2B_PUBLIC as a template for the object to be created. The size of the unique field shall not be checked for consistency with the other object parameters. The command will create and load a Primary Object. The sensitive area is not returned.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(SensitiveCreate))]
    [SpecTypeName("TPM2_CreatePrimary_REQUEST")]
    public partial class Tpm2CreatePrimaryRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP}, or TPM_RH_NULL
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle primaryHandle { get; set; }
        /// <summary>
        /// the sensitive data, see TPM 2.0 Part 1 Sensitive Values
        /// </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "inSensitiveSize", 2)]
        [DataMember()]
        public SensitiveCreate inSensitive { get; set; }
        /// <summary>
        /// the public template
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "inPublicSize", 2)]
        [DataMember()]
        public byte[] inPublic;
        /// <summary>
        /// data that will be included in the creation data for this object to provide permanent, verifiable linkage between this object and some object owner data
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "outsideInfoSize", 2)]
        [DataMember()]
        public byte[] outsideInfo;
        /// <summary>
        /// PCR that will be used in creation data
        /// </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "creationPCRCount", 4)]
        [DataMember()]
        public PcrSelection[] creationPCR;
        public Tpm2CreatePrimaryRequest()
        {
            primaryHandle = new TpmHandle();
            inSensitive = new SensitiveCreate();
            inPublic = null;
            outsideInfo = null;
            creationPCR = null;
        }
        public Tpm2CreatePrimaryRequest(Tpm2CreatePrimaryRequest the_Tpm2CreatePrimaryRequest)
        {
            if((Object) the_Tpm2CreatePrimaryRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            primaryHandle = the_Tpm2CreatePrimaryRequest.primaryHandle;
            inSensitive = the_Tpm2CreatePrimaryRequest.inSensitive;
            inPublic = the_Tpm2CreatePrimaryRequest.inPublic;
            outsideInfo = the_Tpm2CreatePrimaryRequest.outsideInfo;
            creationPCR = the_Tpm2CreatePrimaryRequest.creationPCR;
        }
        ///<param name = "the_primaryHandle">TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP}, or TPM_RH_NULL Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_inSensitive">the sensitive data, see TPM 2.0 Part 1 Sensitive Values</param>
        ///<param name = "the_inPublic">the public template</param>
        ///<param name = "the_outsideInfo">data that will be included in the creation data for this object to provide permanent, verifiable linkage between this object and some object owner data</param>
        ///<param name = "the_creationPCR">PCR that will be used in creation data</param>
        public Tpm2CreatePrimaryRequest(
        TpmHandle the_primaryHandle,
        SensitiveCreate the_inSensitive,
        byte[] the_inPublic,
        byte[] the_outsideInfo,
        PcrSelection[] the_creationPCR
        )
        {
            this.primaryHandle = the_primaryHandle;
            this.inSensitive = the_inSensitive;
            this.inPublic = the_inPublic;
            this.outsideInfo = the_outsideInfo;
            this.creationPCR = the_creationPCR;
        }
        new public Tpm2CreatePrimaryRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2CreatePrimaryRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to create a Primary Object under one of the Primary Seeds or a Temporary Object under TPM_RH_NULL. The command uses a TPM2B_PUBLIC as a template for the object to be created. The size of the unique field shall not be checked for consistency with the other object parameters. The command will create and load a Primary Object. The sensitive area is not returned.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmPublic))]
    [KnownType(typeof(CreationData))]
    [KnownType(typeof(TkCreation))]
    [SpecTypeName("TPM2_CreatePrimary_RESPONSE")]
    public partial class Tpm2CreatePrimaryResponse: TpmStructureBase
    {
        /// <summary>
        /// handle of type TPM_HT_TRANSIENT for created Primary Object
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle objectHandle { get; set; }
        /// <summary>
        /// the public portion of the created object
        /// </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "outPublicSize", 2)]
        [DataMember()]
        public TpmPublic outPublic { get; set; }
        /// <summary>
        /// contains a TPMT_CREATION_DATA
        /// </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "creationDataSize", 2)]
        [DataMember()]
        public CreationData creationData { get; set; }
        /// <summary>
        /// digest of creationData using nameAlg of outPublic
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "creationHashSize", 2)]
        [DataMember()]
        public byte[] creationHash;
        /// <summary>
        /// ticket used by TPM2_CertifyCreation() to validate that the creation data was produced by the TPM
        /// </summary>
        [MarshalAs(4)]
        [DataMember()]
        public TkCreation creationTicket { get; set; }
        /// <summary>
        /// the name of the created object
        /// </summary>
        [MarshalAs(5, MarshalType.VariableLengthArray, "nameSize", 2)]
        [DataMember()]
        public byte[] name;
        public Tpm2CreatePrimaryResponse()
        {
            objectHandle = new TpmHandle();
            outPublic = new TpmPublic();
            creationData = new CreationData();
            creationHash = null;
            creationTicket = new TkCreation();
            name = null;
        }
        public Tpm2CreatePrimaryResponse(Tpm2CreatePrimaryResponse the_Tpm2CreatePrimaryResponse)
        {
            if((Object) the_Tpm2CreatePrimaryResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            objectHandle = the_Tpm2CreatePrimaryResponse.objectHandle;
            outPublic = the_Tpm2CreatePrimaryResponse.outPublic;
            creationData = the_Tpm2CreatePrimaryResponse.creationData;
            creationHash = the_Tpm2CreatePrimaryResponse.creationHash;
            creationTicket = the_Tpm2CreatePrimaryResponse.creationTicket;
            name = the_Tpm2CreatePrimaryResponse.name;
        }
        ///<param name = "the_objectHandle">handle of type TPM_HT_TRANSIENT for created Primary Object</param>
        ///<param name = "the_outPublic">the public portion of the created object</param>
        ///<param name = "the_creationData">contains a TPMT_CREATION_DATA</param>
        ///<param name = "the_creationHash">digest of creationData using nameAlg of outPublic</param>
        ///<param name = "the_creationTicket">ticket used by TPM2_CertifyCreation() to validate that the creation data was produced by the TPM</param>
        ///<param name = "the_name">the name of the created object</param>
        public Tpm2CreatePrimaryResponse(
        TpmHandle the_objectHandle,
        TpmPublic the_outPublic,
        CreationData the_creationData,
        byte[] the_creationHash,
        TkCreation the_creationTicket,
        byte[] the_name
        )
        {
            this.objectHandle = the_objectHandle;
            this.outPublic = the_outPublic;
            this.creationData = the_creationData;
            this.creationHash = the_creationHash;
            this.creationTicket = the_creationTicket;
            this.name = the_name;
        }
        new public Tpm2CreatePrimaryResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2CreatePrimaryResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command enables and disables use of a hierarchy and its associated NV storage. The command allows phEnable, phEnableNV, shEnable, and ehEnable to be changed when the proper authorization is provided.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(byte))]
    [SpecTypeName("TPM2_HierarchyControl_REQUEST")]
    public partial class Tpm2HierarchyControlRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_ENDORSEMENT, TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// the enable being modified
        /// TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM, or TPM_RH_PLATFORM_NV
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle enable { get; set; }
        /// <summary>
        /// YES if the enable should be SET, NO if the enable should be CLEAR
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public byte state { get; set; }
        public Tpm2HierarchyControlRequest()
        {
            authHandle = new TpmHandle();
            enable = new TpmHandle();
            state = 0;
        }
        public Tpm2HierarchyControlRequest(Tpm2HierarchyControlRequest the_Tpm2HierarchyControlRequest)
        {
            if((Object) the_Tpm2HierarchyControlRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2HierarchyControlRequest.authHandle;
            enable = the_Tpm2HierarchyControlRequest.enable;
            state = the_Tpm2HierarchyControlRequest.state;
        }
        ///<param name = "the_authHandle">TPM_RH_ENDORSEMENT, TPM_RH_OWNER or TPM_RH_PLATFORM+{PP} Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_enable">the enable being modified TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM, or TPM_RH_PLATFORM_NV</param>
        ///<param name = "the_state">YES if the enable should be SET, NO if the enable should be CLEAR</param>
        public Tpm2HierarchyControlRequest(
        TpmHandle the_authHandle,
        TpmHandle the_enable,
        byte the_state
        )
        {
            this.authHandle = the_authHandle;
            this.enable = the_enable;
            this.state = the_state;
        }
        new public Tpm2HierarchyControlRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2HierarchyControlRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command enables and disables use of a hierarchy and its associated NV storage. The command allows phEnable, phEnableNV, shEnable, and ehEnable to be changed when the proper authorization is provided.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_HierarchyControl_RESPONSE")]
    public partial class Tpm2HierarchyControlResponse: TpmStructureBase
    {
        public Tpm2HierarchyControlResponse()
        {
        }
        new public Tpm2HierarchyControlResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2HierarchyControlResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows setting of the authorization policy for the lockout (lockoutPolicy), the platform hierarchy (platformPolicy), the storage hierarchy (ownerPolicy), and the endorsement hierarchy (endorsementPolicy).
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPM2_SetPrimaryPolicy_REQUEST")]
    public partial class Tpm2SetPrimaryPolicyRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_LOCKOUT, TPM_RH_ENDORSEMENT, TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// an authorization policy digest; may be the Empty Buffer
        /// If hashAlg is TPM_ALG_NULL, then this shall be an Empty Buffer.
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "authPolicySize", 2)]
        [DataMember()]
        public byte[] authPolicy;
        /// <summary>
        /// the hash algorithm to use for the policy
        /// If the authPolicy is an Empty Buffer, then this field shall be TPM_ALG_NULL.
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }
        public Tpm2SetPrimaryPolicyRequest()
        {
            authHandle = new TpmHandle();
            authPolicy = null;
            hashAlg = TpmAlgId.Null;
        }
        public Tpm2SetPrimaryPolicyRequest(Tpm2SetPrimaryPolicyRequest the_Tpm2SetPrimaryPolicyRequest)
        {
            if((Object) the_Tpm2SetPrimaryPolicyRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2SetPrimaryPolicyRequest.authHandle;
            authPolicy = the_Tpm2SetPrimaryPolicyRequest.authPolicy;
            hashAlg = the_Tpm2SetPrimaryPolicyRequest.hashAlg;
        }
        ///<param name = "the_authHandle">TPM_RH_LOCKOUT, TPM_RH_ENDORSEMENT, TPM_RH_OWNER or TPM_RH_PLATFORM+{PP} Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_authPolicy">an authorization policy digest; may be the Empty Buffer If hashAlg is TPM_ALG_NULL, then this shall be an Empty Buffer.</param>
        ///<param name = "the_hashAlg">the hash algorithm to use for the policy If the authPolicy is an Empty Buffer, then this field shall be TPM_ALG_NULL.</param>
        public Tpm2SetPrimaryPolicyRequest(
        TpmHandle the_authHandle,
        byte[] the_authPolicy,
        TpmAlgId the_hashAlg
        )
        {
            this.authHandle = the_authHandle;
            this.authPolicy = the_authPolicy;
            this.hashAlg = the_hashAlg;
        }
        new public Tpm2SetPrimaryPolicyRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2SetPrimaryPolicyRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows setting of the authorization policy for the lockout (lockoutPolicy), the platform hierarchy (platformPolicy), the storage hierarchy (ownerPolicy), and the endorsement hierarchy (endorsementPolicy).
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_SetPrimaryPolicy_RESPONSE")]
    public partial class Tpm2SetPrimaryPolicyResponse: TpmStructureBase
    {
        public Tpm2SetPrimaryPolicyResponse()
        {
        }
        new public Tpm2SetPrimaryPolicyResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2SetPrimaryPolicyResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This replaces the current platform primary seed (PPS) with a value from the RNG and sets platformPolicy to the default initialization value (the Empty Buffer).
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_ChangePPS_REQUEST")]
    public partial class Tpm2ChangePPSRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        public Tpm2ChangePPSRequest()
        {
            authHandle = new TpmHandle();
        }
        public Tpm2ChangePPSRequest(Tpm2ChangePPSRequest the_Tpm2ChangePPSRequest)
        {
            if((Object) the_Tpm2ChangePPSRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2ChangePPSRequest.authHandle;
        }
        ///<param name = "the_authHandle">TPM_RH_PLATFORM+{PP} Auth Index: 1 Auth Role: USER</param>
        public Tpm2ChangePPSRequest(
        TpmHandle the_authHandle
        )
        {
            this.authHandle = the_authHandle;
        }
        new public Tpm2ChangePPSRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ChangePPSRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This replaces the current platform primary seed (PPS) with a value from the RNG and sets platformPolicy to the default initialization value (the Empty Buffer).
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_ChangePPS_RESPONSE")]
    public partial class Tpm2ChangePPSResponse: TpmStructureBase
    {
        public Tpm2ChangePPSResponse()
        {
        }
        new public Tpm2ChangePPSResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ChangePPSResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This replaces the current endorsement primary seed (EPS) with a value from the RNG and sets the Endorsement hierarchy controls to their default initialization values: ehEnable is SET, endorsementAuth and endorsementPolicy are both set to the Empty Buffer. It will flush any resident objects (transient or persistent) in the Endorsement hierarchy and not allow objects in the hierarchy associated with the previous EPS to be loaded.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_ChangeEPS_REQUEST")]
    public partial class Tpm2ChangeEPSRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_PLATFORM+{PP}
        /// Auth Handle: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        public Tpm2ChangeEPSRequest()
        {
            authHandle = new TpmHandle();
        }
        public Tpm2ChangeEPSRequest(Tpm2ChangeEPSRequest the_Tpm2ChangeEPSRequest)
        {
            if((Object) the_Tpm2ChangeEPSRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2ChangeEPSRequest.authHandle;
        }
        ///<param name = "the_authHandle">TPM_RH_PLATFORM+{PP} Auth Handle: 1 Auth Role: USER</param>
        public Tpm2ChangeEPSRequest(
        TpmHandle the_authHandle
        )
        {
            this.authHandle = the_authHandle;
        }
        new public Tpm2ChangeEPSRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ChangeEPSRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This replaces the current endorsement primary seed (EPS) with a value from the RNG and sets the Endorsement hierarchy controls to their default initialization values: ehEnable is SET, endorsementAuth and endorsementPolicy are both set to the Empty Buffer. It will flush any resident objects (transient or persistent) in the Endorsement hierarchy and not allow objects in the hierarchy associated with the previous EPS to be loaded.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_ChangeEPS_RESPONSE")]
    public partial class Tpm2ChangeEPSResponse: TpmStructureBase
    {
        public Tpm2ChangeEPSResponse()
        {
        }
        new public Tpm2ChangeEPSResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ChangeEPSResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command removes all TPM context associated with a specific Owner.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_Clear_REQUEST")]
    public partial class Tpm2ClearRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_LOCKOUT or TPM_RH_PLATFORM+{PP}
        /// Auth Handle: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        public Tpm2ClearRequest()
        {
            authHandle = new TpmHandle();
        }
        public Tpm2ClearRequest(Tpm2ClearRequest the_Tpm2ClearRequest)
        {
            if((Object) the_Tpm2ClearRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2ClearRequest.authHandle;
        }
        ///<param name = "the_authHandle">TPM_RH_LOCKOUT or TPM_RH_PLATFORM+{PP} Auth Handle: 1 Auth Role: USER</param>
        public Tpm2ClearRequest(
        TpmHandle the_authHandle
        )
        {
            this.authHandle = the_authHandle;
        }
        new public Tpm2ClearRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ClearRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command removes all TPM context associated with a specific Owner.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_Clear_RESPONSE")]
    public partial class Tpm2ClearResponse: TpmStructureBase
    {
        public Tpm2ClearResponse()
        {
        }
        new public Tpm2ClearResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ClearResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// TPM2_ClearControl() disables and enables the execution of TPM2_Clear().
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(byte))]
    [SpecTypeName("TPM2_ClearControl_REQUEST")]
    public partial class Tpm2ClearControlRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_LOCKOUT or TPM_RH_PLATFORM+{PP}
        /// Auth Handle: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle auth { get; set; }
        /// <summary>
        /// YES if the disableOwnerClear flag is to be SET, NO if the flag is to be CLEAR.
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public byte disable { get; set; }
        public Tpm2ClearControlRequest()
        {
            auth = new TpmHandle();
            disable = 0;
        }
        public Tpm2ClearControlRequest(Tpm2ClearControlRequest the_Tpm2ClearControlRequest)
        {
            if((Object) the_Tpm2ClearControlRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            auth = the_Tpm2ClearControlRequest.auth;
            disable = the_Tpm2ClearControlRequest.disable;
        }
        ///<param name = "the_auth">TPM_RH_LOCKOUT or TPM_RH_PLATFORM+{PP} Auth Handle: 1 Auth Role: USER</param>
        ///<param name = "the_disable">YES if the disableOwnerClear flag is to be SET, NO if the flag is to be CLEAR.</param>
        public Tpm2ClearControlRequest(
        TpmHandle the_auth,
        byte the_disable
        )
        {
            this.auth = the_auth;
            this.disable = the_disable;
        }
        new public Tpm2ClearControlRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ClearControlRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// TPM2_ClearControl() disables and enables the execution of TPM2_Clear().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_ClearControl_RESPONSE")]
    public partial class Tpm2ClearControlResponse: TpmStructureBase
    {
        public Tpm2ClearControlResponse()
        {
        }
        new public Tpm2ClearControlResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ClearControlResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows the authorization secret for a hierarchy or lockout to be changed using the current authorization value as the command authorization.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_HierarchyChangeAuth_REQUEST")]
    public partial class Tpm2HierarchyChangeAuthRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_LOCKOUT, TPM_RH_ENDORSEMENT, TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// new authorization value
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "newAuthSize", 2)]
        [DataMember()]
        public byte[] newAuth;
        public Tpm2HierarchyChangeAuthRequest()
        {
            authHandle = new TpmHandle();
            newAuth = null;
        }
        public Tpm2HierarchyChangeAuthRequest(Tpm2HierarchyChangeAuthRequest the_Tpm2HierarchyChangeAuthRequest)
        {
            if((Object) the_Tpm2HierarchyChangeAuthRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2HierarchyChangeAuthRequest.authHandle;
            newAuth = the_Tpm2HierarchyChangeAuthRequest.newAuth;
        }
        ///<param name = "the_authHandle">TPM_RH_LOCKOUT, TPM_RH_ENDORSEMENT, TPM_RH_OWNER or TPM_RH_PLATFORM+{PP} Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_newAuth">new authorization value</param>
        public Tpm2HierarchyChangeAuthRequest(
        TpmHandle the_authHandle,
        byte[] the_newAuth
        )
        {
            this.authHandle = the_authHandle;
            this.newAuth = the_newAuth;
        }
        new public Tpm2HierarchyChangeAuthRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2HierarchyChangeAuthRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows the authorization secret for a hierarchy or lockout to be changed using the current authorization value as the command authorization.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_HierarchyChangeAuth_RESPONSE")]
    public partial class Tpm2HierarchyChangeAuthResponse: TpmStructureBase
    {
        public Tpm2HierarchyChangeAuthResponse()
        {
        }
        new public Tpm2HierarchyChangeAuthResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2HierarchyChangeAuthResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command cancels the effect of a TPM lockout due to a number of successive authorization failures. If this command is properly authorized, the lockout counter is set to zero.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_DictionaryAttackLockReset_REQUEST")]
    public partial class Tpm2DictionaryAttackLockResetRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_LOCKOUT
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle lockHandle { get; set; }
        public Tpm2DictionaryAttackLockResetRequest()
        {
            lockHandle = new TpmHandle();
        }
        public Tpm2DictionaryAttackLockResetRequest(Tpm2DictionaryAttackLockResetRequest the_Tpm2DictionaryAttackLockResetRequest)
        {
            if((Object) the_Tpm2DictionaryAttackLockResetRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            lockHandle = the_Tpm2DictionaryAttackLockResetRequest.lockHandle;
        }
        ///<param name = "the_lockHandle">TPM_RH_LOCKOUT Auth Index: 1 Auth Role: USER</param>
        public Tpm2DictionaryAttackLockResetRequest(
        TpmHandle the_lockHandle
        )
        {
            this.lockHandle = the_lockHandle;
        }
        new public Tpm2DictionaryAttackLockResetRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2DictionaryAttackLockResetRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command cancels the effect of a TPM lockout due to a number of successive authorization failures. If this command is properly authorized, the lockout counter is set to zero.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_DictionaryAttackLockReset_RESPONSE")]
    public partial class Tpm2DictionaryAttackLockResetResponse: TpmStructureBase
    {
        public Tpm2DictionaryAttackLockResetResponse()
        {
        }
        new public Tpm2DictionaryAttackLockResetResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2DictionaryAttackLockResetResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command changes the lockout parameters.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_DictionaryAttackParameters_REQUEST")]
    public partial class Tpm2DictionaryAttackParametersRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_LOCKOUT
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle lockHandle { get; set; }
        /// <summary>
        /// count of authorization failures before the lockout is imposed
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint newMaxTries { get; set; }
        /// <summary>
        /// time in seconds before the authorization failure count is automatically decremented
        /// A value of zero indicates that DA protection is disabled.
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public uint newRecoveryTime { get; set; }
        /// <summary>
        /// time in seconds after a lockoutAuth failure before use of lockoutAuth is allowed
        /// A value of zero indicates that a reboot is required.
        /// </summary>
        [MarshalAs(3)]
        [DataMember()]
        public uint lockoutRecovery { get; set; }
        public Tpm2DictionaryAttackParametersRequest()
        {
            lockHandle = new TpmHandle();
            newMaxTries = 0;
            newRecoveryTime = 0;
            lockoutRecovery = 0;
        }
        public Tpm2DictionaryAttackParametersRequest(Tpm2DictionaryAttackParametersRequest the_Tpm2DictionaryAttackParametersRequest)
        {
            if((Object) the_Tpm2DictionaryAttackParametersRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            lockHandle = the_Tpm2DictionaryAttackParametersRequest.lockHandle;
            newMaxTries = the_Tpm2DictionaryAttackParametersRequest.newMaxTries;
            newRecoveryTime = the_Tpm2DictionaryAttackParametersRequest.newRecoveryTime;
            lockoutRecovery = the_Tpm2DictionaryAttackParametersRequest.lockoutRecovery;
        }
        ///<param name = "the_lockHandle">TPM_RH_LOCKOUT Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_newMaxTries">count of authorization failures before the lockout is imposed</param>
        ///<param name = "the_newRecoveryTime">time in seconds before the authorization failure count is automatically decremented A value of zero indicates that DA protection is disabled.</param>
        ///<param name = "the_lockoutRecovery">time in seconds after a lockoutAuth failure before use of lockoutAuth is allowed A value of zero indicates that a reboot is required.</param>
        public Tpm2DictionaryAttackParametersRequest(
        TpmHandle the_lockHandle,
        uint the_newMaxTries,
        uint the_newRecoveryTime,
        uint the_lockoutRecovery
        )
        {
            this.lockHandle = the_lockHandle;
            this.newMaxTries = the_newMaxTries;
            this.newRecoveryTime = the_newRecoveryTime;
            this.lockoutRecovery = the_lockoutRecovery;
        }
        new public Tpm2DictionaryAttackParametersRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2DictionaryAttackParametersRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command changes the lockout parameters.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_DictionaryAttackParameters_RESPONSE")]
    public partial class Tpm2DictionaryAttackParametersResponse: TpmStructureBase
    {
        public Tpm2DictionaryAttackParametersResponse()
        {
        }
        new public Tpm2DictionaryAttackParametersResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2DictionaryAttackParametersResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to determine which commands require assertion of Physical Presence (PP) in addition to platformAuth/platformPolicy.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_PP_Commands_REQUEST")]
    public partial class Tpm2PpCommandsRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_PLATFORM+PP
        /// Auth Index: 1
        /// Auth Role: USER + Physical Presence
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle auth { get; set; }
        /// <summary>
        /// list of commands to be added to those that will require that Physical Presence be asserted
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "setListCount", 4)]
        [DataMember()]
        public TpmCc[] setList;
        /// <summary>
        /// list of commands that will no longer require that Physical Presence be asserted
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "clearListCount", 4)]
        [DataMember()]
        public TpmCc[] clearList;
        public Tpm2PpCommandsRequest()
        {
            auth = new TpmHandle();
            setList = null;
            clearList = null;
        }
        public Tpm2PpCommandsRequest(Tpm2PpCommandsRequest the_Tpm2PpCommandsRequest)
        {
            if((Object) the_Tpm2PpCommandsRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            auth = the_Tpm2PpCommandsRequest.auth;
            setList = the_Tpm2PpCommandsRequest.setList;
            clearList = the_Tpm2PpCommandsRequest.clearList;
        }
        ///<param name = "the_auth">TPM_RH_PLATFORM+PP Auth Index: 1 Auth Role: USER + Physical Presence</param>
        ///<param name = "the_setList">list of commands to be added to those that will require that Physical Presence be asserted</param>
        ///<param name = "the_clearList">list of commands that will no longer require that Physical Presence be asserted</param>
        public Tpm2PpCommandsRequest(
        TpmHandle the_auth,
        TpmCc[] the_setList,
        TpmCc[] the_clearList
        )
        {
            this.auth = the_auth;
            this.setList = the_setList;
            this.clearList = the_clearList;
        }
        new public Tpm2PpCommandsRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PpCommandsRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to determine which commands require assertion of Physical Presence (PP) in addition to platformAuth/platformPolicy.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_PP_Commands_RESPONSE")]
    public partial class Tpm2PpCommandsResponse: TpmStructureBase
    {
        public Tpm2PpCommandsResponse()
        {
        }
        new public Tpm2PpCommandsResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2PpCommandsResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows the platform to change the set of algorithms that are used by the TPM. The algorithmSet setting is a vendor-dependent value.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_SetAlgorithmSet_REQUEST")]
    public partial class Tpm2SetAlgorithmSetRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_PLATFORM
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// a TPM vendor-dependent value indicating the algorithm set selection
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint algorithmSet { get; set; }
        public Tpm2SetAlgorithmSetRequest()
        {
            authHandle = new TpmHandle();
            algorithmSet = 0;
        }
        public Tpm2SetAlgorithmSetRequest(Tpm2SetAlgorithmSetRequest the_Tpm2SetAlgorithmSetRequest)
        {
            if((Object) the_Tpm2SetAlgorithmSetRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2SetAlgorithmSetRequest.authHandle;
            algorithmSet = the_Tpm2SetAlgorithmSetRequest.algorithmSet;
        }
        ///<param name = "the_authHandle">TPM_RH_PLATFORM Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_algorithmSet">a TPM vendor-dependent value indicating the algorithm set selection</param>
        public Tpm2SetAlgorithmSetRequest(
        TpmHandle the_authHandle,
        uint the_algorithmSet
        )
        {
            this.authHandle = the_authHandle;
            this.algorithmSet = the_algorithmSet;
        }
        new public Tpm2SetAlgorithmSetRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2SetAlgorithmSetRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows the platform to change the set of algorithms that are used by the TPM. The algorithmSet setting is a vendor-dependent value.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_SetAlgorithmSet_RESPONSE")]
    public partial class Tpm2SetAlgorithmSetResponse: TpmStructureBase
    {
        public Tpm2SetAlgorithmSetResponse()
        {
        }
        new public Tpm2SetAlgorithmSetResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2SetAlgorithmSetResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command uses platformPolicy and a TPM Vendor Authorization Key to authorize a Field Upgrade Manifest.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureRsa))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureEcc))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(NullSignature))]
    [SpecTypeName("TPM2_FieldUpgradeStart_REQUEST")]
    public partial class Tpm2FieldUpgradeStartRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_PLATFORM+{PP}
        /// Auth Index:1
        /// Auth Role: ADMIN
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authorization { get; set; }
        /// <summary>
        /// handle of a public area that contains the TPM Vendor Authorization Key that will be used to validate manifestSignature
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }
        /// <summary>
        /// digest of the first block in the field upgrade sequence
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "fuDigestSize", 2)]
        [DataMember()]
        public byte[] fuDigest;
        /// <summary>
        /// selector of the algorithm used to construct the signature
        /// </summary>
        [MarshalAs(3, MarshalType.UnionSelector)]
        public TpmAlgId manifestSignatureSigAlg {
            get {
                if(manifestSignature != null) {
                    return (TpmAlgId)manifestSignature.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// signature over fuDigest using the key associated with keyHandle (not optional)
        /// (One of [SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature])
        /// </summary>
        [MarshalAs(4, MarshalType.Union, "manifestSignatureSigAlg")]
        [DataMember()]
        public ISignatureUnion manifestSignature { get; set; }
        public Tpm2FieldUpgradeStartRequest()
        {
            authorization = new TpmHandle();
            keyHandle = new TpmHandle();
            fuDigest = null;
        }
        public Tpm2FieldUpgradeStartRequest(Tpm2FieldUpgradeStartRequest the_Tpm2FieldUpgradeStartRequest)
        {
            if((Object) the_Tpm2FieldUpgradeStartRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authorization = the_Tpm2FieldUpgradeStartRequest.authorization;
            keyHandle = the_Tpm2FieldUpgradeStartRequest.keyHandle;
            fuDigest = the_Tpm2FieldUpgradeStartRequest.fuDigest;
        }
        ///<param name = "the_authorization">TPM_RH_PLATFORM+{PP} Auth Index:1 Auth Role: ADMIN</param>
        ///<param name = "the_keyHandle">handle of a public area that contains the TPM Vendor Authorization Key that will be used to validate manifestSignature Auth Index: None</param>
        ///<param name = "the_fuDigest">digest of the first block in the field upgrade sequence</param>
        ///<param name = "the_manifestSignature">signature over fuDigest using the key associated with keyHandle (not optional)(One of SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature)</param>
        public Tpm2FieldUpgradeStartRequest(
        TpmHandle the_authorization,
        TpmHandle the_keyHandle,
        byte[] the_fuDigest,
        ISignatureUnion the_manifestSignature
        )
        {
            this.authorization = the_authorization;
            this.keyHandle = the_keyHandle;
            this.fuDigest = the_fuDigest;
            this.manifestSignature = the_manifestSignature;
        }
        new public Tpm2FieldUpgradeStartRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2FieldUpgradeStartRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command uses platformPolicy and a TPM Vendor Authorization Key to authorize a Field Upgrade Manifest.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_FieldUpgradeStart_RESPONSE")]
    public partial class Tpm2FieldUpgradeStartResponse: TpmStructureBase
    {
        public Tpm2FieldUpgradeStartResponse()
        {
        }
        new public Tpm2FieldUpgradeStartResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2FieldUpgradeStartResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command will take the actual field upgrade image to be installed on the TPM. The exact format of fuData is vendor-specific. This command is only possible following a successful TPM2_FieldUpgradeStart(). If the TPM has not received a properly authorized TPM2_FieldUpgradeStart(), then the TPM shall return TPM_RC_FIELDUPGRADE.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_FieldUpgradeData_REQUEST")]
    public partial class Tpm2FieldUpgradeDataRequest: TpmStructureBase
    {
        /// <summary>
        /// field upgrade image data
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "fuDataSize", 2)]
        [DataMember()]
        public byte[] fuData;
        public Tpm2FieldUpgradeDataRequest()
        {
            fuData = null;
        }
        public Tpm2FieldUpgradeDataRequest(Tpm2FieldUpgradeDataRequest the_Tpm2FieldUpgradeDataRequest)
        {
            if((Object) the_Tpm2FieldUpgradeDataRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            fuData = the_Tpm2FieldUpgradeDataRequest.fuData;
        }
        ///<param name = "the_fuData">field upgrade image data</param>
        public Tpm2FieldUpgradeDataRequest(
        byte[] the_fuData
        )
        {
            this.fuData = the_fuData;
        }
        new public Tpm2FieldUpgradeDataRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2FieldUpgradeDataRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command will take the actual field upgrade image to be installed on the TPM. The exact format of fuData is vendor-specific. This command is only possible following a successful TPM2_FieldUpgradeStart(). If the TPM has not received a properly authorized TPM2_FieldUpgradeStart(), then the TPM shall return TPM_RC_FIELDUPGRADE.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHash))]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("TPM2_FieldUpgradeData_RESPONSE")]
    public partial class Tpm2FieldUpgradeDataResponse: TpmStructureBase
    {
        /// <summary>
        /// tagged digest of the next block
        /// TPM_ALG_NULL if field update is complete
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHash nextDigest { get; set; }
        /// <summary>
        /// tagged digest of the first block of the sequence
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHash firstDigest { get; set; }
        public Tpm2FieldUpgradeDataResponse()
        {
            nextDigest = new TpmHash();
            firstDigest = new TpmHash();
        }
        public Tpm2FieldUpgradeDataResponse(Tpm2FieldUpgradeDataResponse the_Tpm2FieldUpgradeDataResponse)
        {
            if((Object) the_Tpm2FieldUpgradeDataResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            nextDigest = the_Tpm2FieldUpgradeDataResponse.nextDigest;
            firstDigest = the_Tpm2FieldUpgradeDataResponse.firstDigest;
        }
        ///<param name = "the_nextDigest">tagged digest of the next block TPM_ALG_NULL if field update is complete</param>
        ///<param name = "the_firstDigest">tagged digest of the first block of the sequence</param>
        public Tpm2FieldUpgradeDataResponse(
        TpmHash the_nextDigest,
        TpmHash the_firstDigest
        )
        {
            this.nextDigest = the_nextDigest;
            this.firstDigest = the_firstDigest;
        }
        new public Tpm2FieldUpgradeDataResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2FieldUpgradeDataResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to read a copy of the current firmware installed in the TPM.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_FirmwareRead_REQUEST")]
    public partial class Tpm2FirmwareReadRequest: TpmStructureBase
    {
        /// <summary>
        /// the number of previous calls to this command in this sequence
        /// set to 0 on the first call
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public uint sequenceNumber { get; set; }
        public Tpm2FirmwareReadRequest()
        {
            sequenceNumber = 0;
        }
        public Tpm2FirmwareReadRequest(Tpm2FirmwareReadRequest the_Tpm2FirmwareReadRequest)
        {
            if((Object) the_Tpm2FirmwareReadRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            sequenceNumber = the_Tpm2FirmwareReadRequest.sequenceNumber;
        }
        ///<param name = "the_sequenceNumber">the number of previous calls to this command in this sequence set to 0 on the first call</param>
        public Tpm2FirmwareReadRequest(
        uint the_sequenceNumber
        )
        {
            this.sequenceNumber = the_sequenceNumber;
        }
        new public Tpm2FirmwareReadRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2FirmwareReadRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to read a copy of the current firmware installed in the TPM.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_FirmwareRead_RESPONSE")]
    public partial class Tpm2FirmwareReadResponse: TpmStructureBase
    {
        /// <summary>
        /// field upgrade image data
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "fuDataSize", 2)]
        [DataMember()]
        public byte[] fuData;
        public Tpm2FirmwareReadResponse()
        {
            fuData = null;
        }
        public Tpm2FirmwareReadResponse(Tpm2FirmwareReadResponse the_Tpm2FirmwareReadResponse)
        {
            if((Object) the_Tpm2FirmwareReadResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            fuData = the_Tpm2FirmwareReadResponse.fuData;
        }
        ///<param name = "the_fuData">field upgrade image data</param>
        public Tpm2FirmwareReadResponse(
        byte[] the_fuData
        )
        {
            this.fuData = the_fuData;
        }
        new public Tpm2FirmwareReadResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2FirmwareReadResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command saves a session context, object context, or sequence object context outside the TPM.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_ContextSave_REQUEST")]
    public partial class Tpm2ContextSaveRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of the resource to save
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle saveHandle { get; set; }
        public Tpm2ContextSaveRequest()
        {
            saveHandle = new TpmHandle();
        }
        public Tpm2ContextSaveRequest(Tpm2ContextSaveRequest the_Tpm2ContextSaveRequest)
        {
            if((Object) the_Tpm2ContextSaveRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            saveHandle = the_Tpm2ContextSaveRequest.saveHandle;
        }
        ///<param name = "the_saveHandle">handle of the resource to save Auth Index: None</param>
        public Tpm2ContextSaveRequest(
        TpmHandle the_saveHandle
        )
        {
            this.saveHandle = the_saveHandle;
        }
        new public Tpm2ContextSaveRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ContextSaveRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command saves a session context, object context, or sequence object context outside the TPM.
    /// </summary>
    [DataContract]
    [KnownType(typeof(Context))]
    [SpecTypeName("TPM2_ContextSave_RESPONSE")]
    public partial class Tpm2ContextSaveResponse: TpmStructureBase
    {
        [MarshalAs(0)]
        [DataMember()]
        public Context context { get; set; }
        public Tpm2ContextSaveResponse()
        {
            context = new Context();
        }
        public Tpm2ContextSaveResponse(Tpm2ContextSaveResponse the_Tpm2ContextSaveResponse)
        {
            if((Object) the_Tpm2ContextSaveResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            context = the_Tpm2ContextSaveResponse.context;
        }
        ///<param name = "the_context"></param>
        public Tpm2ContextSaveResponse(
        Context the_context
        )
        {
            this.context = the_context;
        }
        new public Tpm2ContextSaveResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ContextSaveResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to reload a context that has been saved by TPM2_ContextSave().
    /// </summary>
    [DataContract]
    [KnownType(typeof(Context))]
    [SpecTypeName("TPM2_ContextLoad_REQUEST")]
    public partial class Tpm2ContextLoadRequest: TpmStructureBase
    {
        /// <summary>
        /// the context blob
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public Context context { get; set; }
        public Tpm2ContextLoadRequest()
        {
            context = new Context();
        }
        public Tpm2ContextLoadRequest(Tpm2ContextLoadRequest the_Tpm2ContextLoadRequest)
        {
            if((Object) the_Tpm2ContextLoadRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            context = the_Tpm2ContextLoadRequest.context;
        }
        ///<param name = "the_context">the context blob</param>
        public Tpm2ContextLoadRequest(
        Context the_context
        )
        {
            this.context = the_context;
        }
        new public Tpm2ContextLoadRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ContextLoadRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to reload a context that has been saved by TPM2_ContextSave().
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_ContextLoad_RESPONSE")]
    public partial class Tpm2ContextLoadResponse: TpmStructureBase
    {
        /// <summary>
        /// the handle assigned to the resource after it has been successfully loaded
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle loadedHandle { get; set; }
        public Tpm2ContextLoadResponse()
        {
            loadedHandle = new TpmHandle();
        }
        public Tpm2ContextLoadResponse(Tpm2ContextLoadResponse the_Tpm2ContextLoadResponse)
        {
            if((Object) the_Tpm2ContextLoadResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            loadedHandle = the_Tpm2ContextLoadResponse.loadedHandle;
        }
        ///<param name = "the_loadedHandle">the handle assigned to the resource after it has been successfully loaded</param>
        public Tpm2ContextLoadResponse(
        TpmHandle the_loadedHandle
        )
        {
            this.loadedHandle = the_loadedHandle;
        }
        new public Tpm2ContextLoadResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ContextLoadResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command causes all context associated with a loaded object, sequence object, or session to be removed from TPM memory.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_FlushContext_REQUEST")]
    public partial class Tpm2FlushContextRequest: TpmStructureBase
    {
        /// <summary>
        /// the handle of the item to flush
        /// NOTE	This is a use of a handle as a parameter.
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle flushHandle { get; set; }
        public Tpm2FlushContextRequest()
        {
            flushHandle = new TpmHandle();
        }
        public Tpm2FlushContextRequest(Tpm2FlushContextRequest the_Tpm2FlushContextRequest)
        {
            if((Object) the_Tpm2FlushContextRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            flushHandle = the_Tpm2FlushContextRequest.flushHandle;
        }
        ///<param name = "the_flushHandle">the handle of the item to flush NOTE	This is a use of a handle as a parameter.</param>
        public Tpm2FlushContextRequest(
        TpmHandle the_flushHandle
        )
        {
            this.flushHandle = the_flushHandle;
        }
        new public Tpm2FlushContextRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2FlushContextRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command causes all context associated with a loaded object, sequence object, or session to be removed from TPM memory.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_FlushContext_RESPONSE")]
    public partial class Tpm2FlushContextResponse: TpmStructureBase
    {
        public Tpm2FlushContextResponse()
        {
        }
        new public Tpm2FlushContextResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2FlushContextResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows certain Transient Objects to be made persistent or a persistent object to be evicted.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_EvictControl_REQUEST")]
    public partial class Tpm2EvictControlRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Handle: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle auth { get; set; }
        /// <summary>
        /// the handle of a loaded object
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle objectHandle { get; set; }
        /// <summary>
        /// if objectHandle is a transient object handle, then this is the persistent handle for the object
        /// if objectHandle is a persistent object handle, then it shall be the same value as persistentHandle
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle persistentHandle { get; set; }
        public Tpm2EvictControlRequest()
        {
            auth = new TpmHandle();
            objectHandle = new TpmHandle();
            persistentHandle = new TpmHandle();
        }
        public Tpm2EvictControlRequest(Tpm2EvictControlRequest the_Tpm2EvictControlRequest)
        {
            if((Object) the_Tpm2EvictControlRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            auth = the_Tpm2EvictControlRequest.auth;
            objectHandle = the_Tpm2EvictControlRequest.objectHandle;
            persistentHandle = the_Tpm2EvictControlRequest.persistentHandle;
        }
        ///<param name = "the_auth">TPM_RH_OWNER or TPM_RH_PLATFORM+{PP} Auth Handle: 1 Auth Role: USER</param>
        ///<param name = "the_objectHandle">the handle of a loaded object Auth Index: None</param>
        ///<param name = "the_persistentHandle">if objectHandle is a transient object handle, then this is the persistent handle for the object if objectHandle is a persistent object handle, then it shall be the same value as persistentHandle</param>
        public Tpm2EvictControlRequest(
        TpmHandle the_auth,
        TpmHandle the_objectHandle,
        TpmHandle the_persistentHandle
        )
        {
            this.auth = the_auth;
            this.objectHandle = the_objectHandle;
            this.persistentHandle = the_persistentHandle;
        }
        new public Tpm2EvictControlRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2EvictControlRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows certain Transient Objects to be made persistent or a persistent object to be evicted.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_EvictControl_RESPONSE")]
    public partial class Tpm2EvictControlResponse: TpmStructureBase
    {
        public Tpm2EvictControlResponse()
        {
        }
        new public Tpm2EvictControlResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2EvictControlResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command reads the current TPMS_TIME_INFO structure that contains the current setting of Time, Clock, resetCount, and restartCount.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_ReadClock_REQUEST")]
    public partial class Tpm2ReadClockRequest: TpmStructureBase
    {
        public Tpm2ReadClockRequest()
        {
        }
        new public Tpm2ReadClockRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ReadClockRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command reads the current TPMS_TIME_INFO structure that contains the current setting of Time, Clock, resetCount, and restartCount.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TimeInfo))]
    [SpecTypeName("TPM2_ReadClock_RESPONSE")]
    public partial class Tpm2ReadClockResponse: TpmStructureBase
    {
        [MarshalAs(0)]
        [DataMember()]
        public TimeInfo currentTime { get; set; }
        public Tpm2ReadClockResponse()
        {
            currentTime = new TimeInfo();
        }
        public Tpm2ReadClockResponse(Tpm2ReadClockResponse the_Tpm2ReadClockResponse)
        {
            if((Object) the_Tpm2ReadClockResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            currentTime = the_Tpm2ReadClockResponse.currentTime;
        }
        ///<param name = "the_currentTime"></param>
        public Tpm2ReadClockResponse(
        TimeInfo the_currentTime
        )
        {
            this.currentTime = the_currentTime;
        }
        new public Tpm2ReadClockResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ReadClockResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to advance the value of the TPMs Clock. The command will fail if newTime is less than the current value of Clock or if the new time is greater than FFFF00000000000016. If both of these checks succeed, Clock is set to newTime. If either of these checks fails, the TPM shall return TPM_RC_VALUE and make no change to Clock.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(ulong))]
    [SpecTypeName("TPM2_ClockSet_REQUEST")]
    public partial class Tpm2ClockSetRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Handle: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle auth { get; set; }
        /// <summary>
        /// new Clock setting in milliseconds
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ulong newTime { get; set; }
        public Tpm2ClockSetRequest()
        {
            auth = new TpmHandle();
            newTime = new ulong();
        }
        public Tpm2ClockSetRequest(Tpm2ClockSetRequest the_Tpm2ClockSetRequest)
        {
            if((Object) the_Tpm2ClockSetRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            auth = the_Tpm2ClockSetRequest.auth;
            newTime = the_Tpm2ClockSetRequest.newTime;
        }
        ///<param name = "the_auth">TPM_RH_OWNER or TPM_RH_PLATFORM+{PP} Auth Handle: 1 Auth Role: USER</param>
        ///<param name = "the_newTime">new Clock setting in milliseconds</param>
        public Tpm2ClockSetRequest(
        TpmHandle the_auth,
        ulong the_newTime
        )
        {
            this.auth = the_auth;
            this.newTime = the_newTime;
        }
        new public Tpm2ClockSetRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ClockSetRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to advance the value of the TPMs Clock. The command will fail if newTime is less than the current value of Clock or if the new time is greater than FFFF00000000000016. If both of these checks succeed, Clock is set to newTime. If either of these checks fails, the TPM shall return TPM_RC_VALUE and make no change to Clock.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_ClockSet_RESPONSE")]
    public partial class Tpm2ClockSetResponse: TpmStructureBase
    {
        public Tpm2ClockSetResponse()
        {
        }
        new public Tpm2ClockSetResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ClockSetResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command adjusts the rate of advance of Clock and Time to provide a better approximation to real time.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(ClockAdjust))]
    [SpecTypeName("TPM2_ClockRateAdjust_REQUEST")]
    public partial class Tpm2ClockRateAdjustRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Handle: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle auth { get; set; }
        /// <summary>
        /// Adjustment to current Clock update rate
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ClockAdjust rateAdjust { get; set; }
        public Tpm2ClockRateAdjustRequest()
        {
            auth = new TpmHandle();
            rateAdjust = new ClockAdjust();
        }
        public Tpm2ClockRateAdjustRequest(Tpm2ClockRateAdjustRequest the_Tpm2ClockRateAdjustRequest)
        {
            if((Object) the_Tpm2ClockRateAdjustRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            auth = the_Tpm2ClockRateAdjustRequest.auth;
            rateAdjust = the_Tpm2ClockRateAdjustRequest.rateAdjust;
        }
        ///<param name = "the_auth">TPM_RH_OWNER or TPM_RH_PLATFORM+{PP} Auth Handle: 1 Auth Role: USER</param>
        ///<param name = "the_rateAdjust">Adjustment to current Clock update rate</param>
        public Tpm2ClockRateAdjustRequest(
        TpmHandle the_auth,
        ClockAdjust the_rateAdjust
        )
        {
            this.auth = the_auth;
            this.rateAdjust = the_rateAdjust;
        }
        new public Tpm2ClockRateAdjustRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ClockRateAdjustRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command adjusts the rate of advance of Clock and Time to provide a better approximation to real time.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_ClockRateAdjust_RESPONSE")]
    public partial class Tpm2ClockRateAdjustResponse: TpmStructureBase
    {
        public Tpm2ClockRateAdjustResponse()
        {
        }
        new public Tpm2ClockRateAdjustResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2ClockRateAdjustResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns various information regarding the TPM and its current state.
    /// </summary>
    [DataContract]
    [KnownType(typeof(Cap))]
    [SpecTypeName("TPM2_GetCapability_REQUEST")]
    public partial class Tpm2GetCapabilityRequest: TpmStructureBase
    {
        /// <summary>
        /// group selection; determines the format of the response
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public Cap capability { get; set; }
        /// <summary>
        /// further definition of information
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint property { get; set; }
        /// <summary>
        /// number of properties of the indicated type to return
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public uint propertyCount { get; set; }
        public Tpm2GetCapabilityRequest()
        {
            capability = new Cap();
            property = 0;
            propertyCount = 0;
        }
        public Tpm2GetCapabilityRequest(Tpm2GetCapabilityRequest the_Tpm2GetCapabilityRequest)
        {
            if((Object) the_Tpm2GetCapabilityRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            capability = the_Tpm2GetCapabilityRequest.capability;
            property = the_Tpm2GetCapabilityRequest.property;
            propertyCount = the_Tpm2GetCapabilityRequest.propertyCount;
        }
        ///<param name = "the_capability">group selection; determines the format of the response</param>
        ///<param name = "the_property">further definition of information</param>
        ///<param name = "the_propertyCount">number of properties of the indicated type to return</param>
        public Tpm2GetCapabilityRequest(
        Cap the_capability,
        uint the_property,
        uint the_propertyCount
        )
        {
            this.capability = the_capability;
            this.property = the_property;
            this.propertyCount = the_propertyCount;
        }
        new public Tpm2GetCapabilityRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2GetCapabilityRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command returns various information regarding the TPM and its current state.
    /// </summary>
    [DataContract]
    [KnownType(typeof(byte))]
    [KnownType(typeof(Cap))]
    [KnownType(typeof(CcArray))]
    [KnownType(typeof(CcaArray))]
    [KnownType(typeof(HandleArray))]
    [KnownType(typeof(PcrSelectionArray))]
    [KnownType(typeof(AlgPropertyArray))]
    [KnownType(typeof(TaggedTpmPropertyArray))]
    [KnownType(typeof(TaggedPcrPropertyArray))]
    [KnownType(typeof(EccCurveArray))]
    [SpecTypeName("TPM2_GetCapability_RESPONSE")]
    public partial class Tpm2GetCapabilityResponse: TpmStructureBase
    {
        /// <summary>
        /// flag to indicate if there are more values of this type
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public byte moreData { get; set; }
        /// <summary>
        /// the capability
        /// </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public Cap capabilityDataCapability {
            get { return (Cap)capabilityData.GetUnionSelector(); }
        }
        /// <summary>
        /// the capability data
        /// (One of [AlgPropertyArray, HandleArray, CcaArray, CcArray, CcArray, PcrSelectionArray, TaggedTpmPropertyArray, TaggedPcrPropertyArray, EccCurveArray])
        /// </summary>
        [MarshalAs(2, MarshalType.Union, "capabilityDataCapability")]
        [DataMember()]
        public ICapabilitiesUnion capabilityData { get; set; }
        public Tpm2GetCapabilityResponse()
        {
            moreData = 0;
        }
        public Tpm2GetCapabilityResponse(Tpm2GetCapabilityResponse the_Tpm2GetCapabilityResponse)
        {
            if((Object) the_Tpm2GetCapabilityResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            moreData = the_Tpm2GetCapabilityResponse.moreData;
        }
        ///<param name = "the_moreData">flag to indicate if there are more values of this type</param>
        ///<param name = "the_capabilityData">the capability data(One of AlgPropertyArray, HandleArray, CcaArray, CcArray, CcArray, PcrSelectionArray, TaggedTpmPropertyArray, TaggedPcrPropertyArray, EccCurveArray)</param>
        public Tpm2GetCapabilityResponse(
        byte the_moreData,
        ICapabilitiesUnion the_capabilityData
        )
        {
            this.moreData = the_moreData;
            this.capabilityData = the_capabilityData;
        }
        new public Tpm2GetCapabilityResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2GetCapabilityResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to check to see if specific combinations of algorithm parameters are supported.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(SymcipherParms))]
    [KnownType(typeof(KeyedhashParms))]
    [KnownType(typeof(AsymParms))]
    [KnownType(typeof(RsaParms))]
    [KnownType(typeof(EccParms))]
    [SpecTypeName("TPM2_TestParms_REQUEST")]
    public partial class Tpm2TestParmsRequest: TpmStructureBase
    {
        /// <summary>
        /// the algorithm to be tested
        /// </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId parametersType {
            get { return (TpmAlgId)parameters.GetUnionSelector(); }
        }
        /// <summary>
        /// algorithm parameters to be validated
        /// (One of [KeyedhashParms, SymcipherParms, RsaParms, EccParms, AsymParms])
        /// </summary>
        [MarshalAs(1, MarshalType.Union, "parametersType")]
        [DataMember()]
        public IPublicParmsUnion parameters { get; set; }
        public Tpm2TestParmsRequest()
        {
        }
        public Tpm2TestParmsRequest(Tpm2TestParmsRequest the_Tpm2TestParmsRequest)
        {
            if((Object) the_Tpm2TestParmsRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
        }
        ///<param name = "the_parameters">algorithm parameters to be validated(One of KeyedhashParms, SymcipherParms, RsaParms, EccParms, AsymParms)</param>
        public Tpm2TestParmsRequest(
        IPublicParmsUnion the_parameters
        )
        {
            this.parameters = the_parameters;
        }
        new public Tpm2TestParmsRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2TestParmsRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to check to see if specific combinations of algorithm parameters are supported.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_TestParms_RESPONSE")]
    public partial class Tpm2TestParmsResponse: TpmStructureBase
    {
        public Tpm2TestParmsResponse()
        {
        }
        new public Tpm2TestParmsResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2TestParmsResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command defines the attributes of an NV Index and causes the TPM to reserve space to hold the data associated with the NV Index. If a definition already exists at the NV Index, the TPM will return TPM_RC_NV_DEFINED.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(NvPublic))]
    [SpecTypeName("TPM2_NV_DefineSpace_REQUEST")]
    public partial class Tpm2NvDefineSpaceRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// the authorization value
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "authSize", 2)]
        [DataMember()]
        public byte[] auth;
        /// <summary>
        /// the public parameters of the NV area
        /// </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "publicInfoSize", 2)]
        [DataMember()]
        public NvPublic publicInfo { get; set; }
        public Tpm2NvDefineSpaceRequest()
        {
            authHandle = new TpmHandle();
            auth = null;
            publicInfo = new NvPublic();
        }
        public Tpm2NvDefineSpaceRequest(Tpm2NvDefineSpaceRequest the_Tpm2NvDefineSpaceRequest)
        {
            if((Object) the_Tpm2NvDefineSpaceRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2NvDefineSpaceRequest.authHandle;
            auth = the_Tpm2NvDefineSpaceRequest.auth;
            publicInfo = the_Tpm2NvDefineSpaceRequest.publicInfo;
        }
        ///<param name = "the_authHandle">TPM_RH_OWNER or TPM_RH_PLATFORM+{PP} Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_auth">the authorization value</param>
        ///<param name = "the_publicInfo">the public parameters of the NV area</param>
        public Tpm2NvDefineSpaceRequest(
        TpmHandle the_authHandle,
        byte[] the_auth,
        NvPublic the_publicInfo
        )
        {
            this.authHandle = the_authHandle;
            this.auth = the_auth;
            this.publicInfo = the_publicInfo;
        }
        new public Tpm2NvDefineSpaceRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvDefineSpaceRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command defines the attributes of an NV Index and causes the TPM to reserve space to hold the data associated with the NV Index. If a definition already exists at the NV Index, the TPM will return TPM_RC_NV_DEFINED.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_NV_DefineSpace_RESPONSE")]
    public partial class Tpm2NvDefineSpaceResponse: TpmStructureBase
    {
        public Tpm2NvDefineSpaceResponse()
        {
        }
        new public Tpm2NvDefineSpaceResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvDefineSpaceResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command removes an Index from the TPM.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_NV_UndefineSpace_REQUEST")]
    public partial class Tpm2NvUndefineSpaceRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// the NV Index to remove from NV space
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }
        public Tpm2NvUndefineSpaceRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
        }
        public Tpm2NvUndefineSpaceRequest(Tpm2NvUndefineSpaceRequest the_Tpm2NvUndefineSpaceRequest)
        {
            if((Object) the_Tpm2NvUndefineSpaceRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2NvUndefineSpaceRequest.authHandle;
            nvIndex = the_Tpm2NvUndefineSpaceRequest.nvIndex;
        }
        ///<param name = "the_authHandle">TPM_RH_OWNER or TPM_RH_PLATFORM+{PP} Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_nvIndex">the NV Index to remove from NV space Auth Index: None</param>
        public Tpm2NvUndefineSpaceRequest(
        TpmHandle the_authHandle,
        TpmHandle the_nvIndex
        )
        {
            this.authHandle = the_authHandle;
            this.nvIndex = the_nvIndex;
        }
        new public Tpm2NvUndefineSpaceRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvUndefineSpaceRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command removes an Index from the TPM.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_NV_UndefineSpace_RESPONSE")]
    public partial class Tpm2NvUndefineSpaceResponse: TpmStructureBase
    {
        public Tpm2NvUndefineSpaceResponse()
        {
        }
        new public Tpm2NvUndefineSpaceResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvUndefineSpaceResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows removal of a platform-created NV Index that has TPMA_NV_POLICY_DELETE SET.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_NV_UndefineSpaceSpecial_REQUEST")]
    public partial class Tpm2NvUndefineSpaceSpecialRequest: TpmStructureBase
    {
        /// <summary>
        /// Index to be deleted
        /// Auth Index: 1
        /// Auth Role: ADMIN
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }
        /// <summary>
        /// TPM_RH_PLATFORM + {PP}
        /// Auth Index: 2
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle platform { get; set; }
        public Tpm2NvUndefineSpaceSpecialRequest()
        {
            nvIndex = new TpmHandle();
            platform = new TpmHandle();
        }
        public Tpm2NvUndefineSpaceSpecialRequest(Tpm2NvUndefineSpaceSpecialRequest the_Tpm2NvUndefineSpaceSpecialRequest)
        {
            if((Object) the_Tpm2NvUndefineSpaceSpecialRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            nvIndex = the_Tpm2NvUndefineSpaceSpecialRequest.nvIndex;
            platform = the_Tpm2NvUndefineSpaceSpecialRequest.platform;
        }
        ///<param name = "the_nvIndex">Index to be deleted Auth Index: 1 Auth Role: ADMIN</param>
        ///<param name = "the_platform">TPM_RH_PLATFORM + {PP} Auth Index: 2 Auth Role: USER</param>
        public Tpm2NvUndefineSpaceSpecialRequest(
        TpmHandle the_nvIndex,
        TpmHandle the_platform
        )
        {
            this.nvIndex = the_nvIndex;
            this.platform = the_platform;
        }
        new public Tpm2NvUndefineSpaceSpecialRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvUndefineSpaceSpecialRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows removal of a platform-created NV Index that has TPMA_NV_POLICY_DELETE SET.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_NV_UndefineSpaceSpecial_RESPONSE")]
    public partial class Tpm2NvUndefineSpaceSpecialResponse: TpmStructureBase
    {
        public Tpm2NvUndefineSpaceSpecialResponse()
        {
        }
        new public Tpm2NvUndefineSpaceSpecialResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvUndefineSpaceSpecialResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to read the public area and Name of an NV Index. The public area of an Index is not privacy-sensitive and no authorization is required to read this data.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_NV_ReadPublic_REQUEST")]
    public partial class Tpm2NvReadPublicRequest: TpmStructureBase
    {
        /// <summary>
        /// the NV Index
        /// Auth Index: None
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }
        public Tpm2NvReadPublicRequest()
        {
            nvIndex = new TpmHandle();
        }
        public Tpm2NvReadPublicRequest(Tpm2NvReadPublicRequest the_Tpm2NvReadPublicRequest)
        {
            if((Object) the_Tpm2NvReadPublicRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            nvIndex = the_Tpm2NvReadPublicRequest.nvIndex;
        }
        ///<param name = "the_nvIndex">the NV Index Auth Index: None</param>
        public Tpm2NvReadPublicRequest(
        TpmHandle the_nvIndex
        )
        {
            this.nvIndex = the_nvIndex;
        }
        new public Tpm2NvReadPublicRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvReadPublicRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to read the public area and Name of an NV Index. The public area of an Index is not privacy-sensitive and no authorization is required to read this data.
    /// </summary>
    [DataContract]
    [KnownType(typeof(NvPublic))]
    [SpecTypeName("TPM2_NV_ReadPublic_RESPONSE")]
    public partial class Tpm2NvReadPublicResponse: TpmStructureBase
    {
        /// <summary>
        /// the public area of the NV Index
        /// </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "nvPublicSize", 2)]
        [DataMember()]
        public NvPublic nvPublic { get; set; }
        /// <summary>
        /// the Name of the nvIndex
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "nvNameSize", 2)]
        [DataMember()]
        public byte[] nvName;
        public Tpm2NvReadPublicResponse()
        {
            nvPublic = new NvPublic();
            nvName = null;
        }
        public Tpm2NvReadPublicResponse(Tpm2NvReadPublicResponse the_Tpm2NvReadPublicResponse)
        {
            if((Object) the_Tpm2NvReadPublicResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            nvPublic = the_Tpm2NvReadPublicResponse.nvPublic;
            nvName = the_Tpm2NvReadPublicResponse.nvName;
        }
        ///<param name = "the_nvPublic">the public area of the NV Index</param>
        ///<param name = "the_nvName">the Name of the nvIndex</param>
        public Tpm2NvReadPublicResponse(
        NvPublic the_nvPublic,
        byte[] the_nvName
        )
        {
            this.nvPublic = the_nvPublic;
            this.nvName = the_nvName;
        }
        new public Tpm2NvReadPublicResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvReadPublicResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command writes a value to an area in NV memory that was previously defined by TPM2_NV_DefineSpace().
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_NV_Write_REQUEST")]
    public partial class Tpm2NvWriteRequest: TpmStructureBase
    {
        /// <summary>
        /// handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// the NV Index of the area to write
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }
        /// <summary>
        /// the data to write
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "dataSize", 2)]
        [DataMember()]
        public byte[] data;
        /// <summary>
        /// the offset into the NV Area
        /// </summary>
        [MarshalAs(3)]
        [DataMember()]
        public ushort offset { get; set; }
        public Tpm2NvWriteRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
            data = null;
            offset = 0;
        }
        public Tpm2NvWriteRequest(Tpm2NvWriteRequest the_Tpm2NvWriteRequest)
        {
            if((Object) the_Tpm2NvWriteRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2NvWriteRequest.authHandle;
            nvIndex = the_Tpm2NvWriteRequest.nvIndex;
            data = the_Tpm2NvWriteRequest.data;
            offset = the_Tpm2NvWriteRequest.offset;
        }
        ///<param name = "the_authHandle">handle indicating the source of the authorization value Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_nvIndex">the NV Index of the area to write Auth Index: None</param>
        ///<param name = "the_data">the data to write</param>
        ///<param name = "the_offset">the offset into the NV Area</param>
        public Tpm2NvWriteRequest(
        TpmHandle the_authHandle,
        TpmHandle the_nvIndex,
        byte[] the_data,
        ushort the_offset
        )
        {
            this.authHandle = the_authHandle;
            this.nvIndex = the_nvIndex;
            this.data = the_data;
            this.offset = the_offset;
        }
        new public Tpm2NvWriteRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvWriteRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command writes a value to an area in NV memory that was previously defined by TPM2_NV_DefineSpace().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_NV_Write_RESPONSE")]
    public partial class Tpm2NvWriteResponse: TpmStructureBase
    {
        public Tpm2NvWriteResponse()
        {
        }
        new public Tpm2NvWriteResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvWriteResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to increment the value in an NV Index that has the TPM_NT_COUNTER attribute. The data value of the NV Index is incremented by one.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_NV_Increment_REQUEST")]
    public partial class Tpm2NvIncrementRequest: TpmStructureBase
    {
        /// <summary>
        /// handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// the NV Index to increment
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }
        public Tpm2NvIncrementRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
        }
        public Tpm2NvIncrementRequest(Tpm2NvIncrementRequest the_Tpm2NvIncrementRequest)
        {
            if((Object) the_Tpm2NvIncrementRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2NvIncrementRequest.authHandle;
            nvIndex = the_Tpm2NvIncrementRequest.nvIndex;
        }
        ///<param name = "the_authHandle">handle indicating the source of the authorization value Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_nvIndex">the NV Index to increment Auth Index: None</param>
        public Tpm2NvIncrementRequest(
        TpmHandle the_authHandle,
        TpmHandle the_nvIndex
        )
        {
            this.authHandle = the_authHandle;
            this.nvIndex = the_nvIndex;
        }
        new public Tpm2NvIncrementRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvIncrementRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to increment the value in an NV Index that has the TPM_NT_COUNTER attribute. The data value of the NV Index is incremented by one.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_NV_Increment_RESPONSE")]
    public partial class Tpm2NvIncrementResponse: TpmStructureBase
    {
        public Tpm2NvIncrementResponse()
        {
        }
        new public Tpm2NvIncrementResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvIncrementResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command extends a value to an area in NV memory that was previously defined by TPM2_NV_DefineSpace.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_NV_Extend_REQUEST")]
    public partial class Tpm2NvExtendRequest: TpmStructureBase
    {
        /// <summary>
        /// handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// the NV Index to extend
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }
        /// <summary>
        /// the data to extend
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "dataSize", 2)]
        [DataMember()]
        public byte[] data;
        public Tpm2NvExtendRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
            data = null;
        }
        public Tpm2NvExtendRequest(Tpm2NvExtendRequest the_Tpm2NvExtendRequest)
        {
            if((Object) the_Tpm2NvExtendRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2NvExtendRequest.authHandle;
            nvIndex = the_Tpm2NvExtendRequest.nvIndex;
            data = the_Tpm2NvExtendRequest.data;
        }
        ///<param name = "the_authHandle">handle indicating the source of the authorization value Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_nvIndex">the NV Index to extend Auth Index: None</param>
        ///<param name = "the_data">the data to extend</param>
        public Tpm2NvExtendRequest(
        TpmHandle the_authHandle,
        TpmHandle the_nvIndex,
        byte[] the_data
        )
        {
            this.authHandle = the_authHandle;
            this.nvIndex = the_nvIndex;
            this.data = the_data;
        }
        new public Tpm2NvExtendRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvExtendRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command extends a value to an area in NV memory that was previously defined by TPM2_NV_DefineSpace.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_NV_Extend_RESPONSE")]
    public partial class Tpm2NvExtendResponse: TpmStructureBase
    {
        public Tpm2NvExtendResponse()
        {
        }
        new public Tpm2NvExtendResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvExtendResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to SET bits in an NV Index that was created as a bit field. Any number of bits from 0 to 64 may be SET. The contents of data are ORed with the current contents of the NV Index starting at offset.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(ulong))]
    [SpecTypeName("TPM2_NV_SetBits_REQUEST")]
    public partial class Tpm2NvSetBitsRequest: TpmStructureBase
    {
        /// <summary>
        /// handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// NV Index of the area in which the bit is to be set
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }
        /// <summary>
        /// the data to OR with the current contents
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public ulong bits { get; set; }
        public Tpm2NvSetBitsRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
            bits = new ulong();
        }
        public Tpm2NvSetBitsRequest(Tpm2NvSetBitsRequest the_Tpm2NvSetBitsRequest)
        {
            if((Object) the_Tpm2NvSetBitsRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2NvSetBitsRequest.authHandle;
            nvIndex = the_Tpm2NvSetBitsRequest.nvIndex;
            bits = the_Tpm2NvSetBitsRequest.bits;
        }
        ///<param name = "the_authHandle">handle indicating the source of the authorization value Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_nvIndex">NV Index of the area in which the bit is to be set Auth Index: None</param>
        ///<param name = "the_bits">the data to OR with the current contents</param>
        public Tpm2NvSetBitsRequest(
        TpmHandle the_authHandle,
        TpmHandle the_nvIndex,
        ulong the_bits
        )
        {
            this.authHandle = the_authHandle;
            this.nvIndex = the_nvIndex;
            this.bits = the_bits;
        }
        new public Tpm2NvSetBitsRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvSetBitsRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command is used to SET bits in an NV Index that was created as a bit field. Any number of bits from 0 to 64 may be SET. The contents of data are ORed with the current contents of the NV Index starting at offset.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_NV_SetBits_RESPONSE")]
    public partial class Tpm2NvSetBitsResponse: TpmStructureBase
    {
        public Tpm2NvSetBitsResponse()
        {
        }
        new public Tpm2NvSetBitsResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvSetBitsResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// If the TPMA_NV_WRITEDEFINE or TPMA_NV_WRITE_STCLEAR attributes of an NV location are SET, then this command may be used to inhibit further writes of the NV Index.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_NV_WriteLock_REQUEST")]
    public partial class Tpm2NvWriteLockRequest: TpmStructureBase
    {
        /// <summary>
        /// handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// the NV Index of the area to lock
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }
        public Tpm2NvWriteLockRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
        }
        public Tpm2NvWriteLockRequest(Tpm2NvWriteLockRequest the_Tpm2NvWriteLockRequest)
        {
            if((Object) the_Tpm2NvWriteLockRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2NvWriteLockRequest.authHandle;
            nvIndex = the_Tpm2NvWriteLockRequest.nvIndex;
        }
        ///<param name = "the_authHandle">handle indicating the source of the authorization value Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_nvIndex">the NV Index of the area to lock Auth Index: None</param>
        public Tpm2NvWriteLockRequest(
        TpmHandle the_authHandle,
        TpmHandle the_nvIndex
        )
        {
            this.authHandle = the_authHandle;
            this.nvIndex = the_nvIndex;
        }
        new public Tpm2NvWriteLockRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvWriteLockRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// If the TPMA_NV_WRITEDEFINE or TPMA_NV_WRITE_STCLEAR attributes of an NV location are SET, then this command may be used to inhibit further writes of the NV Index.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_NV_WriteLock_RESPONSE")]
    public partial class Tpm2NvWriteLockResponse: TpmStructureBase
    {
        public Tpm2NvWriteLockResponse()
        {
        }
        new public Tpm2NvWriteLockResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvWriteLockResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// The command will SET TPMA_NV_WRITELOCKED for all indexes that have their TPMA_NV_GLOBALLOCK attribute SET.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_NV_GlobalWriteLock_REQUEST")]
    public partial class Tpm2NvGlobalWriteLockRequest: TpmStructureBase
    {
        /// <summary>
        /// TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        public Tpm2NvGlobalWriteLockRequest()
        {
            authHandle = new TpmHandle();
        }
        public Tpm2NvGlobalWriteLockRequest(Tpm2NvGlobalWriteLockRequest the_Tpm2NvGlobalWriteLockRequest)
        {
            if((Object) the_Tpm2NvGlobalWriteLockRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2NvGlobalWriteLockRequest.authHandle;
        }
        ///<param name = "the_authHandle">TPM_RH_OWNER or TPM_RH_PLATFORM+{PP} Auth Index: 1 Auth Role: USER</param>
        public Tpm2NvGlobalWriteLockRequest(
        TpmHandle the_authHandle
        )
        {
            this.authHandle = the_authHandle;
        }
        new public Tpm2NvGlobalWriteLockRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvGlobalWriteLockRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// The command will SET TPMA_NV_WRITELOCKED for all indexes that have their TPMA_NV_GLOBALLOCK attribute SET.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_NV_GlobalWriteLock_RESPONSE")]
    public partial class Tpm2NvGlobalWriteLockResponse: TpmStructureBase
    {
        public Tpm2NvGlobalWriteLockResponse()
        {
        }
        new public Tpm2NvGlobalWriteLockResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvGlobalWriteLockResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command reads a value from an area in NV memory previously defined by TPM2_NV_DefineSpace().
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_NV_Read_REQUEST")]
    public partial class Tpm2NvReadRequest: TpmStructureBase
    {
        /// <summary>
        /// the handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// the NV Index to be read
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }
        /// <summary>
        /// number of octets to read
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public ushort size { get; set; }
        /// <summary>
        /// octet offset into the area
        /// This value shall be less than or equal to the size of the nvIndex data.
        /// </summary>
        [MarshalAs(3)]
        [DataMember()]
        public ushort offset { get; set; }
        public Tpm2NvReadRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
            size = 0;
            offset = 0;
        }
        public Tpm2NvReadRequest(Tpm2NvReadRequest the_Tpm2NvReadRequest)
        {
            if((Object) the_Tpm2NvReadRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2NvReadRequest.authHandle;
            nvIndex = the_Tpm2NvReadRequest.nvIndex;
            size = the_Tpm2NvReadRequest.size;
            offset = the_Tpm2NvReadRequest.offset;
        }
        ///<param name = "the_authHandle">the handle indicating the source of the authorization value Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_nvIndex">the NV Index to be read Auth Index: None</param>
        ///<param name = "the_size">number of octets to read</param>
        ///<param name = "the_offset">octet offset into the area This value shall be less than or equal to the size of the nvIndex data.</param>
        public Tpm2NvReadRequest(
        TpmHandle the_authHandle,
        TpmHandle the_nvIndex,
        ushort the_size,
        ushort the_offset
        )
        {
            this.authHandle = the_authHandle;
            this.nvIndex = the_nvIndex;
            this.size = the_size;
            this.offset = the_offset;
        }
        new public Tpm2NvReadRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvReadRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command reads a value from an area in NV memory previously defined by TPM2_NV_DefineSpace().
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_NV_Read_RESPONSE")]
    public partial class Tpm2NvReadResponse: TpmStructureBase
    {
        /// <summary>
        /// the data read
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "dataSize", 2)]
        [DataMember()]
        public byte[] data;
        public Tpm2NvReadResponse()
        {
            data = null;
        }
        public Tpm2NvReadResponse(Tpm2NvReadResponse the_Tpm2NvReadResponse)
        {
            if((Object) the_Tpm2NvReadResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            data = the_Tpm2NvReadResponse.data;
        }
        ///<param name = "the_data">the data read</param>
        public Tpm2NvReadResponse(
        byte[] the_data
        )
        {
            this.data = the_data;
        }
        new public Tpm2NvReadResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvReadResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// If TPMA_NV_READ_STCLEAR is SET in an Index, then this command may be used to prevent further reads of the NV Index until the next TPM2_Startup (TPM_SU_CLEAR).
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_NV_ReadLock_REQUEST")]
    public partial class Tpm2NvReadLockRequest: TpmStructureBase
    {
        /// <summary>
        /// the handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// the NV Index to be locked
        /// Auth Index: None
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }
        public Tpm2NvReadLockRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
        }
        public Tpm2NvReadLockRequest(Tpm2NvReadLockRequest the_Tpm2NvReadLockRequest)
        {
            if((Object) the_Tpm2NvReadLockRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            authHandle = the_Tpm2NvReadLockRequest.authHandle;
            nvIndex = the_Tpm2NvReadLockRequest.nvIndex;
        }
        ///<param name = "the_authHandle">the handle indicating the source of the authorization value Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_nvIndex">the NV Index to be locked Auth Index: None</param>
        public Tpm2NvReadLockRequest(
        TpmHandle the_authHandle,
        TpmHandle the_nvIndex
        )
        {
            this.authHandle = the_authHandle;
            this.nvIndex = the_nvIndex;
        }
        new public Tpm2NvReadLockRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvReadLockRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// If TPMA_NV_READ_STCLEAR is SET in an Index, then this command may be used to prevent further reads of the NV Index until the next TPM2_Startup (TPM_SU_CLEAR).
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_NV_ReadLock_RESPONSE")]
    public partial class Tpm2NvReadLockResponse: TpmStructureBase
    {
        public Tpm2NvReadLockResponse()
        {
        }
        new public Tpm2NvReadLockResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvReadLockResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows the authorization secret for an NV Index to be changed.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPM2_NV_ChangeAuth_REQUEST")]
    public partial class Tpm2NvChangeAuthRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of the entity
        /// Auth Index: 1
        /// Auth Role: ADMIN
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }
        /// <summary>
        /// new authorization value
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "newAuthSize", 2)]
        [DataMember()]
        public byte[] newAuth;
        public Tpm2NvChangeAuthRequest()
        {
            nvIndex = new TpmHandle();
            newAuth = null;
        }
        public Tpm2NvChangeAuthRequest(Tpm2NvChangeAuthRequest the_Tpm2NvChangeAuthRequest)
        {
            if((Object) the_Tpm2NvChangeAuthRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            nvIndex = the_Tpm2NvChangeAuthRequest.nvIndex;
            newAuth = the_Tpm2NvChangeAuthRequest.newAuth;
        }
        ///<param name = "the_nvIndex">handle of the entity Auth Index: 1 Auth Role: ADMIN</param>
        ///<param name = "the_newAuth">new authorization value</param>
        public Tpm2NvChangeAuthRequest(
        TpmHandle the_nvIndex,
        byte[] the_newAuth
        )
        {
            this.nvIndex = the_nvIndex;
            this.newAuth = the_newAuth;
        }
        new public Tpm2NvChangeAuthRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvChangeAuthRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This command allows the authorization secret for an NV Index to be changed.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_NV_ChangeAuth_RESPONSE")]
    public partial class Tpm2NvChangeAuthResponse: TpmStructureBase
    {
        public Tpm2NvChangeAuthResponse()
        {
        }
        new public Tpm2NvChangeAuthResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvChangeAuthResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// The purpose of this command is to certify the contents of an NV Index or portion of an NV Index.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeEcdaa))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(NullSigScheme))]
    [SpecTypeName("TPM2_NV_Certify_REQUEST")]
    public partial class Tpm2NvCertifyRequest: TpmStructureBase
    {
        /// <summary>
        /// handle of the key used to sign the attestation structure
        /// Auth Index: 1
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle signHandle { get; set; }
        /// <summary>
        /// handle indicating the source of the authorization value for the NV Index
        /// Auth Index: 2
        /// Auth Role: USER
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }
        /// <summary>
        /// Index for the area to be certified
        /// Auth Index: None
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }
        /// <summary>
        /// user-provided qualifying data
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "qualifyingDataSize", 2)]
        [DataMember()]
        public byte[] qualifyingData;
        /// <summary>
        /// scheme selector
        /// </summary>
        [MarshalAs(4, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get {
                if(inScheme != null) {
                    return (TpmAlgId)inScheme.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        /// (One of [SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme])
        /// </summary>
        [MarshalAs(5, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public ISigSchemeUnion inScheme { get; set; }
        /// <summary>
        /// number of octets to certify
        /// </summary>
        [MarshalAs(6)]
        [DataMember()]
        public ushort size { get; set; }
        /// <summary>
        /// octet offset into the area
        /// This value shall be less than or equal to the size of the nvIndex data.
        /// </summary>
        [MarshalAs(7)]
        [DataMember()]
        public ushort offset { get; set; }
        public Tpm2NvCertifyRequest()
        {
            signHandle = new TpmHandle();
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
            qualifyingData = null;
            size = 0;
            offset = 0;
        }
        public Tpm2NvCertifyRequest(Tpm2NvCertifyRequest the_Tpm2NvCertifyRequest)
        {
            if((Object) the_Tpm2NvCertifyRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            signHandle = the_Tpm2NvCertifyRequest.signHandle;
            authHandle = the_Tpm2NvCertifyRequest.authHandle;
            nvIndex = the_Tpm2NvCertifyRequest.nvIndex;
            qualifyingData = the_Tpm2NvCertifyRequest.qualifyingData;
            size = the_Tpm2NvCertifyRequest.size;
            offset = the_Tpm2NvCertifyRequest.offset;
        }
        ///<param name = "the_signHandle">handle of the key used to sign the attestation structure Auth Index: 1 Auth Role: USER</param>
        ///<param name = "the_authHandle">handle indicating the source of the authorization value for the NV Index Auth Index: 2 Auth Role: USER</param>
        ///<param name = "the_nvIndex">Index for the area to be certified Auth Index: None</param>
        ///<param name = "the_qualifyingData">user-provided qualifying data</param>
        ///<param name = "the_inScheme">signing scheme to use if the scheme for signHandle is TPM_ALG_NULL(One of SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme)</param>
        ///<param name = "the_size">number of octets to certify</param>
        ///<param name = "the_offset">octet offset into the area This value shall be less than or equal to the size of the nvIndex data.</param>
        public Tpm2NvCertifyRequest(
        TpmHandle the_signHandle,
        TpmHandle the_authHandle,
        TpmHandle the_nvIndex,
        byte[] the_qualifyingData,
        ISigSchemeUnion the_inScheme,
        ushort the_size,
        ushort the_offset
        )
        {
            this.signHandle = the_signHandle;
            this.authHandle = the_authHandle;
            this.nvIndex = the_nvIndex;
            this.qualifyingData = the_qualifyingData;
            this.inScheme = the_inScheme;
            this.size = the_size;
            this.offset = the_offset;
        }
        new public Tpm2NvCertifyRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvCertifyRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// The purpose of this command is to certify the contents of an NV Index or portion of an NV Index.
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullUnion))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureRsa))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureEcc))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(NullSignature))]
    [SpecTypeName("TPM2_NV_Certify_RESPONSE")]
    public partial class Tpm2NvCertifyResponse: TpmStructureBase
    {
        /// <summary>
        /// the structure that was signed
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "certifyInfoSize", 2)]
        [DataMember()]
        public byte[] certifyInfo;
        /// <summary>
        /// selector of the algorithm used to construct the signature
        /// </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get {
                if(signature != null) {
                    return (TpmAlgId)signature.GetUnionSelector();
                } else {
                    return TpmAlgId.Null;
                }
            }
        }
        /// <summary>
        /// the asymmetric signature over certifyInfo using the key referenced by signHandle
        /// (One of [SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature])
        /// </summary>
        [MarshalAs(2, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }
        public Tpm2NvCertifyResponse()
        {
            certifyInfo = null;
        }
        public Tpm2NvCertifyResponse(Tpm2NvCertifyResponse the_Tpm2NvCertifyResponse)
        {
            if((Object) the_Tpm2NvCertifyResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            certifyInfo = the_Tpm2NvCertifyResponse.certifyInfo;
        }
        ///<param name = "the_certifyInfo">the structure that was signed</param>
        ///<param name = "the_signature">the asymmetric signature over certifyInfo using the key referenced by signHandle(One of SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa, SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature)</param>
        public Tpm2NvCertifyResponse(
        byte[] the_certifyInfo,
        ISignatureUnion the_signature
        )
        {
            this.certifyInfo = the_certifyInfo;
            this.signature = the_signature;
        }
        new public Tpm2NvCertifyResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2NvCertifyResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This is a placeholder to allow testing of the dispatch code.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_Vendor_TCG_Test_REQUEST")]
    public partial class Tpm2VendorTcgTestRequest: TpmStructureBase
    {
        /// <summary>
        /// dummy data
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "inputDataSize", 2)]
        [DataMember()]
        public byte[] inputData;
        public Tpm2VendorTcgTestRequest()
        {
            inputData = null;
        }
        public Tpm2VendorTcgTestRequest(Tpm2VendorTcgTestRequest the_Tpm2VendorTcgTestRequest)
        {
            if((Object) the_Tpm2VendorTcgTestRequest == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            inputData = the_Tpm2VendorTcgTestRequest.inputData;
        }
        ///<param name = "the_inputData">dummy data</param>
        public Tpm2VendorTcgTestRequest(
        byte[] the_inputData
        )
        {
            this.inputData = the_inputData;
        }
        new public Tpm2VendorTcgTestRequest Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2VendorTcgTestRequest>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// This is a placeholder to allow testing of the dispatch code.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2_Vendor_TCG_Test_RESPONSE")]
    public partial class Tpm2VendorTcgTestResponse: TpmStructureBase
    {
        /// <summary>
        /// dummy data
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "outputDataSize", 2)]
        [DataMember()]
        public byte[] outputData;
        public Tpm2VendorTcgTestResponse()
        {
            outputData = null;
        }
        public Tpm2VendorTcgTestResponse(Tpm2VendorTcgTestResponse the_Tpm2VendorTcgTestResponse)
        {
            if((Object) the_Tpm2VendorTcgTestResponse == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            outputData = the_Tpm2VendorTcgTestResponse.outputData;
        }
        ///<param name = "the_outputData">dummy data</param>
        public Tpm2VendorTcgTestResponse(
        byte[] the_outputData
        )
        {
            this.outputData = the_outputData;
        }
        new public Tpm2VendorTcgTestResponse Copy()
        {
            return Marshaller.FromTpmRepresentation<Tpm2VendorTcgTestResponse>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Underlying type comment: These are the RSA schemes that only need a hash algorithm as a scheme parameter.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_RSASSA")]
    public partial class SchemeRsassa: SigSchemeRsassa
    {
        public SchemeRsassa()
        {
        }
        public SchemeRsassa(SchemeRsassa the_SchemeRsassa)
        : base(the_SchemeRsassa)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SchemeRsassa(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
    }
    /// <summary>
    /// Underlying type comment: These are the RSA schemes that only need a hash algorithm as a scheme parameter.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_RSAPSS")]
    public partial class SchemeRsapss: SigSchemeRsapss
    {
        public SchemeRsapss()
        {
        }
        public SchemeRsapss(SchemeRsapss the_SchemeRsapss)
        : base(the_SchemeRsapss)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SchemeRsapss(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
    }
    /// <summary>
    /// Underlying type comment: Most of the ECC signature schemes only require a hash algorithm to complete the definition and can be typed as TPMS_SCHEME_HASH. Anonymous algorithms also require a count value so they are typed to be TPMS_SCHEME_ECDAA.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_ECDSA")]
    public partial class SchemeEcdsa: SigSchemeEcdsa
    {
        public SchemeEcdsa()
        {
        }
        public SchemeEcdsa(SchemeEcdsa the_SchemeEcdsa)
        : base(the_SchemeEcdsa)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SchemeEcdsa(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
    }
    /// <summary>
    /// Underlying type comment: Most of the ECC signature schemes only require a hash algorithm to complete the definition and can be typed as TPMS_SCHEME_HASH. Anonymous algorithms also require a count value so they are typed to be TPMS_SCHEME_ECDAA.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_SM2")]
    public partial class SchemeSm2: SigSchemeSm2
    {
        public SchemeSm2()
        {
        }
        public SchemeSm2(SchemeSm2 the_SchemeSm2)
        : base(the_SchemeSm2)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SchemeSm2(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
    }
    /// <summary>
    /// Underlying type comment: Most of the ECC signature schemes only require a hash algorithm to complete the definition and can be typed as TPMS_SCHEME_HASH. Anonymous algorithms also require a count value so they are typed to be TPMS_SCHEME_ECDAA.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_ECSCHNORR")]
    public partial class SchemeEcschnorr: SigSchemeEcschnorr
    {
        public SchemeEcschnorr()
        {
        }
        public SchemeEcschnorr(SchemeEcschnorr the_SchemeEcschnorr)
        : base(the_SchemeEcschnorr)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SchemeEcschnorr(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
    }
    /// <summary>
    /// Underlying type comment: These are the RSA encryption schemes that only need a hash algorithm as a controlling parameter.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_OAEP")]
    public partial class SchemeOaep: EncSchemeOaep
    {
        public SchemeOaep()
        {
        }
        public SchemeOaep(SchemeOaep the_SchemeOaep)
        : base(the_SchemeOaep)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SchemeOaep(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
    }
    /// <summary>
    /// Underlying type comment: These are the RSA encryption schemes that only need a hash algorithm as a controlling parameter.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_RSAES")]
    public partial class SchemeRsaes: EncSchemeRsaes
    {
        public SchemeRsaes()
        {
        }
    }
    /// <summary>
    /// Underlying type comment: These are the ECC schemes that only need a hash algorithm as a controlling parameter.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_ECDH")]
    public partial class SchemeEcdh: KeySchemeEcdh
    {
        public SchemeEcdh()
        {
        }
        public SchemeEcdh(SchemeEcdh the_SchemeEcdh)
        : base(the_SchemeEcdh)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SchemeEcdh(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
    }
    /// <summary>
    /// Underlying type comment: These are the ECC schemes that only need a hash algorithm as a controlling parameter.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_ECMQV")]
    public partial class SchemeEcmqv: KeySchemeEcmqv
    {
        public SchemeEcmqv()
        {
        }
        public SchemeEcmqv(SchemeEcmqv the_SchemeEcmqv)
        : base(the_SchemeEcmqv)
        {
        }
        ///<param name = "the_hashAlg">the hash algorithm used to digest the message</param>
        public SchemeEcmqv(
        TpmAlgId the_hashAlg
        )
        : base(the_hashAlg)
        {
        }
    }
    /// <summary>
    /// Contains the public and the plaintext-sensitive and/or encrypted private part of a TPM key (or other object)
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmPublic))]
    [KnownType(typeof(Sensitive))]
    [KnownType(typeof(TpmPrivate))]
    [SpecTypeName("TssObject")]
    public partial class TssObject: TpmStructureBase
    {
        /// <summary>
        /// Public part of key
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmPublic publicPart { get; set; }
        /// <summary>
        /// Sensitive part of key
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public Sensitive sensitivePart { get; set; }
        /// <summary>
        /// Private part is the encrypted sensitive part of key
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmPrivate privatePart { get; set; }
        public TssObject()
        {
            publicPart = new TpmPublic();
            sensitivePart = new Sensitive();
            privatePart = new TpmPrivate();
        }
        public TssObject(TssObject the_TssObject)
        {
            if((Object) the_TssObject == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            publicPart = the_TssObject.publicPart;
            sensitivePart = the_TssObject.sensitivePart;
            privatePart = the_TssObject.privatePart;
        }
        ///<param name = "the_publicPart">Public part of key</param>
        ///<param name = "the_sensitivePart">Sensitive part of key</param>
        ///<param name = "the_privatePart">Private part is the encrypted sensitive part of key</param>
        public TssObject(
        TpmPublic the_publicPart,
        Sensitive the_sensitivePart,
        TpmPrivate the_privatePart
        )
        {
            this.publicPart = the_publicPart;
            this.sensitivePart = the_sensitivePart;
            this.privatePart = the_privatePart;
        }
        new public TssObject Copy()
        {
            return Marshaller.FromTpmRepresentation<TssObject>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Contains a PCR index and associated hash(pcr-value) [TSS]
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("PcrValue")]
    public partial class PcrValue: TpmStructureBase
    {
        /// <summary>
        /// PCR Index
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public uint index { get; set; }
        /// <summary>
        /// PCR Value
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHash value { get; set; }
        public PcrValue()
        {
            index = 0;
            value = new TpmHash();
        }
        public PcrValue(PcrValue the_PcrValue)
        {
            if((Object) the_PcrValue == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            index = the_PcrValue.index;
            value = the_PcrValue.value;
        }
        ///<param name = "the_index">PCR Index</param>
        ///<param name = "the_value">PCR Value</param>
        public PcrValue(
        uint the_index,
        TpmHash the_value
        )
        {
            this.index = the_index;
            this.value = the_value;
        }
        new public PcrValue Copy()
        {
            return Marshaller.FromTpmRepresentation<PcrValue>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Structure representing a session block in a command buffer [TSS]
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(SessionAttr))]
    [SpecTypeName("SessionIn")]
    public partial class SessionIn: TpmStructureBase
    {
        /// <summary>
        /// Session handle
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }
        /// <summary>
        /// Caller nonce
        /// </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "nonceCallerSize", 2)]
        [DataMember()]
        public byte[] nonceCaller;
        /// <summary>
        /// Session attributes
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public SessionAttr attributes { get; set; }
        /// <summary>
        /// AuthValue (or HMAC)
        /// </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "authSize", 2)]
        [DataMember()]
        public byte[] auth;
        public SessionIn()
        {
            handle = new TpmHandle();
            nonceCaller = null;
            attributes = new SessionAttr();
            auth = null;
        }
        public SessionIn(SessionIn the_SessionIn)
        {
            if((Object) the_SessionIn == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            handle = the_SessionIn.handle;
            nonceCaller = the_SessionIn.nonceCaller;
            attributes = the_SessionIn.attributes;
            auth = the_SessionIn.auth;
        }
        ///<param name = "the_handle">Session handle</param>
        ///<param name = "the_nonceCaller">Caller nonce</param>
        ///<param name = "the_attributes">Session attributes</param>
        ///<param name = "the_auth">AuthValue (or HMAC)</param>
        public SessionIn(
        TpmHandle the_handle,
        byte[] the_nonceCaller,
        SessionAttr the_attributes,
        byte[] the_auth
        )
        {
            this.handle = the_handle;
            this.nonceCaller = the_nonceCaller;
            this.attributes = the_attributes;
            this.auth = the_auth;
        }
        new public SessionIn Copy()
        {
            return Marshaller.FromTpmRepresentation<SessionIn>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Structure representing a session block in a response buffer [TSS]
    /// </summary>
    [DataContract]
    [KnownType(typeof(SessionAttr))]
    [SpecTypeName("SessionOut")]
    public partial class SessionOut: TpmStructureBase
    {
        /// <summary>
        /// TPM nonce
        /// </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "nonceTpmSize", 2)]
        [DataMember()]
        public byte[] nonceTpm;
        /// <summary>
        /// Session attributes
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public SessionAttr attributes { get; set; }
        /// <summary>
        /// HMAC value
        /// </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "authSize", 2)]
        [DataMember()]
        public byte[] auth;
        public SessionOut()
        {
            nonceTpm = null;
            attributes = new SessionAttr();
            auth = null;
        }
        public SessionOut(SessionOut the_SessionOut)
        {
            if((Object) the_SessionOut == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            nonceTpm = the_SessionOut.nonceTpm;
            attributes = the_SessionOut.attributes;
            auth = the_SessionOut.auth;
        }
        ///<param name = "the_nonceTpm">TPM nonce</param>
        ///<param name = "the_attributes">Session attributes</param>
        ///<param name = "the_auth">HMAC value</param>
        public SessionOut(
        byte[] the_nonceTpm,
        SessionAttr the_attributes,
        byte[] the_auth
        )
        {
            this.nonceTpm = the_nonceTpm;
            this.attributes = the_attributes;
            this.auth = the_auth;
        }
        new public SessionOut Copy()
        {
            return Marshaller.FromTpmRepresentation<SessionOut>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Command header [TSS]
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmSt))]
    [KnownType(typeof(TpmCc))]
    [SpecTypeName("CommandHeader")]
    public partial class CommandHeader: TpmStructureBase
    {
        /// <summary>
        /// Command tag (sessions, or no sessions)
        /// </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmSt Tag { get; set; }
        /// <summary>
        /// Total command buffer length
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint CommandSize { get; set; }
        /// <summary>
        /// Command code
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmCc CommandCode { get; set; }
        public CommandHeader()
        {
            Tag = new TpmSt();
            CommandSize = 0;
            CommandCode = new TpmCc();
        }
        public CommandHeader(CommandHeader the_CommandHeader)
        {
            if((Object) the_CommandHeader == null ) throw new ArgumentException(Globs.GetResourceString("parmError"));
            Tag = the_CommandHeader.Tag;
            CommandSize = the_CommandHeader.CommandSize;
            CommandCode = the_CommandHeader.CommandCode;
        }
        ///<param name = "the_Tag">Command tag (sessions, or no sessions)</param>
        ///<param name = "the_CommandSize">Total command buffer length</param>
        ///<param name = "the_CommandCode">Command code</param>
        public CommandHeader(
        TpmSt the_Tag,
        uint the_CommandSize,
        TpmCc the_CommandCode
        )
        {
            this.Tag = the_Tag;
            this.CommandSize = the_CommandSize;
            this.CommandCode = the_CommandCode;
        }
        new public CommandHeader Copy()
        {
            return Marshaller.FromTpmRepresentation<CommandHeader>(this.GetTpmRepresentation());
        }
    }
    /// <summary>
    /// Auto-derived from TPM2B_DIGEST
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_DIGEST_Symcipher")]
    public partial class Tpm2bDigestSymcipher: Tpm2bDigest
    {
        public Tpm2bDigestSymcipher()
        {
        }
        public Tpm2bDigestSymcipher(Tpm2bDigestSymcipher the_Tpm2bDigestSymcipher)
        : base(the_Tpm2bDigestSymcipher)
        {
        }
        ///<param name = "the_buffer">the buffer area that can be no larger than a digest</param>
        public Tpm2bDigestSymcipher(
        byte[] the_buffer
        )
        : base(the_buffer)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Symcipher;
        }
    }
    /// <summary>
    /// Auto-derived from TPM2B_DIGEST
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM2B_DIGEST_Keyedhash")]
    public partial class Tpm2bDigestKeyedhash: Tpm2bDigest
    {
        public Tpm2bDigestKeyedhash()
        {
        }
        public Tpm2bDigestKeyedhash(Tpm2bDigestKeyedhash the_Tpm2bDigestKeyedhash)
        : base(the_Tpm2bDigestKeyedhash)
        {
        }
        ///<param name = "the_buffer">the buffer area that can be no larger than a digest</param>
        public Tpm2bDigestKeyedhash(
        byte[] the_buffer
        )
        : base(the_buffer)
        {
        }
        public override TpmAlgId GetUnionSelector()
        {
            return TpmAlgId.Keyedhash;
        }
    }
    //-----------------------------------------------------------------------------
    //------------------------- COMMAND INFO -----------------------------------
    //-----------------------------------------------------------------------------
    public static class CommandInformation {
        public static CommandInfo[] Info = new CommandInfo[]{
            new CommandInfo(TpmCc.Startup, 0, 0, 0, typeof(Tpm2StartupRequest), typeof(Tpm2StartupResponse), 0, ""),
            new CommandInfo(TpmCc.Shutdown, 0, 0, 0, typeof(Tpm2ShutdownRequest), typeof(Tpm2ShutdownResponse), 0, ""),
            new CommandInfo(TpmCc.SelfTest, 0, 0, 0, typeof(Tpm2SelfTestRequest), typeof(Tpm2SelfTestResponse), 0, ""),
            new CommandInfo(TpmCc.IncrementalSelfTest, 0, 0, 0, typeof(Tpm2IncrementalSelfTestRequest), typeof(Tpm2IncrementalSelfTestResponse), 10, ""),
            new CommandInfo(TpmCc.GetTestResult, 0, 0, 0, typeof(Tpm2GetTestResultRequest), typeof(Tpm2GetTestResultResponse), 4, ""),
            new CommandInfo(TpmCc.StartAuthSession, 2, 1, 0, typeof(Tpm2StartAuthSessionRequest), typeof(Tpm2StartAuthSessionResponse), 5, "TPMI_DH_OBJECT TPMI_DH_ENTITY"),
            new CommandInfo(TpmCc.PolicyRestart, 1, 0, 0, typeof(Tpm2PolicyRestartRequest), typeof(Tpm2PolicyRestartResponse), 0, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.Create, 1, 0, 1, typeof(Tpm2CreateRequest), typeof(Tpm2CreateResponse), 1, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Load, 1, 1, 1, typeof(Tpm2LoadRequest), typeof(Tpm2LoadResponse), 4, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.LoadExternal, 0, 1, 0, typeof(Tpm2LoadExternalRequest), typeof(Tpm2LoadExternalResponse), 5, ""),
            new CommandInfo(TpmCc.ReadPublic, 1, 0, 0, typeof(Tpm2ReadPublicRequest), typeof(Tpm2ReadPublicResponse), 4, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.ActivateCredential, 2, 0, 2, typeof(Tpm2ActivateCredentialRequest), typeof(Tpm2ActivateCredentialResponse), 5, "TPMI_DH_OBJECT TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.MakeCredential, 1, 0, 0, typeof(Tpm2MakeCredentialRequest), typeof(Tpm2MakeCredentialResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Unseal, 1, 0, 1, typeof(Tpm2UnsealRequest), typeof(Tpm2UnsealResponse), 4, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.ObjectChangeAuth, 2, 0, 1, typeof(Tpm2ObjectChangeAuthRequest), typeof(Tpm2ObjectChangeAuthResponse), 1, "TPMI_DH_OBJECT TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.CreateLoaded, 1, 1, 1, typeof(Tpm2CreateLoadedRequest), typeof(Tpm2CreateLoadedResponse), 1, "TPMI_DH_PARENT"),
            new CommandInfo(TpmCc.Duplicate, 2, 0, 1, typeof(Tpm2DuplicateRequest), typeof(Tpm2DuplicateResponse), 5, "TPMI_DH_OBJECT TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Rewrap, 2, 0, 1, typeof(Tpm2RewrapRequest), typeof(Tpm2RewrapResponse), 0, "TPMI_DH_OBJECT TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Import, 1, 0, 1, typeof(Tpm2ImportRequest), typeof(Tpm2ImportResponse), 1, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.RsaEncrypt, 1, 0, 0, typeof(Tpm2RsaEncryptRequest), typeof(Tpm2RsaEncryptResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.RsaDecrypt, 1, 0, 1, typeof(Tpm2RsaDecryptRequest), typeof(Tpm2RsaDecryptResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.EcdhKeyGen, 1, 0, 0, typeof(Tpm2EcdhKeyGenRequest), typeof(Tpm2EcdhKeyGenResponse), 4, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.EcdhZGen, 1, 0, 1, typeof(Tpm2EcdhZGenRequest), typeof(Tpm2EcdhZGenResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.EccParameters, 0, 0, 0, typeof(Tpm2EccParametersRequest), typeof(Tpm2EccParametersResponse), 0, ""),
            new CommandInfo(TpmCc.ZGen2Phase, 1, 0, 1, typeof(Tpm2ZGen2PhaseRequest), typeof(Tpm2ZGen2PhaseResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.EncryptDecrypt, 1, 0, 1, typeof(Tpm2EncryptDecryptRequest), typeof(Tpm2EncryptDecryptResponse), 4, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Hash, 0, 0, 0, typeof(Tpm2HashRequest), typeof(Tpm2HashResponse), 5, ""),
            new CommandInfo(TpmCc.Hmac, 1, 0, 1, typeof(Tpm2HmacRequest), typeof(Tpm2HmacResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.GetRandom, 0, 0, 0, typeof(Tpm2GetRandomRequest), typeof(Tpm2GetRandomResponse), 4, ""),
            new CommandInfo(TpmCc.StirRandom, 0, 0, 0, typeof(Tpm2StirRandomRequest), typeof(Tpm2StirRandomResponse), 1, ""),
            new CommandInfo(TpmCc.HmacStart, 1, 1, 1, typeof(Tpm2HmacStartRequest), typeof(Tpm2HmacStartResponse), 1, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.HashSequenceStart, 0, 1, 0, typeof(Tpm2HashSequenceStartRequest), typeof(Tpm2HashSequenceStartResponse), 1, ""),
            new CommandInfo(TpmCc.SequenceUpdate, 1, 0, 1, typeof(Tpm2SequenceUpdateRequest), typeof(Tpm2SequenceUpdateResponse), 1, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.SequenceComplete, 1, 0, 1, typeof(Tpm2SequenceCompleteRequest), typeof(Tpm2SequenceCompleteResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.EventSequenceComplete, 2, 0, 2, typeof(Tpm2EventSequenceCompleteRequest), typeof(Tpm2EventSequenceCompleteResponse), 9, "TPMI_DH_PCR TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Certify, 2, 0, 2, typeof(Tpm2CertifyRequest), typeof(Tpm2CertifyResponse), 5, "TPMI_DH_OBJECT TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.CertifyCreation, 2, 0, 1, typeof(Tpm2CertifyCreationRequest), typeof(Tpm2CertifyCreationResponse), 5, "TPMI_DH_OBJECT TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Quote, 1, 0, 1, typeof(Tpm2QuoteRequest), typeof(Tpm2QuoteResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.GetSessionAuditDigest, 3, 0, 2, typeof(Tpm2GetSessionAuditDigestRequest), typeof(Tpm2GetSessionAuditDigestResponse), 5, "TPMI_RH_ENDORSEMENT TPMI_DH_OBJECT TPMI_SH_HMAC"),
            new CommandInfo(TpmCc.GetCommandAuditDigest, 2, 0, 2, typeof(Tpm2GetCommandAuditDigestRequest), typeof(Tpm2GetCommandAuditDigestResponse), 5, "TPMI_RH_ENDORSEMENT TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.GetTime, 2, 0, 2, typeof(Tpm2GetTimeRequest), typeof(Tpm2GetTimeResponse), 5, "TPMI_RH_ENDORSEMENT TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Commit, 1, 0, 1, typeof(Tpm2CommitRequest), typeof(Tpm2CommitResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.EcEphemeral, 0, 0, 0, typeof(Tpm2EcEphemeralRequest), typeof(Tpm2EcEphemeralResponse), 4, ""),
            new CommandInfo(TpmCc.VerifySignature, 1, 0, 0, typeof(Tpm2VerifySignatureRequest), typeof(Tpm2VerifySignatureResponse), 1, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Sign, 1, 0, 1, typeof(Tpm2SignRequest), typeof(Tpm2SignResponse), 1, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.SetCommandCodeAuditStatus, 1, 0, 1, typeof(Tpm2SetCommandCodeAuditStatusRequest), typeof(Tpm2SetCommandCodeAuditStatusResponse), 0, "TPMI_RH_PROVISION"),
            new CommandInfo(TpmCc.PcrExtend, 1, 0, 1, typeof(Tpm2PcrExtendRequest), typeof(Tpm2PcrExtendResponse), 2, "TPMI_DH_PCR"),
            new CommandInfo(TpmCc.PcrEvent, 1, 0, 1, typeof(Tpm2PcrEventRequest), typeof(Tpm2PcrEventResponse), 9, "TPMI_DH_PCR"),
            new CommandInfo(TpmCc.PcrRead, 0, 0, 0, typeof(Tpm2PcrReadRequest), typeof(Tpm2PcrReadResponse), 2, ""),
            new CommandInfo(TpmCc.PcrAllocate, 1, 0, 1, typeof(Tpm2PcrAllocateRequest), typeof(Tpm2PcrAllocateResponse), 2, "TPMI_RH_PLATFORM"),
            new CommandInfo(TpmCc.PcrSetAuthPolicy, 1, 0, 1, typeof(Tpm2PcrSetAuthPolicyRequest), typeof(Tpm2PcrSetAuthPolicyResponse), 1, "TPMI_RH_PLATFORM"),
            new CommandInfo(TpmCc.PcrSetAuthValue, 1, 0, 1, typeof(Tpm2PcrSetAuthValueRequest), typeof(Tpm2PcrSetAuthValueResponse), 1, "TPMI_DH_PCR"),
            new CommandInfo(TpmCc.PcrReset, 1, 0, 1, typeof(Tpm2PcrResetRequest), typeof(Tpm2PcrResetResponse), 0, "TPMI_DH_PCR"),
            new CommandInfo(TpmCc.PolicySigned, 2, 0, 0, typeof(Tpm2PolicySignedRequest), typeof(Tpm2PolicySignedResponse), 5, "TPMI_DH_OBJECT TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicySecret, 2, 0, 1, typeof(Tpm2PolicySecretRequest), typeof(Tpm2PolicySecretResponse), 5, "TPMI_DH_ENTITY TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyTicket, 1, 0, 0, typeof(Tpm2PolicyTicketRequest), typeof(Tpm2PolicyTicketResponse), 1, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyOR, 1, 0, 0, typeof(Tpm2PolicyORRequest), typeof(Tpm2PolicyORResponse), 2, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyPCR, 1, 0, 0, typeof(Tpm2PolicyPCRRequest), typeof(Tpm2PolicyPCRResponse), 1, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyLocality, 1, 0, 0, typeof(Tpm2PolicyLocalityRequest), typeof(Tpm2PolicyLocalityResponse), 0, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyNV, 3, 0, 1, typeof(Tpm2PolicyNVRequest), typeof(Tpm2PolicyNVResponse), 1, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyCounterTimer, 1, 0, 0, typeof(Tpm2PolicyCounterTimerRequest), typeof(Tpm2PolicyCounterTimerResponse), 1, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyCommandCode, 1, 0, 0, typeof(Tpm2PolicyCommandCodeRequest), typeof(Tpm2PolicyCommandCodeResponse), 0, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyPhysicalPresence, 1, 0, 0, typeof(Tpm2PolicyPhysicalPresenceRequest), typeof(Tpm2PolicyPhysicalPresenceResponse), 0, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyCpHash, 1, 0, 0, typeof(Tpm2PolicyCpHashRequest), typeof(Tpm2PolicyCpHashResponse), 1, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyNameHash, 1, 0, 0, typeof(Tpm2PolicyNameHashRequest), typeof(Tpm2PolicyNameHashResponse), 1, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyDuplicationSelect, 1, 0, 0, typeof(Tpm2PolicyDuplicationSelectRequest), typeof(Tpm2PolicyDuplicationSelectResponse), 1, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyAuthorize, 1, 0, 0, typeof(Tpm2PolicyAuthorizeRequest), typeof(Tpm2PolicyAuthorizeResponse), 1, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyAuthValue, 1, 0, 0, typeof(Tpm2PolicyAuthValueRequest), typeof(Tpm2PolicyAuthValueResponse), 0, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyPassword, 1, 0, 0, typeof(Tpm2PolicyPasswordRequest), typeof(Tpm2PolicyPasswordResponse), 0, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyGetDigest, 1, 0, 0, typeof(Tpm2PolicyGetDigestRequest), typeof(Tpm2PolicyGetDigestResponse), 4, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyNvWritten, 1, 0, 0, typeof(Tpm2PolicyNvWrittenRequest), typeof(Tpm2PolicyNvWrittenResponse), 0, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyTemplate, 1, 0, 0, typeof(Tpm2PolicyTemplateRequest), typeof(Tpm2PolicyTemplateResponse), 1, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyAuthorizeNV, 3, 0, 1, typeof(Tpm2PolicyAuthorizeNVRequest), typeof(Tpm2PolicyAuthorizeNVResponse), 0, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.CreatePrimary, 1, 1, 1, typeof(Tpm2CreatePrimaryRequest), typeof(Tpm2CreatePrimaryResponse), 5, "TPMI_RH_HIERARCHY"),
            new CommandInfo(TpmCc.HierarchyControl, 1, 0, 1, typeof(Tpm2HierarchyControlRequest), typeof(Tpm2HierarchyControlResponse), 0, "TPMI_RH_HIERARCHY"),
            new CommandInfo(TpmCc.SetPrimaryPolicy, 1, 0, 1, typeof(Tpm2SetPrimaryPolicyRequest), typeof(Tpm2SetPrimaryPolicyResponse), 1, "TPMI_RH_HIERARCHY_AUTH"),
            new CommandInfo(TpmCc.ChangePPS, 1, 0, 1, typeof(Tpm2ChangePPSRequest), typeof(Tpm2ChangePPSResponse), 0, "TPMI_RH_PLATFORM"),
            new CommandInfo(TpmCc.ChangeEPS, 1, 0, 1, typeof(Tpm2ChangeEPSRequest), typeof(Tpm2ChangeEPSResponse), 0, "TPMI_RH_PLATFORM"),
            new CommandInfo(TpmCc.Clear, 1, 0, 1, typeof(Tpm2ClearRequest), typeof(Tpm2ClearResponse), 0, "TPMI_RH_CLEAR"),
            new CommandInfo(TpmCc.ClearControl, 1, 0, 1, typeof(Tpm2ClearControlRequest), typeof(Tpm2ClearControlResponse), 0, "TPMI_RH_CLEAR"),
            new CommandInfo(TpmCc.HierarchyChangeAuth, 1, 0, 1, typeof(Tpm2HierarchyChangeAuthRequest), typeof(Tpm2HierarchyChangeAuthResponse), 1, "TPMI_RH_HIERARCHY_AUTH"),
            new CommandInfo(TpmCc.DictionaryAttackLockReset, 1, 0, 1, typeof(Tpm2DictionaryAttackLockResetRequest), typeof(Tpm2DictionaryAttackLockResetResponse), 0, "TPMI_RH_LOCKOUT"),
            new CommandInfo(TpmCc.DictionaryAttackParameters, 1, 0, 1, typeof(Tpm2DictionaryAttackParametersRequest), typeof(Tpm2DictionaryAttackParametersResponse), 0, "TPMI_RH_LOCKOUT"),
            new CommandInfo(TpmCc.PpCommands, 1, 0, 1, typeof(Tpm2PpCommandsRequest), typeof(Tpm2PpCommandsResponse), 2, "TPMI_RH_PLATFORM"),
            new CommandInfo(TpmCc.SetAlgorithmSet, 1, 0, 1, typeof(Tpm2SetAlgorithmSetRequest), typeof(Tpm2SetAlgorithmSetResponse), 0, "TPMI_RH_PLATFORM"),
            new CommandInfo(TpmCc.FieldUpgradeStart, 2, 0, 1, typeof(Tpm2FieldUpgradeStartRequest), typeof(Tpm2FieldUpgradeStartResponse), 1, "TPMI_RH_PLATFORM TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.FieldUpgradeData, 0, 0, 0, typeof(Tpm2FieldUpgradeDataRequest), typeof(Tpm2FieldUpgradeDataResponse), 1, ""),
            new CommandInfo(TpmCc.FirmwareRead, 0, 0, 0, typeof(Tpm2FirmwareReadRequest), typeof(Tpm2FirmwareReadResponse), 4, ""),
            new CommandInfo(TpmCc.ContextSave, 1, 0, 0, typeof(Tpm2ContextSaveRequest), typeof(Tpm2ContextSaveResponse), 0, "TPMI_DH_CONTEXT"),
            new CommandInfo(TpmCc.ContextLoad, 0, 1, 0, typeof(Tpm2ContextLoadRequest), typeof(Tpm2ContextLoadResponse), 0, ""),
            new CommandInfo(TpmCc.FlushContext, 1, 0, 0, typeof(Tpm2FlushContextRequest), typeof(Tpm2FlushContextResponse), 0, "TPMI_DH_CONTEXT"),
            new CommandInfo(TpmCc.EvictControl, 2, 0, 1, typeof(Tpm2EvictControlRequest), typeof(Tpm2EvictControlResponse), 0, "TPMI_RH_PROVISION TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.ReadClock, 0, 0, 0, typeof(Tpm2ReadClockRequest), typeof(Tpm2ReadClockResponse), 0, ""),
            new CommandInfo(TpmCc.ClockSet, 1, 0, 1, typeof(Tpm2ClockSetRequest), typeof(Tpm2ClockSetResponse), 0, "TPMI_RH_PROVISION"),
            new CommandInfo(TpmCc.ClockRateAdjust, 1, 0, 1, typeof(Tpm2ClockRateAdjustRequest), typeof(Tpm2ClockRateAdjustResponse), 0, "TPMI_RH_PROVISION"),
            new CommandInfo(TpmCc.GetCapability, 0, 0, 0, typeof(Tpm2GetCapabilityRequest), typeof(Tpm2GetCapabilityResponse), 0, ""),
            new CommandInfo(TpmCc.TestParms, 0, 0, 0, typeof(Tpm2TestParmsRequest), typeof(Tpm2TestParmsResponse), 0, ""),
            new CommandInfo(TpmCc.NvDefineSpace, 1, 0, 1, typeof(Tpm2NvDefineSpaceRequest), typeof(Tpm2NvDefineSpaceResponse), 1, "TPMI_RH_PROVISION"),
            new CommandInfo(TpmCc.NvUndefineSpace, 2, 0, 1, typeof(Tpm2NvUndefineSpaceRequest), typeof(Tpm2NvUndefineSpaceResponse), 0, "TPMI_RH_PROVISION TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvUndefineSpaceSpecial, 2, 0, 2, typeof(Tpm2NvUndefineSpaceSpecialRequest), typeof(Tpm2NvUndefineSpaceSpecialResponse), 0, "TPMI_RH_NV_INDEX TPMI_RH_PLATFORM"),
            new CommandInfo(TpmCc.NvReadPublic, 1, 0, 0, typeof(Tpm2NvReadPublicRequest), typeof(Tpm2NvReadPublicResponse), 4, "TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvWrite, 2, 0, 1, typeof(Tpm2NvWriteRequest), typeof(Tpm2NvWriteResponse), 1, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvIncrement, 2, 0, 1, typeof(Tpm2NvIncrementRequest), typeof(Tpm2NvIncrementResponse), 0, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvExtend, 2, 0, 1, typeof(Tpm2NvExtendRequest), typeof(Tpm2NvExtendResponse), 1, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvSetBits, 2, 0, 1, typeof(Tpm2NvSetBitsRequest), typeof(Tpm2NvSetBitsResponse), 0, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvWriteLock, 2, 0, 1, typeof(Tpm2NvWriteLockRequest), typeof(Tpm2NvWriteLockResponse), 0, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvGlobalWriteLock, 1, 0, 1, typeof(Tpm2NvGlobalWriteLockRequest), typeof(Tpm2NvGlobalWriteLockResponse), 0, "TPMI_RH_PROVISION"),
            new CommandInfo(TpmCc.NvRead, 2, 0, 1, typeof(Tpm2NvReadRequest), typeof(Tpm2NvReadResponse), 4, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvReadLock, 2, 0, 1, typeof(Tpm2NvReadLockRequest), typeof(Tpm2NvReadLockResponse), 0, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvChangeAuth, 1, 0, 1, typeof(Tpm2NvChangeAuthRequest), typeof(Tpm2NvChangeAuthResponse), 1, "TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvCertify, 3, 0, 2, typeof(Tpm2NvCertifyRequest), typeof(Tpm2NvCertifyResponse), 5, "TPMI_DH_OBJECT TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.VendorTcgTest, 0, 0, 0, typeof(Tpm2VendorTcgTestRequest), typeof(Tpm2VendorTcgTestResponse), 5, "")
        };
    }
}