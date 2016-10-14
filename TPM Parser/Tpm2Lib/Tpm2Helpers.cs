/*++

Copyright (c) 2010-2015 Microsoft Corporation
Microsoft Confidential

*/
using System;

namespace Tpm2Lib
{
    /// <summary>
    /// TpmHelpers is a set of routines accessible like
    ///     tpm.Helpers.Primaries.CreateRsaPrimary(...)
    /// that perform common operations.  Programming the TPM is simplified because the libraries 
    /// string together command sequences that are needed to get a job done, or because we set up 
    /// complex data structures with default (and commonly desired) settings.
    /// 
    /// </summary>
    public class TpmHelpers
    {
        // These are the default settings for TPM operations
        public TpmAlgId NameHash = TpmAlgId.Sha256;
        public IAsymSchemeUnion RsaSigScheme = new SchemeRsassa(TpmAlgId.Sha1);

        internal TpmHelpers(Tpm2 associatedTpm)
        { }

        /// <summary>
        /// Check if this TPM implements the given command.
        /// The method sends the GetCapability command the first time it is called,
        /// and reuses its results during subsequent invocations.
        /// </summary>
        /// <param name="commandCode">The command code to check.</param>
        /// <returns>true if the given command is supported by this TPM instance.</returns>
        public bool IsImplemented(TpmCc commandCode)
        {
            return true;
        }

        /// <summary>
        /// Check if this TPM implements the given algorithm.
        /// The method sends the GetCapability command the first time it is called,
        /// and reuses its results during subsequent invocations.
        /// </summary>
        /// <param name="commandCode">Algorithm ID to check.</param>
        /// <returns>true if the given algorithm is supported by this TPM instance.</returns>
        public bool IsImplemented(TpmAlgId algId)
        {
            return true;
        }

        /// <summary>
        /// Returns the value of an enumerator that was renamed in one of the TPM 2.0 spec revisions.
        /// </summary>
        public static E GetEnumerator<E>(string oldName, string newName) where E : struct
        {
            E val;
            if (Enum.TryParse<E>(newName, out val) || Enum.TryParse<E>(oldName, out val))
            {
                return val;
            }
            throw new Exception("Invalid enumerator names " + oldName + ", " + newName + " for enum " + typeof(E));
        }
    }

    public class TpmErrorHelpers
    {
        /// <summary>
        /// Checks if the given response code uses Format-One.
        /// </summary>
        public static bool IsFmt1 (TpmRc responseCode)
        {
            return ((uint)responseCode & 0x80) != 0;
        }

        /// <summary>
        /// Returns error number, i.e. what is left after masking out auxiliary data
        /// (such as format selector, version, and bad parameter index) from the
        /// response code returned by TPM.
        /// </summary>
        public static TpmRc ErrorNumber (TpmRc rawResponse)
        {
            const uint Fmt1 = (uint)TpmRc.RcFmt1;   // Format 1 code (TPM 2 only)
            const uint Ver1 = (uint)TpmRc.RcVer1;   // TPM 1 code (format 0 only)
            const uint Warn = (uint)TpmRc.RcWarn;   // Code is a warning (format 0 only)
            uint mask = IsFmt1(rawResponse) ? Fmt1 | 0x3F : Warn | Ver1 | 0x7F;
            return (TpmRc)((uint)rawResponse & mask);
        }
    }

}
