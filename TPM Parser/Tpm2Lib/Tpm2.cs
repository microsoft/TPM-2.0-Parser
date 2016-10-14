/*++

Copyright (c) 2010-2015 Microsoft Corporation
Microsoft Confidential

*/
using System;
using System.Reflection;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Globalization;

namespace Tpm2Lib
{
    /// <summary>
    /// Mode of the Tpm2 object operations.
    /// </summary>
    public enum Behavior
    {
        None = 0,

        /// <summary>
        /// If no mode flags are set, the default behavior of a Tpm2 object is to:
        /// - automatically provide auth sessions when they are necessary and not
        ///   specified explicitly;
        /// - automatically compute names of objects/NV indices;
        /// - do not do any command parameter validation before sending the command
        ///   to TPM (if only this is not necessary to prevent the client side code
        ///   from crashing).
        /// The other flags override this default behavior.  
        /// </summary>
        Default = Passthrough,

        /// <summary>
        /// When set, Tpm2 object does not issue any TPM commands of its own (i.e.
        /// commands not explicitly invoked by the user). This means that all the
        /// information required for building TPM command request and processing the
        /// command response (such as session objects, entity names) must be provided
        /// explicitly by the user whenever necessary.
        /// </summary>
        Strict = 1,

        /// <summary>
        /// Do not do any command parameter validation before sending the command to TPM.
        /// </summary>
        Passthrough = 2
    }

    /// <summary>
    /// Tpm2 provides methods to create TPM-compatible byte streams and unmarshal responses.  It is used in conjunction with a TPM device
    /// (implementing Tpm2Device) that communicates with the actual TPM device.
    /// TPM commands map 1:1 to corresponding methods in Tpm2 (with parameter translations described elsewhere).  
    /// Tpm2 also provides a few commands that are tagged with Ex (like Tpm2.StartAuthSessionEx).  These commands provide a slightly higher 
    /// level of abstraction when using the underlying native TPM command is tricky or verbose.
    /// Tpm2 also provides a few commands that are preceded by _ like _AllowErrors().  These commands are not sent to the TPM, but instead
    /// change the behavior of later TPM commands (often for the next command invocation only).
    /// Finally, Tpm2.Instrumentation provides access to TPM debug functionality (will not be
    /// available on release/production TPMs.)
    /// </summary>
    //  Note - Actual TPM command stubs are auto-generated and are in a separate file
    public sealed partial class Tpm2 : IDisposable
    {
        /// <summary>
        /// Auth value associated with the storage hierarchy (TpmRh.Owner).
        /// </summary>
        public AuthValue   OwnerAuth = new AuthValue();

        /// <summary>
        /// Auth value associated with the endorsement hierarchy (TpmRh.Endorsement).
        /// </summary>
        public AuthValue   EndorsementAuth = new AuthValue();

        /// <summary>
        /// Auth value associated with the platform hierarchy (TpmRh.Platform).
        /// </summary>
        public AuthValue   PlatformAuth = new AuthValue();

        /// <summary>
        /// Auth value associated with the dictionary attack lockout reset (TpmRh.Lockout).
        /// </summary>
        public AuthValue   LockoutAuth = new AuthValue();

        // The following variables apply to the next command invocation. THey are typically set using the style - 
        // tpm[session].ExepectError(TpmRc.Auth).Command(parm1, parm2)
        // and are cleared when an actual command is invoked.  Note that if no command is invoked the state variables will
        // apply to the next call (probably in error)

        /// <summary>
        /// List of temporary session object handless created to authorize the current command.
        /// These sessions are flushed upon the command completion.
        /// </summary>
        private readonly List<SessionBase> TempSessions = new List<SessionBase>();

        /// <summary>
        /// List of handles, the associated name of which, must be reset upon the current
        /// command completion. Currently they can be only yet unwritten NV indices.
        /// </summary>
        private readonly List<TpmHandle> TempNames = new List<TpmHandle>();

        /// <summary>
        /// Hash algorithm to compute a digest of a private part that is used to index
        /// AuthValues dictionary.
        /// </summary>
        private const TpmAlgId PrivHashAlg = TpmAlgId.Sha1;

        /// <summary>
        /// A dictionary internally maintained to pass information about objects' auth
        /// values changed/set by a command to the corresponding wrapper classes managed
        /// by TSS.Net.
        /// </summary>
        private readonly Dictionary<TpmHash, AuthValue> AuthValues = new Dictionary<TpmHash, AuthValue>();

        /// <summary>
        /// A dictionary internally used to pass parameters of newly created auth sessions
        /// to the corresponding wrapper classes managed by TSS.Net.
        /// </summary>
        private Dictionary<TpmHandle, AuthSession> SessionParams = new Dictionary<TpmHandle, AuthSession>();

        /// <summary>
        /// An internal array of handles of PCRs that have an auth value assigned.
        /// </summary>
        internal TpmHandle[] PcrHandles;

        private readonly CommandModifier ActiveModifiers = new CommandModifier();

        // Debugging support. Various callbacks allow a debugger, profiler or monitor 
        // to be informed of TPM commands and responses. They are called at different 
        // times and places in the conversation between the tester and the TPM.

        public delegate void TraceCallback(byte[] inBuf, byte[] outBuf);

        public delegate void ParamsTraceCallback(TpmCc commandCode, TpmStructureBase inParms, TpmStructureBase outParms);

        public delegate bool CmdParamsCallback(CommandInfo info, ref byte[] parms, TpmHandle[] handles);

        public delegate bool CmdBufCallback(ref byte[] command);

        public delegate bool CmdStatsCallback(TpmCc command, TpmRc maskedError, double executionTime);

        public delegate bool AlternateActionCallback(TpmCc ordinal,
                                                     TpmStructureBase inParms,
                                                     Type expectedResponseType,
                                                     out TpmStructureBase outParms,
                                                     out bool desiredSuccessCode);

        /// <summary>
        /// Methods in Helpers enable quick and easy access to common TPM commands and command
        /// sequences
        /// </summary>
        public TpmHelpers Helpers;

        // If an ErrorHandler is registered then it is called instead 
        public delegate void ErrorHandler(TpmRc returnCode, TpmRc[] expectedResponses);

        public static string GetErrorString(Type inParmsType, uint resultCode, out TpmRc theMaskedError)
        {
            // There are two encoding for errors - format 0 and format 1.  Decode the error type
            var resultCodeValue = resultCode;
            bool formatOneErrorType = ((resultCodeValue & 0x80) != 0);
            uint resultCodeMask = formatOneErrorType ? 0xBFU : 0x97FU;

            // Extract the actual error code
            uint maskedErrorVal = resultCode & resultCodeMask;
            var maskedError = (TpmRc)maskedErrorVal;
            theMaskedError = maskedError;

            string errorEntity = "Unknown";
            uint errorEntityIndex = 0;
            string errorParmName = "Unknown";
            if (formatOneErrorType)
            {
                errorEntityIndex = (resultCodeValue & 0xF00U) >> 8;
                if (errorEntityIndex == 0)
                {
                    // ReSharper disable once RedundantAssignment
                    errorEntity = "Unknown";
                }
                if ((resultCodeValue & 0x40) != 0)
                {
                    errorEntity = "Parameter";
                    errorParmName = GetParmName(inParmsType, errorEntityIndex);
                }
                else
                {
                    if (errorEntityIndex >= 8)
                    {
                        errorEntityIndex -= 8;
                        errorEntity = "Session";
                    }
                    else
                    {
                        errorEntity = "handle";
                    }
                }
            }

            string errorString = String.Format(
                                               "[Code=TpmRc.{0}],[FullVal=0x{1:X},{1}]\n" +
                                               "[ErrorEntity={2}],[ParmNum={3}]" +
                                               "[ParmName={4}]",
                                               new Object[] {
                                                   maskedError.ToString(), 
                                                   //(uint)maskedError, 
                                                   resultCodeValue,
                                                   errorEntity,
                                                   errorEntityIndex,
                                                   errorParmName
                                               });
            return errorString;
        }

        public static TpmRc GetBaseErrorCode(TpmRc resultCode)
        {
            var resultCodeValue = (uint)resultCode;
            bool formatOneErrorType = ((resultCodeValue & 0x80) != 0);
            uint resultCodeMask = formatOneErrorType ? 0xBFU : 0x97FU;

            // Extract the actual error code
            uint maskedErrorVal = (uint)resultCode & resultCodeMask;
            var maskedError = (TpmRc)maskedErrorVal;
            return maskedError;
        }

        /// <summary>
        /// Lookup (non-handle) parameter number in input structure.
        /// </summary>
        /// <param name="inParmType"></param>
        /// <param name="parmNumber"></param>
        /// <returns></returns>
        private static string GetParmName(Type inParmType, uint parmNumber)
        {
            // Exclude prefix 'Tpm2' and suffix 'Request' from the structure containing
            // command input parameters. What remains is the command name.
            string cmdName = inParmType.Name.Substring(4, inParmType.Name.Length - 11);
            MethodInfo mi = typeof(Tpm2).GetMethod(cmdName);
            ParameterInfo[] pi = mi.GetParameters();

            int idx = 0;
            // Skip handles
            while (idx < pi.Length && pi[idx].ParameterType == typeof (TpmHandle)) ++idx;
            idx += (int)parmNumber - 1; // parmNumber is 1 based
            return idx < pi.Length ? pi[idx].Name : "Undefined (parameter index too big)";
        }

        /// <summary>
        /// Name processing for Load-style operations
        /// </summary>
        /// <param name="h"></param>
        /// <param name="tpmAssignedName"></param>
        /// <param name="publicPart"></param>
        internal void ProcessName(TpmHandle h, byte[] tpmAssignedName, TpmPublic publicPart)
        {
            // Has been configured to *not* throw an exception if the TPM returns an error.
            if (tpmAssignedName.Length == 0)
                return;

            // If the load-command fails then the name returned is NULL.
            if (!NamesEqual(publicPart.GetName(), tpmAssignedName))
            {
                Globs.Throw("TPM assigned name differs from what is expected");
            }
            h.Name = tpmAssignedName;
        }

        /// <summary>
        /// The TPM name is an opaque byte-array comprising the hashAlg concatenated with the hash value
        /// </summary>
        /// <param name="name"></param>
        /// <param name="tpmAssignedName"></param>
        /// <returns></returns>
        private static bool NamesEqual(byte[] name, byte[] tpmAssignedName)
        {
            return Globs.ArraysAreEqual(name, tpmAssignedName);
        }

        /// <summary>
        /// Reference to parameter decryption session, or null.
        /// It is not used to manage lifetime of the associated TPM session handle.
        /// </summary>
        private AuthSession DecSession;

        /// <summary>
        /// Reference to response encryption session, or null.
        /// It is not used to manage lifetime of the associated TPM session handle.
        /// </summary>
        private AuthSession EncSession;

        private void CheckParamEncSessCandidate(AuthSession candidate, SessionAttr directionFlag)
        {
            if (!candidate.Attrs.HasFlag(directionFlag))
            {
                return;
            }

            bool decrypt = directionFlag == SessionAttr.Decrypt;

            if (!candidate.CanEncrypt())
            {
                Globs.Throw(string.Format("{0} session is missing symmetric algorithm",
                                          decrypt ? "Decryption" : "Encryption"));
            }
            if ((decrypt ? DecSession : EncSession) != null)
            {
                Globs.Throw(string.Format("Multiple {0} sessions",
                                          decrypt ? "decryption" : "encryption"));
            }
            if (decrypt)
            {
                DecSession = candidate;
            }
            else
            {
                EncSession = candidate;
            }
        }

        /// <summary>
        /// Updates information associated by the library with TPM entity handles upon
        /// successful completion of a command that either creates a new entity or
        /// changes the properties of an existing one.
        /// 
        /// Some important data associated with TPM entities cannot be retrieved from
        /// TPM either because of their sensitivity or because of substantial overhead.
        /// The information of the former kind is an auth value (for permanent handles,
        /// transient and persistent objects, NV indices) and a bound handle (for
        /// sessions). Information tracked for the sake of performance optimization
        /// is objects and NV index name.
        /// </summary>
        /// <param name="ordinal"></param>
        /// <param name="inParms"></param>
        /// <param name="inHandles"></param>
        // ReSharper disable once UnusedParameter.Local
        private void UpdateHandleData(TpmCc ordinal, TpmStructureBase inParms, TpmHandle[] inHandles, TpmStructureBase outParms)
        {
            switch (ordinal)
            {
                case TpmCc.Create:
                {
                    var req = (Tpm2CreateRequest)inParms;
                    var resp = (Tpm2CreateResponse)outParms;
                    TpmHash priv = TpmHash.FromData(PrivHashAlg, resp.outPrivate.buffer);
                    AuthValues[priv] = Globs.CopyData(req.inSensitive.userAuth);
                    break;
                }
                case TpmCc.CreatePrimary:
                {
                    var req = (Tpm2CreatePrimaryRequest)inParms;
                    var resp = (Tpm2CreatePrimaryResponse)outParms;
                    resp.objectHandle.Auth = req.inSensitive.userAuth;
                    ProcessName(resp.objectHandle, resp.name, resp.outPublic);
                    break;
                }
                case TpmCc.Load:
                {
                    var req = (Tpm2LoadRequest)inParms;
                    var resp = (Tpm2LoadResponse)outParms;
                    TpmHash priv = TpmHash.FromData(PrivHashAlg, req.inPrivate.buffer);
                    if (AuthValues.ContainsKey(priv))
                        resp.objectHandle.Auth = AuthValues[priv];
                    ProcessName(resp.objectHandle, resp.name, req.inPublic);
                    break;
                }
                case TpmCc.LoadExternal:
                {
                    var req = (Tpm2LoadExternalRequest)inParms;

                    if (req.inPublic.nameAlg != TpmAlgId.Null)
                    {
                        var resp = (Tpm2LoadExternalResponse)outParms;
                        byte[] name = req.inPublic.GetName();
                        ProcessName(resp.objectHandle, resp.name, req.inPublic);
                    }
                    break;
                }
                case TpmCc.StartAuthSession:
                {
                    var req = (Tpm2StartAuthSessionRequest)inParms;
                    var resp = (Tpm2StartAuthSessionResponse)outParms;
                    SessionParams[resp.sessionHandle] =
                            new AuthSession(req.sessionType, req.tpmKey, req.bind,
                                            req.nonceCaller, resp.nonceTPM,
                                            req.symmetric, req.authHash);
                    break;
                }
                case TpmCc.HmacStart:
                {
                    var req = (Tpm2HmacStartRequest)inParms;
                    var resp = (Tpm2HmacStartResponse)outParms;
                    resp.sequenceHandle.Auth = req.auth;
                    resp.sequenceHandle.Name = null;
                    break;
                }
                case TpmCc.NvDefineSpace:
                {
                    var req = (Tpm2NvDefineSpaceRequest)inParms;
                    req.publicInfo.nvIndex.Auth = req.auth;
                    req.publicInfo.nvIndex.Name = null;
                    break;
                }
                case TpmCc.NvChangeAuth:
                {
                    var req = (Tpm2NvChangeAuthRequest)inParms;
                    req.nvIndex.Auth = req.newAuth;
                    break;
                }
                case TpmCc.ObjectChangeAuth:
                {
                    var req = (Tpm2ObjectChangeAuthRequest)inParms;
                    var resp = (Tpm2ObjectChangeAuthResponse)outParms;
                    TpmHash priv = TpmHash.FromData(PrivHashAlg, resp.outPrivate.buffer);
                    AuthValues[priv] = Globs.CopyData(req.newAuth);
                    break;
                }
                case TpmCc.HierarchyChangeAuth:
                {
                    var req = (Tpm2HierarchyChangeAuthRequest)inParms;
                    AuthValue auth = Globs.CopyData(req.newAuth);
                    switch (req.authHandle.handle)
                    {
                        case (uint)TpmRh.Owner: OwnerAuth = auth; break;
                        case (uint)TpmRh.Endorsement: EndorsementAuth = auth; break;
                        case (uint)TpmRh.Platform: PlatformAuth = auth; break;
                        case (uint)TpmRh.Lockout: LockoutAuth = auth; break;
                    }
                    req.authHandle.Auth = auth;
                    break;
                }
                case TpmCc.PcrSetAuthValue:
                {
                    var req = (Tpm2PcrSetAuthValueRequest)inParms;
                    req.pcrHandle.Auth = req.auth;
                    if (PcrHandles == null)
                    {
                        PcrHandles = new TpmHandle[24];
                    }
                    int pcrId = (int)req.pcrHandle.GetOffset();
                    Debug.Assert(pcrId < PcrHandles.Length);
                    PcrHandles[pcrId] = req.pcrHandle;
                    break;
                }
                case TpmCc.EvictControl:
                {
                    var req = (Tpm2EvictControlRequest)inParms;
                    var resp = (Tpm2EvictControlResponse)outParms;
                    if (req.objectHandle.GetType() != Ht.Persistent)
                    {
                        req.persistentHandle.Auth = req.objectHandle.Auth;
                        req.persistentHandle.Name = req.objectHandle.Name;
                    }
                    break;
                }
                case TpmCc.Clear:
                {
                    OwnerAuth = new AuthValue();
                    EndorsementAuth = new AuthValue();
                    LockoutAuth = new AuthValue();
                    break;
                }
                case TpmCc.NvWrite:
                {
                    var req = (Tpm2NvWriteRequest)inParms;
                    // Force name recalculation before next use
                    req.nvIndex.Name = null;
                    break;
                }
                case TpmCc.NvWriteLock:
                {
                    var req = (Tpm2NvWriteLockRequest)inParms;
                    // Force name recalculation before next use
                    req.nvIndex.Name = null;
                    break;
                }
                case TpmCc.NvReadLock:
                {
                    var req = (Tpm2NvReadLockRequest)inParms;
                    // Force name recalculation before next use
                    req.nvIndex.Name = null;
                    break;
                }
                case TpmCc.HashSequenceStart:
                {
                    var req = (Tpm2HashSequenceStartRequest)inParms;
                    var resp = (Tpm2HashSequenceStartResponse)outParms;
                    resp.sequenceHandle.Auth = req.auth;
                    break;
                }
                case TpmCc.Startup:
                {
                    var req = (Tpm2StartupRequest)inParms;
                    if (req.startupType == Su.Clear)
                    {
                        PlatformAuth = new AuthValue();
                    }
                    break;
                }
                case TpmCc.ContextSave:
                {
                    var req = (Tpm2ContextSaveRequest)inParms;
                    var resp = (Tpm2ContextSaveResponse)outParms;
                    resp.context.savedHandle.Auth = req.saveHandle.Auth;
                    resp.context.savedHandle.Name = req.saveHandle.Name;
                    break;
                }
                case TpmCc.ContextLoad:
                {
                    var req = (Tpm2ContextLoadRequest)inParms;
                    var resp = (Tpm2ContextLoadResponse)outParms;
                    resp.loadedHandle.Auth = req.context.savedHandle.Auth;
                    resp.loadedHandle.Name = req.context.savedHandle.Name;
                    break;
                }
                case TpmCc.NvUndefineSpaceSpecial:
                {
                    var req = (Tpm2NvUndefineSpaceSpecialRequest)inParms;
                    req.nvIndex.Auth = null;
                    break;
                }
            }
        } // UpdateHandleData()

        /// <summary>
        /// The response hash includes the command ordinal, response code, and the actual command bytes.
        /// </summary>
        /// <param name="hashAlg"></param>
        /// <param name="commandCode"></param>
        /// <param name="responseCode"></param>
        /// <param name="responseParmsNoHandles"></param>
        /// <returns></returns>
        private byte[] GetExpectedResponseHash(
            TpmAlgId hashAlg,
            byte[] responseParmsNoHandles,
            TpmCc commandCode,
            TpmRc responseCode)
        {
            var temp = new Marshaller();
            temp.Put(responseCode, "responseCode");
            temp.Put(commandCode, "currentCommand");
            temp.Put(responseParmsNoHandles, null);

            byte[] parmsHash = CryptoLib.HashData(hashAlg, temp.GetBytes());
            return parmsHash;
        }

        private byte[] GetRandomBytes(int numBytes)
        {
            // todo - caller settable
            return Globs.GetRandomBytes(numBytes);
        }

        public void Dispose()
        { }

        /// <summary>
        /// Return a structure describing a command given a commandCode
        /// </summary>
        /// <param name="commandCode"></param>
        /// <returns></returns>
        public static CommandInfo CommandInfoFromCommandCode(TpmCc commandCode)
        {
            // TODO: faster lookup
            CommandInfo command = null;
            // ReSharper disable once LoopCanBeConvertedToQuery
            foreach (CommandInfo theInfo in CommandInformation.Info)
            {
                if (theInfo.CommandCode == commandCode)
                {
                    command = theInfo;
                    break;
                }
            }

            return command;
        }

        //public static bool IsTbsError(uint code)
        //{
            //var res = (TbsResult)code;
            //return res == TbsResult.TBS_E_BLOCKED
                   //|| res == TbsResult.TBS_E_INTERNAL_ERROR
                   //|| res == TbsResult.TBS_E_BAD_PARAMETER
                   //|| res == TbsResult.TBS_E_COMMAND_CANCELED;
        //}
    }

    // Only length prepended first-in or first-out parms can be encrypted.
    [Flags]
    public enum ParmCryptInfo
    {
        EncIn2 = 1,
        EncIn4 = 2,
        DecOut2 = 4,
        DecOut4 = 8
    }

    /// <summary>
    /// Information about a command derived from the specification
    /// </summary>
    public class CommandInfo
    {
        // TODO: add NumAuthHandles and USER/ADMIN auth requirements
        public CommandInfo(
            TpmCc theCode,
            uint inHandleCount,
            uint outHandleCount,
            uint inAuthHandleCount,
            Type inStructType,
            Type outStructType,
            uint parmCryptInfo,
            string origInputHandleTypes)
        {
            CommandCode = theCode;
            HandleCountIn = inHandleCount;
            HandleCountOut = outHandleCount;
            AuthHandleCountIn = inAuthHandleCount;
            InStructType = inStructType;
            OutStructType = outStructType;
            TheParmCryptInfo = (ParmCryptInfo)parmCryptInfo;
            InHandleOrigTypes = origInputHandleTypes;
        }

        public TpmCc CommandCode;
        public uint HandleCountIn;
        public uint AuthHandleCountIn;
        public uint HandleCountOut;
        public Type InStructType;
        public Type OutStructType;
        public ParmCryptInfo TheParmCryptInfo;
        public string InHandleOrigTypes;

        public override string ToString()
        {
            return CommandCode.ToString();
        }
    }

    public class CommandProcessor
    {
        /// <summary>
        /// Splits a TpmStructureBase command or response, and splits it into 
        /// handles and the parms data
        /// </summary>
        /// <param name="s"></param>
        /// <param name="numHandles"></param>
        /// <param name="handles"></param>
        /// <param name="parms"></param>
        public static void Fragment(TpmStructureBase s, uint numHandles, out TpmHandle[] handles, out byte[] parms)
        {
            handles = new TpmHandle[numHandles];
            // Get the handles (note we need to return the actual object because it contains the name.
            // The handles are always first, and will be simple fields or get/set props.
            MemberInfo[] fields;
            try
            {
                fields = s.GetType().GetMembers(BindingFlags.Public | BindingFlags.Instance);
            }
            catch (Exception)
            {
                throw;
            }

            int fieldPos = 0;
            for (int j = 0; j < numHandles; j++)
            {
                MemberInfo f;
                do
                {
                    // Ignore setters
                    f = fields[fieldPos++];
                } while (f.Name.StartsWith("set_"));
                // Either a simple field
                var ff = f as FieldInfo;
                if (ff != null)
                {
                    handles[j] = (TpmHandle)ff.GetValue(s);
                }
                // A get or set accessor
                var mm = f as MethodInfo;
                if (mm != null)
                {
                    object hRep = mm.Invoke(s, null);
                    handles[j] = hRep is TpmHandle ? (TpmHandle)hRep : ((TpmHandleX)hRep).Handle;
                }
            }
            // And the rest is the parms
            byte[] b = Marshaller.GetTpmRepresentation(s);
            parms = new byte[b.Length - numHandles * 4];
            Array.Copy(b, (int)numHandles * 4, parms, 0, b.Length - (int)numHandles * 4);
        }

        public static CrackedCommand CrackCommand(byte[] command)
        {

            var c = new CrackedCommand();
            bool success = CrackCommand(command, out c.Header, out c.Handles, out c.Sessions, out c.CommandParms);
            if (!success)
            {
                return null;
            }
            return c;
        }

        /// <summary>
        /// Opens a properly-formed TPM command stream into its constituent components.
        /// Note: commandParams does NOT include handles.
        /// </summary>
        /// <param name="command"></param>
        /// <param name="header"></param>
        /// <param name="handles"></param>
        /// <param name="sessions"></param>
        /// <param name="commandParms"></param>
        public static bool CrackCommand(
            byte[] command,
            out CommandHeader header,
            out TpmHandle[] handles,
            out SessionIn[] sessions,
            out byte[] commandParms)
        {
            var m = new Marshaller(command);
            header = m.Get<CommandHeader>();
            CommandInfo commandInfo = Tpm2.CommandInfoFromCommandCode(header.CommandCode);
            if (header.Tag == TpmSt.Null)
            {
                // A diagnostics command. Pass through unmodified
                handles = null;
                sessions = null;
                commandParms = null;
                return false;
            }
            handles = new TpmHandle[commandInfo.HandleCountIn];
            for (int j = 0; j < handles.Length; j++)
            {
                handles[j] = m.Get<TpmHandle>();
            }
            // Note sessions are only present if the command tag indicates sessions
            if (header.Tag == TpmSt.Sessions)
            {
                uint sessionLength = m.Get<uint>();
                uint sessionStart = m.GetGetPos();
                uint sessionEnd = sessionStart + sessionLength;
                // if bytes between m.GetGetPos() and sessionEnd are all 0xAA this is
                // a censored session.
                byte[] sessionArray = m.GetNBytes((int)sessionLength);
                if (Array.TrueForAll<byte>(sessionArray, element => { return element == 0xAA; }))
                {
                    // yes, censored buffer, try to replace with intelligent guess
                    // authorization field consist of:
                    //  TPM20_HANDLE Handle;  // authHandle: TPM_RH_PW
                    //  UINT16 Nonce2B;       // TPM2B_NONCE
                    //  UINT8 Session;        // TPMA_SESSION
                    //  UINT16 Auth2B;        // TPM2B_AUTH
                    // to make intelligent guess about size of nonce and auth,
                    // subtract constant sized field (9 bytes). Nonce is usually
                    // a hash, so it should be either 20, 32, 48, or 64 bytes.
                    // the auth value would make up the rest, but also usually
                    // be the result of a hash operation.
                    sessionLength = sessionLength - sizeof(uint) - sizeof(ushort) - sizeof(byte) - sizeof(ushort);
                    ushort nonceSize;
                    if (sessionLength/2 == TpmHash.DigestSize(TpmAlgId.Sha1) ||
                        sessionLength/2 == TpmHash.DigestSize(TpmAlgId.Sha256) ||
                        sessionLength/2 == TpmHash.DigestSize(TpmAlgId.Sha384) ||
                        sessionLength/2 == TpmHash.DigestSize(TpmAlgId.Sha512))
                    {
                        nonceSize = (ushort)(sessionLength / 2);
                    }
                    else if (sessionLength >= TpmHash.DigestSize(TpmAlgId.Sha512))
                    {
                        nonceSize = TpmHash.DigestSize(TpmAlgId.Sha512);
                    }
                    else if (sessionLength >= TpmHash.DigestSize(TpmAlgId.Sha384))
                    {
                        nonceSize = TpmHash.DigestSize(TpmAlgId.Sha384);
                    }
                    else if (sessionLength >= TpmHash.DigestSize(TpmAlgId.Sha256))
                    {
                        nonceSize = TpmHash.DigestSize(TpmAlgId.Sha256);
                    }
                    else if (sessionLength >= TpmHash.DigestSize(TpmAlgId.Sha1))
                    {
                        nonceSize = TpmHash.DigestSize(TpmAlgId.Sha1);
                    }
                    else
                    {
                        // 0 <= sessionLength < size of SHA1 digest
                        nonceSize = (ushort)sessionLength;
                    }
                    // marshal nonceSize
                    sessionArray[4] = (byte)nonceSize;
                    sessionArray[5] = (byte)(nonceSize >> 8);
                    // marshall session
                    int sessionOffset = sizeof(uint) + sizeof(ushort) + nonceSize;
                    sessionArray[sessionOffset] = 0;
                    // marshall authSize
                    ushort authSize = (ushort)(sessionLength - nonceSize);
                    sessionArray[sessionOffset + 1] = (byte)authSize;
                    sessionArray[sessionOffset + 2] = (byte)(authSize >> 8);

                    m.SetBytes(sessionArray, sessionStart);
                }
                m.SetGetPos(sessionStart);
                var inSessions = new List<SessionIn>();
                while (m.GetGetPos() < sessionEnd)
                {
                    var s = m.Get<SessionIn>();
                    inSessions.Add(s);
                }
                sessions = inSessions.ToArray();
            }
            else
            {
                sessions = new SessionIn[0];
            }
            // And finally parameters
            commandParms = m.GetArray<byte>((int)(m.GetValidLength() - m.GetGetPos()));
            if (m.GetValidLength() != header.CommandSize)
            {
                Globs.Throw("Command length in header does not match input byte-stream");
                return false;
            }
            return true;
        }

        /// <summary>
        /// Create a TPM command byte stream from constituent components
        /// </summary>
        /// <param name="commandCode"></param>
        /// <param name="handles"></param>
        /// <param name="sessions"></param>
        /// <param name="parmsWithoutHandles"></param>
        /// <returns></returns>
        public static byte[] CreateCommand(
            TpmCc commandCode,
            TpmHandle[] handles,
            SessionIn[] sessions,
            byte[] parmsWithoutHandles)
        {

            // ReSharper disable once UnusedVariable
            CommandInfo commandInfo = Tpm2.CommandInfoFromCommandCode(commandCode);

            var m = new Marshaller();
            TpmSt tag = sessions.Length == 0 ? TpmSt.NoSessions : TpmSt.Sessions;
            m.Put(tag, "tag");
            m.PushLength(4);
            m.Put(commandCode, "commandCode");
            foreach (TpmHandle h in handles)
            {
                m.Put(h, "handle");
            }

            if (tag == TpmSt.Sessions)
            {
                var m2 = new Marshaller();
                foreach (SessionIn s in sessions)
                {
                    m2.Put(s, "session");
                }
                m.PutUintPrependedArray(m2.GetBytes(), "sessions");
            }

            m.Put(parmsWithoutHandles, "parms");

            m.PopAndSetLengthToTotalLength();
            return m.GetBytes();
        }

        public static ResponseInfo SplitResponse(byte[] response, uint numHandles)
        {
            var r = new ResponseInfo();
            SplitResponse(response,
                          numHandles,
                          out r.Tag,
                          out r.ParamSize,
                          out r.ResponseCode,
                          out r.Handles,
                          out r.Sessions,
                          out r.ResponseParmsNoHandles,
                          out r.ResponseParmsWithHandles);
            return r;
        }

        public static void SplitResponse(
            byte[] response,
            uint numHandles,
            out TpmSt tag,
            out uint paramSize,
            out TpmRc responseCode,
            out TpmHandle[] handles,
            out SessionOut[] sessions,
            out byte[] responseParmsNoHandles,
            out byte[] responseParmsWithHandles)
        {
            var m = new Marshaller(response);
            tag = m.Get<TpmSt>();
            paramSize = m.Get<uint>();
            responseCode = m.Get<TpmRc>();
            // If error we only get the header
            if (responseCode != TpmRc.Success)
            {
                handles = new TpmHandle[0];
                sessions = new SessionOut[0];
                responseParmsNoHandles = new byte[0];
                responseParmsWithHandles = new byte[0];
                return;
            }

            handles = new TpmHandle[numHandles];
            for (int j = 0; j < numHandles; j++)
            {
                handles[j] = m.Get<TpmHandle>();
            }
            uint parmsEnd = m.GetValidLength();
            if (tag == TpmSt.Sessions)
            {
                var sessionOffset = m.Get<uint>();
                uint startOfParmsX = m.GetGetPos();
                parmsEnd = startOfParmsX + sessionOffset;
                m.SetGetPos(parmsEnd);
                var sessX = new List<SessionOut>();
                while (m.GetGetPos() < m.GetValidLength())
                {
                    var s = m.Get<SessionOut>();
                    sessX.Add(s);
                }
                sessions = sessX.ToArray();
                m.SetGetPos(startOfParmsX);
            }
            else
            {
                sessions = new SessionOut[0];
            }

            uint startOfParms = m.GetGetPos();
            uint parmsLength = parmsEnd - m.GetGetPos();

            // Get the response buf with no handles
            responseParmsNoHandles = new byte[parmsLength];
            Array.Copy(response, (int)startOfParms, responseParmsNoHandles, 0, (int)parmsLength);

            // Get the response buf with handles
            responseParmsWithHandles = new byte[parmsLength + numHandles * 4];
            Array.Copy(response, 10, responseParmsWithHandles, 0, (int)numHandles * 4);
            Array.Copy(response, (int)startOfParms, responseParmsWithHandles, (int)numHandles * 4, (int)parmsLength);
        }

        public static byte[] CreateResponse(
            TpmRc responseCode,
            TpmHandle[] handles,
            SessionOut[] sessions,
            byte[] responseParmsNoHandles)
        {
            var m = new Marshaller();
            TpmSt tag = sessions.Length == 0 ? TpmSt.NoSessions : TpmSt.Sessions;

            m.Put(tag, "tag");
            m.PushLength(4);
            m.Put(responseCode, "responseCode");

            foreach (TpmHandle h in handles)
            {
                m.Put(h, "handle");
            }

            if (tag == TpmSt.Sessions)
            {
                m.Put((uint)responseParmsNoHandles.Length, "parmsLenght");
            }

            m.Put(responseParmsNoHandles, "parms");
            foreach (SessionOut s in sessions)
                m.Put(s, "session");
            m.PopAndSetLengthToTotalLength();
            return m.GetBytes();
        }

        public static string ParseCommand(byte[] buf)
        {
            CommandHeader commandHeader;
            TpmHandle[] inHandles;
            SessionIn[] inSessions;
            byte[] commandParmsNoHandles;
            string response = "";

            bool ok = CrackCommand(buf, out commandHeader, out inHandles, out inSessions, out commandParmsNoHandles);
            if (!ok)
            {
                response = "The TPM command is not properly formatted.  Doing the best I can...\n";
            }
            CommandInfo command = Tpm2.CommandInfoFromCommandCode(commandHeader.CommandCode);
            if (command == null)
            {
                response += String.Format("The command-code {0} is not defined.  Aborting\n", commandHeader.CommandCode);
                return response;
            }
            response += "Header:\n";
            response += commandHeader + "\n";

            var m2 = new Marshaller();
            foreach (TpmHandle h in inHandles)
            {
                m2.Put(h, "");
            }

            byte[] commandParmsWithHandles = Globs.Concatenate(new[] {m2.GetBytes(), commandParmsNoHandles});
            var m = new Marshaller(commandParmsWithHandles);
            object inParms = m.Get(command.InStructType, "");
            response += "Command Parameters:\n";
            response += inParms + "\n";
            response += "Sessions [" + inSessions.Length + "]\n";
            for (int j = 0; j < inSessions.Length; j++)
            {
                // ReSharper disable once FormatStringProblem
                response += String.Format("{0}: 0x{1:x}\n", j, inSessions[j]);
            }
            return response;
        }

        public static TpmRc GetResponseCode(byte[] response)
        {
            if (response.Length > 10)
                return TpmRc.Success;

            var m = new Marshaller(response);
            // ReSharper disable once UnusedVariable
            var tag = m.Get<TpmSt>();
            // ReSharper disable once UnusedVariable
            var paramSize = m.Get<uint>();
            var responseCode = m.Get<TpmRc>();
            TpmRc maskedResponse = Tpm2.GetBaseErrorCode(responseCode);
            return maskedResponse;

        }

        public static string ParseResponse(string commandCode, byte[] buf)
        {
            TpmHandle[] outHandles;
            SessionOut[] outSessions;
            byte[] responseParmsNoHandles;
            byte[] responseParmsWithHandles;
            string response = "";
            if (1 != CommandInformation.Info.Count(item => item.CommandCode.ToString() == commandCode))
            {
                response = "Command code not recognized.  Defined command codes are:\n";
                // ReSharper disable once LoopCanBeConvertedToQuery
                foreach (CommandInfo info in CommandInformation.Info)
                {
                    response += info.CommandCode.ToString() + " ";
                }
                return response;
            }

            CommandInfo command = CommandInformation.Info.First(item => item.CommandCode.ToString() == commandCode);
            TpmSt tag;
            uint paramSize;
            TpmRc responseCode;

            SplitResponse(buf,
                          command.HandleCountOut,
                          out tag,
                          out paramSize,
                          out responseCode,
                          out outHandles,
                          out outSessions,
                          out responseParmsNoHandles,
                          out responseParmsWithHandles);
            if (responseCode != TpmRc.Success)
            {
                TpmRc resultCode;
                response += "Error:\n";
                response += Tpm2.GetErrorString(command.InStructType, (uint)responseCode, out resultCode);
                return response;
            }

            // At this point in the processing stack we cannot deal with encrypted responses
            bool responseIsEncrypted = false;
            foreach (SessionOut s in outSessions)
            {
                if (s.attributes.HasFlag(SessionAttr.Encrypt)
                    &&
                    (command.TheParmCryptInfo.HasFlag(ParmCryptInfo.DecOut2) ||
                     command.TheParmCryptInfo.HasFlag(ParmCryptInfo.DecOut2))
                    )
                    responseIsEncrypted = true;
            }

            response += "Response Header:\n";
            response += "    Tag=" + tag.ToString() + "\n";
            response += "    Response code=" + responseCode.ToString() + "\n";

            response += "Response Parameters:\n";
            if (!responseIsEncrypted)
            {
                var m2 = new Marshaller(responseParmsWithHandles);
                Object inParms = m2.Get(command.OutStructType, "");
                response += inParms + "\n";
            }
            else
            {
                var m2 = new Marshaller(responseParmsWithHandles);
                Object encOutParms = null;
                switch (command.TheParmCryptInfo)
                {
                    // TODO: this is not the right type if we ever do size-checks
                    case ParmCryptInfo.DecOut2:
                        encOutParms = m2.Get(typeof (Tpm2bMaxBuffer), "");
                        break;
                    default:
                        Globs.Throw<NotImplementedException>("NOT IMPLEMENTED");
                        break;
                }
                response += "Encrypted: " + encOutParms + "\n";
            }

            response += "Sessions [" + outSessions.Length + "]\n";
            for (int j = 0; j < outSessions.Length; j++)
            {
                // ReSharper disable once FormatStringProblem
                response += String.Format("{0}: 0x{1:x}\n", j, outSessions[j]);
            }
            return response;
        }

        public static string CleanHex(string s)
        {
            // split into lines
            string[] lines = s.Split(new[] { '\n', '\r' });
            List<string> nonEmptyLines = new List<string>();
            foreach (string line in lines)
            {
                // if line ended with "\r\n", empty line is created, eliminate those
                if (string.IsNullOrEmpty(line))
                    continue;

                // replace each character that cannot be interpreted as hexadecimal
                // number with a space.
                string allowedChars = "0123456789abcdefABCDEF ";
                char[] lineChars = line.ToCharArray();
                for (int index = 0; index < lineChars.Length; index++)
                {
                    if (!allowedChars.Contains(lineChars[index]))
                    {
                        lineChars[index] = ' ';
                    }
                }
                string hexLine = new string(lineChars);
                nonEmptyLines.Add(hexLine.Trim());
            }

            // lines may start with an index, which is a hexadecimal number
            // that number increases in each line and should be the count of all
            // other hexadecimal characters (except the index).
            List<uint> indices = new List<uint>();
            List<uint> remainingHexCharacters = new List<uint>();
            bool haveIndices = true;
            foreach (string line in nonEmptyLines)
            {
                string[] lineSegments = line.Split(new[] { ' ' });
                bool first = true;
                int segmentCount = 0;
                int characterCount = 0;
                foreach (string segment in lineSegments)
                {
                    if (string.IsNullOrEmpty(segment))
                        continue;

                    segmentCount++;

                    if (first)
                    {
                        uint index;
                        if (UInt32.TryParse(segment, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out index))
                        {
                            indices.Add(index);
                        }
                        first = false;
                    }
                    else
                    {
                        characterCount += segment.Length;
                    }
                }
                if (segmentCount > 1)
                {
                    remainingHexCharacters.Add((uint)characterCount);
                }
                else
                {
                    // a line with indices has at least 2 segments: the index
                    // and the hexadecimal numbers
                    haveIndices = false;
                    break;
                }
            }

            if (haveIndices)
            {
                if (indices.Count != remainingHexCharacters.Count)
                    haveIndices = false;
            }
            if (haveIndices)
            {
                // if only one line, stop checking
                if (indices.Count < 2)
                    haveIndices = false;
            }
            if (haveIndices)
            {
                // check if indices are equally spaced
                uint step = indices[1] - indices[0];
                for (int currentLine = 2;
                     haveIndices && (currentLine < indices.Count);
                     currentLine++)
                {
                    if (step != (indices[currentLine] - indices[currentLine - 1]))
                        haveIndices = false;
                }
            }
            if (haveIndices)
            {
                // check if count of numbers after indices match
                uint expectedIndex = 0;
                for (int currentLine = 0;
                     haveIndices && (currentLine < indices.Count);
                     currentLine++)
                {
                    // there may be extra characters beyond the hexadecimal
                    // numbers. They are currently counted as if they are 
                    // hexadecimal numbers. That's why the test is only for
                    // greater than, not for strict inequality.
                    if (indices[currentLine] > expectedIndex)
                    {
                        haveIndices = false;
                        break;
                    }

                    // the index field would indicate number of bytes. For each byte
                    // two hexadecimal characters are printed. Divide characterCount before
                    // recording. Also add counted bytes to current index to keep error
                    // small.
                    expectedIndex = indices[currentLine] + remainingHexCharacters[currentLine] / 2;
                }
            }

            string retVal = "";
            if (haveIndices)
            {
                // when aggregating lines with indices, leave out any extra
                // hexadecimal numbers at the end of the line.
                int currentLine = 0;
                foreach (string line in nonEmptyLines)
                {
                    string[] lineSegments = line.Split(new[] { ' ' });

                    foreach (string segment in lineSegments.Skip(1))
                    {
                        if (string.IsNullOrEmpty(segment))
                            continue;

                        // do not divide segment.Length by 2, or segments of size 1 don't have
                        // a size.
                        if ((currentLine < nonEmptyLines.Count - 1) &&
                            (retVal.Length + segment.Length <= indices[currentLine + 1] * 2))
                        {
                            retVal += segment;
                        }
                        else if (currentLine == nonEmptyLines.Count - 1)
                        {
                            // add all segments for last line
                            retVal += segment;
                        }
                    }

                    currentLine++;
                }
            }
            else
            {
                foreach (string line in nonEmptyLines)
                    retVal += string.Join("", line.Split(new[] { ' ' }));
            }

            // Stick it back together
            return retVal;
        }

        /// <summary>
        /// Interpret a HEX command string into a parsed command.  
        /// </summary>
        /// <param name="s"></param>
        public static string ParseCommand(string s)
        {
            s = CleanHex(s);
            byte[] commandBytes = Globs.ByteArrayFromHex(s);
            return ParseCommand(commandBytes);
        }

        /// <summary>
        /// Interpret a HEX command string into a parsed command.  
        /// </summary>
        /// <param name="commandName"></param>
        /// <param name="s"></param>
        public static string ParseResponse(string commandName, string s)
        {
            s = CleanHex(s);
            byte[] commandBytes = Globs.ByteArrayFromHex(s);
            return ParseResponse(commandName, commandBytes);
        }

    }

    public class ResponseInfo
    {
        public TpmSt Tag;
        public uint ParamSize;
        public TpmRc ResponseCode;
        public TpmHandle[] Handles;
        public SessionOut[] Sessions;
        public byte[] ResponseParmsNoHandles;
        public byte[] ResponseParmsWithHandles;
    }

    public class CrackedCommand
    {
        public CommandHeader Header;
        public TpmHandle[] Handles;
        public SessionIn[] Sessions;
        public byte[] CommandParms;
    }

    public class CommandModifier
    {
        public byte ActiveLocality = 0;
    }
}
