function Invoke-Paranoia {
    param(
        [String[]] $watchUsers,
        [String[]] $watchProcesses,
        [String[]] $watchGroups

    )

    $defaultprocesses = @("taskmgr.exe", "mmc.exe", "wireshark.exe", "tcpview.exe", "procdump.exe", "procexp.exe", "procmon.exe", "netstat.exe", "psloggedon.exe", "logonsessions.exe", "processhacker.exe", "autoruns.exe", "autorunsc.exe")
    $watchProcesses = $watchProcesses + $defaultprocesses
    $defaultgroups = @("Domain Admins")
    $watchGroups = $watchGroups + $defaultgroups
    $groups_members = @{}

    function get_groupmembers {
        param([String[]] $groups)

        $root=([ADSI]"").distinguishedName
        $enumd_groups = @{}
        $groups | foreach {
            $to_search = $_
            $enumd_groups.Add($to_search, @())
            $group = [ADSI]("LDAP://CN=" + $to_search + ", CN=Users,$root")
            $group.member|foreach {
                $enumd_groups[$to_search] += $_.split(",")[0].split("=")[1]
            }
        }
        return $enumd_groups
    }
    
    function process_proc {
        param($proc,$group_members)
        $userdom = ($proc.getOwner().Domain + "\" + $proc.getOwner().User).tolower()
        $watchUsers | foreach {
            if ($userdom -eq $_.tolower()) {
                "USER_DETECTED: $userdom : "+ $proc.name + "`n"
            }
            if ($proc.getOwner().Domain.tolower() -eq  $env:COMPUTERNAME -and $proc.getOwner().User.tolower() -eq $_) {
                "USER_DETECTED_LOCAL: $userdom : "+ $proc.name + "`n"
            }
        }
        foreach ($group in $group_members.keys) {
            foreach ($user in $group_members[$group]) {
                if ($proc.getOwner().User.tolower() -eq $user.tolower() -and $proc.getOwner().Domain -ne $env:COMPUTERNAME) {
                    "USER_DETECTED_GROUP: $userdom : $group :" + $proc.name + "`n"
                }
            }
        }
        $watchProcesses | foreach {
            if($proc.name.tolower() -eq $_.tolower()) {
                "PROCESS_DETECTED: $userdom : " + $proc.name + "`n"
            }
        }
        Get-WmiObject Win32_LogicalDisk | Where-Object {($_.DriveType -eq 2) -and ($_.DeviceID -ne 'A:')} | %{
            if( ($proc.path.split(":")[0]+":").tolower() -eq $_.DeviceID) {
                "USB_PROCESS_DETECTED: " + $proc.path  + "`n"
            }
        }
    }

    $groups_members = get_groupmembers $watchGroups

    # Main loop
    while($True) {
        Sleep 3
        Get-WmiObject win32_process | %{
            process_proc -proc $_ -group_members $groups_members
        }
    }
}
