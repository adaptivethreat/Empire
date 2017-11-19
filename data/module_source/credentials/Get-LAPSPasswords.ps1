function Get-LAPSPasswords
{
    <#
        .Synopsis
           This module will query Active Directory for the hostname, LAPS (local administrator) stored password, 
		   and password expiration for each computer account.
        .DESCRIPTION
           This module will query Active Directory for the hostname, LAPS (local administrator) stored password, 
		   and password expiration for each computer account. The script filters out disabled domain computers. 
		   LAPS password storage can be identified by querying the (domain user available) ms-MCS-AdmPwdExpirationTime 
		   attribute. If the attribute (timestamp) exists, LAPS is in use for local administrator passwords. Access to
		   ms-MCS-AdmPwd attribute should be restricted to privileged accounts.  Also, since the script uses data tables 
		   to output affected systems the results can be easily piped to other commands such as test-connection or a Export-Csv.
        .EXAMPLE
           The example below shows the standard command usage. Disabled system are excluded by default. If your user doesn't
		   have the rights to read the password, then it will show 0 for Readable.
		   PS C:\> Get-LAPSPasswords -DomainController 192.168.1.1 -Credential demo.com\administrator | Format-Table -AutoSize
           
           Hostname                    Stored Readable Password       Expiration         
		   --------                    ------ -------- --------       ----------         
		   WIN-M8V16OTGIIN.test.domain 0      0                       NA                 
		   WIN-M8V16OTGIIN.test.domain 0      0                       NA                 
		   ASSESS-WIN7-TES.test.domain 1      1        $sl+xbZz2&qtDr 6/3/2015 7:09:28 PM                  
        .EXAMPLE
           The example below shows how to write the output to a csv file.
           PS C:\> Get-LAPSPasswords -DomainController 192.168.1.1 -Credential demo.com\administrator | Export-Csv c:\temp\output.csv -NoTypeInformation
        .LINK
           https://blog.netspi.com/running-laps-around-cleartext-passwords/
           https://github.com/kfosaaen/Get-LAPSPasswords
		   https://technet.microsoft.com/en-us/library/security/3062591
           
        .NOTES
           Author: Karl Fosaaen - 2015, NetSPI
           Version: Get-LAPSPasswords.psm1 v1.0
           Comments: The technique used to query LDAP was based on the "Get-AuditDSComputerAccount" 
           function found in Carlos Perez's PoshSec-Mod project.  The general idea is based off of  
           a Twitter conversation with @_wald0. The bones of this were borrowed (with permission) from 
		   Scott Sutherland's Get-ExploitableSystems function.
    
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Credentials to use when connecting to a Domain Controller.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$DomainController,

        [Parameter(Mandatory=$false,
        HelpMessage="Maximum number of Objects to pull from AD, limit is 1,000.")]
        [int]$Limit = 1000,

        [Parameter(Mandatory=$false,
        HelpMessage="scope of a search as either a base, one-level, or subtree search, default is subtree.")]
        [ValidateSet("Subtree","OneLevel","Base")]
        [string]$SearchScope = "Subtree",

        [Parameter(Mandatory=$false,
        HelpMessage="Distinguished Name Path to limit search to.")]

        [string]$SearchDN
    )
    Begin
    {
        if ($DomainController -and $Credential.GetNetworkCredential().Password)
        {
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)", $Credential.UserName,$Credential.GetNetworkCredential().Password
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
        else
        {
            $objDomain = [ADSI]""  
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
    }

    Process
    {
        # Status user
        Write-Verbose "[*] Grabbing computer accounts from Active Directory..."

        # Create data table for hostnames, and passwords from LDAP
        $TableAdsComputers = New-Object System.Data.DataTable 
        $TableAdsComputers.Columns.Add('Hostname') | Out-Null
        $TableAdsComputers.Columns.Add('Stored') | Out-Null
        $TableAdsComputers.Columns.Add('Readable') | Out-Null
        $TableAdsComputers.Columns.Add('Password') | Out-Null
        $TableAdsComputers.Columns.Add('Expiration') | Out-Null

        # ----------------------------------------------------------------
        # Grab computer account information from Active Directory via LDAP
        # ----------------------------------------------------------------
        $CompFilter = "(&(objectCategory=Computer))"
        $ObjSearcher.PageSize = $Limit
        $ObjSearcher.Filter = $CompFilter
        $ObjSearcher.SearchScope = "Subtree"

        if ($SearchDN)
        {
            $objSearcher.SearchDN = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($SearchDN)")
        }

        $ObjSearcher.FindAll() | ForEach-Object {

            # Setup fields
            $CurrentHost = $($_.properties['dnshostname'])
            $CurrentUac = $($_.properties['useraccountcontrol'])
			$CurrentPassword = $($_.properties['ms-MCS-AdmPwd'])
            if ($_.properties['ms-MCS-AdmPwdExpirationTime'] -ge 0){$CurrentExpiration = $([datetime]::FromFileTime([convert]::ToInt64($_.properties['ms-MCS-AdmPwdExpirationTime'],10)))}
            else{$CurrentExpiration = "NA"}
                        
            $PasswordAvailable = 0
            $PasswordStored = 1

            # Convert useraccountcontrol to binary so flags can be checked
            # http://support.microsoft.com/en-us/kb/305144
            # http://blogs.technet.com/b/askpfeplat/archive/2014/01/15/understanding-the-useraccountcontrol-attribute-in-active-directory.aspx
            $CurrentUacBin = [convert]::ToString($CurrentUac,2)

            # Check the 2nd to last value to determine if its disabled
            $DisableOffset = $CurrentUacBin.Length - 2
            $CurrentDisabled = $CurrentUacBin.Substring($DisableOffset,1)

            # Set flag if stored password is not available
            if ($CurrentExpiration -eq "NA"){$PasswordStored = 0}


            if ($CurrentPassword.length -ge 1){$PasswordAvailable = 1}


            # Add computer to list if it's enabled
            if ($CurrentDisabled  -eq 0){
                # Add domain computer to data table
                $TableAdsComputers.Rows.Add($CurrentHost,$PasswordStored,$PasswordAvailable,$CurrentPassword, $CurrentExpiration) | Out-Null
            }

            # Display results
            $TableAdsComputers | Sort-Object {$_.Hostname} -Descending
         }
    }
    End
    {
    }
}