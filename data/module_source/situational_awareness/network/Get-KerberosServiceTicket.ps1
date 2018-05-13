Function Get-KerberosServiceTicket {
<#
.SYNOPSIS

    Retrieves IP addresses and usernames using event ID 4769 this can allow identification of a users machine. Can only run on a domain controller.

    Author: Liam Glanfield (@OneLogicalMyth)
    Required Dependencies: None
    Optional Dependencies: None
    Version: 18.3.14.0
 
.DESCRIPTION

    Get-KerberosServiceTicket searches the windows event for event ID 4769. This event marks the initial logons through the granting of TGTs. Service tickets are obtained whenever a user or computer accesses a server on the network and as such can help locate a potential IP address for an individual of interest.

.EXAMPLE

    PS C:\> Get-KerberosServiceTicket -MaxEvents 200

    Returns the first 200 records relating to event ID 4769.

.EXAMPLE

    PS C:\> Get-KerberosServiceTicket -UserName liam@domain.local
    
    Returns all unique IP addresses for the user liam@domain.local.

.LINK
    
    https://github.com/OneLogicalMyth/Empire
    https://www.sans.org/reading-room/whitepapers/forensics/windows-logon-forensics-34132
#>
    
    [CmdletBinding()]
	param([string]$UserName=$null,[int]$MaxEvents=1000,[bool]$ExcludeComputers=$true)

    #Check if username is in the right format
    if(-not [System.String]::IsNullOrEmpty($UserName))
    {
	    if($UserName -notlike '*@*')
	    {
	        throw 'UserName is in the incorrect format, please use "username@domainfqdn.local"'
	    }
    }

    #Check if this computer is a domain controller
    $DomainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
    if($DomainRole -lt 4)
    {
	    throw 'Unable to continue this is not a domain controller.'
    }

    #Check if this is Windows Server 2008 or higher
    $WindowsVista = [System.Version]'6.0'
    $OS           = Get-WmiObject win32_operatingsystem
    $OSVersion    = [Version]$OS.Version
    if ($OSVersion.CompareTo($WindowsVista) -lt 0)
    {
	    throw 'Unable to continue Windows Server 2008 or higher is only supported.'
    }


	#Build filter to only output logon events in the last 24 hours
    $XMLFilter = @"
<QueryList>
    <Query Id="0" Path="Security">
        <Select Path="Security">
            *[System[(EventID=4769)]]
$(if(-not [System.String]::IsNullOrEmpty($UserName)){'	            and'})
$(if(-not [System.String]::IsNullOrEmpty($UserName)){"            *[EventData[Data[@Name=`"TargetUserName`"]='$UserName']]"})
        </Select>
    </Query>
</QueryList>
"@

	 $Results = Get-WinEvent -FilterXml $XMLFilter -MaxEvents $MaxEvents | ForEach-Object {

		$Event = $_

		$EventDateTime  = $Event.TimeCreated
		$EventXML       = [XML]$Event.ToXML()
		$EventData      = $EventXML.Event.EventData.Data
						
		$UName       = $EventData[0].'#text'
		$IPAddress      = $EventData[6].'#text'.Replace('::ffff:','')

        #Clean up the event time so that it can be made unique
        $EventDateTime = $EventDateTime.ToString()
        					
		$Result = New-Object PSObject
		$Result | Add-Member NoteProperty UserName $UName
		$Result | Add-Member NoteProperty IPAddress $IPAddress
		$Result | Add-Member NoteProperty DateTime $EventDateTime

		$Result

	}

    if($ExcludeComputers)
    {
        $Results | Where-Object { $_.UserName -notlike '*$@*' } | Sort-Object DateTime -Descending | Select-Object -Property * -Unique
    }else{
        $Results | Sort-Object DateTime -Descending | Select-Object -Property * -Unique
    }
    

}