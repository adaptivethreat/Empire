function Get-BrowserInformation {
<#
    .SYNOPSIS

        Dumps Browser Information
        Author: @424f424f
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Enumerates browser history or bookmarks for a Chrome, Internet Explorer,
        and/or Firefox browsers on Windows machines.

    .PARAMETER Browser

        The type of browser to enumerate, 'Chrome', 'IE', 'Firefox' or 'All'

    .PARAMETER Datatype

        Type of data to enumerate, 'History' or 'Bookmarks'

    .PARAMETER UserName

        Specific username to search browser information for.

    .PARAMETER Search

        Term to search for

    .EXAMPLE

        PS C:\> Get-BrowserInformation

        Enumerates browser information for all supported browsers for all current users.

    .EXAMPLE

        PS C:\> Get-BrowserInformation -Browser IE -Datatype Bookmarks -UserName user1

        Enumerates bookmarks for Internet Explorer for the user 'user1'.

    .EXAMPLE

        PS C:\> Get-BrowserInformation -Browser All -Datatype History -UserName user1 -Search 'github'

        Enumerates bookmarks for Internet Explorer for the user 'user1' and only returns
        results matching the search term 'github'.
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(Position = 0)]
        [String[]]
        [ValidateSet('Chrome','IE','FireFox', 'All')]
        $Browser = 'All',

        [Parameter(Position = 1)]
        [String[]]
        [ValidateSet('History','Bookmarks','All')]
        $DataType = 'All',

        [Parameter(Position = 2)]
        [String]
        $UserName = '',

        [Parameter(Position = 3)]
        [String]
        $Search = ''
    )



    function ConvertFrom-Json20([object] $item){
        #http://stackoverflow.com/a/29689642
        Add-Type -AssemblyName System.Web.Extensions
        $ps_js = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        return ,$ps_js.DeserializeObject($item)
        
    }

    function Get-ChromeHistory {
        $Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History"
        if (-not (Test-Path -Path $Path)) {
            Write-Verbose "[!] Could not find Chrome History for username: $UserName"
        }
        $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
        $Value = Get-Content -Path "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History"|Select-String -AllMatches $regex |% {($_.Matches).Value} |Sort -Unique
        $Value | ForEach-Object {
            $Key = $_
            if ($Key -match $Search){
                New-Object -TypeName PSObject -Property @{
                    User = $UserName
                    Browser = 'Chrome'
                    DataType = 'History'
                    Data = $_
                }
            }
        }        
    }

    function Get-ChromeBookmarks {
    $Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
    if (-not (Test-Path -Path $Path)) {
        Write-Verbose "[!] Could not find FireFox Bookmarks for username: $UserName"
    }   else {
            $Json = Get-Content $Path
            $Output = ConvertFrom-Json20($Json)
            $Jsonobject = $Output.roots.bookmark_bar.children
            $Jsonobject.url |Sort -Unique | ForEach-Object {
                if ($_ -match $Search) {
                    New-Object -TypeName PSObject -Property @{
                        User = $UserName
                        Browser = 'Firefox'
                        DataType = 'Bookmark'
                        Data = $_
                    }
                }
            }
        }
    }

    function Get-InternetExplorerHistory {
        #https://crucialsecurityblog.harris.com/2011/03/14/typedurls-part-1/

        $Null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
        $Paths = Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

        ForEach($Path in $Paths) {

            $User = ([System.Security.Principal.SecurityIdentifier] $Path.PSChildName).Translate( [System.Security.Principal.NTAccount]) | Select -ExpandProperty Value

            $Path = $Path | Select-Object -ExpandProperty PSPath

            $UserPath = "$Path\Software\Microsoft\Internet Explorer\TypedURLs"
            if (-not (Test-Path -Path $UserPath)) {
                Write-Verbose "[!] Could not find IE History for SID: $Path"
            }
            else {
                Get-Item -Path $UserPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $Key = $_
                    $Key.GetValueNames() | ForEach-Object {
                        $Value = $Key.GetValue($_)
                        if ($Value -match $Search) {
                            New-Object -TypeName PSObject -Property @{
                                User = $UserName
                                Browser = 'IE'
                                DataType = 'History'
                                Data = $Value
                            }
                        }
                    }
                }
            }
        }
    }

    function Get-InternetExplorerBookmarks {
        $URLs = Get-ChildItem -Path "$Env:systemdrive\Users\" -Filter "*.url" -Recurse -ErrorAction SilentlyContinue
        ForEach ($URL in $URLs) {
            if ($URL.FullName -match 'Favorites') {
                $User = $URL.FullName.split('\')[2]
                Get-Content -Path $URL.FullName | ForEach-Object {
                    try {
                        if ($_.StartsWith('URL')) {
                            # parse the .url body to extract the actual bookmark location
                            $URL = $_.Substring($_.IndexOf('=') + 1)

                            if($URL -match $Search) {
                                New-Object -TypeName PSObject -Property @{
                                    User = $User
                                    Browser = 'IE'
                                    DataType = 'Bookmark'
                                    Data = $URL
                                }
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Error parsing url: $_"
                    }
                }
            }
        }
    }

    function Get-FireFoxHistory {
        $Path = "$Env:systemdrive\Users\$UserName\AppData\Roaming\Mozilla\Firefox\Profiles\"
        if (-not (Test-Path -Path $Path)) {
            Write-Verbose "[!] Could not find FireFox History for username: $UserName"
        }
        else {
            $Profiles = Get-ChildItem -Path "$Path\*.default\" -ErrorAction SilentlyContinue
            $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
            $Value = Get-Content $Profiles\places.sqlite | Select-String -Pattern $Regex -AllMatches |Select-Object -ExpandProperty Matches |Sort -Unique
            $Value.Value |ForEach-Object {
                if ($_ -match $Search) {
                    ForEach-Object {
                    New-Object -TypeName PSObject -Property @{
                        User = $UserName
                        Browser = 'Firefox'
                        DataType = 'History'
                        Data = $_
                        }    
                    }
                }
            }
        }
    }

    if (!$UserName) {
        $UserName = "$ENV:USERNAME"
    }

    if(($Browser -Contains 'All') -or ($Browser -Contains 'Chrome')) {
        if (($DataType -Contains 'All') -or ($DataType -Contains 'History')) {
            Get-ChromeHistory
        }
        if (($DataType -Contains 'All') -or ($DataType -Contains 'Bookmarks')) {
            Get-ChromeBookmarks
        }
    }

    if(($Browser -Contains 'All') -or ($Browser -Contains 'IE')) {
        if (($DataType -Contains 'All') -or ($DataType -Contains 'History')) {
            Get-InternetExplorerHistory
        }
        if (($DataType -Contains 'All') -or ($DataType -Contains 'Bookmarks')) {
            Get-InternetExplorerBookmarks
        }
    }

    if(($Browser -Contains 'All') -or ($Browser -Contains 'FireFox')) {
        if (($DataType -Contains 'All') -or ($DataType -Contains 'History')) {
            Get-FireFoxHistory
        }
    }
}