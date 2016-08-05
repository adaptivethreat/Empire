function Invoke-RunAs {
<#
.DESCRIPTION
Runas knockoff. Will bypass GPO path restrictions.

.PARAMETER UserName
Provide a user

.PARAMETER Password
Provide a password

.PARAMETER Domain
Provide optional domain

.PARAMETER Cmd
Command to execute.

.PARAMETER ShowWindow
Show the window being created instead if hiding it (the default).

.Example
Invoke-RunAs -username administrator -password "P@$$word!" -domain CORPA -Cmd notepad.exe
#>
    [CmdletBinding()]Param (
    [Parameter(
        ValueFromPipeline=$True)]
        [String]$username,
    [Parameter(
        ValueFromPipeline=$True)]
        [String]$password,
    [Parameter(
        ValueFromPipeline=$True)]
        [String]$domain,
    [Parameter(
        ValueFromPipeline=$True)]
        [String]$cmd,
    [Parameter()]
        [String]$Arguments,
    [Parameter()]
        [Switch]$ShowWindow
    )
    PROCESS {
        try{
            $startinfo = new-object System.Diagnostics.ProcessStartInfo

            $startinfo.FileName = $cmd
            $startinfo.UseShellExecute = $false

            if(-not ($ShowWindow)) {
                $startinfo.CreateNoWindow = $True
                $startinfo.WindowStyle = "Hidden"
            }

            if($Arguments) {
                $startinfo.Arguments = $Arguments
            }

            if($UserName) {
                # if we're using alternate credentials
                $startinfo.UserName = $username
                $sec_password = convertto-securestring $password -asplaintext -force
                $startinfo.Password = $sec_password
                $startinfo.Domain = $domain
            }
            
            [System.Diagnostics.Process]::Start($startinfo) | out-string
        }
        catch {
            "[!] Error in runas: $_"
        }

    }
}
