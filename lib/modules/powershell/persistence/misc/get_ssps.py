from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-SecurityPackages',

            'Author': ['@mattifestation'],

            'Description': ('Enumerates all loaded security packages (SSPs).'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
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
function Get-SecurityPackages
{
<#
.SYNOPSIS

Enumerates all loaded security packages (SSPs).

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Get-SecurityPackages is a wrapper for secur32!EnumerateSecurityPackages.
It also parses the returned SecPkgInfo struct array.

.EXAMPLE

Get-SecurityPackages
#>

    [CmdletBinding()] Param()

    #region P/Invoke declarations for secur32.dll
    $DynAssembly = New-Object System.Reflection.AssemblyName('SSPI')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('SSPI', $False)

    $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
    $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
    $StructAttributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'

    $EnumBuilder = $ModuleBuilder.DefineEnum('SSPI.SECPKG_FLAG', 'Public', [Int32])
    $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    $null = $EnumBuilder.DefineLiteral('INTEGRITY', 1)
    $null = $EnumBuilder.DefineLiteral('PRIVACY', 2)
    $null = $EnumBuilder.DefineLiteral('TOKEN_ONLY', 4)
    $null = $EnumBuilder.DefineLiteral('DATAGRAM', 8)
    $null = $EnumBuilder.DefineLiteral('CONNECTION', 0x10)
    $null = $EnumBuilder.DefineLiteral('MULTI_REQUIRED', 0x20)
    $null = $EnumBuilder.DefineLiteral('CLIENT_ONLY', 0x40)
    $null = $EnumBuilder.DefineLiteral('EXTENDED_ERROR', 0x80)
    $null = $EnumBuilder.DefineLiteral('IMPERSONATION', 0x100)
    $null = $EnumBuilder.DefineLiteral('ACCEPT_WIN32_NAME', 0x200)
    $null = $EnumBuilder.DefineLiteral('STREAM', 0x400)
    $null = $EnumBuilder.DefineLiteral('NEGOTIABLE', 0x800)
    $null = $EnumBuilder.DefineLiteral('GSS_COMPATIBLE', 0x1000)
    $null = $EnumBuilder.DefineLiteral('LOGON', 0x2000)
    $null = $EnumBuilder.DefineLiteral('ASCII_BUFFERS', 0x4000)
    $null = $EnumBuilder.DefineLiteral('FRAGMENT', 0x8000)
    $null = $EnumBuilder.DefineLiteral('MUTUAL_AUTH', 0x10000)
    $null = $EnumBuilder.DefineLiteral('DELEGATION', 0x20000)
    $null = $EnumBuilder.DefineLiteral('READONLY_WITH_CHECKSUM', 0x40000)
    $null = $EnumBuilder.DefineLiteral('RESTRICTED_TOKENS', 0x80000)
    $null = $EnumBuilder.DefineLiteral('NEGO_EXTENDER', 0x100000)
    $null = $EnumBuilder.DefineLiteral('NEGOTIABLE2', 0x200000)
    $null = $EnumBuilder.DefineLiteral('APPCONTAINER_PASSTHROUGH', 0x400000)
    $null = $EnumBuilder.DefineLiteral('APPCONTAINER_CHECKS', 0x800000)
    $SECPKG_FLAG = $EnumBuilder.CreateType()

    $TypeBuilder = $ModuleBuilder.DefineType('SSPI.SecPkgInfo', $StructAttributes, [Object], [Reflection.Emit.PackingSize]::Size8)
    $null = $TypeBuilder.DefineField('fCapabilities', $SECPKG_FLAG, 'Public')
    $null = $TypeBuilder.DefineField('wVersion', [Int16], 'Public')
    $null = $TypeBuilder.DefineField('wRPCID', [Int16], 'Public')
    $null = $TypeBuilder.DefineField('cbMaxToken', [Int32], 'Public')
    $null = $TypeBuilder.DefineField('Name', [IntPtr], 'Public')
    $null = $TypeBuilder.DefineField('Comment', [IntPtr], 'Public')
    $SecPkgInfo = $TypeBuilder.CreateType()

    $TypeBuilder = $ModuleBuilder.DefineType('SSPI.Secur32', 'Public, Class')
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('EnumerateSecurityPackages',
        'secur32.dll',
        'Public, Static',
        [Reflection.CallingConventions]::Standard,
        [Int32],
        [Type[]] @([Int32].MakeByRefType(),
            [IntPtr].MakeByRefType()),
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::Ansi)

    $Secur32 = $TypeBuilder.CreateType()

    $PackageCount = 0
    $PackageArrayPtr = [IntPtr]::Zero
    $Result = $Secur32::EnumerateSecurityPackages([Ref] $PackageCount, [Ref] $PackageArrayPtr)

    if ($Result -ne 0)
    {
        throw "Unable to enumerate seucrity packages. Error (0x$($Result.ToString('X8')))"
    }

    if ($PackageCount -eq 0)
    {
        Write-Verbose 'There are no installed security packages.'
        return
    }

    $StructAddress = $PackageArrayPtr

    foreach ($i in 1..$PackageCount)
    {
        $SecPackageStruct = [Runtime.InteropServices.Marshal]::PtrToStructure($StructAddress, [Type] $SecPkgInfo)
        $StructAddress = [IntPtr] ($StructAddress.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([Type] $SecPkgInfo))

        $Name = $null

        if ($SecPackageStruct.Name -ne [IntPtr]::Zero)
        {
            $Name = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($SecPackageStruct.Name)
        }

        $Comment = $null

        if ($SecPackageStruct.Comment -ne [IntPtr]::Zero)
        {
            $Comment = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($SecPackageStruct.Comment)
        }

        $Attributes = @{
            Name = $Name
            Comment = $Comment
            Capabilities = $SecPackageStruct.fCapabilities
            MaxTokenSize = $SecPackageStruct.cbMaxToken
        }

        $SecPackage = New-Object PSObject -Property $Attributes
        $SecPackage.PSObject.TypeNames[0] = 'SECUR32.SECPKGINFO'

        $SecPackage
    }
} Get-SecurityPackages"""

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    script += " -" + str(option) + " " + str(values['Value']) 
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
