from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-LockWorkStation',

            'Author': ['@harmj0y'],

            'Description': ("Locks the workstation's display."),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'http://poshcode.org/1640'
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
Function Invoke-LockWorkStation {
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
Invoke-LockWorkStation; "Workstation locked."
"""
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
