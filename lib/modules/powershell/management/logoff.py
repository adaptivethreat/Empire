from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Logoff User',

            'Author': ['@harmj0y'],

            'Description': ("Logs the current user (or all users) off the machine."),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,
            
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
            'AllUsers' : {
                'Description'   :   'Switch. Log off all current users.',
                'Required'      :   False,
                'Value'         :   ''
            },            
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
        
        allUsers = self.options['AllUsers']['Value']

        if allUsers.lower() == "true":
            script = "'Logging off all users.'; Start-Sleep -s 3; $null = (gwmi win32_operatingsystem).Win32Shutdown(4)"
        else:
            script = "'Logging off current user.'; Start-Sleep -s 3; shutdown /l /f"
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
