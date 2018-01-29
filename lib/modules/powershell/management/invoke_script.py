from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-Script',

            'Author': ['@harmj0y'],

            'Description': ('Run a custom script. Useful for mass-taskings or script autoruns.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

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
            'ScriptPath' : {
                'Description'   :   'Full path to the PowerShell script.ps1 to run (on attacker machine)',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ScriptCmd' : {
                'Description'   :   'Script command (Invoke-X) from file to run, along with any specified arguments.',
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
        
        scriptPath = self.options['ScriptPath']['Value']
        scriptCmd = self.options['ScriptCmd']['Value']
        script = ''

        if(scriptPath != ''):
            try:
                f = open(scriptPath, 'r')
            except:
                print helpers.color("[!] Could not read script source path at: " + str(scriptPath))
                return ""

            script = f.read()
            f.close()
            script += '\n'

        script += "%s" %(scriptCmd)
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
