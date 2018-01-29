from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-MailSearch',

            'Author': ['@xorrior'],

            'Description': ("Searches the given Outlook folder for items (Emails, Contacts, Tasks, Notes, etc. *Depending on the folder*) and returns any matches found."),

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
            'DefaultFolder' : {
                'Description'   :   'Folder to search in.',
                'Required'      :   True,
                'Value'         :   'Inbox'
            },
            'Keywords' : {
                'Description'   :   'Keyword/s to search for.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'MaxResults' : {
                'Description'   :   'Maximum number of results to return.',
                'Required'      :   False,
                'Value'         :   '100'
            },
            'MaxSearch' : {
                'Description'   :   'Maximum number of emails to search through.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'MaxThreads' : {
                'Description'   :   'Maximum number of threads to use when searching.',
                'Required'      :   True,
                'Value'         :   '15'
            },
            'File' : {
                'Description'   :   'Path to results file (instead of stdout).',
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
