from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-RunAs',

            'Author': ['rvrsh3ll (@424f424f)'],

            'Description': ('Runas knockoff. Will bypass GPO path restrictions.'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/RunAs.ps1'
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
            'CredID' : {
                'Description'   :   'CredID from the store to use.',
                'Required'      :   False,
                'Value'         :   ''                
            },
            'Domain' : {
                'Description'   :   'Optional domain.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'UserName' : {
                'Description'   :   'Username to run the command as.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'Password for the specified username.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Cmd' : {
                'Description'   :   'Command to run.',
                'Required'      :   True,
                'Value'         :   'notepad.exe'
            },
            'Arguments' : {
                'Description'   :   'Optional arguments for the supplied binary.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ShowWindow' : {
                'Description'   :   'Switch. Show the window for the created process instead of hiding it.',
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
        
        # read in the common powerup.ps1 module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/management/Invoke-RunAs.ps1"
        if obfuscate:
            helpers.obfuscate_module(moduleSource=moduleSource, obfuscationCommand=obfuscationCommand)
            moduleSource = moduleSource.replace("module_source", "obfuscated_module_source")
        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        script = f.read()
        f.close()

        scriptEnd = "\nInvoke-RunAs "

        # if a credential ID is specified, try to parse
        credID = self.options["CredID"]['Value']
        if credID != "":
            
            if not self.mainMenu.credentials.is_credential_valid(credID):
                print helpers.color("[!] CredID is invalid!")
                return ""

            (credID, credType, domainName, userName, password, host, os, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]

            if credType != "plaintext":
                print helpers.color("[!] A CredID with a plaintext password must be used!")
                return ""

            if domainName != "":
                self.options["Domain"]['Value'] = domainName
            if userName != "":
                self.options["UserName"]['Value'] = userName
            if password != "":
                self.options["Password"]['Value'] = password
        
        if self.options["Domain"]['Value'] == "" or self.options["UserName"]['Value'] == "" or self.options["Password"]['Value'] == "":
            print helpers.color("[!] Domain/UserName/Password or CredID required!")
            return ""


        for option,values in self.options.iteritems():
            if option.lower() != "agent" and option.lower() != "credid":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " " + str(values['Value']) 
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
