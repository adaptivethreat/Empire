from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-RickAstley',

            'Author': ['@SadProcessor', '@harmj0y'],

            'Description': ("Runs @SadProcessor's beeping rickroll."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                "https://gist.github.com/SadProcessor/3e413f9542b01ee90979"
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
        
        # read in the common powerup.ps1 module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/trollsploit/Get-RickAstley.ps1"
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

        scriptEnd = moduleName + " "

        scriptEnd += ' | Out-String | %{$_ + \"`n\"};"`n'+str(moduleName)+' completed!"'
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
