from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Set-ADObject',

            'Author': ['@harmj0y'],

            'Description': ('Takes a SID, name, or SamAccountName to query for a specified '
                            'domain object, and then sets a specified "PropertyName" to a '
                            'specified "PropertyValue". Part of PowerView.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/'
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
            'SID' : {
                'Description'   :   "The SID of the domain object you're querying for.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'Name' : {
                'Description'   :   "The name of the domain object you're querying for.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'SamAccountName' : {
                'Description'   :   "The SamAccountName of the domain object you're querying for",
                'Required'      :   False,
                'Value'         :   ''
            },
            'Domain' : {
                'Description'   :   'The domain to query for objects, defaults to the current domain.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'PropertyName' : {
                'Description'   :   'The property name to set.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'PropertyValue' : {
                'Description'   :   'The value to set for PropertyName.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'PropertyXorValue' : {
                'Description'   :   'Integer calue to binary xor (-bxor) with the current int value.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ClearValue' : {
                'Description'   :   'Switch. Clear the value of PropertyName.',
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

        moduleName = self.info["Name"]
        
        # read in the common powerview.ps1 module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/network/powerview.ps1"

        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        # get just the code needed for the specified function
        script = helpers.generate_dynamic_powershell_script(moduleCode, moduleName)

        script += moduleName + " "

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value']) 

        script += ' | Out-String | %{$_ + \"`n\"};"`n'+str(moduleName)+' completed!"'
        if obfuscate:
            script = helpers.obfuscate(psScript=script, obfuscationCommand=obfuscationCommand)
        return script
