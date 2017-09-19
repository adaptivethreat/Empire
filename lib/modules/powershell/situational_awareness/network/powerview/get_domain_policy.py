from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-DomainPolicy',

            'Author': ['@harmj0y'],

            'Description': ('Returns the default domain or DC policy for a given domain or domain controller. Part of PowerView.'),

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
            'Source' : {
                'Description'   :   'Extract Domain or DC (domain controller) policies.',
                'Required'      :   True,
                'Value'         :   'Domain'
            },
            'Domain' : {
                'Description'   :   'The domain to query for default policies, defaults to the current domain.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'DomainController' : {
                'Description'   :   'Domain controller to reflect LDAP queries through.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ResolveSids' : {
                'Description'   :   'Switch. Resolve Sids from a DC policy to object names.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'FullData' : {
                'Description'   :   'Switch. Return full subnet objects instead of just object names (the default).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ExpandObject' : {
                'Description'   :   'Expand a specific object from the domain policy. For example \'System Access\', entered without quotes',
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

        pscript = ""
        expand = False
        value_to_expand = ""
        for option,values in self.options.iteritems():
            if option.lower() != "agent" and option.lower() != "expandobject":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        pscript += " -" + str(option)
                    else:
                        pscript += " -" + str(option) + " " + str(values['Value']) 
            if option.lower() == "expandobject" and values['Value']:
                expand = True
                value_to_expand += values['Value']

        if expand: 
            script += "(" + moduleName + " " + pscript + ")." + "'" + value_to_expand + "'" + ' | fl | Out-String | %{$_ + \"`n\"};"`n'+str(moduleName)+' completed!"'
        else:
            script += moduleName + " " + pscript + ' | fl | Out-String | %{$_ + \"`n\"};"`n'+str(moduleName)+' completed! Use ExpandObject option to expand one of the objects above such as \'System Access\'"'
        if obfuscate:
            script = helpers.obfuscate(psScript=script, obfuscationCommand=obfuscationCommand)
        return script
