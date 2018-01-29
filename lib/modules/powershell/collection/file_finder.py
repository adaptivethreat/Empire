from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-FileFinder',

            'Author': ['@harmj0y'],

            'Description': ('Finds sensitive files on the domain.'),

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
            'ComputerName' : {
                'Description'   :   'Hosts to enumerate.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ComputerFilter' : {
                'Description'   :   'Host filter name to query AD for, wildcards accepted.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ShareList' : {
                'Description'   :   "List of '\\\\HOST\shares' (on the target) to search through.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'Terms' : {
                'Description'   :   "Comma-separated terms to search for (overrides defaults).",
                'Required'      :   False,
                'Value'         :   ''
            },
            'OfficeDocs' : {
                'Description'   :   "Switch. Return only office documents.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'FreshEXES' : {
                'Description'   :   "Switch. Find .EXEs accessed in the last week.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'LastAccessTime' : {
                'Description'   :   "Only return files with a LastAccessTime greater than this date value.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'CreationTime' : {
                'Description'   :   "Only return files with a CreationDate greater than this date value.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'FreshEXES' : {
                'Description'   :   "Switch. Find .EXEs accessed in the last week.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'ExcludeHidden' : {
                'Description'   :   "Switch. Exclude hidden files and folders from the search results.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'CheckWriteAccess' : {
                'Description'   :   "Switch. Only returns files the current user has write access to.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'NoPing' : {
                'Description'   :   "Switch. Don't ping each host to ensure it's up before enumerating.",
                'Required'      :   False,
                'Value'         :   ''
            },            
            'Delay' : {
                'Description'   :   "Delay between enumerating hosts, defaults to 0.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'Domain' : {
                'Description'   :   "Domain to query for machines.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'SearchSYSVOL' : {
                'Description'   :   "Switch. Search for login scripts on the SYSVOL of the primary DCs for each specified domain.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'Threads' : {
                'Description'   :   "The maximum concurrent threads to execute.",
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
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
