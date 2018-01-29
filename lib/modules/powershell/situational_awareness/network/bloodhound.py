from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-BloodHound',

            'Author': ['@harmj0y', '@_wald0', '@cptjesus'],

            'Description': ('Execute BloodHound data collection.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://bit.ly/getbloodhound'
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
                'Description'   :   'Array of one or more computers to enumerate',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ComputerADSpath' : {
                'Description'   :   'The LDAP source to search through for computers, e.g. "LDAP://OU=secret,DC=testlab,DC=local"',
                'Required'      :   False,
                'Value'         :   ''
            },
            'UserADSPath' : {
                'Description'   :   'The LDAP source to search through for users/groups, e.g. "LDAP://OU=secret,DC=testlab,DC=local"',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Domain' : {
                'Description'   :   'The domain to use for the query, defaults to the current domain.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'DomainController' : {
                'Description'   :   'Domain controller to reflect LDAP queries through.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'CollectionMethod' : {
                'Description'   :   "The method to collect data. 'Group', 'ComputerOnly', 'LocalGroup', 'GPOLocalGroup', 'Session', 'LoggedOn', 'Trusts, 'Stealth', or 'Default'.",
                'Required'      :   True,
                'Value'         :   'Default'
            },
            'SearchForest' : {
                'Description'   :   'Switch. Search all domains in the forest.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'CSVFolder' : {
                'Description'   :   'The CSV folder to use for output, defaults to the current folder location.',
                'Required'      :   False,
                'Value'         :   '$(Get-Location)'
            },
            'CSVPrefix' : {
                'Description'   :   'A prefix for all CSV files.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'URI' : {
                'Description'   :   'The BloodHound neo4j URL location (http://host:port/)',
                'Required'      :   False,
                'Value'         :   ''
            },
            'UserPass' : {
                'Description'   :   'The "user:password" for the BloodHound neo4j instance',
                'Required'      :   False,
                'Value'         :   ''
            },
            'GlobalCatalog' : {
                'Description'   :   'The global catalog location to resolve user memberships from.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SkipGCDeconfliction' : {
                'Description'   :   'Switch. Skip global catalog enumeration for session deconfliction',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Threads' : {
                'Description'   :   'The maximum concurrent threads to execute.',
                'Required'      :   True,
                'Value'         :   '20'
            },
            'Throttle' : {
                'Description'   :   'The number of cypher queries to queue up for neo4j RESTful API ingestion.',
                'Required'      :   True,
                'Value'         :   '1000'
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

        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/network/BloodHound.ps1"
        if obfuscate:
            helpers.obfuscate_module(moduleSource=moduleSource, obfuscationCommand=obfuscationCommand)
            moduleSource = moduleSource.replace("module_source", "obfuscated_module_source")
        # TODO: just CSV output for this bloodhound version? no output to file?

        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = "%s\n" %(moduleCode)
        scriptEnd = moduleName

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " " + str(values['Value']) 

        scriptEnd += ' | Out-String | %{$_ + \"`n\"};"`n'+str(moduleName)+' completed!"'
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script

