from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-ReverseDNSLookup',

            'Author': ['DarkOperator'],

            'Description': ('Performs a DNS Reverse Lookup of a given IPv4 IP Range.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1'
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
            'Range' : {
                'Description'   :   "Range to perform reverse DNS on.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'CIDR' : {
                'Description'   :   "CIDR to perform reverse DNS on.",
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
        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/network/Invoke-ReverseDNSLookup.ps1"
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

        scriptEnd = "Invoke-ReverseDNSLookup"

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " " + str(values['Value']) 

        # only return objects where HostName is not an IP (i.e. the address resolves)
        scriptEnd += " | % {try{$entry=$_; $ipObj = [System.Net.IPAddress]::parse($entry.HostName); if(-not [System.Net.IPAddress]::tryparse([string]$_.HostName, [ref]$ipObj)) { $entry }} catch{$entry} } | Select-Object HostName, AddressList | ft -autosize | Out-String | %{$_ + \"`n\"}"
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
