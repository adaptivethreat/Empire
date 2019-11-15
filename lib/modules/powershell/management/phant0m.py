from __future__ import print_function
from builtins import str
from builtins import object
import base64

from lib.common import helpers


class Module(object):
    def __init__(self, mainMenu, params=[]):
        self.info = {
            'Name': 'Invoke-Phant0m',
            'Author': ['@leesoh'],
            'Description': ('Kills Event Log Service Threads'),
            'Background': False,
            'OutputExtension': None,
            'NeedsAdmin': True,
            'OpsecSafe': True,
            'Language': 'powershell',
            'MinLanguageVersion': '2',
            'Comments':
            ['Invoke-Phant0m: https://github.com/hlldz/Invoke-Phant0m']
        }

        # any options needed by the module, settable during runtime
        self.options = {

            # format:
            #   value_name : {description, required, default_value}
            'Agent': {
                'Description': 'Agent to run module on.',
                'Required': True,
                'Value': ''
            }
        }

        self.mainMenu = mainMenu
        for param in params:
            # parameter format is [Name, Value]
            option, value = param

            if option in self.options:
                self.options[option]['Value'] = value

    def generate(self, obfuscate=False, obfuscationCommand=""):
        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/management/Invoke-Phant0m.ps1"

        if obfuscate:
            helpers.obfuscate_module(
                moduleSource=moduleSource,
                obfuscationCommand=obfuscationCommand)
            moduleSource = moduleSource.replace("module_source",
                                                "obfuscated_module_source")

        try:
            f = open(moduleSource, 'r')
        except:
            print(helpers.color("[!] Could not read module source path at: " +
                                str(moduleSource)))
            return ""

        moduleCode = f.read()
        f.close()
        script = moduleCode
        scriptEnd = "\nInvoke-Phant0m"

        for option, values in self.options.items():
            if option.lower() != "agent" and option.lower() != "showall":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " " + str(
                            values['Value'])

        if obfuscate:

            scriptEnd = helpers.obfuscate(
                psScript=scriptEnd, obfuscationCommand=obfuscationCommand)

        script += scriptEnd
        script += "| Out-String"
        return script
