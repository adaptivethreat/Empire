import os
import string

from lib.common import helpers


class Module:
    def __init__(self, mainMenu, params=None):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'SOCKSv5 Proxy',

            # list of one or more authors for the module
            'Author': ['klustic'],

            # more verbose multi-line description of the module
            'Description': ('Spawn an AROX relay to extend a SOCKS proxy through your agent.'),

            # True if the module needs to run in the background
            'Background': True,

            # File extension to save the file as
            # no need to base64 return data
            'OutputExtension': None,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': True,

            # the module language
            'Language': 'python',

            # Needs administrative privs
            'NeedsAdmin': False,

            # the minimum language version needed
            'MinLanguageVersion': '2.7',

            # list of any references/other comments
            'Comments': [
                'You must set up a standalone AlmondRocks server for this to connect to! Refer to the AlmondRocks Github project for more details.',
                'Repo: https://github.com/klustic/AlmondRocks'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description': 'Agent to run the AROX relay on',
                'Required': True,
                'Value': ''
            },
            'server': {
                'Description': 'FQDN/IPv4 and port of the AROX server (e.g. 1.2.3.4:443 or hax0r.com:443)',
                'Required': True,
                'Value': ''
            },
        }

        # save off a copy of the mainMenu object to access external functionality like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        # This is mostly in case options are passed on the command line
        if params is not None:
            for param in params:
                # parameter format is [Name, Value]
                option, value = param
                if option.lower in self.options:
                    self.options[option.lower()]['Value'] = value

    def generate(self, obfuscate=False, obfuscationCommand=""):
        tunnel_addr = self.options['server']['Value']

        # Read in the module source template
        module_source_file = os.path.join(self.mainMenu.installPath,
                                          'data/module_source/python/management/socks-src.py')
        try:
            with open(module_source_file) as f:
                module_source = f.read()
        except:
            print helpers.color("[!] Could not read module source path at: " + str(module_source_file))
            return ''

        # Render the module_template
        module_template = string.Template(module_source)
        try:
            module = module_template.substitute(TUNNEL_ADDR=tunnel_addr)
        except KeyError as e:
            print helpers.color("[!] Error rendering module template: {0}".format(e))
            return ''

        return module
