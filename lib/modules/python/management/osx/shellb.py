import shlex
class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'shellb',

            # list of one or more authors for the module
            'Author': ['@xorrior'],

            # more verbose multi-line description of the module
            'Description': ('execute a shell command in the background'),

            # True if the module needs to run in the background
            'Background' : True,

            # File extension to save the file as
            'OutputExtension' : '',

            # if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : False,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': [ ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to execute module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Command' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Command to execute.',
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

    def generate(self):

        cmdstring = self.options['Command']['Value']
        script = """
import shlex
arg = shlex.split("%s")
p = subprocess.Popen(arg, stdout=PIPE)
res = p.stdout.read()
print res
""" % (cmdstring)
        return script
