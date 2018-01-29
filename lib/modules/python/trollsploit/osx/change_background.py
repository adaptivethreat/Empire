class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Change Login Message for the user.',

            # list of one or more authors for the module
            'Author': ['@424f424f'],

            # more verbose multi-line description of the module
            'Description': 'Change the login message for the user.',

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : "",

            # if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : False,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': ['']
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to run on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Image' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Location of the image to use.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Desktop' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'True/False to change the desktop background.',
                'Required'      :   False,
                'Value'         :   'False'
            },
            'Login' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'True/False to change the login background.',
                'Required'      :   False,
                'Value'         :   'False'
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

        image = self.options['Image']['Value']
        desktop = self.options['Desktop']['Value']
        login = self.options['Login']['Value']

        # the Python script itself, with the command to invoke
        #   for execution appended to the end. Scripts should output
        #   everything to the pipeline for proper parsing.
        #
        # the script should be stripped of comments, with a link to any
        #   original reference script included in the comments.
        script = """
import subprocess
desktop = %s
login = %s
if desktop == True:
    try:
        cmd = \"""osascript -e 'tell application "Finder" to set desktop picture to "%s" as POSIX file'""\"
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        print "Desktop background changed!"
    except Exception as e:
        print "Changing desktop background failed"
        print e

if login == True:
    try:
        cmd = \"""cp %s /Library/Caches/com.apple.desktop.admin.png""\"
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        print "Login background changed!"
    except Exception as e:
        print "Changing login background failed"
        print e


""" % (desktop, login, image, image)
        return script
