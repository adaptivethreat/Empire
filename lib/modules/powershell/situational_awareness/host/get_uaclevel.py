from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-UACLevel',

            'Author': ['Petr Medonos'],

            'Description': ('Enumerates UAC level'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://gallery.technet.microsoft.com/How-to-switch-UAC-level-0ac3ea11'
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
function Get-UACLevel
{
    <#  
    .Synopsis
       Enumerates the UAC Level
       Author: Petr Medonos

    .DESCRIPTION
       Enumerates the UAC Level
    .EXAMPLE
       C:\> Get-UACLevel
    #>  

    New-Variable -Name Key 
    New-Variable -Name PromptOnSecureDesktop_Name 
    New-Variable -Name ConsentPromptBehaviorAdmin_Name 
    
    
    $Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" 
    $ConsentPromptBehaviorAdmin_Name = "ConsentPromptBehaviorAdmin" 
    $PromptOnSecureDesktop_Name = "PromptOnSecureDesktop" 
    
    $ConsentPromptBehaviorAdmin_Value = (Get-ItemProperty $Key $ConsentPromptBehaviorAdmin_Name).$ConsentPromptBehaviorAdmin_Name
    $PromptOnSecureDesktop_Value = (Get-ItemProperty $Key $PromptOnSecureDesktop_Name).$PromptOnSecureDesktop_Name
    If($ConsentPromptBehaviorAdmin_Value -Eq 0 -And $PromptOnSecureDesktop_Value -Eq 0){ 
        "Never notify" 
    }   
    ElseIf($ConsentPromptBehaviorAdmin_Value -Eq 5 -And $PromptOnSecureDesktop_Value -Eq 0){ 
        "Notify me only when apps try to make changes to my computer (do not dim my desktop)" 
    }   
    ElseIf($ConsentPromptBehaviorAdmin_Value -Eq 5 -And $PromptOnSecureDesktop_Value -Eq 1){ 
        "Notify me only when apps try to make changes to my computer (default)" 
    }   
    ElseIf($ConsentPromptBehaviorAdmin_Value -Eq 2 -And $PromptOnSecureDesktop_Value -Eq 1){ 
        "Always notify" 
    }   
    Else{ 
        "Unknown" 
    }   
} Get-UACLevel"""

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value']) 

        return script
