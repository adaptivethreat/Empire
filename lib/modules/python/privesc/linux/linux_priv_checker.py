class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'LinuxPrivChecker',

            # list of one or more authors for the module
            'Author': ['@Killswitch_GUI', '@SecuritySift'],

            # more verbose multi-line description of the module
            'Description': ('This script is intended to be executed locally on'
                            'a Linux box to enumerate basic system info, and search for common' 
                            'privilege escalation vectors with pure python.'),

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            'OutputExtension': "",

            # if the module needs administrative privileges
            'NeedsAdmin': False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': True,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': ['For full comments and code: www.securitysift.com/download/linuxprivchecker.py']
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to run on.',
                'Required'      :   True,
                'Value'         :   ''
            },
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

    def generate(self, obfuscate=False, obfuscationCommand=""):
        ###############################################################################################################
        ## [Title]: linuxprivchecker.py -- a Linux Privilege Escalation Check Script
        ## [Author]: Mike Czumak (T_v3rn1x) -- @SecuritySift
        ##-------------------------------------------------------------------------------------------------------------
        ## [Details]: 
        ## This script is intended to be executed locally on a Linux box to enumerate basic system info and 
        ## search for common privilege escalation vectors such as world writable files, misconfigurations, clear-text
        ## passwords and applicable exploits. 
        ##-------------------------------------------------------------------------------------------------------------
        ## [Warning]:
        ## This script comes as-is with no promise of functionality or accuracy.  I have no plans to maintain updates, 
        ## I did not write it to be efficient and in some cases you may find the functions may not produce the desired 
        ## results.  For example, the function that links packages to running processes is based on keywords and will 
        ## not always be accurate.  Also, the exploit list included in this function will need to be updated over time. 
        ## Feel free to change or improve it any way you see fit.
        ##-------------------------------------------------------------------------------------------------------------   
        ## [Modification, Distribution, and Attribution]:
        ## You are free to modify and/or distribute this script as you wish.  I only ask that you maintain original
        ## author attribution and not attempt to sell it or incorporate it into any commercial offering (as if it's 
        ## worth anything anyway :)
        ###############################################################################################################
        script = """
def callFunctionLinux():
    try:
        import subprocess as sub
        compatmode = 0 # newer version of python, no need for compatibility mode
    except ImportError:
        import os # older version of python, need to use os instead
        compatmode = 1

    # title / formatting
    bigline = "================================================================================================="
    smlline = "-------------------------------------------------------------------------------------------------"

    print bigline 
    print "LINUX PRIVILEGE ESCALATION CHECKER"
    print bigline
    print

    # loop through dictionary, execute the commands, store the results, return updated dict
    def execCmd(cmdDict):
        for item in cmdDict:
            cmd = cmdDict[item]["cmd"]
            if compatmode == 0: # newer version of python, use preferred subprocess
                out, error = sub.Popen([cmd], stdout=sub.PIPE, stderr=sub.PIPE, shell=True).communicate()
                results = out.split('\\n')
            else: # older version of python, use os.popen
                echo_stdout = os.popen(cmd, 'r')  
                results = echo_stdout.read().split('\\n')
            cmdDict[item]["results"]=results
        return cmdDict

    # print results for each previously executed command, no return value
    def printResults(cmdDict):
        for item in cmdDict:
            msg = cmdDict[item]["msg"]
            results = cmdDict[item]["results"]
            print "[+] " + msg
            for result in results:
                if result.strip() != "":
                    print "    " + result.strip()
            print
        return

    def writeResults(msg, results):
        f = open("privcheckout.txt", "a");
        f.write("[+] " + str(len(results)-1) + " " + msg)
        for result in results:
            if result.strip() != "":
                f.write("    " + result.strip())
        f.close()
        return

    # Basic system info
    print "[*] GETTING BASIC SYSTEM INFO...\\n"

    results=[]

    sysInfo = {"OS":{"cmd":"cat /etc/issue","msg":"Operating System","results":results}, 
               "KERNEL":{"cmd":"cat /proc/version","msg":"Kernel","results":results}, 
               "HOSTNAME":{"cmd":"hostname", "msg":"Hostname", "results":results}
               }

    sysInfo = execCmd(sysInfo)
    printResults(sysInfo)

    # Networking Info

    print "[*] GETTING NETWORKING INFO...\\n"

    netInfo = {"NETINFO":{"cmd":"/sbin/ifconfig -a", "msg":"Interfaces", "results":results},
           "ROUTE":{"cmd":"route", "msg":"Route", "results":results},
           "NETSTAT":{"cmd":"netstat -antup | grep -v 'TIME_WAIT'", "msg":"Netstat", "results":results}
          }

    netInfo = execCmd(netInfo)
    printResults(netInfo)

    # File System Info
    print "[*] GETTING FILESYSTEM INFO...\\n"

    driveInfo = {"MOUNT":{"cmd":"mount","msg":"Mount results", "results":results},
             "FSTAB":{"cmd":"cat /etc/fstab 2>/dev/null", "msg":"fstab entries", "results":results}
            }

    driveInfo = execCmd(driveInfo)
    printResults(driveInfo)

    # Scheduled Cron Jobs
    cronInfo = {"CRON":{"cmd":"ls -la /etc/cron* 2>/dev/null", "msg":"Scheduled cron jobs", "results":results},
            "CRONW": {"cmd":"ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$/' 2>/dev/null", "msg":"Writable cron dirs", "results":results}
           }

    cronInfo = execCmd(cronInfo)
    printResults(cronInfo)

    # User Info
    print "\\n[*] ENUMERATING USER AND ENVIRONMENTAL INFO...\\n"

    userInfo = {"WHOAMI":{"cmd":"whoami", "msg":"Current User", "results":results},
            "ID":{"cmd":"id","msg":"Current User ID", "results":results},
            "ALLUSERS":{"cmd":"cat /etc/passwd", "msg":"All users", "results":results},
            "SUPUSERS":{"cmd":"grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'", "msg":"Super Users Found:", "results":results},
            "HISTORY":{"cmd":"ls -la ~/.*_history; ls -la /root/.*_history 2>/dev/null", "msg":"Root and current user history (depends on privs)", "results":results},
            "ENV":{"cmd":"env 2>/dev/null | grep -v 'LS_COLORS'", "msg":"Environment", "results":results},
            "SUDOERS":{"cmd":"cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null", "msg":"Sudoers (privileged)", "results":results},
            "LOGGEDIN":{"cmd":"w 2>/dev/null", "msg":"Logged in User Activity", "results":results}
           }

    userInfo = execCmd(userInfo)
    printResults(userInfo)

    if "root" in userInfo["ID"]["results"][0]:
        print "[!] ARE YOU SURE YOU'RE NOT ROOT ALREADY?\\n"

    # File/Directory Privs
    print "[*] ENUMERATING FILE AND DIRECTORY PERMISSIONS/CONTENTS...\\n"

    fdPerms = {"WWDIRSROOT":{"cmd":"find / \\( -wholename '/home/homedir*' -prune \\) -o \\( -type d -perm -0002 \\) -exec ls -ld '{}' ';' 2>/dev/null | grep root", "msg":"World Writeable Directories for User/Group 'Root'", "results":results},
           "WWDIRS":{"cmd":"find / \\( -wholename '/home/homedir*' -prune \\) -o \\( -type d -perm -0002 \\) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root", "msg":"World Writeable Directories for Users other than Root", "results":results},
           "WWFILES":{"cmd":"find / \\( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \\) -o \\( -type f -perm -0002 \\) -exec ls -l '{}' ';' 2>/dev/null", "msg":"World Writable Files", "results":results},
           "SUID":{"cmd":"find / \\( -perm -2000 -o -perm -4000 \\) -exec ls -ld {} \\; 2>/dev/null", "msg":"SUID/SGID Files and Directories", "results":results},
           "ROOTHOME":{"cmd":"ls -ahlR /root 2>/dev/null", "msg":"Checking if root's home folder is accessible", "results":results}
          }

    fdPerms = execCmd(fdPerms) 
    printResults(fdPerms)

    pwdFiles = {"LOGPWDS":{"cmd":"find /var/log -name '*.log' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null", "msg":"Logs containing keyword 'password'", "results":results},
            "CONFPWDS":{"cmd":"find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null", "msg":"Config files containing keyword 'password'", "results":results},
            "SHADOW":{"cmd":"cat /etc/shadow 2>/dev/null", "msg":"Shadow File (Privileged)", "results":results}
           }

    pwdFiles = execCmd(pwdFiles)
    printResults(pwdFiles)

    # Processes and Applications
    print "[*] ENUMERATING PROCESSES AND APPLICATIONS...\\n"

    if "debian" in sysInfo["KERNEL"]["results"][0] or "ubuntu" in sysInfo["KERNEL"]["results"][0]:
        getPkgs = "dpkg -l | awk '{$1=$4=\\"\\"; print $0}'" # debian
    else:
        getPkgs = "rpm -qa | sort -u" # RH/other

    getAppProc = {"PROCS":{"cmd":"ps aux | awk '{print $1,$2,$9,$10,$11}'", "msg":"Current processes", "results":results},
                  "PKGS":{"cmd":getPkgs, "msg":"Installed Packages", "results":results}
             }

    getAppProc = execCmd(getAppProc)
    printResults(getAppProc) # comment to reduce output

    otherApps = { "SUDO":{"cmd":"sudo -V | grep version 2>/dev/null", "msg":"Sudo Version (Check out http://www.exploit-db.com/search/?action=search&filter_page=1&filter_description=sudo)", "results":results},
              "APACHE":{"cmd":"apache2 -v; apache2ctl -M; httpd -v; apachectl -l 2>/dev/null", "msg":"Apache Version and Modules", "results":results},
              "APACHECONF":{"cmd":"cat /etc/apache2/apache2.conf 2>/dev/null", "msg":"Apache Config File", "results":results}
            }

    otherApps = execCmd(otherApps)
    printResults(otherApps)

    print "[*] IDENTIFYING PROCESSES AND PACKAGES RUNNING AS ROOT OR OTHER SUPERUSER...\\n"

    # find the package information for the processes currently running
    # under root or another super user

    procs = getAppProc["PROCS"]["results"]
    pkgs = getAppProc["PKGS"]["results"]
    supusers = userInfo["SUPUSERS"]["results"]
    procdict = {} # dictionary to hold the processes running as super users
      
    for proc in procs: # loop through each process
        relatedpkgs = [] # list to hold the packages related to a process    
        try:
            for user in supusers: # loop through the known super users
                if (user != "") and (user in proc): # if the process is being run by a super user
                    procname = proc.split(" ")[4] # grab the process name
                    if "/" in procname:
                        splitname = procname.split("/")
                        procname = splitname[len(splitname)-1]
                    for pkg in pkgs: # loop through the packages
                        if not len(procname) < 3: # name too short to get reliable package results
                            if procname in pkg: 
                                if procname in procdict: 
                                    relatedpkgs = procdict[proc] # if already in the dict, grab its pkg list
                                if pkg not in relatedpkgs:
                                    relatedpkgs.append(pkg) # add pkg to the list
                    procdict[proc]=relatedpkgs # add any found related packages to the process dictionary entry
        except:
            pass

    for key in procdict:
        print "    " + key # print the process name
        try:
            if not procdict[key][0] == "": # only print the rest if related packages were found
                print "        Possible Related Packages: " 
                for entry in procdict[key]: 
                    print "            " + entry # print each related package
        except:
            pass

    # EXPLOIT ENUMERATION

    # First discover the avaialable tools 
    print
    print "[*] ENUMERATING INSTALLED LANGUAGES/TOOLS FOR SPLOIT BUILDING...\\n"

    devTools = {"TOOLS":{"cmd":"which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null", "msg":"Installed Tools", "results":results}}
    devTools = execCmd(devTools)
    printResults(devTools)

    print "[+] Related Shell Escape Sequences...\\n"
    escapeCmd = {"vi":[":!bash", ":set shell=/bin/bash:shell"], "awk":["awk 'BEGIN {system(\\"/bin/bash\\")}'"], "perl":["perl -e 'exec \\"/bin/bash\\";'"], "find":["find / -exec /usr/bin/awk 'BEGIN {system(\\"/bin/bash\\")}' \\\\;"], "nmap":["--interactive"]}
    for cmd in escapeCmd:
        for result in devTools["TOOLS"]["results"]:
            if cmd in result:
                for item in escapeCmd[cmd]:
                    print "    " + cmd + "-->\\t" + item
    print
    print "[*] FINDING RELEVENT PRIVILEGE ESCALATION EXPLOITS...\\n"

    # Now check for relevant exploits (note: this list should be updated over time; source: Exploit-DB)
    # sploit format = sploit name : {minversion, maxversion, exploitdb#, language, {keywords for applicability}} -- current keywords are 'kernel', 'proc', 'pkg' (unused), and 'os'
    sploits= {      "2.2.x-2.4.x ptrace kmod local exploit":{"minver":"2.2", "maxver":"2.4.99", "exploitdb":"3", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "< 2.4.20 Module Loader Local Root Exploit":{"minver":"0", "maxver":"2.4.20", "exploitdb":"12", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.4.22 "'do_brk()'" local Root Exploit (PoC)":{"minver":"2.4.22", "maxver":"2.4.22", "exploitdb":"129", "lang":"asm", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "<= 2.4.22 (do_brk) Local Root Exploit (working)":{"minver":"0", "maxver":"2.4.22", "exploitdb":"131", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.4.x mremap() bound checking Root Exploit":{"minver":"2.4", "maxver":"2.4.99", "exploitdb":"145", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "<= 2.4.29-rc2 uselib() Privilege Elevation":{"minver":"0", "maxver":"2.4.29", "exploitdb":"744", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.4 uselib() Privilege Elevation Exploit":{"minver":"2.4", "maxver":"2.4", "exploitdb":"778", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.4.x / 2.6.x uselib() Local Privilege Escalation Exploit":{"minver":"2.4", "maxver":"2.6.99", "exploitdb":"895", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.4/2.6 bluez Local Root Privilege Escalation Exploit (update)":{"minver":"2.4", "maxver":"2.6.99", "exploitdb":"926", "lang":"c", "keywords":{"loc":["proc","pkg"], "val":"bluez"}},
            "<= 2.6.11 (CPL 0) Local Root Exploit (k-rad3.c)":{"minver":"0", "maxver":"2.6.11", "exploitdb":"1397", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "MySQL 4.x/5.0 User-Defined Function Local Privilege Escalation Exploit":{"minver":"0", "maxver":"99", "exploitdb":"1518", "lang":"c", "keywords":{"loc":["proc","pkg"], "val":"mysql"}},
            "2.6.13 <= 2.6.17.4 sys_prctl() Local Root Exploit":{"minver":"2.6.13", "maxver":"2.6.17.4", "exploitdb":"2004", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.6.13 <= 2.6.17.4 sys_prctl() Local Root Exploit (2)":{"minver":"2.6.13", "maxver":"2.6.17.4", "exploitdb":"2005", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.6.13 <= 2.6.17.4 sys_prctl() Local Root Exploit (3)":{"minver":"2.6.13", "maxver":"2.6.17.4", "exploitdb":"2006", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.6.13 <= 2.6.17.4 sys_prctl() Local Root Exploit (4)":{"minver":"2.6.13", "maxver":"2.6.17.4", "exploitdb":"2011", "lang":"sh", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "<= 2.6.17.4 (proc) Local Root Exploit":{"minver":"0", "maxver":"2.6.17.4", "exploitdb":"2013", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.6.13 <= 2.6.17.4 prctl() Local Root Exploit (logrotate)":{"minver":"2.6.13", "maxver":"2.6.17.4", "exploitdb":"2031", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "Ubuntu/Debian Apache 1.3.33/1.3.34 (CGI TTY) Local Root Exploit":{"minver":"4.10", "maxver":"7.04", "exploitdb":"3384", "lang":"c", "keywords":{"loc":["os"], "val":"debian"}},
            "Linux/Kernel 2.4/2.6 x86-64 System Call Emulation Exploit":{"minver":"2.4", "maxver":"2.6", "exploitdb":"4460", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "< 2.6.11.5 BLUETOOTH Stack Local Root Exploit":{"minver":"0", "maxver":"2.6.11.5", "exploitdb":"4756", "lang":"c", "keywords":{"loc":["proc","pkg"], "val":"bluetooth"}},
            "2.6.17 - 2.6.24.1 vmsplice Local Root Exploit":{"minver":"2.6.17", "maxver":"2.6.24.1", "exploitdb":"5092", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.6.23 - 2.6.24 vmsplice Local Root Exploit":{"minver":"2.6.23", "maxver":"2.6.24", "exploitdb":"5093", "lang":"c", "keywords":{"loc":["os"], "val":"debian"}},
            "Debian OpenSSL Predictable PRNG Bruteforce SSH Exploit":{"minver":"0", "maxver":"99", "exploitdb":"5720", "lang":"python", "keywords":{"loc":["os"], "val":"debian"}},
            "Linux Kernel < 2.6.22 ftruncate()/open() Local Exploit":{"minver":"0", "maxver":"2.6.22", "exploitdb":"6851", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "< 2.6.29 exit_notify() Local Privilege Escalation Exploit":{"minver":"0", "maxver":"2.6.29", "exploitdb":"8369", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.6 UDEV Local Privilege Escalation Exploit":{"minver":"2.6", "maxver":"2.6.99", "exploitdb":"8478", "lang":"c", "keywords":{"loc":["proc","pkg"], "val":"udev"}},
            "2.6 UDEV < 141 Local Privilege Escalation Exploit":{"minver":"2.6", "maxver":"2.6.99", "exploitdb":"8572", "lang":"c", "keywords":{"loc":["proc","pkg"], "val":"udev"}},
            "2.6.x ptrace_attach Local Privilege Escalation Exploit":{"minver":"2.6", "maxver":"2.6.99", "exploitdb":"8673", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.6.29 ptrace_attach() Local Root Race Condition Exploit":{"minver":"2.6.29", "maxver":"2.6.29", "exploitdb":"8678", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "Linux Kernel <=2.6.28.3 set_selection() UTF-8 Off By One Local Exploit":{"minver":"0", "maxver":"2.6.28.3", "exploitdb":"9083", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "Test Kernel Local Root Exploit 0day":{"minver":"2.6.18", "maxver":"2.6.30", "exploitdb":"9191", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "PulseAudio (setuid) Priv. Escalation Exploit (ubu/9.04)(slack/12.2.0)":{"minver":"2.6.9", "maxver":"2.6.30", "exploitdb":"9208", "lang":"c", "keywords":{"loc":["pkg"], "val":"pulse"}},
            "2.x sock_sendpage() Local Ring0 Root Exploit":{"minver":"2", "maxver":"2.99", "exploitdb":"9435", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.x sock_sendpage() Local Root Exploit 2":{"minver":"2", "maxver":"2.99", "exploitdb":"9436", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.4/2.6 sock_sendpage() ring0 Root Exploit (simple ver)":{"minver":"2.4", "maxver":"2.6.99", "exploitdb":"9479", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.6 < 2.6.19 (32bit) ip_append_data() ring0 Root Exploit":{"minver":"2.6", "maxver":"2.6.19", "exploitdb":"9542", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.4/2.6 sock_sendpage() Local Root Exploit (ppc)":{"minver":"2.4", "maxver":"2.6.99", "exploitdb":"9545", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "< 2.6.19 udp_sendmsg Local Root Exploit (x86/x64)":{"minver":"0", "maxver":"2.6.19", "exploitdb":"9574", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "< 2.6.19 udp_sendmsg Local Root Exploit":{"minver":"0", "maxver":"2.6.19", "exploitdb":"9575", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.4/2.6 sock_sendpage() Local Root Exploit [2]":{"minver":"2.4", "maxver":"2.6.99", "exploitdb":"9598", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.4/2.6 sock_sendpage() Local Root Exploit [3]":{"minver":"2.4", "maxver":"2.6.99", "exploitdb":"9641", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.4.1-2.4.37 and 2.6.1-2.6.32-rc5 Pipe.c Privelege Escalation":{"minver":"2.4.1", "maxver":"2.6.32", "exploitdb":"9844", "lang":"python", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "'pipe.c' Local Privilege Escalation Vulnerability":{"minver":"2.4.1", "maxver":"2.6.32", "exploitdb":"10018", "lang":"sh", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.6.18-20 2009 Local Root Exploit":{"minver":"2.6.18", "maxver":"2.6.20", "exploitdb":"10613", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "Apache Spamassassin Milter Plugin Remote Root Command Execution":{"minver":"0", "maxver":"99", "exploitdb":"11662", "lang":"sh", "keywords":{"loc":["proc"], "val":"spamass-milter"}},
            "<= 2.6.34-rc3 ReiserFS xattr Privilege Escalation":{"minver":"0", "maxver":"2.6.34", "exploitdb":"12130", "lang":"python", "keywords":{"loc":["mnt"], "val":"reiser"}},
            "Ubuntu PAM MOTD local root":{"minver":"7", "maxver":"10.04", "exploitdb":"14339", "lang":"sh", "keywords":{"loc":["os"], "val":"ubuntu"}},
            "< 2.6.36-rc1 CAN BCM Privilege Escalation Exploit":{"minver":"0", "maxver":"2.6.36", "exploitdb":"14814", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "Kernel ia32syscall Emulation Privilege Escalation":{"minver":"0", "maxver":"99", "exploitdb":"15023", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "Linux RDS Protocol Local Privilege Escalation":{"minver":"0", "maxver":"2.6.36", "exploitdb":"15285", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "<= 2.6.37 Local Privilege Escalation":{"minver":"0", "maxver":"2.6.37", "exploitdb":"15704", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "< 2.6.37-rc2 ACPI custom_method Privilege Escalation":{"minver":"0", "maxver":"2.6.37", "exploitdb":"15774", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "CAP_SYS_ADMIN to root Exploit":{"minver":"0", "maxver":"99", "exploitdb":"15916", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "CAP_SYS_ADMIN to Root Exploit 2 (32 and 64-bit)":{"minver":"0", "maxver":"99", "exploitdb":"15944", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "< 2.6.36.2 Econet Privilege Escalation Exploit":{"minver":"0", "maxver":"2.6.36.2", "exploitdb":"17787", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "Sendpage Local Privilege Escalation":{"minver":"0", "maxver":"99", "exploitdb":"19933", "lang":"ruby", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.4.18/19 Privileged File Descriptor Resource Exhaustion Vulnerability":{"minver":"2.4.18", "maxver":"2.4.19", "exploitdb":"21598", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.2.x/2.4.x Privileged Process Hijacking Vulnerability (1)":{"minver":"2.2", "maxver":"2.4.99", "exploitdb":"22362", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "2.2.x/2.4.x Privileged Process Hijacking Vulnerability (2)":{"minver":"2.2", "maxver":"2.4.99", "exploitdb":"22363", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "Samba 2.2.8 Share Local Privilege Elevation Vulnerability":{"minver":"2.2.8", "maxver":"2.2.8", "exploitdb":"23674", "lang":"c", "keywords":{"loc":["proc","pkg"], "val":"samba"}},
            "open-time Capability file_ns_capable() - Privilege Escalation Vulnerability":{"minver":"0", "maxver":"99", "exploitdb":"25307", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
            "open-time Capability file_ns_capable() Privilege Escalation":{"minver":"0", "maxver":"99", "exploitdb":"25450", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
    }

    # variable declaration
    os = sysInfo["OS"]["results"][0]
    version = sysInfo["KERNEL"]["results"][0].split(" ")[2].split("-")[0]
    langs = devTools["TOOLS"]["results"]
    procs = getAppProc["PROCS"]["results"]
    kernel = str(sysInfo["KERNEL"]["results"][0])
    mount = driveInfo["MOUNT"]["results"]
    #pkgs = getAppProc["PKGS"]["results"] # currently not using packages for sploit appicability but my in future


    # lists to hold ranked, applicable sploits
    # note: this is a best-effort, basic ranking designed to help in prioritizing priv escalation exploit checks
    # all applicable exploits should be checked and this function could probably use some improvement
    avgprob = []
    highprob = []

    for sploit in sploits:
        lang = 0 # use to rank applicability of sploits
        keyword = sploits[sploit]["keywords"]["val"]
        sploitout = sploit + " || " + "http://www.exploit-db.com/exploits/" + sploits[sploit]["exploitdb"] + " || " + "Language=" + sploits[sploit]["lang"]
        # first check for kernell applicability
        if (version >= sploits[sploit]["minver"]) and (version <= sploits[sploit]["maxver"]):
            # next check language applicability
            if (sploits[sploit]["lang"] == "c") and (("gcc" in str(langs)) or ("cc" in str(langs))):
                lang = 1 # language found, increase applicability score 
            elif sploits[sploit]["lang"] == "sh": 
                lang = 1 # language found, increase applicability score 
            elif (sploits[sploit]["lang"] in str(langs)):
                lang = 1 # language found, increase applicability score
            if lang == 0:
                sploitout = sploitout + "**" # added mark if language not detected on system 
            # next check keyword matches to determine if some sploits have a higher probability of success
            for loc in sploits[sploit]["keywords"]["loc"]:
                if loc == "proc":
                    for proc in procs:
                        if keyword in proc:
                            highprob.append(sploitout) # if sploit is associated with a running process consider it a higher probability/applicability
                            break
                            break
                elif loc == "os":
                    if (keyword in os) or (keyword in kernel):
                        highprob.append(sploitout) # if sploit is specifically applicable to this OS consider it a higher probability/applicability
                        break  
                elif loc == "mnt":
                    if keyword in mount:
                        highprob.append(sploitout) # if sploit is specifically applicable to a mounted file system consider it a higher probability/applicability
                        break
                else:
                    avgprob.append(sploitout) # otherwise, consider average probability/applicability based only on kernel version

    print "    Note: Exploits relying on a compile/scripting language not detected on this system are marked with a '**' but should still be tested!"
    print

    print "    The following exploits are ranked higher in probability of success because this script detected a related running process, OS, or mounted file system" 
    for exploit in highprob:
        print "    - " + exploit
    print

    print "    The following exploits are applicable to this kernel version and should be investigated as well"
    for exploit in avgprob:
        print "    - " + exploit

    print   
    print "Finished"
    print bigline


callFunctionLinux()

"""
        return script
