"""

Empire encryption functions.

Includes:

    pad()                       -   performs PKCS#7 padding
    depad()                     -   Performs PKCS#7 depadding
    rsa_xml_to_key()            -   parses a PowerShell RSA xml import and builds a M2Crypto object
    rsa_encrypt()               -   encrypts data using the M2Crypto crypto object
    aes_encrypt()               -   encrypts data using a pyCrypto AES object
    aes_encrypt_then_hmac()     -   encrypts and SHA256 HMACs data using a pyCrypto AES object
    aes_decrypt()               -   decrypts data using a pyCrypto AES object
    verify_hmac()               -   verifies a SHA256 HMAC for a data blob
    aes_decrypt_and_verify()    -   AES decrypts data if the HMAC is validated
    generate_aes_key()          -   generates a ranodm AES key using pyCrypto's Random functionality
    rc4()                       -   encrypt/decrypt a data blob using an RC4 key
    DiffieHellman()             -   Mark Loiseau's DiffieHellman implementation, see ./data/licenses/ for license info

"""

import base64
import hashlib
import hmac
import string
import M2Crypto

from xml.dom.minidom import parseString
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random
from binascii import hexlify


def to_bufferable(binary):
    return binary

def _get_byte(c):
    return ord(c)

# Python 3 compatibility stuffz
try:
    xrange
except Exception:
    xrange = range

    def to_bufferable(binary):
        if isinstance(binary, bytes):
            return binary
        return bytes(ord(b) for b in binary)

    def _get_byte(c):
        return c

# If a secure random number generator is unavailable, exit with an error.
try:
    import ssl
    random_function = ssl.RAND_bytes
    random_provider = "Python SSL"
except (AttributeError, ImportError):
    import OpenSSL
    random_function = OpenSSL.rand.bytes
    random_provider = "OpenSSL"


def pad(data):
    """
    Performs PKCS#7 padding for 128 bit block size.
    """

    pad = 16 - (len(data) % 16)
    return data + to_bufferable(chr(pad) * pad)

    # return str(s) + chr(16 - len(str(s)) % 16) * (16 - len(str(s)) % 16)


def depad(data):
    """
    Performs PKCS#7 depadding for 128 bit block size.
    """
    if len(data) % 16 != 0:
        raise ValueError("invalid length")

    pad = _get_byte(data[-1])
    return data[:-pad]

    # return s[:-(ord(s[-1]))]


def rsa_xml_to_key(xml):
    """
    Parse powershell RSA.ToXmlString() public key string and
    return a M2Crypto key object.

    Used during PowerShell RSA-EKE key exchange in agents.py.

    Reference- http://stackoverflow.com/questions/10367072/m2crypto-import-keys-from-non-standard-file
    """
    try:
        # parse the xml DOM and extract the exponent/modulus
        dom = parseString(xml)
        e = base64.b64decode(dom.getElementsByTagName('Exponent')[0].childNodes[0].data)
        n = base64.b64decode(dom.getElementsByTagName('Modulus')[0].childNodes[0].data)

        # build the new key
        key = M2Crypto.RSA.new_pub_key((
            M2Crypto.m2.bn_to_mpi(M2Crypto.m2.hex_to_bn(hexlify(e))),
            M2Crypto.m2.bn_to_mpi(M2Crypto.m2.hex_to_bn(hexlify(n))),
            ))

        return key
    # if there's an XML parsing error, return None
    except:
        return None


def rsa_encrypt(key, data):
    """
    Take a M2Crypto key object and use it to encrypt the passed data.
    """
    return key.public_encrypt(data, M2Crypto.RSA.pkcs1_padding)


def aes_encrypt(key, data):
    """
    Generate a random IV and new AES cipher object with the given
    key, and return IV + encryptedData.
    """
    IV = Random.new().read(16)
    cipher = AES.new(key, AES.MODE_CBC, IV)
    return IV + cipher.encrypt(pad(data))


def aes_encrypt_then_hmac(key, data):
    """
    Encrypt the data then calculate HMAC over the ciphertext.
    """
    data = aes_encrypt(key, data)
    mac = hmac.new(str(key), data, hashlib.sha256).digest()
    return data + mac[0:10]


def aes_decrypt(key, data):
    """
    Generate an AES cipher object, pull out the IV from the data
    and return the unencrypted data.
    """
    if len(data) > 16:
        IV = data[0:16]
        cipher = AES.new(key, AES.MODE_CBC, IV)
        return depad(cipher.decrypt(data[16:]))


def verify_hmac(key, data):
    """
    Verify the HMAC supplied in the data with the given key.
    """
    if len(data) > 20:
        mac = data[-10:]
        data = data[:-10]
        expected = hmac.new(key, data, hashlib.sha256).digest()[0:10]
        # Double HMAC to prevent timing attacks. hmac.compare_digest() is
        # preferable, but only available since Python 2.7.7.
        return hmac.new(str(key), expected).digest() == hmac.new(str(key), mac).digest()
    else:
        return False


def aes_decrypt_and_verify(key, data):
    """
    Decrypt the data, but only if it has a valid MAC.
    """
    if len(data) <= 32:
        raise Exception("Invalid ciphertext length received.")
    if not verify_hmac(key, data):
        raise Exception("Invalid hmac received.")
    #if len(data) > 32 and verify_hmac(key, data):
    return aes_decrypt(key, data[:-10])
    #raise Exception("Invalid ciphertext received.")


def generate_aes_key():
    """
    Generate a random new 128-bit AES key using Pycrypto's secure Random functions.
    """
    punctuation = '!#$%&()*+,-./:;<=>?@[\]^_`{|}~'
    return ''.join(random.sample(string.ascii_letters + string.digits + '!#$%&()*+,-./:;<=>?@[\]^_`{|}~', 32))


def rc4(key, data):
    """
    RC4 encrypt/decrypt the given data input with the specified key.

    From: http://stackoverflow.com/questions/29607753/how-to-decrypt-a-file-that-encrypted-with-rc4-using-python
    """

    S, j, out = range(256), 0, []

    # KSA Phase
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA Phase
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))

    return ''.join(out)


class DiffieHellman(object):
    """
    A reference implementation of the Diffie-Hellman protocol.
    By default, this class uses the 6144-bit MODP Group (Group 17) from RFC 3526.
    This prime is sufficient to generate an AES 256 key when used with
    a 540+ bit exponent.

    Authored by Mark Loiseau's implementation at https://github.com/lowazo/pyDHE
        version 3.0 of the GNU General Public License
        see ./data/licenses/pyDHE_license.txt for license info

    Also used in ./data/agent/stager.py for the Python key-negotiation stager
    """

    def __init__(self, generator=2, group=17, keyLength=540):
        """
        Generate the public and private keys.
        """
        min_keyLength = 180

        default_generator = 2
        valid_generators = [2, 3, 5, 7]

        # Sanity check fors generator and keyLength
        if(generator not in valid_generators):
            print("Error: Invalid generator. Using default.")
            self.generator = default_generator
        else:
            self.generator = generator

        if(keyLength < min_keyLength):
            print("Error: keyLength is too small. Setting to minimum.")
            self.keyLength = min_keyLength
        else:
            self.keyLength = keyLength

        self.prime = self.getPrime(group)

        self.privateKey = self.genPrivateKey(keyLength)
        self.publicKey = self.genPublicKey()

    def getPrime(self, group=17):
        """
        Given a group number, return a prime.
        """
        default_group = 17

        primes = {
        5:  0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
        14: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
        15: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF,
        16: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF,
        17:
        0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF,
        18:
        0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF
        }

        if group in primes.keys():
            return primes[group]
        else:
            print("Error: No prime with group %i. Using default." % group)
            return primes[default_group]

    def genRandom(self, bits):
        """
        Generate a random number with the specified number of bits
        """
        _rand = 0
        _bytes = bits // 8 + 8

        while(len(bin(_rand))-2 < bits):
            try:
                # Python 3
                _rand = int.from_bytes(random_function(_bytes), byteorder='big')
            except:
                # Python 2
                _rand = int(OpenSSL.rand.bytes(_bytes).encode('hex'), 16)

        return _rand

    def genPrivateKey(self, bits):
        """
        Generate a private key using a secure random number generator.
        """
        return self.genRandom(bits)

    def genPublicKey(self):
        """
        Generate a public key X with g**x % p.
        """
        return pow(self.generator, self.privateKey, self.prime)

    def checkPublicKey(self, otherKey):
        """
        Check the other party's public key to make sure it's valid.
        Since a safe prime is used, verify that the Legendre symbol == 1
        """
        if(otherKey > 2 and otherKey < self.prime - 1):
            if(pow(otherKey, (self.prime - 1)//2, self.prime) == 1):
                return True
        return False

    def genSecret(self, privateKey, otherKey):
        """
        Check to make sure the public key is valid, then combine it with the
        private key to generate a shared secret.
        """
        if(self.checkPublicKey(otherKey) is True):
            sharedSecret = pow(otherKey, privateKey, self.prime)
            return sharedSecret
        else:
            raise Exception("Invalid public key.")

    def genKey(self, otherKey):
        """
        Derive the shared secret, then hash it to obtain the shared key.
        """
        self.sharedSecret = self.genSecret(self.privateKey, otherKey)

        # Convert the shared secret (int) to an array of bytes in network order
        # Otherwise hashlib can't hash it.
        try:
            _sharedSecretBytes = self.sharedSecret.to_bytes(
                len(bin(self.sharedSecret))-2 // 8 + 1, byteorder="big")
        except AttributeError:
            _sharedSecretBytes = str(self.sharedSecret)

        s = hashlib.sha256()
        s.update(bytes(_sharedSecretBytes))
        self.key = s.digest()

    def getKey(self):
        """
        Return the shared secret key
        """
        return self.key
