
import os, base64, urllib
from pyparsing import *
from utility import MalleableError, MalleableUtil, MalleableObject

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# TRANSFORMATION
#
# Defining the model through which arbitrary data can undergo
# reversable transformations.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

class Transform(MalleableObject):
    """A class housing the arbitrary functionality of a reversable transformation.

    Attributes:
        type (int): Type of Transform to implement.
        arg (str): Argument to pass to the implementation.

    Functions:
        transform (func): Execute the forward transformation on an arbitrary string.
            Args:
                data (str): The data to be transformed.
            Returns:
                str: The transformed data.
        transform_r (func): Execute the reverse transformation on an arbitrary string.
            Args:
                data (str): The data to be transformed.
            Returns:
                str: The transformed data.
        generate_python (func): Generate the python code that would execute the
            transformation on an arbitrary string using the given variable name.
            Args:
                var (str): The variable name to be used in the code.
            Returns:
                str: The python code that would execute the transformation on an arbitrary
                    string.
        generate_python_r (func): Generate the python code that would execute the
            reverse transformation on an arbitrary string using the given variable name.
            Args:
                var (str): The variable name to be used in the code.
            Returns:
                str: The python code that would execute the reverse transformation on an
                    arbitrary string.
        generate_powershell (func): Generate the powershell code that would execute the
            transformation on an arbitrary string using the given variable name.
            Args:
                var (str): The variable name to be used in the code.
            Returns:
                str: The powershell code that would execute the transformation on an arbitrary
                    string.
        generate_powershell_r (func): Generating the powershell code that would
            execute the reverse transformation on an arbitrary string using the given variable name.
            Args:
                var (str): The variable name to be used in the code.
            Returns:
                str: The powershell code that would execute the reverse transformation on an
                    arbitrary string.
    """
    NONE = 0
    APPEND = 1
    BASE64 = 2
    BASE64URL = 3
    MASK = 4
    NETBIOS = 5
    NETBIOSU = 6
    PREPEND = 7

    def __init__(self, type=0, arg=None):
        """Constructor for a Transform object.

        Args:
            type (int, optional): Choose the type of Transform to implement.
            arg (str, optional): Argument to pass to the implementation.
        """
        self.type = type
        self.arg = arg
        super(Transform, self).__init__()

    def _defaults(self):
        """Default initialization for the Transform object."""
        super(Transform, self)._defaults()
        self.apply_transform(self.type, self.arg)

    def _clone(self):
        """Deep copy of a Transform object.

        Returns:
            Transform object
        """
        new = super(Transform, self)._clone()
        new.type = self.type
        new.arg = self.arg
        new.apply_transform(new.type, new.arg)
        return new

    def _serialize(self):
        """Serialize the Transform object.

        Returns:
            dict (str, obj)
        """
        return dict(super(Transform, self)._serialize().items() + {
            "type" : self.type,
            "arg" : self.arg if self.type != Transform.MASK else MalleableUtil.to_hex(self.arg[0])
        }.items())

    @classmethod
    def _deserialize(cls, data):
        """Deserialize data into a Transform object.

        Args:
            dict (str, obj): Serialized data (json)

        Returns:
            Transform object
        """
        transform = super(Transform, cls)._deserialize(data)
        if data:
            transform.type = data["type"] if "type" in data else Transform.NONE
            transform.arg = (data["arg"] if transform.type != Transform.MASK else MalleableUtil.from_hex(data["arg"])) if "arg" in data else None
            transform.apply_transform(transform.type, transform.arg)
        return transform

    @classmethod
    def _pattern(cls):
        """Define the pattern to recognize a Transform object while parsing a file.

        Returns:
            pyparsing object
        """
        return (
            Group(Literal("append") + cls.VALUE) |
            Group(Literal("base64url")) |
            Group(Literal("base64")) |
            Group(Literal("mask")) |
            Group(Literal("netbiosu")) |
            Group(Literal("netbios")) |
            Group(Literal("prepend") + cls.VALUE)
        ) + cls.SEMICOLON

    def apply_transform(self, type, arg):
        """Apply the appropriate transformation to the Transform object.

        Args:
            type (int): Type of Transform to implement.
            arg (str): Argument to pass to the implementation.
        """
        if type == Transform.APPEND: self._append(arg)
        elif type == Transform.BASE64: self._base64()
        elif type == Transform.BASE64URL: self._base64url()
        elif type == Transform.MASK: self._mask(arg)
        elif type == Transform.NETBIOS: self._netbios()
        elif type == Transform.NETBIOSU: self._netbiosu()
        elif type == Transform.PREPEND: self._prepend(arg)
        else: self._none()

    def _none(self):
        """Configure the `none` Transform, which does nothing."""
        self.transform = lambda data: data,
        self.transform_r = lambda data: data,
        self.generate_python = lambda var: "",
        self.generate_python_r = lambda var: "",
        self.generate_powershell = lambda var: "",
        self.generate_powershell_r = lambda var: ""

    def _append(self, string):
        """Configure the `append` Transform, which appends a static string to an arbitrary input.

        Args:
            string (str): The static string to be appended.

        Raises:
            MalleableError: If `string` is null.
        """
        if string is None:
            MalleableError.throw(Transform.__class__, "append", "string argument must not be null")
        self.transform = lambda data: data + string
        self.transform_r = lambda data: data[:-len(string)]
        self.generate_python = lambda var: "%(var)s+='%(string)s'\n" % {"var":var, "string":string}
        self.generate_python_r = lambda var: "%(var)s=%(var)s[:-%(len)i]\n" % {"var":var, "len":len(string)}
        self.generate_powershell = lambda var: "%(var)s+='%(string)s';" % {"var":var, "string":string}
        self.generate_powershell_r = lambda var: "%(var)s=%(var)s.Substring(0,%(var)s.Length-%(len)i);" % {"var":var, "len":len(string)}

    def _base64(self):
        """Configure the `base64` Transform, which base64 encodes an arbitrary input."""
        self.transform = lambda data: base64.b64encode(data)
        self.transform_r = lambda data: base64.b64decode(data)
        self.generate_python = lambda var: "%(var)s=base64.b64encode(%(var)s)\n" % {"var":var}
        self.generate_python_r = lambda var: "%(var)s=base64.b64decode(%(var)s)\n" % {"var":var}
        self.generate_powershell = lambda var: "%(var)s=[Convert]::ToBase64String([System.Text.Encoding]::Default.GetBytes(%(var)s));" % {"var":var}
        self.generate_powershell_r = lambda var: "%(var)s=[System.Text.Encoding]::Default.GetString([System.Convert]::FromBase64String(%(var)s));" % {"var":var}

    def _base64url(self):
        """Configure the `base64url` Transform, which base64 encodes an arbitary input using url-safe characters."""
        self.transform = lambda data: urllib.quote(base64.b64encode(data))
        self.transform_r = lambda data: base64.b64decode(urllib.unquote(data))
        self.generate_python = lambda var: "%(var)s=urllib.quote(base64.b64encode(%(var)s))\n" % {"var":var}
        self.generate_python_r = lambda var: "%(var)s=base64.b64decode(urllib.unquote(%(var)s))\n" % {"var":var}
        self.generate_powershell = lambda var: "Add-Type -AssemblyName System.Web;%(var)s=[System.Web.HttpUtility]::UrlEncode([System.Convert]::ToBase64string([System.Text.Encoding]::Default.GetBytes(%(var)s)));" % {"var":var}
        self.generate_powershell_r = lambda var: "Add-Type -AssemblyName System.Web;%(var)s=[System.Text.Encoding]::Default.GetString([System.Convert]::FromBase64String([System.Web.HttpUtility]::UrlDecode(%(var)s)));" % {"var":var}

    def _mask(self, key):
        """Configure the `mask` Transform, which encodes an arbitrary input using the XOR operation
        and a random key.

        Args:
            key (str): The key with which to encode / decode.

        Raises:
            MalleableError: If `key` is null or empty.
        """
        if not key:
            MalleableError.throw(Transform.__class__, "mask", "key argument must not be empty")
        self.transform = lambda data: "".join([chr(ord(c)^ord(key[0])) for c in data])
        self.transform_r = self.transform
        self.generate_python = lambda var: "%(var)s=''.join([chr(ord(_)^%(key)s) for _ in %(var)s])\n" % {"key":ord(key[0]), "var":var}
        self.generate_python_r = self.generate_python
        self.generate_powershell = lambda var: "%(var)s=[System.Text.Encoding]::Default.GetString($(for($_=0;$_ -lt %(var)s.length;$_++){[System.Text.Encoding]::Default.GetBytes(%(var)s)[$_] -bxor %(key)s}));" % {"key":ord(key[0]), "var":var}
        self.generate_powershell_r = self.generate_powershell

    def _netbios(self):
        """Configure the `netbios` Transform, which encodes an arbitrary input using the lower-case
        netbios algorithm."""
        self.transform = lambda data: "".join([chr((ord(c)>>4)+0x61)+chr((ord(c)&0xF)+0x61) for c in data])
        self.transform_r = lambda data: "".join([chr(((ord(data[i])-0x61)<<4)|((ord(data[i+1])-0x61)&0xF)) for i in range(0, len(data), 2)])
        self.generate_python = lambda var: "%(var)s=''.join([chr((ord(_)>>4)+0x61)+chr((ord(_)&0xF)+0x61) for _ in %(var)s])\n" % {"var":var}
        self.generate_python_r = lambda var: "%(var)s=''.join([chr(((ord(%(var)s[_])-0x61)<<4)|((ord(%(var)s[_+1])-0x61)&0xF)) for _ in range(0,len(%(var)s),2)])\n" % {"var":var}
        self.generate_powershell = lambda var: "%(var)s=[System.Text.Encoding]::Default.GetString($(for($_=0;$_ -lt %(var)s.length;$_++){([System.Text.Encoding]::Default.GetBytes(%(var)s)[$_] -shr 4)+97;([System.Text.Encoding]::Default.GetBytes(%(var)s)[$_] -band 15)+97;}));" % {"var":var}
        self.generate_powershell_r = lambda var: "%(var)s=[System.Text.Encoding]::Default.GetString($(for($_=0;$_ -lt %(var)s.length;$_+=2){(([System.Text.Encoding]::Default.GetBytes(%(var)s)[$_]-97) -shl 4) -bor (([System.Text.Encoding]::Default.GetBytes(%(var)s)[$_+1]-97) -band 15);}));" % {"var":var}

    def _netbiosu(self):
        """Configure the `netbiosu` Transform, which encodes an arbitrary input using the upper-case
        netbios algorithm."""
        self.transform = lambda data: "".join([chr((ord(c)>>4)+0x41)+chr((ord(c)&0xF)+0x41) for c in data])
        self.transform_r = lambda data: "".join([chr(((ord(data[i])-0x41)<<4)|((ord(data[i+1])-0x41)&0xF)) for i in range(0, len(data), 2)])
        self.generate_python = lambda var: "%(var)s=''.join([chr((ord(_)>>4)+0x41)+chr((ord(_)&0xF)+0x41) for _ in %(var)s])\n" % {"var":var}
        self.generate_python_r = lambda var: "%(var)s=''.join([chr(((ord(%(var)s[_])-0x41)<<4)|((ord(%(var)s[_+1])-0x41)&0xF)) for _ in range(0,len(%(var)s),2)])\n" % {"var":var}
        self.generate_powershell = lambda var: "%(var)s=[System.Text.Encoding]::Default.GetString($(for($_=0;$_ -lt %(var)s.length;$_++){([System.Text.Encoding]::Default.GetBytes(%(var)s)[$_] -shr 4)+65;([System.Text.Encoding]::Default.GetBytes(%(var)s)[$_] -band 15)+65;}));" % {"var":var}
        self.generate_powershell_r = lambda var: "%(var)s=[System.Text.Encoding]::Default.GetString($(for($_=0;$_ -lt %(var)s.length;$_+=2){(([System.Text.Encoding]::Default.GetBytes(%(var)s)[$_]-65) -shl 4) -bor (([System.Text.Encoding]::Default.GetBytes(%(var)s)[$_+1]-65) -band 15);}));" % {"var":var}

    def _prepend(self, string):
        """Configure the `prepend` Transform, which prepends a static string to an arbitrary input.

        Args:
            string (str): The static string to be prepended.

        Raises:
            MalleableError: If `string` is null.
        """
        if string is None:
            MalleableError.throw(Transform.__class__, "prepend", "string argument must not be null")
        self.transform = lambda data: string + data
        self.transform_r = lambda data: data[len(string):]
        self.generate_python = lambda var: "%(var)s='%(string)s'+%(var)s\n" % {"var":var, "string":string}
        self.generate_python_r = lambda var: "%(var)s=%(var)s[%(len)i:]\n" % {"var":var, "len":len(string)}
        self.generate_powershell = lambda var: "%(var)s='%(string)s'+%(var)s;" % {"var":var, "string":string}
        self.generate_powershell_r = lambda var: "%(var)s=%(var)s.substring(%(len)i,%(var)s.Length-%(len)i);" % {"var":var, "len":len(string)}

class Terminator(MalleableObject):
    """A class housing the arbitrary functionality of a reversable data storage mechanism.

    The Terminator defines where data is stored after completing a Transform sequence and where
    to retrieve data before starting a reverse Transform sequence.

    Attributes:
        type (int): Type of Terminator to implement.
        arg (str): Argument to pass to the implementation.
    """
    NONE = 0
    PRINT = 1
    HEADER = 2
    PARAMETER = 3
    URIAPPEND = 4

    def __init__(self, type=1, arg=None):
        """Constructor for a Terminator object

        Args:
            type (int, optional): Type of Terminator to implement.
            arg (str, optional): Argument to pass to the implementation.
        """
        self.type = type
        self.arg = arg
        super(Terminator, self).__init__()

    def _clone(self):
        """Deep copy of a Terminator object.

        Returns:
            Terminator
        """
        new = super(Terminator, self)._clone()
        new.type = self.type
        new.arg = self.arg
        return new

    def _serialize(self):
        """Serialize the Terminator object.

        Returns:
            dict (str, obj)
        """
        return dict(super(Terminator, self)._serialize().items() + {
            "type" : self.type,
            "arg" : self.arg
        }.items())

    @classmethod
    def _deserialize(cls, data):
        """Deserialize data into a Terminator object.

        Args:
            dict (str, obj): Serialized data (json)

        Returns:
            Terminator object
        """
        terminator = super(Terminator, cls)._deserialize(data)
        if data:
            terminator.type = data["type"] if "type" in data else Terminator.NONE
            terminator.arg = data["arg"] if "arg" in data else None
        return terminator

    @classmethod
    def _pattern(cls):
        """Define the pattern to recognize a Terminator object while parsing a file.

        Returns:
            pyparsing object
        """
        return (
            Group(Literal("header") + cls.VALUE) |
            Group(Literal("parameter") + cls.VALUE) |
            Group(Literal("print")) |
            Group(Literal("uri-append"))
        ) + cls.SEMICOLON

class Container(MalleableObject):
    """A class housing a sequence of Transforms.

    Once initialized, a Container object can be used in the following ways:
        - Add a Transform to the existing sequence.
        - Assign a Terminator to the Transform sequence.
        - Execute the sequence of Transforms.

    Attributes:
        transforms (list (Transform))
        terminator (Terminator)
    """

    def _defaults(self):
        """Default initialization for the Container object."""
        super(Container, self)._defaults()
        self.transforms = []
        self.terminator = Terminator()

    def _clone(self):
        """Deep copy of the Container object.

        Returns:
            Container
        """
        new = super(Container, self)._clone()
        new.transforms = [t._clone() for t in self.transforms]
        new.terminator = self.terminator._clone()
        return new

    def _serialize(self):
        """Serialize the Container object.

        Returns:
            dict (str, obj): Serialized data (json)
        """
        return dict(super(Container, self)._serialize().items() + {
            "transforms" : [t._serialize() for t in self.transforms],
            "terminator" : self.terminator._serialize()
        }.items())

    @classmethod
    def _deserialize(cls, data):
        """Deserialize data into a Container object.

        Args:
            dict (str, obj): Serialized data (json)

        Returns:
            Container object
        """
        container = super(Container, cls)._deserialize(data)
        if data:
            container.transforms = [Transform._deserialize(d) for d in data["transforms"]] if "transforms" in data else []
            container.terminator = Terminator._deserialize(data["terminator"]) if "terminator" in data else Terminator()
        return container

    @classmethod
    def _pattern(cls):
        """Define the pattern to recognize a Container object while parsing a file.

        Returns:
            pyparsing object
        """
        return (cls.FIELD + Group(Suppress("{") + ZeroOrMore(
                cls.COMMENT |
                Transform._pattern() |
                Terminator._pattern()
            ) + Suppress("}")))

    def _parse(self, data):
        """Store the information from a parsed pyparsing result.

        Args:
            data: pyparsing data
        """
        if data:
            for item in [d for d in data if d]:
                type = item[0]
                arg = item[1] if len(item) > 1 else None
                if type:
                    type = type.lower()
                    if type == "append": self.append(arg)
                    elif type == "base64": self.base64()
                    elif type == "base64url": self.base64url()
                    elif type == "mask": self.mask()
                    elif type == "netbios": self.netbios()
                    elif type == "netbiosu": self.netbiosu()
                    elif type == "prepend": self.prepend(arg)

                    elif type == "print": self.print_()
                    elif type == "header": self.header(arg)
                    elif type == "parameter": self.parameter(arg)
                    elif type == "uri-append": self.uriappend()

    def append(self, string):
        """Add the `append` Transform to the Container's Transform sequence.

        Args:
            string (str): The static string to be appended.
        """
        self.transforms.append(Transform(type=Transform.APPEND, arg=string))

    def base64(self):
        """Add the `base64` Transform to the Container's Transform sequence."""
        self.transforms.append(Transform(type=Transform.BASE64))

    def base64url(self):
        """Add the `base64url` Transform to the Container's Transform sequence."""
        self.transforms.append(Transform(type=Transform.BASE64URL))

    def mask(self, key=None):
        """Add the `mask` Transform to the Container's Transform sequence.

        Args:
            key (str, optional): The key with which to encode / decode.
        """
        if not key:
            key = os.urandom(1)
        while (ord(key) < 0 or ord(key) > 127): key = os.urandom(1)  # Requirement for powershell
        self.transforms.append(Transform(type=Transform.MASK, arg=key))

    def netbios(self):
        """Add the `netbios` Transform to the Container's Transform sequence."""
        self.transforms.append(Transform(type=Transform.NETBIOS))

    def netbiosu(self):
        """Add the `netbiosu` Transform to the Container's Transform sequence."""
        self.transforms.append(Transform(type=Transform.NETBIOSU))

    def prepend(self, string):
        """Add the `prepend` Transform to the Container's Transform sequence.

        Args:
            string (str): The static string to be prepended.
        """
        self.transforms.append(Transform(type=Transform.PREPEND, arg=string))

    def print_(self):
        """Specify that the data be stored in the request body after transformation."""
        self.terminator = Terminator(type=Terminator.PRINT)

    def header(self, header):
        """Use the specified header to store the data after transformation.

        Args:
            header (str)

        Rasie:
            MalleableError: If `header` is empty.
        """
        if not header:
            MalleableError.throw(Container, "header", "argument must not be null")
        self.terminator = Terminator(type=Terminator.HEADER, arg=header)

    def parameter(self, parameter):
        """Use the specified parameter to store the data after transformation.

        Args:
            parameter (str)

        Rasie:
            MalleableError: If `parameter` is empty.
        """
        if not parameter:
            MalleableError.throw(Container, "parameter", "argument must not be null")
        self.terminator = Terminator(type=Terminator.PARAMETER, arg=parameter)

    def uriappend(self):
        """Specify that the data append to the uri after transformation."""
        self.terminator = Terminator(type=Terminator.URIAPPEND)

    def transform(self, data):
        """Transform the provided data using the sequence of Transforms.

        Args:
            data (str): The data to be transformed.

        Returns:
            str: The transformed data.
        """
        if data is None: data = ""
        for t in self.transforms:
            data = t.transform(data)
        return data

    def transform_r(self, data):
        """Transform the provided data using the sequence of Transforms in reverse.

        Args:
            data (str): The data to be reverse-transformed.

        Returns:
            str: The reverse-transformed data.
        """
        if data is None: data = ""
        for t in self.transforms[::-1]:
            data = t.transform_r(data)
        return data

    def generate_python(self, var):
        """Generate python code that would transform arbitrary data using the sequence
            of Transforms.

        Args:
            var (str): The variable name to be used in the python code.

        Returns:
            str: The python code.

        Raises:
            MalleableError: If `var` is empty.
        """
        if not var:
            MalleableError.throw(Container, "generate_python", "var must not be empty")
        code = ""
        for t in self.transforms:
            code += t.generate_python(var)
        return code

    def generate_python_r(self, var):
        """Generate python code that would transform arbitrary data using the sequence
            of Transforms in reverse.

        Args:
            var (str): The variable name to be used in the python code.

        Returns:
            str: The python code.

        Raises:
            MalleableError: If `var` is empty.
        """
        if not var:
            MalleableError.throw(Container, "generate_python_r", "var must not be empty")
        code = ""
        for t in self.transforms[::-1]:
            code += t.generate_python_r(var)
        return code

    def generate_powershell(self, var):
        """Generate powershell code that would transform arbitrary data using the sequence
            of Transforms.

        Args:
            var (str): The variable name to be used in the powershell code.

        Returns:
            str: The powershell code.

        Raises:
            MalleableError: If `var` is empty.
        """
        if not var:
            MalleableError.throw(Container, "generate_powershell", "var must not be empty")
        code = ""
        for t in self.transforms:
            code += t.generate_powershell(var)
        return code

    def generate_powershell_r(self, var):
        """Generate powershell code that would transform arbitrary data using the sequence
            of Transforms in reverse.

        Args:
            var (str): The variable name to be used in the powershell code.

        Returns:
            str: The powershell code.

        Raises:
            MalleableError: If `var` is empty.
        """
        if not var:
            MalleableError.throw(Container, "generate_powershell_r", "var must not be empty")
        code = ""
        for t in self.transforms[::-1]:
            code += t.generate_powershell_r(var)
        return code
