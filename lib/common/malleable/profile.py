import os, string
from pyparsing import *
from utility import MalleableError, MalleableUtil, MalleableObject
from transformation import Transform, Terminator, Container
from transaction import MalleableRequest, MalleableResponse, Transaction
from implementation import Get, Post, Stager

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# PROFILE
#
# Defining the top-layer object to be interacted with.
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

class Profile(MalleableObject):
    """A class housing all the functionality of a Malleable C2 profile.

    Attributes:
        get (Get (Transaction))
        post (Post (Transaction))
        stager (Stager (Transaction))

        useragent (str, property)
        sleeptime (int) [milliseconds]
        jitter (int) [percent]
    """

    def _defaults(self):
        """Default initialization for the Profile object."""
        super(Profile, self)._defaults()
        self.get = Get()
        self.post = Post()
        self.stager = Stager()
        self.sleeptime = 60000
        self.jitter = 0

    def _clone(self):
        """Deep copy of the Profile object.

        Returns:
            Profile
        """
        new = super(Profile, self)._clone()
        new.get = self.get._clone()
        new.post = self.post._clone()
        new.stager = self.stager._clone()
        new.sleeptime = self.sleeptime
        new.jitter = self.jitter
        return new

    def _serialize(self):
        """Serialize the Profile object.

        Returns:
            dict (str, obj): Serialized data (json)
        """
        return dict(super(Profile, self)._serialize().items() + {
            "get" : self.get._serialize(),
            "post" : self.post._serialize(),
            "stager" : self.stager._serialize(),
            "sleeptime" : self.sleeptime,
            "jitter" : self.jitter
        }.items())

    @classmethod
    def _deserialize(cls, data):
        """Deserialize data into a Profile object.

        Args:
            data (dict (str, obj)): Serialized data (json)

        Returns:
            Profile object
        """
        profile = super(Profile, cls)._deserialize(data)
        if data:
            try:
                profile.get = Get._deserialize(data["get"]) if "get" in data else Get()
                profile.post = Post._deserialize(data["post"] if "post" in data else Post())
                profile.stager = Stager._deserialize(data["stager"] if "stager" in data else Stager())
                profile.sleeptime = int(data["sleeptime"]) if "sleeptime" in data else 60000
                profile.jitter = int(data["jitter"]) if "jitter" in data else 0
            except Exception as e:
                MalleableError.throw(cls, "_deserialize", "An error occurred: " + str(e))
        return profile

    @classmethod
    def _pattern(cls):
        """Define the pattern to recognize a Profile object while parsing a file.

        Returns:
            pyparsing object
        """
        return ZeroOrMore(
            cls.COMMENT |
            (Literal("set") + Group(cls.FIELD + cls.VALUE) + cls.SEMICOLON) |
            Get._pattern() |
            Post._pattern() |
            Stager._pattern())

    def _parse(self, data):
        """Store the information from a parsed pyparsing result.

        Args:
            data: pyparsing data
        """
        if data:
            for group in [d for d in data if d]:
                for i in range(0, len(group), 2):
                    item = group[i]
                    arg = group[i+1] if len(group) > i+1 else None
                    if item and arg:
                        if item.lower() == "set" and len(arg) > 1:
                            key, value = arg[0], arg[1]
                            if key and value:
                                setattr(self, key, value)
                        elif item.lower() == "http-get":
                            self.get._parse(arg)
                        elif item.lower() == "http-post":
                            self.post._parse(arg)
                        elif item.lower() == "http-stager":
                            self.stager._parse(arg)

    @property
    def useragent(self):
        """Get the profile useragent.

        Returns:
            str: useragent
        """
        return self.get.client.headers["User-Agent"] if "User-Agent" in self.get.client.headers else None

    @useragent.setter
    def useragent(self, useragent):
        """Set the profile useragent.

        Args:
            useragent (str)
        """
        self.get.client.headers["User-Agent"] = useragent
        self.post.client.headers["User-Agent"] = useragent
        self.stager.client.headers["User-Agent"] = useragent

    def validate(self):
        """Validate the profile to verify it will succeed when used.

        Returns:
            bool: True if no checks fail.

        Raises:
            MalleableError: If a check fails.
        """
        host = "http://domain.com:80"
        data = string.printable
        for format, p in [("base", self), ("clone", self._clone()), ("serialized", Profile._deserialize(self._serialize()))]:
            test = p.get.construct_client(host, data)
            clone = MalleableRequest()
            clone.url = test.url
            clone.verb = test.verb
            clone.headers = test.headers
            clone.body = test.body
            if self.get.extract_client(clone) != data:
                MalleableError.throw(self.__class__, "validate", "Data-integrity check failed: %s-get-client-metadata" % format)

            test = p.get.construct_server(data)
            clone = MalleableResponse()
            clone.headers = test.headers
            clone.body = test.body
            if self.get.extract_server(clone) != data:
                MalleableError.throw(self.__class__, "validate", "Data-integrity check failed: %s-get-server-output" % format)

            test = p.post.construct_client(host, data, data)
            clone = MalleableRequest()
            clone.url = test.url
            clone.verb = test.verb
            clone.headers = test.headers
            clone.body = test.body
            id, output = self.post.extract_client(clone)
            if id != data:
                MalleableError.throw(self.__class__, "validate", "Data-integrity check failed: %s-post-client-id" % format)
            if output != data:
                MalleableError.throw(self.__class__, "validate", "Data-integrity check failed: %s-post-client-output" % format)

            test = p.post.construct_server(data)
            clone = MalleableResponse()
            clone.headers = test.headers
            clone.body = test.body
            if self.post.extract_server(clone) != data:
                MalleableError.throw(self.__class__, "validate", "Data-integrity check failed: %s-post-server-output" % format)

            test = p.stager.construct_client(host, data)
            clone = MalleableRequest()
            clone.url = test.url
            clone.verb = test.verb
            clone.headers = test.headers
            clone.body = test.body
            if self.stager.extract_client(clone) != data:
                MalleableError.throw(self.__class__, "validate", "Data-integrity check failed: %s-stager-client-metadata" % format)

            test = p.stager.construct_server(data)
            clone = MalleableResponse()
            clone.headers = test.headers
            clone.body = test.body
            if self.stager.extract_server(clone) != data:
                MalleableError.throw(self.__class__, "validate", "Data-integrity check failed: %s-stager-server-output" % format)

        if set(self.get.client.uris).intersection(set(self.post.client.uris)) or \
            set(self.post.client.uris).intersection(set(self.stager.client.uris)) or \
            set(self.stager.client.uris).intersection(set(self.get.client.uris)) or \
            len(self.get.client.uris + (self.post.client.uris if self.post.client.uris else ["/"])) == 0 or \
            len(self.post.client.uris + (self.stager.client.uris if self.stager.client.uris else ["/"])) == 0 or \
            len(self.stager.client.uris + (self.get.client.uris if self.get.client.uris else ["/"])) == 0 or \
            ("/" in self.get.client.uris and len(self.post.client.uris) == 0) or \
            ("/" in self.get.client.uris and len(self.stager.client.uris) == 0) or \
            ("/" in self.post.client.uris and len(self.stager.client.uris) == 0) or \
            ("/" in self.post.client.uris and len(self.get.client.uris) == 0) or \
            ("/" in self.stager.client.uris and len(self.get.client.uris) == 0) or \
            ("/" in self.stager.client.uris and len(self.post.client.uris) == 0):
            MalleableError.throw(self.__class__, "validate", "Cannot have duplicate uris: %s - %s - %s" % (
                self.get.client.uris if self.get.client.uris else ["/"],
                self.post.client.uris if self.post.client.uris else ["/"],
                self.stager.client.uris if self.stager.client.uris else ["/"]
            ))

        return True

    def ingest(self, file):
        """Ingest a profile file into the Profile object.

        Args:
            file (str): Filename to be read and parsed.
        """
        if not file or not os.path.isfile(file):
            MalleableError.throw(self.__class__, "ingest", "Invalid file: %s" % str(file))

        content = None
        with open(file) as f:
            content = f.read()

        if not content:
            MalleableError.throw(self.__class__, "ingest", "Empty file: %s" % str(file))

        self._parse(self._pattern().searchString(content))
