import random, urlparse, urllib
from pyparsing import *
from utility import MalleableError, MalleableUtil, MalleableObject
from transformation import Transform, Terminator, Container

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# TRANSACTION
#
# Defining the core components of an interaction between a web
# client request and a web server response.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

class MalleableRequest(MalleableObject):
    """A generic request class used to transfer the contents of an html request.

    Attributes:
        _url (urlparse.SplitResult)
        url (str, property)
        verb (str)
        scheme (str, property)
        netloc (str, property)
        host (str, property)
        port (str, property)
        path (str, property)
        parameters (dict (str, str))
        extra (str)
        headers (dict (str, str))
        body (str)
    """

    def _defaults(self):
        """Default initialization for the MalleableRequest object."""
        super(MalleableRequest, self)._defaults()
        self._url = urlparse.SplitResult("http","","/","","")
        self.verb = "GET"
        self.extra = ""
        self.headers = {}
        self.body = ""

    def _clone(self):
        """Deep copy of the MalleableRequest object.

        Returns:
            MalleableRequest
        """
        new = super(MalleableRequest, self)._clone()
        new._url = self._url
        new.verb = self.verb
        new.extra = self.extra
        new.headers = {k:v for k,v in self.headers.items()}
        new.body = self.body
        return new

    def _serialize(self):
        """Serialize the MalleableRequest object.

        Returns:
            dict (str, obj)
        """
        return dict(super(MalleableRequest, self)._serialize().items() + {
            "url" : self.url,
            "verb" : self.verb,
            "extra" : self.extra,
            "headers" : self.headers,
            "body" : self.body
        }.items())

    @classmethod
    def _deserialize(cls, data):
        """Deserialize data into a MalleableRequest object.

        Args:
            data (dict (str, obj)): Serialized data (json)

        Returns:
            MalleableRequest object
        """
        request = super(MalleableRequest, cls)._deserialize(data)
        if data:
            request.url = data["url"] if "url" in data else ""
            request.verb = data["verb"] if "verb" in data else "GET"
            request.extra = data["extra"] if "extra" in data else ""
            request.headers = data["headers"] if "headers" in data else {}
            request.body = data["body"] if "body" in data else ""
        return request

    @classmethod
    def _pattern(cls):
        """Define the pattern to recognize a MalleableRequest object while parsing a file.

        Returns:
            pyparsing object
        """
        return Group(Suppress("{") + ZeroOrMore(
            cls.COMMENT |
            (Literal("header") + Group(cls.VALUE + cls.VALUE) + cls.SEMICOLON) |
            (Literal("parameter") + Group(cls.VALUE + cls.VALUE) + cls.SEMICOLON) |
            Container._pattern()
        ) + Suppress("}"))

    def _parse(self, data):
        """Store the information from a parsed pyparsing result.

        Args:
            data: pyparsing data
        """
        if data:
            for i in range(0, len(data), 2):
                item = data[i]
                arg = data[i+1] if len(data) > i+1 else None
                if item and arg:
                    if item.lower() == "header" and len(arg) > 1:
                        key, value = arg[0], arg[1]
                        if key and value:
                            self.header(key, value)
                    elif item.lower() == "parameter" and len(arg) > 1:
                        key, value = arg[0], arg[1]
                        if key and value:
                            self.parameter(key, value)

    def _replace(self, scheme=None, host=None, port=None, path=None, parameters=None, verb=None, extra=None, headers=None, body=None):
        """Clone the MalleableRequest object while replacing the provided attributes.

        Args:
            scheme (str, optional)
            host (str, optional)
            port (str, optional)
            path (str, optional)
            parameters (dict (str, str), optional)
            verb (str, optional)
            extra (str, optional)
            headers (dict (str, str), optional)
            body (str, optional)

        Returns:
            MalleableRequest object
        """
        new = self._clone()
        if scheme is not None: new.scheme = scheme
        if host is not None: new.host = host
        if port is not None: new.port = port
        if path is not None: new.path = path
        if parameters is not None: new.parameters = parameters
        if verb is not None: new.verb = verb
        if extra is not None: new.extra = extra
        if headers is not None: new.headers = headers
        if body is not None: new.body = body
        return new

    @property
    def url(self):
        """Getter for the full url.

        Note: Actually generates from the urlparse.SplitResult _url.

        Returns:
            str: url
        """
        return urlparse.urlunsplit(self._url) + self.extra

    @url.setter
    def url(self, url):
        """Setter for the full url.

        Note: Actually sets parses the input into the urlparse.SplitResult _url.

        Args:
            url (str)
        """
        if "://" in url:
            if "http://" not in url.lower() and "https://" not in url.lower():
                MalleableError.throw(self.__class__, "url", "Scheme not supported: %s" % url)
        else:
            url = "http://" + url
        self._url = urlparse.urlsplit(url)

    @property
    def scheme(self):
        """Getter for the scheme.

        Returns:
            str: scheme
        """
        return self._url.scheme

    @scheme.setter
    def scheme(self, scheme):
        """Setter for the scheme.

        Args:
            scheme (str)
        """
        self._url = self._url._replace(scheme=scheme.lower() if scheme else "")

    @property
    def netloc(self):
        """Getter for the netloc.

        Returns:
            str: netloc
        """
        return self._url.netloc

    @netloc.setter
    def netloc(self, netloc):
        """Setter for the netloc.

        Args:
            netloc (str)
        """
        self._url = self._url._replace(netloc=netloc)

    @property
    def host(self):
        """Getter for the host.

        Returns:
            str: host
        """
        return self._url.hostname

    @host.setter
    def host(self, host):
        """Setter for the host.

        Args:
            host (str)

        Raises:
            MalleableError: If scheme not supported.
        """
        if "://" in host:
            if "http://" in host:
                host = host.lstrip("http://")
                self.scheme = "http"
            elif "https://" in host:
                host = host.lstrip("https://")
                self.scheme = "https"
            else:
                MalleableError.throw(self.__class__, "host", "Scheme not supported: %s" % host)
        if ":" not in host and self._url.port:
            host += ":" + str(self._url.port)
        self._url = self._url._replace(netloc=host)

    @property
    def port(self):
        """Getter for the port.

        Returns:
            str: port
        """
        return self._url.port

    @port.setter
    def port(self, port):
        """Setter for the port.

        Args:
            port (int)
        """
        hostname = self._url.hostname
        netloc = (str(hostname) if hostname else "") + ((":"+str(port)) if port else "")
        self._url = self._url._replace(netloc=netloc)

    @property
    def path(self):
        """Getter for the path.

        Returns:
            str: path
        """
        return self._url.path

    @path.setter
    def path(self, path):
        """Setter for the path.

        Args:
            path (str)
        """
        self._url = self._url._replace(path=path)

    @property
    def query(self):
        """Getter for the query string.

        Returns:
            str: query
        """
        return self._url.query

    @query.setter
    def query(self, query):
        """Setter for the query string.

        Args:
            query (str)
        """
        self._url = self._url._replace(query=query)

    @property
    def parameters(self):
        """Getter for the parameters.

        Note: Actually generated from urlparse.SplitResult _url.

        Returns:
            dict (str, str): parameters
        """
        return dict(urlparse.parse_qsl(self._url.query))

    @parameters.setter
    def parameters(self, parameters):
        """Setter for the parameters.

        Note: Actually sets the query string in urlparse.SplitResult _url.

        Args:
            parameters (dict(str, str))
        """
        query = urllib.urlencode(parameters) if parameters else ""
        self._url = self._url._replace(query=query)

    def parameter(self, parameter, value):
        """Add a single parameter.

        Args:
            parameter (str)
            value (str)
        """
        p = self.parameters
        p[parameter] = value
        self.parameters = p

    def get_parameter(self, parameter):
        """Get a single parameter value.

        Args:
            parameter (str)

        Returns:
            parameter value if exists else None.
        """
        if parameter:
            parameter = parameter.lower()
            if self.parameters:
                parameters = {k.lower():v for k,v in self.parameters.items()}
                if parameter in parameters:
                    return parameters[parameter]
        return None

    def header(self, header, value):
        """Set a single header value.

        Args:
            header (str)
            value (str)
        """
        self.headers[header] = value

    def get_header(self, header):
        """Get a single header value.

        Args:
            header (str)

        Returns:
            header value if exists else None.
        """
        if header:
            header = header.lower()
            if self.headers:
                headers = {k.lower():v for k,v in self.headers.items()}
                if header in headers:
                    return headers[header]
        return None

    def store(self, data, terminator):
        """Store the data according to the specified terminator.

        Args:
            data (str): The data to be stored.
            terminator (Terminator): The terminator specifying where to store the data.
        """
        if terminator.type == Terminator.HEADER: self.header(terminator.arg, data)
        elif terminator.type == Terminator.PARAMETER: self.parameter(terminator.arg, data)
        elif terminator.type == Terminator.URIAPPEND: self.extra = data
        elif terminator.type == Terminator.PRINT: self.body = data

    def extract(self, original, terminator):
        """Extract the data according to the specified terminator.

        Args:
            original (MalleableRequest): The original request to compare to.
            terminator (Terminator): The terminator specifying where the data is stored.
        """
        data = None
        if terminator.type == Terminator.HEADER:
            data = self.get_header(terminator.arg)
            if data: data = urllib.unquote(data)
        elif terminator.type == Terminator.PARAMETER:
            data = self.get_parameter(terminator.arg)
            if data: data = urllib.unquote(data)
        elif terminator.type == Terminator.URIAPPEND:
            if self.extra:
                data = urllib.unquote(self.extra)
            elif original.parameters:
                for p in sorted(original.parameters, key=len, reverse=True):
                    known = original.parameters[p]
                    shown = self.get_parameter(p)
                    if shown and known.lower() in shown.lower() and len(shown) > len(known):
                        data = known.split(known)[-1]
                        if data: data = urllib.unquote(data)
                        break
            else:
                for known in sorted(original.uris, key=len, reverse=True):
                    shown = self.path
                    if known.lower() in shown.lower() and len(shown) > len(known):
                        data = shown.split(known)[-1]
                        if data: data = urllib.unquote(data)
                        break
        elif terminator.type == Terminator.PRINT: data = self.body
        return data

class MalleableResponse(MalleableObject):
    """A generate response class used to transfer the contents of an html response.

    Attributes:
        code (int)
        headers (dict (str, str))
        body (str)
    """

    def _defaults(self):
        """Default initialization for the MalleableResponse object."""
        super(MalleableResponse, self)._defaults()
        self.code = 200
        self.headers = {}
        self.body = ""

    def _clone(self):
        """Deep copy of the MalleableResponse object.

        Returns:
            MalleableResponse
        """
        new = super(MalleableResponse, self)._clone()
        new.code = self.code
        new.headers = {k: v for k,v in self.headers.items()}
        new.body = self.body
        return new

    def _serialize(self):
        """Serialize the MalleableResponse object.

        Returns:
            dict (str, obj)
        """
        return dict(super(MalleableResponse, self)._serialize().items() + {
            "code" : self.code,
            "headers" : self.headers,
            "body" : self.body
        }.items())

    @classmethod
    def _deserialize(cls, data):
        """Deserialize data into a MalleableReponse object.

        Args:
            data (str): Serialized data (json)

        Returns:
            MalleableResponse object
        """
        response = super(MalleableResponse, cls)._deserialize(data)
        if data:
            response.code = data["code"] if "code" in data else 200
            response.headers = data["headers"] if "headers" in data else {}
            response.body = data["body"] if "body" in data else ""
        return response

    @classmethod
    def _pattern(cls):
        """Define the pattern to recognize a MalleableResponse object while parsing a file.

        Returns:
            pyparsing object
        """
        return Group(Suppress("{") + ZeroOrMore(
            cls.COMMENT |
            (Literal("header") + Group(cls.VALUE + cls.VALUE) + cls.SEMICOLON) |
            Container._pattern()
        ) + Suppress("}"))

    def _parse(self, data):
        """Store the information from a parsed pyparsing result.

        Args:
            data: pyparsing data
        """
        if data:
            for i in range(0, len(data), 2):
                item = data[i]
                arg = data[i+1] if len(data) > i+1 else None
                if item and arg:
                    if item.lower() == "header" and len(arg) > 1:
                        key, value = arg[0], arg[1]
                        if key and value:
                            self.header(key, value)

    def get_header(self, header):
        """Get a single header value.

        Args:
            header (str)

        Returns:
            header value if exists else None.
        """
        if header:
            header = header.lower()
            if self.headers:
                headers = {k.lower():v for k,v in self.headers.items()}
                if header in headers:
                    return headers[header]
        return None

    def header(self, header, value):
        """Set a single header value.

        Args:
            header (str)
            value (str)
        """
        self.headers[header] = value

    def store(self, data, terminator):
        """Store the data according to the specified terminator.

        Args:
            data (str): The data to be stored.
            terminator (Terminator): The terminator specifying where to store the data.
        """
        if terminator.type == Terminator.HEADER: self.header(terminator.arg, data)
        elif terminator.type == Terminator.PRINT: self.body = data

    def extract(self, original, terminator):
        """Extract the data according to the specified terminator.

        Args:
            original (MalleableResponse): The original request to compare to.
            terminator (Terminator): The terminator specifying where the data is stored.
        """
        data = None
        if terminator.type == Terminator.HEADER:
            data = self.get_header(terminator.arg)
            if data: data = urllib.unquote(data)
        elif terminator.type == Terminator.PRINT:
            data = self.body
        return data

class Transaction(MalleableObject):
    """A class housing the core components of an interaction between a web client request and
        a web server response.

    Attributes:
        client (MalleableRequest): Client object containing client request attributes.
        server (MalleableResponse): Server object containing server response attributes.
    """

    def _defaults(self):
        """Default initialization for the Transaction object."""
        super(Transaction, self)._defaults()
        self.client = Transaction.Client()
        self.server = Transaction.Server()

    def _clone(self):
        """Deep copy of the Transaction object.

        Returns:
            Transaction
        """
        new = super(Transaction, self)._clone()
        new.client = self.client._clone()
        new.server = self.server._clone()
        return new

    def _serialize(self):
        """Serialize the Transaction object.

        Returns:
            dict (str, obj)
        """
        return dict(super(Transaction, self)._serialize().items() + {
            "client" : self.client._serialize(),
            "server" : self.server._serialize()
        }.items())

    @classmethod
    def _deserialize(cls, data):
        """Deserialize data into a Transaction object.

        Args:
            data (str): Serialized data (json)

        Returns:
            Transaction object
        """
        transaction = super(Transaction, cls)._deserialize(data)
        if data:
            transaction.client = Transaction.Client._deserialize(data["client"]) if "client" in data else Transaction.Client()
            transaction.server = Transaction.Server._deserialize(data["server"]) if "server" in data else Transaction.Server()
        return transaction

    @classmethod
    def _pattern(cls):
        """Define the pattern to recognize a Transaction object while parsing a file.

        Returns:
            pyparsing object
        """
        return Group(Suppress("{") + ZeroOrMore(
                cls.COMMENT |
                (Literal("set") + Group(cls.FIELD + cls.VALUE) + cls.SEMICOLON) |
                cls.Client._pattern() |
                cls.Server._pattern()
            ) + Suppress("}"))

    def _parse(self, data):
        """Store the information from a parsed pyparsing result.

        Args:
            data: pyparsing data
        """
        if data:
            for i in range(0, len(data), 2):
                item = data[i]
                arg = data[i+1] if len(data) > i+1 else None
                if item and arg:
                    if item.lower() == "set" and len(arg) > 1:
                        key, value = arg[0], arg[1]
                        if key and value:
                            if key.lower() == "uri":
                                for u in value.split():
                                    self.client.uri(u)
                            elif key.lower() == "uri_x86":
                                for u in value.split():
                                    self.client.uri(u, x86=True)
                            elif key.lower() == "uri_x64":
                                for u in value.split():
                                    self.client.uri(u, x64=True)
                            else:
                                setattr(self, key, value)
                    elif item.lower() == "client":
                        self.client._parse(arg)
                    elif item.lower() == "server":
                        self.server._parse(arg)

    @property
    def verb(self):
        """Getter for the verb attribute.

        Returns:
            verb (str)
        """
        return self.client.verb

    @verb.setter
    def verb(self, verb):
        """Setter for the verb attribute.

        Note: verb actually lives in the client, this is here for compatibility.

        Args:
            verb (str)
        """
        self.client.verb = verb

    class Client(MalleableRequest):
        """A class housing the core components of a web client request.

        Attributes:
            uris (list (str)): Uris to which client traffic will be directed.
            uris_x86 (list (str)): x86-only uris to which client traffic will be directed.
            uris_x64 (list (str)): x64-only uris to which client traffic will be directed.
        """

        def _defaults(self):
            """Default initialization for the Client object."""
            super(Transaction.Client, self)._defaults()
            self.uris = []
            self.uris_x86 = []
            self.uris_x64 = []

        def _clone(self):
            """Deep copy of the Client object.

            Returns:
                Client
            """
            new = super(Transaction.Client, self)._clone()
            new.uris = [u for u in self.uris]
            new.uris_x86 = [u for u in self.uris_x86]
            new.uris_x64 = [u for u in self.uris_x64]
            return new

        def _serialize(self):
            """Serialize the Client object.

            Returns:
                dict (str, obj)
            """
            return dict(super(Transaction.Client, self)._serialize().items() + {
                "uris" : self.uris,
                "uris_x86" : self.uris_x86,
                "uris_x64" : self.uris_x64
            }.items())

        @classmethod
        def _deserialize(self, data):
            """Deserialize data into a Client object.

            Args:
                data (str): Serialized data (json)

            Returns:
                Client object
            """
            client = super(Transaction.Client, self)._deserialize(data)
            if data:
                client.uris = data["uris"] if "uris" in data else []
                client.uris_x86 = data["uris_x86"] if "uris_x86" in data else []
                client.uris_x64 = data["uris_x64"] if "uris_x64" in data else []
            return client

        @classmethod
        def _pattern(cls):
            """Define the pattern to recognize a Transaction Client object while parsing a file.

            Returns:
                pyparsing object
            """
            return Literal("client") + super(Transaction.Client, cls)._pattern()

        def stringify(self):
            """Serialize into a string compatible with Powershell Empire."""
            return "|".join([
                ",".join(self.uris if self.uris else ["/"]),
                str(self.get_header("User-Agent"))
                ] + [":".join([h,v]) for h,v in self.headers.items() if h.lower() != "user-agent"])

        def uri(self, uri, x86=False, x64=False):
            """Add a uri to the list of uris

            Args:
                uri (str)
            """
            self.uris = list(set(self.uris).union(set([uri])))
            if x86:
                self.uris_x86 = list(set(self.uris_x86).union(set([uri])))
            if x64:
                self.uris_x64 = list(set(self.uris_x64).union(set([uri])))

        def random_uri(self, x86=False, x64=False, default="/"):
            """Returns a random uri from the list.

            Args:
                x86 (bool, optional): Only include x86 uris
                x64 (bool, optional): Only include x64 uris
                default (str, optional): Default uri to use if list is empty
            """
            if x86 and x64:
                uris = self.uris
            elif x86:
                uris = self.uris_x86
            elif x64:
                uris = self.uris_x64
            else:
                uris = self.uris
            return (random.choice(uris) if uris else default)

    class Server(MalleableResponse):
        """A class housing the core components of a web server response."""

        @classmethod
        def _pattern(cls):
            """Define the pattern to recognize a Transaction Server object while parsing a file.

            Returns:
                pyparsing object
            """
            return Literal("server") + super(Transaction.Server, cls)._pattern()
