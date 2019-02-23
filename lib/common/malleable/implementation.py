import urllib
from pyparsing import *
from utility import MalleableError, MalleableUtil, MalleableObject
from transformation import Transform, Terminator, Container
from transaction import MalleableRequest, MalleableResponse, Transaction

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# IMPLEMENTATION
#
# Defining the specific implementations of an interaction
# between a web client request and a web server response.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

class Get(Transaction):
    """The Get implementation of a Transaction.

    The Get Transaction is used to fetch tasking from the server. In a Get Transaction,
    the following data is transmitted:
        - (Client) metadata     (Session metadata)
        - (Server) output       (Beacon's tasks)
    """

    def _defaults(self):
        """Default initialization for the Get Transaction."""
        super(Get, self)._defaults()
        self.client.metadata = Container()
        self.server.output = Container()
        self.client.verb = "GET"

    def _clone(self):
        """Deep copy of the Get Transaction.

        Returns:
            Get Transaction
        """
        new = super(Get, self)._clone()
        new.client.metadata = self.client.metadata._clone()
        new.server.output = self.server.output._clone()
        new.client.verb = self.client.verb
        return new

    def _serialize(self):
        """Serialize the Get Transaction.

        Returns:
            dict (str, obj)
        """
        d = super(Get, self)._serialize()
        d["client"] = dict((d["client"].items() if "client" in d else []) + {
            "metadata" : self.client.metadata._serialize()
        }.items())
        d["server"] = dict((d["server"].items() if "server" in d else []) + {
            "output" : self.server.output._serialize()
        }.items())
        return dict(d.items() + {

        }.items())

    @classmethod
    def _deserialize(cls, data):
        """Deserialize data into a Get Transaction.

        Args:
            data (dict (str, obj)): Serialized data (json)

        Returns:
            Get Transaction
        """
        get = super(Get, cls)._deserialize(data)
        if data:
            get.client.metadata = Container._deserialize(data["client"]["metadata"]) if ("client" in data and "metadata" in data["client"]) else Container()
            get.server.output = Container._deserialize(data["server"]["output"]) if ("server" in data and "output" in data["server"]) else Container()
        return get

    @classmethod
    def _pattern(cls):
        """Define the pattern to recognize a Get object while parsing a file.

        Returns:
            pyparsing object
        """
        return Literal("http-get") + super(Get, cls)._pattern()

    def _parse(self, data):
        """Store the information from a parsed pyparsing result.

        Args:
            data: pyparsing data
        """
        super(Get, self)._parse(data)
        if data:
            for i in range(0, len(data), 2):
                item = data[i]
                arg = data[i+1] if len(data) > i+1 else None
                if item and arg:
                    if item.lower() == "client":
                        for j in range(0, len(arg), 2):
                            item2 = arg[j]
                            arg2 = arg[j+1] if len(arg) > j+1 else None
                            if item2 and arg2:
                                if item2.lower() == "metadata":
                                    self.client.metadata._parse(arg2)
                    elif item.lower() == "server":
                        for j in range(0, len(arg), 2):
                            item2 = arg[j]
                            arg2 = arg[j+1] if len(arg) > j+1 else None
                            if item2 and arg2:
                                if item2.lower() == "output":
                                    self.server.output._parse(arg2)

    def construct_client(self, host, metadata):
        """Construct a Client request using the provided metadata to the provided host.

        Args:
            host (str): Host to direct client request to.
            metadata (str): Metadata to include in the request.

        Returns:
            Transaction.Client: Constructed Client request.
        """
        request = self.client._clone()
        request.host = host
        request.path = self.client.random_uri()
        request.store(self.client.metadata.transform(metadata), self.client.metadata.terminator)
        return request

    def extract_client(self, request):
        """Extract the metadata from the provided MalleableRequest.

        Args:
            request (MalleableRequest)

        Returns:
            str: metadata
        """
        for u in (self.client.uris if self.client.uris else ["/"]):
            if u.lower() in request.path.lower():
                metadata = request.extract(self.client, self.client.metadata.terminator)
                if metadata:
                    m = self.client.metadata.transform_r(metadata)
                    return m
        return None

    def construct_server(self, output):
        """Construct a Server response using the provided output.

        Args:
            output (str): Output to include in the request.

        Returns:
            Transaction.Server: Constructed Server response.
        """
        response = self.server._clone()
        response.store(self.server.output.transform(output), self.server.output.terminator)
        return response

    def extract_server(self, response):
        """Extract the output from the provided MalleableResponse.

        Args:
            response (MalleableResponse)

        Returns:
            str: output
        """
        output = response.extract(self.server, self.server.output.terminator)
        return self.server.output.transform_r(output) if output else None

class Post(Transaction):
    """The Post implementation of a Transaction.

    The Post Transaction is used to exchange information with the server. In a Post Transaction,
    the following data is transmitted:
        - (Client) id       (Session ID)
        - (Client) output   (Beacon's responses)
        - (Server) output   (Empty)
    """

    def _defaults(self):
        """Default initialization for the Post Transaction."""
        super(Post, self)._defaults()
        self.client.id = Container()
        self.client.output = Container()
        self.server.output = Container()
        self.client.verb = "POST"

    def _clone(self):
        """Deep copy of the Post Transaction.

        Returns:
            Post Transaction
        """
        new = super(Post, self)._clone()
        new.client.id = self.client.id._clone()
        new.client.output = self.client.output._clone()
        new.server.output = self.server.output._clone()
        new.client.verb = self.client.verb
        return new

    def _serialize(self):
        """Serialize the Post Transaction.

        Returns:
            dict (str, obj)
        """
        d = super(Post, self)._serialize()
        d["client"] = dict((d["client"].items() if "client" in d else []) + {
            "id" : self.client.id._serialize(),
            "output" : self.client.output._serialize()
        }.items())
        d["server"] = dict((d["server"].items() if "server" in d else []) + {
            "output" : self.server.output._serialize()
        }.items())
        return dict(d.items() + {

        }.items())

    @classmethod
    def _deserialize(cls, data):
        """Deserialize data into a Post Transaction.

        Args:
            data (dict (str, obj)): Serialized data (json)

        Returns:
            Post Transaction
        """
        post = super(Post, cls)._deserialize(data)
        if data:
            post.client.id = Container._deserialize(data["client"]["id"]) if ("client" in data and "id" in data["client"]) else Container()
            post.client.output = Container._deserialize(data["client"]["output"]) if ("client" in data and "output" in data["client"]) else Container()
            post.server.output = Container._deserialize(data["server"]["output"]) if ("server" in data and "output" in data["server"]) else Container()
        return post

    @classmethod
    def _pattern(cls):
        """Define the pattern to recognize a Post object while parsing a file.

        Returns:
            pyparsing object
        """
        return Literal("http-post") + super(Post, cls)._pattern()

    def _parse(self, data):
        """Store the information from a parsed pyparsing result.

        Args:
            data: pyparsing data
        """
        super(Post, self)._parse(data)
        if data:
            for i in range(0, len(data), 2):
                item = data[i]
                arg = data[i+1] if len(data) > i+1 else None
                if item and arg:
                    if item.lower() == "client":
                        for j in range(0, len(arg), 2):
                            item2 = arg[j]
                            arg2 = arg[j+1] if len(arg) > j+1 else None
                            if item2 and arg2:
                                if item2.lower() == "id":
                                    self.client.id._parse(arg2)
                                elif item2.lower() == "output":
                                    self.client.output._parse(arg2)
                    elif item.lower() == "server":
                        for j in range(0, len(arg), 2):
                            item2 = arg[j]
                            arg2 = arg[j+1] if len(arg) > j+1 else None
                            if item2 and arg2:
                                if item2.lower() == "output":
                                    self.server.output._parse(arg2)

    def construct_client(self, host, id, output):
        """Construct a Client request using the provided id and output to the provided host.

        Args:
            host (str): Host to direct client request to.
            id (str): id to include in the request.
            output (str): output to include in the request.

        Returns:
            Transaction.Client: Constructed Client request.
        """
        request = self.client._clone()
        request.host = host
        request.path = self.client.random_uri()
        request.store(self.client.id.transform(id), self.client.id.terminator)
        request.store(self.client.output.transform(output), self.client.output.terminator)
        return request

    def extract_client(self, request):
        """Extract the id and output from the provided MalleableRequest.

        Args:
            request (MalleableRequest)

        Returns:
            tuple: id, output
        """
        for u in (self.client.uris if self.client.uris else ["/"]):
            if u.lower() in request.path.lower():
                id = request.extract(self.client, self.client.id.terminator)
                output = request.extract(self.client, self.client.output.terminator)
                return (
                    self.client.id.transform_r(id) if id else None,
                    self.client.output.transform_r(output) if output else None
                )
        return (None, None)

    def construct_server(self, output):
        """Construct a Server response using the provided output.

        Args:
            output (str): Output to include in the request.

        Returns:
            Transaction.Server: Constructed Server response.
        """
        response = self.server._clone()
        response.store(self.server.output.transform(output), self.server.output.terminator)
        return response

    def extract_server(self, response):
        """Extract the output from the provided MalleableResponse.

        Args:
            response (MalleableResponse)

        Returns:
            str: output
        """
        output = response.extract(self.server, self.server.output.terminator)
        return self.server.output.transform_r(output) if output else None

class Stager(Transaction):
    """The Stager implementation of a Transaction.

    The Stager Transaction is used to fetch a payload stage corresponding to the provided
    metadata. In a Stager Transaction, the following data is transmitted:
        - (Client) metadata (Session info)
        - (Server) output   (Encoded payload stage)
    """

    def _defaults(self):
        """Default initialization for the Stager Transaction."""
        super(Stager, self)._defaults()
        self.client.metadata = Container()
        self.server.output = Container()
        self.client.verb = "GET"

    def _clone(self):
        """Deep copy of the Stager Transaction.

        Returns:
            Stager Transaction
        """
        new = super(Stager, self)._clone()
        new.client.metadata = self.client.metadata._clone()
        new.server.output = self.server.output._clone()
        new.client.verb = self.client.verb
        return new

    def _serialize(self):
        """Serialize the Stager Transaction.

        Returns:
            dict (str, obj)
        """
        d = super(Stager, self)._serialize()
        d["client"] = dict((d["client"].items() if "client" in d else []) + {
            "metadata" : self.client.metadata._serialize()
        }.items())
        d["server"] = dict((d["server"].items() if "server" in d else []) + {
            "output" : self.server.output._serialize()
        }.items())
        return dict(d.items() + {

        }.items())

    @classmethod
    def _deserialize(cls, data):
        """Deserialize data into a Stager Transaction.

        Args:
            data (dict (str, obj)): Serialized data (json)

        Returns:
            Stager Transaction
        """
        stager = super(Stager, cls)._deserialize(data)
        if data:
            stager.client.metadata = Container._deserialize(data["client"]["metadata"]) if ("client" in data and "metadata" in data["client"]) else Container()
            stager.server.output = Container._deserialize(data["server"]["output"]) if ("server" in data and "output" in data["server"]) else Container()
        return stager

    @classmethod
    def _pattern(cls):
        """Define the pattern to recognize a Stager object while parsing a file.

        Returns:
            pyparsing object
        """
        return Literal("http-stager") + super(Stager, cls)._pattern()

    def _parse(self, data):
        """Store the information from a parsed pyparsing result.

        Args:
            data: pyparsing data
        """
        super(Stager, self)._parse(data)
        if data:
            for i in range(0, len(data), 2):
                item = data[i]
                arg = data[i+1] if len(data) > i+1 else None
                if item and arg:
                    if item.lower() == "client":
                        for j in range(0, len(arg), 2):
                            item2 = arg[j]
                            arg2 = arg[j+1] if len(arg) > j+1 else None
                            if item2 and arg2:
                                if item2.lower() == "metadata":
                                    self.client.metadata._parse(arg2)
                    elif item.lower() == "server":
                        for j in range(0, len(arg), 2):
                            item2 = arg[j]
                            arg2 = arg[j+1] if len(arg) > j+1 else None
                            if item2 and arg2:
                                if item2.lower() == "output":
                                    self.server.output._parse(arg2)

    def construct_client(self, host, metadata):
        """Construct a Client request using the provided metadata to the provided host.

        Args:
            host (str): Host to direct client request to.

        Returns:
            Transaction.Client: Constructed Client request.
        """
        request = self.client._clone()
        request.host = host
        request.path = self.client.random_uri()
        request.store(self.client.metadata.transform(metadata), self.client.metadata.terminator)
        return request

    def extract_client(self, request):
        """Extract the metadata from the provided MalleableRequest.

        Args:
            request (MalleableRequest)

        Returns: None
        """
        for u in (self.client.uris if self.client.uris else ["/"]):
            if u.lower() in request.path.lower():
                metadata = request.extract(self.client, self.client.metadata.terminator)
                if metadata:
                    return self.client.metadata.transform_r(metadata)
        return None

    def construct_server(self, output):
        """Construct a Server response using the provided output.

        Args:
            output (str): Output to include in the request.

        Returns:
            Transaction.Server: Constructed Server response.
        """
        response = self.server._clone()
        response.store(self.server.output.transform(output), self.server.output.terminator)
        return response

    def extract_server(self, response):
        """Extract the output from the provided MalleableResponse.

        Args:
            response (MalleableResponse)

        Returns:
            str: output
        """
        output = response.extract(self.server, self.server.output.terminator)
        return self.server.output.transform_r(output) if output else None
