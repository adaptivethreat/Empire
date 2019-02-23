# MalleableC2Parser

A [**Malleable Command and Control Profile**](https://www.cobaltstrike.com/help-malleable-c2) is a "simple program that specifies how to transform data and store it in a transaction", and is a key feature of [**Cobal Strike**](https://www.cobaltstrike.com/)'s Beacon payload.  This library is an attempt to abstract that functionality out so that other toolsets may use the same files to define their own communication profiles.

## Usage

```
import malleable
try:
  p = malleable.Profile()
  p.ingest("amazon.profile")
  if p.validate():
    request = p.get.construct_client("mydomain.sample", "mydata")
    print request.url, request.headers, request.body
except MalleableError as e:
  print str(e)
```

## Architecture

### Profile

The `Profile` houses all the functionality of the Malleable C2 profile and is capable of ingesting and validating profiles.  A standard Malleable C2 profile contains a `Get Implementation`, a `Post Implementation`, and possibly a `Stager Implementation`, as well as several global variables like `sleeptime`, `jitter`, and `useragent`.

### Implementation

An `Implementation` is the specific instantiation of an HTTP client-server `Transaction`, and there are three defined: `Get`, `Post`, and `Stager`.  Each `Implementation` has its own storage paradigm and purpose within the communication profile.

- Get: Fetch tasking from the C2
  - Client: metadata (Session metadata)
  - Server: output (Beacon's tasks)
- Post: Return results to the C2
  - Client: id (Session ID), output (Beacon's responses)
  - Server: output (Empty)
- Stager: Download a payload stage
  - Client: metadata (Empty)
  - Server: output (Encoded payload stage)
  
### Transaction

A `Transaction` defines the core components of an interaction between a web client request and a web server response.  As such, a `Transaction` houses a `Client` and `Server` object, each holding the appropriate components included in their part of the transaction.

- Client: url, verb scheme, host, port, path, parameters, headers, body
  
- Server: code, headers, body

Each `Client` and `Server` object of a `Transaction` also includes the ability to *store* and *extract* encoded data within its structure, houseing the true value of a Malleable C2 profile.

### Transformation

This group of classes defines the model through which arbitrary data can undergo a sequence of reversable transformations.  A `Transform` houses the arbitrary functionality of a reversable transformation, and the following are defined:

- Append
- Base64
- Base64Url
- Mask
- Netbios
- Netbiosu
- Prepend

A `Terminator` houses the arbitrary functionality of a reversable storage mechanism, and the following are defined:

- Print
- Header
- Parameter
- UriAppend

And finally, a `Container` houses a sequence of `Transforms` and their defined `Terminator`.  For example, a `Get Implementation` might include the `metadata Container`, which houses the `Base64Url Transform` and the `UriAppend Terminator`.  This means that the metadata to be sent in a GET request to the C2 server will first be Base64 encoded and url encoded, then stored at the end of the url.  The server will then retrieve the encoded data from the end of the url and proceed to url decode and base64 decode it.
