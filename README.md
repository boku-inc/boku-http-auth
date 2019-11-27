# Boku API HTTP Signature Authentication Library

## Overview

This package contains both production ready library code, plus some demo applications to show how it is used and to aid
in testing.

The code is split into several modules, of which in a typical integration you will only need one or two:

 - **core**: Core message signing functionality common to client and server. If you're integrating into a client or
             server platform not already supported, you would just use this.
 - **client**: Provides integration with Apache HttpClient, and also provides a fully functional and easy to use REST
               client built on top of HttpClient that is well suited to using Boku's public APIs.
 - **server**: Provides integratation with servlet-based server applications by means of a servlet Filter.
 - **tools**: Tools to aid in testing your integration, or even test an alternate implementation in another language,
              and sample code illustrating how to use this library.
 - **integration-tests**: Some basic integration tests of of the library functionality, which you can use to test
                          changes.

The following sections go into detail regarding the various modules.

## Core

This code is located under the `com.boku.auth.http` package and sub-packages.

### Dependencies

The core module depends only on the SLF4J API, which is used for logging.

SLF4J is a logging API that has many different pluggable implementations. If you currently use an alternate logging
framework such as Log4j or JUL there should be a bridge library you can use to send all SLF4J logging calls to your
library of choice - see http://www.slf4j.org for details.  
If you'd rather not use SLF4J at all, feel free to remove SLF4J from the classpath and fix the calls to Logger.

There are several additional unit-test-only dependencies. These are only required to build and run the tests, and are
not referenced in the final jar that is produced.

### Usage

Note: before you use the core module directly, consider interfacing instead with the higher-level client or server
modules.

If you do wish to use the core library directly, the main interface is
`com.boku.auth.http.httpsigner.HttpMessageSigner`, most methods of which take an `AuthorizationHeader` and a
`CanonicalHttpMessage` of some sort.

To construct an instance of `HttpMessageSigner` you will need to supply an instance of `StringSigner`. The provided
`BasicStringSignerImpl` class should work for most use cases.  
The string signer depends on `KeyProvider` in order to get access to API keys - you should provide an appropriate
implementation that supplies the keys from where ever you have them stored, preferably from an encrypted and access
controlled data store of some kind.  
There is a provided `PropertiesKeyProvider` implementation which, although useful for testing, is not intended for use
in production systems. Also provided is a `KeystoreKeyProvider` implementation which may be slightly more secure,
although where to keep this keystore and where to get the passphrase from is left as an an exercise for the reader.  
(At Boku we implement StringSigner by delegating to our internal key management service.)

When generating or verifying a signature, you must construct an instance of `CanonicalHttpRequest` or
`CanonicalHttpResponse` describing the request or response that is being sent. It is recommended that you generate these
directly based off of whatever classes your HTTP framework uses to represent requests and responses, so it can be
ensured that the data used for signing is identical to the actual messages sent, and two code paths are not required
when constructing said messages.

When verifying a signature, the `AuthorizationHeader` object comes from parsing the received HTTP header value.

When generating a new signature, the `AuthorizationHeader` need only be populated with the correct `partner-id`,
`key-id`, and `signed-headers` if appropriate. The actual timestamp and signature will then be filled in by
the `HttpMessageSigner`. 


## Client

The Apache HttpClient integration code is located under `com.boku.auth.http.httpclient`, and the Boku REST API client
is located under `com.boku.auth.http.client`.

### Dependencies

In addition to depending on the `core` module, the client code depends only on Apache HttpClient v4.5:  
https://hc.apache.org/httpcomponents-client-4.5.x/

Marshalling occurs via the JREs built in JAX-B support. If you want marshalling support for e.g. JSON, you will need to
slot in extra libraries to do so.

### Usage: BokuAPIClient

#### Setup

In order to construct a `BokuAPIClient` instance you must pass it an Apache HttpClient instance configured to your
preference that will be used for the underlying HTTP requests. (Please pay special attention to connection pooling and
timeout settings.)

`BokuAPIClient` also requires a `HttpMessageSigner` instance in order to sign its requests - see documentation for the
`core` module for how to construct the message signer.

If you want to use automatic entity marshalling / unmarshalling support, you should supply an `EntityMarshaller`
instance. The provided `XMLEntityMarshaller` supports XML via JAX-B as used by most of Boku's APIs.  
For other formats, you may provide an alternate implementation of `EntityMarshaller` - this interface is very simple and
should be quick to implement with most serialization libraries such as Jackson, GSON, etc.

#### Sending Requests

`BokuAPIClient` supports a fluid interface, you'd use it something like this:

    AuthorizationHeader ah = new AuthorizationHeader();
    ah.setPartnerId("my-merchant-id");
    ah.setKeyId("1");

    MyRequestObject request = new MyRequestObject();
    request.setStuff(123);

    MyResponseObject response = client.put("https://api.boku.com/some-resource")
        .withAuthorization(ah)
        .withEntity(request)
        .execute(MyResponseObject.class);

In the background your request will be signed, and the response signature is verified before returning to you.

#### Sample Code

You can find example usage code for the client in `com.boku.auth.http.tools.Example_BokuAPIClient` in the tools module.


### Usage: HttpClient

If you'd rather not use the Boku client, but still want to use the lower-level Apache HttpClient to sign arbitrary
HTTP requests, then you can use the provided `ApacheHttpClientCanonicalHttpMessageFactory`.  
This class takes Apache HttpClient request and response objects and translates them into the `CanonicalHttpMessage`
structures required by the core library. From there, see the documentation of the `core` module for how to proceed in
generating and verifying signatures.

Please see the program `com.boku.auth.http.tools.Example_ApacheHttpClient` in the `tools` module for sample code.


## Server

This code is located under `com.boku.auth.http.server`.

### Dependencies

In addition to depending on the `core` module, the server code depends on the Java Servlet API v3.0.1.

This code should be compatible with earlier and later versions of the servlet API, but depending on your web server
environment you may need to exclude the servlet API dependency or make other version management adjustments to make
things work well together.

### Usage

The server library has two main pieces:

 - `com.boku.auth.http.server.servletfilter.BokuHttpAuthFilter`: This filter collects information about the request for
   authentication purposes, and automatically signs HTTP responses. It must be installed around any resource you wish to
   be authenticated, but it **DOES NOT** reject unauthenticated requests automatically - for that you also need the next
   item.
 - `com.boku.auth.http.server.AuthorizationContextProvider`: This class is used to get the authentication status of the
   current request. If the request does not have a valid signature, it will throw an `AuthorizationException`, which
   you should catch and turn into an appropriate response.

To help you wire the various server pieces together, the class `ServerAuthorizationComponentsFactory` is provided.

Ideally, you should create an instance of this factory by supplying it a `KeyProvider` and then use it to get instances
of `AuthorizationContextProvider` and `BokuHttpAuthFilter` which can be wired into your system.

In some application environments, such as when using the original `web.xml` specification with no dependency injection
support then an existing servlet filter instance cannot be used, and nor can constructor arguments be used to pass
dependencies.  
In this case, set up `BokuHttpAuthFilter` as a normal servlet in in your web.xml, which will cause it to use a static
instance of the `ServerAuthorizationComponentsFactory`, and then get your instance of `AuthorizationContextProvider`
from the static factory available at
`ServerAuthorizationComponentsFactory.getInstance().getAuthorizationContextProvider()`.  
When using this static version of `ServerAuthorizationComponentsFactory` configuration occurs via filter init-params
(or system properties) rather than via constructor arguments - see documentation on the
`com.boku.auth.http.server.servletfilter.BokuHttpAuthFilter.init` method for what parameters are available.


## Tools

This module contains standalone programs that are designed to be used as-is for testing purposes, rather than code
to be imported into production applications.  

To get started, build the project and then run `java -jar tools/target/boku-http-auth-tools-1.1-main.jar` - the online
help should let you proceed from there.

If you have trouble building these tools, a pre-built package is available under the name `boku-auth-tools-1.1.zip`.  

There are several classes under `com.boku.auth.http.tools` that start with the prefix `Example_` - we have attempted
to make these as simple as possible, and although they are not production quality code they can be used to see how
to set up and use some of the provided library components.

Code in the other non-Example classes may also be consulted, but please keep in mind a lot of the code in the tools
package is geared towards displaying as much debug information as possible, and may not be a good example of how to
write concise and efficient production code.




