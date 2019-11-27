# Boku API HTTP Signature Authentication Tools

## Overview

This package contains tools to help with testing implementations of the Boku HTTP signing scheme.

All commands are located inside a single jar, which can be executed using `java -jar auth-tools.jar`. From there, the
online help should guide you on how to use the tools.


## Configuration

The tools use a configuration file, by default `config.properties`, which you will have to edit to include the relevant
API keys needed to test against an external system.  
Please see the comments inside the included config.properties for how to do so.


## Included files

Summary of the files included in this bundle:

 - _README.md_: this file
 - _LICENCE.txt_: software licence
 - _auth-tools.jar_: executable jar containing various programs
 - _config.properties_: configuration file used by tools jar
 - _test-vectors_: a directory containing HTTP request and response files copied from auth specification section 5.  
   May be verified against this implementation using `java -jar auth-tools.jar check test-vectors/$file`
 - _example-files_: just some sample static files you can use as inputs while testing the tools. For example to simulate
   what a request/response might look like:
     - Server: `java -jar auth-tools.jar server -port 8080`
     - Client: `java -jar auth-tools.jar client -H "Content-Type: text/xml;charset=utf8" -body example-files/charge-request.xml POST http://localhost:8080/example-files/charge-response.xml`

