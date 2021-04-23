# Overview

This document describes a generic scheme for authenticating HTTP requests and responses between Boku and a partner, and applies across several different APIs.

This scheme attempts to ensure that the request method, path, any query string parameters, important headers, and the request body have all been constructed by the intended party, and can not have been modified in transport (via man-in-the-middle attacks). This is accomplished via concatenating certain message components in a standard way, and then cryptographically signing them. The signing is currently done with a pre-shared key.

Note that in addition to using this HTTP message signing scheme, it's also strongly recommended (and usually required) that the HTTP connection itself is over a TLS secured channel.

# Protocol Exchange / Format

## Request / Response Flow
* With every HTTP request, the client must submit an **Authorization** header advertising their identity, and authenticating the request as from them.
* If for any reason the submitted Authorization is deemed invalid by the sever, a HTTP **401 Unauthorized** response will be returned.
  - The body of this error response should be text/plain, so as to be application layer API agnostic.
  - Authentication / Authorization related error responses will not be signed by the server.
* If the submitted Authorization is deemed correct, the request will be processed and an application specific response returned.
* Every application layer API response (i.e. HTTP 200 OK) will be signed so as to authenticate the server to the client, in the same fashion that the client signed it's request.
* The server response authentication information is placed in the **X-SignedResponse** header, the format of which is identical to the request **Authorization** header.

## Header Format
All requests <ins>must</ins> submit an **Authorization** header.

All responses to authorized requests with a HTTP 200 OK status must return an **X-SignedResponse** header.

Here is an example value, valid for both the above headers:
```
2/HMAC_SHA256(H+SHA256(E)) p0f56ffb77b8f4662f462c916a02f8e85a566441ee82a2639de5a1
```

The format of the header is:
```
scheme + " " + parameter_list
```

Where **scheme** identifies the authentication or signature mechanism used for the request or response. The scheme covered by this document is identified as "**2/HMAC_SHA256(H+SHA256(E))**".

**parameter_list** is a comma separated list of key/value pairs:
```
key_1 + "=" + value_1 + ", " +
key_2 + "=" + value_2 + ", " +
...
key_last + "=" + value_last
```

Keys are by convention lower-case and hyphenated. To simplify parsing, values never contain commas, cannot be quoted, and provide no character escaping mechanism.

A table of valid parameters are in the following table:

| <nobr>Param name</nobr> |  Description  | Type | Example | Required |
|:----------|:----------|:----------|:----------|:----------:|
| partner-id | The name of the remote client | String | examplemerchant | Y |
| key-id | Identifier for the key used for signing | String | 123A | Y |
| signed-headers | A semi-colon separated list of HTTP headers that were included during the signing process. (See below section [More on signed headers](#more-on-signed-headers))<br/><br/>If not present, no headers were signed. | String | Content-Type;X-App-Specific-Foo | N |
| timestamp | The time the request or response was signed, as the number of seconds since the UTC unix epoch (1970/01/01).<br/><br/>This is used to mitigate certain replay attacks by making a signed message valid only for a fixed time period. | Integer (unsigned) | 1402285260 | Y |
| signature | The actual calculated signature of the HTTP request or response that this header accompanies.<br/><br/>In this scheme, the value is a lower-case hex encoded SHA-256 digest, i.e. 64 chars long. | String | 9df1f39b8030f56ffb77b\ 8f4662f462c916a02f8e8\ 5a566441ee82a2639de5a1 | Y |

# Signature Generation Process

To sign a message, certain important parts of the message are concatenated together into a single string using the method defined below, this string is then combined with the same timestamp value that appears in **Authorization**[_timestamp_], and the result is then passed into a keyed secure hash function.

## Constructing the Message To Sign - General
The following illustrates how to construct the message to sign, where:
* `+` is a concatenation operator
* Literals are in double quotes - `"`
* Optional sections are enclosed in parentheses followed by a question mark - `( foo )?`
* Named parts of the HTTP message are defined in the table below

```
method + " " + path + ( "?" + query_string )? + "\n" +
    signed_header_1_name + ":" + " " + signed_header_1_value + "\n" +
    ...
    signed_header_N_name + ":" + " " + signed_header_N_value + "\n" +
    ( entity_digest )? + "\n"
    timestamp
```

| Symbol | Explanation | Request / Response | Example |
|:----------|:----------|:----------|:----------|
| method | The HTTP method, **in upper-case** | Request | GET |
| path | The resource path the request is against, exactly as it appears in the request. | Request | /api/1.2/transaction/1234/status |
| query_string | Query part, if any, exactly as it appears in the request. | Request | param=123&other=xyz |
| signed_header_N_name | A HTTP header name, formatted **exactly** as given in Authorization[_signed-headers_], including character case ("content-type" vs "Content-Type"), irrespective of the formatting(s) used when the header appears in the request.<br/><br/>(See the section [More on signed headers](#more-on-signed-headers) for examples) | Both | Content-Type |
| signed_header_N_value | A HTTP header value, **with any whitespace at the beginning or end trimmed**. Must exactly match the string value submitted to the server. For example, if "charset=UTF-8" is submitted the value used for signing must match the exact characters used including the case. | Both | text/xml; charset=utf8 |
| entity_digest | The **lower-case** hex encoded **digest** (by digest, this refers to the hash, not HMAC) of the message entity (body), using the algorithm as appropriate for this scheme. (In this version, SHA-256 is the digest used.)<br/><br/>The **raw** encoded version entity data as sent across the wire should be passed to the digest function, e.g. in the case of text a UTF-8 encoded version of an entity would have different signature to a UTF-16 encoded version of the exact same entity.<br/><br/>(**Note:** as shown above, if no entity is present in the message the trailing delimiter is still present) | Both | |
| timestamp | The timestamp string, exactly as given in Authorization[_timestamp_] | Both | 1401143938 |

## Message To Sign example - HTTP Request
Given the following HTTP request:

<pre>
<span style="background:green;color:white;">POST</span><span style="background:yellow;color:white;">&nbsp;</span><span style="background:blue;color:white;">/test/echo?foo=bar&hoge=piyo</span> HTTP/1.1
Host: api.boku.com
Accept: text/xml
<span style="background:purple;color:white;">Content-type: text/xml; charset=utf-8</span>
Content-length: 282

<span style="background:red;color:white;">&lt;?xml version="1.0" encoding="UTF-8" standalone="yes"?&gt;
&lt;optin-request&gt;
    &lt;country&gt;US&lt;/country&gt;
    &lt;merchant-id&gt;gatewaymerchant&lt;/merchant-id&gt;
    &lt;merchant-request-id&gt;1002001&lt;/merchant-request-id&gt;
    &lt;msisdn&gt;14155551234&lt;/msisdn&gt;
    &lt;optin-type&gt;otp&lt;/optin-type&gt;
&lt;/optin-request&gt;</span>
</pre>

And assuming a partial **Authorization** header to be sent with the request:
```
2/HMAC_SHA256(H+SHA256(E)) partner-id=..., key-id=..., timestamp=1401143938, signed-headers=Content-Type
```

Then the message to sign would be:
```
POST /test/echo?foo=bar&hoge=piyo
Content-Type: text/xml; charset=utf-8
8538819f1ad1a2cada094259ab7366e4fed03274d7e35d948d2edaec0a1b7752
1401143938
```

(For more examples of request signing, including the actual results, see the [Test Vectors](#test-vectors) appendix.)

## Message To Sign example - HTTP Response
Given the following HTTP response:
```
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Content-Type: text/plain
Content-Length: 17
Date: Wed, 30 May 2014 02:12:14 GMT
Connection: close
 
Example response!
```

And assuming a partial **X-SignedResponse** header to be sent with the response:
```
2/HMAC_SHA256(H+SHA256(E)) partner-id=..., key-id=..., timestamp=1401143938, signed-headers=Content-Type
```

Then the message to sign would be:
```
Content-Type: text/plain
595ac2d36521c5c5c9cce91148aeabf2d2c4a6ee9c45b53cc18a6894d251c85d
1401143938
```

(For more examples of response signing, including the actual results, see the [Test Vectors](#test-vectors) appendix.)

## More on signed-headers
If an API makes use of HTTP headers to transmit certain important metadata about the request or response, those headers should be signed so that they cannot be altered in transit by a potential attacker.

Here are some additional rules and clarifications regarding including signed-headers into the Message to Sign:
* If a header is specified in the signed-headers field of the authorization header, it **must** appear in the request or response, otherwise an error will be raised.
* Each unique header name must appear only once in the signed-headers list.
* Headers are included in the Message to Sign in the order specified in the signed-headers list, **not** the order they appeared in the HTTP message.
* Header keys are included into the Message to Sign using the **exact same case** as specified in the signed-headers field, **not** the case of the field in the HTTP request itself.
    - Example:
    - Authorization header contains: _signed-headers=x-foo_
    - Authorization header contains: _signed-headers=x-foo_
    - Message to sign contains: _x-foo: fooValue_
* All instances of a header called out in the signed-headers field will be included in the signature, in the order they were found in the HTTP message.
    - Example showing this combined with above rules:
    - Authorization header contains: _signed-headers=Accept-Language;Content-Type_
    - HTTP request contains:
        * _accept-language: zh-TW, zh-CN;q=0.5_
        * _Content-Type: text/xml_
        * _ACCEPT-LANGUAGE: en;q=0.1_
    - Message to Sign contains:
        * _Accept-Language: zh-TW, zh-CN;q=0.5_
        * _Accept-Language: en;q=0.1_
        * _Content-Type: text/xml_

For more examples of signing headers, see the [Test Vectors](#test-vectors) appendix.

## Calculating the signature
Once you have the Message to Sign and the rest of the Authorization header parameters filled out, calculating the signature is a simple matter of:
```
secretKey = lookupKey(Authorization[key-id])
Authorization[signature] = hex(hmac_sha256(secretKey, messageToSign))
```

This signature should be places in the _signature_ parameter of the Authorization header to allow verification by the remote peer.

# Signature Verification

All messages received from the remote peer should be verified as correctly signed before they are processed, unless the API in question calls for otherwise.

The verification steps are as follows:
* Check if an **Authorization** (request) or **X-SignedResponse** header is present.
    - If the header is absent, the message should be rejected
* Parse the authorization header. The message should be rejected if:
    - It is malformed
    - Required fields as given in the [Header Format](#header-format) table above are missing, or their values are malformed.
* Check if the **timestamp** given in the Authorization header is valid
    - Reject if the timestamp is older than the configured limit (usually 5 minutes in the past)
    - Reject if the timestamp is newer than the configured limit (usually 5 minutes into the future)
    - I.e. Reject if _abs(currentTimeSeconds() - Authorization[timestamp]) > 5 * 60_
* Locate the key corresponding to the given **partner-id** and **key-id** parameters
    - Reject if the specified key is unknown.
* Calculate the signature of the received message using the same steps as detailed in [Signature Generation Process](#signature-generation-process).
    - Reject if the calculated signature does not equal the signature supplied in the authorization header.

If the signature matches, the request or response may be processed. In the case of a request, care should be taken to check that the partner-id referenced in the header really is authorized to perform the requested operation.

# Test Vectors

This section contains various examples of correctly signed HTTP requests and responses, designed to allow verification of an implementation of this specification. The secret key value used for these examples is the ASCII value "secret_key_change_me".

Only those types of requests which are used by the higher level application level API are required to be implemented for things to work, but to be fully compliant with this specification all of the below must produce matching signatures.

## Standard POST request
```
POST /test/echo HTTP/1.1
Accept: text/xml
Authorization: 2/HMAC_SHA256(H+SHA256(E)) timestamp=1402300605, signature=082d44d627606b85512ee9f4fc19c94bd611a7079b58ae048cb8a7a286b55cc0, signed-headers=Content-Type, key-id=k1, partner-id=blahmerchant
Host: api.boku.com
Content-Length: 138
Content-Type: text/xml;charset=utf-8
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<example-request>
    <some-data>an example request</some-data>
</example-request>
```

## Standard entity OK response to same
```
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
X-SignedResponse: 2/HMAC_SHA256(H+SHA256(E)) partner-id=blahmerchant, key-id=k1, signed-headers=Content-Type, timestamp=1402300605, signature=fd0b95074619dba2b1ca52a12002b9680108073177a2278e18674e254aabb32f
Content-Type: text/xml;charset=utf-8
Content-Length: 138
Date: Mon, 09 Jun 2014 07:56:45 GMT
Connection: close
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<example-request>
    <some-data>an example request</some-data>
</example-request>
```

## POST with query string
```
POST /test/echo?foo=bar&hoge=piyo HTTP/1.1
Accept: text/xml
Authorization: 2/HMAC_SHA256(H+SHA256(E)) timestamp=1402300605, signature=007507bf0cd1e5a69152c904f4fa73b6adf703b5b3a2cf334b6fbc026603539b, signed-headers=Content-Type, key-id=k1, partner-id=blahmerchant
Host: api.boku.com
Content-Length: 138
Content-Type: text/xml;charset=utf-8
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<example-request>
    <some-data>an example request</some-data>
</example-request>
```

## POST with more complicated signed-headers
```
POST /test/echo HTTP/1.1
Accept: text/xml
Accept-Language: en-US, en;q=0.5
Accept-Language: fr;q=0.1
Authorization: 2/HMAC_SHA256(H+SHA256(E)) timestamp=1402300605, signature=79d86933093dbdc13093bf20018947405d88655ef1dda6920138cea7ea773809, signed-headers=Content-Type;Accept-Language, key-id=k1, partner-id=blahmerchant
Host: api.boku.com
Content-Length: 138
Content-Type: text/xml;charset=utf-8
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<example-request>
    <some-data>an example request</some-data>
</example-request>
```

## POST with spurious whitespace in signed header
```
POST /test/echo HTTP/1.1
Accept: text/xml
Authorization: 2/HMAC_SHA256(H+SHA256(E)) timestamp=1402300605, signature=082d44d627606b85512ee9f4fc19c94bd611a7079b58ae048cb8a7a286b55cc0, signed-headers=Content-Type, key-id=k1, partner-id=blahmerchant
Host: api.boku.com
Content-Length: 138
Content-Type:  text/xml;charset=utf-8
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<example-request>
    <some-data>an example request</some-data>
</example-request>
```

## Standard GET
```
GET /test/canned/api-resp HTTP/1.1
Accept: text/xml
Authorization: 2/HMAC_SHA256(H+SHA256(E)) timestamp=1402300605, signature=942c3dfd5cb329a2d208c022eb215ef9ae9cb988d17fa39633f446726a650477, key-id=k1, partner-id=blahmerchant
Host: api.boku.com
```

## OK response to same
```
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
X-SignedResponse: 2/HMAC_SHA256(H+SHA256(E)) partner-id=blahmerchant, key-id=k1, timestamp=1402300605, signature=f921262e0642e1524a961d377ec7eb74f13301ab16a4799633726b2163741fc4
Content-Type: text/html;charset=utf-8
Content-Length: 215
Date: Mon, 09 Jun 2014 07:56:45 GMT
Connection: close
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<example-response>
    <result status="OK">
        <message>Success</message>
    </result>
    <some-data>an example response</some-data>
</example-response>
```

## GET with query string
```
GET /test/canned/api-resp?param_a=value%20a&param-b=value-b HTTP/1.1
Accept: text/xml
Authorization: 2/HMAC_SHA256(H+SHA256(E)) timestamp=1402300605, signature=8633c930e6e7c1e567fcc877732929495d36c9e73b68eac6219706e4ed139d63, key-id=k1, partner-id=blahmerchant
Host: api.boku.com
```

## GET with strange query string
```
GET /test/canned/api-resp?&somekey=a&b=a+space&somekey=b?foo HTTP/1.1
Accept: text/xml
Authorization: 2/HMAC_SHA256(H+SHA256(E)) timestamp=1402300605, signature=198df7ee7ee6ab62105a319dcf0a5b23d624797e84138d6ed90fb8a22f4d2f3c, key-id=k1, partner-id=blahmerchant
Host: api.boku.com
```

## DELETE request
```
DELETE /test/canned/api-resp HTTP/1.1
Accept: text/xml
Authorization: 2/HMAC_SHA256(H+SHA256(E)) timestamp=1402300605, signature=c264eff145793bbce18e06865a7b403336db701c7c46eb7acee2faa00fe28ac8, key-id=k1, partner-id=blahmerchant
Host: api.boku.com
```

## DELETE response
```
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
X-SignedResponse: 2/HMAC_SHA256(H+SHA256(E)) partner-id=blahmerchant, key-id=k1, timestamp=1402300605,signature=92a2c4d87a237f3dddebd254f8f82ef964d57d8a84354ac71a13450f760f64fd
Content-Length: 0
Date: Mon, 09 Jun 2014 07:56:45 GMT
Connection: close
```
