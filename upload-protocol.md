# Resumable uploads over HTTP. Protocol specification

Valery Kholodkov [\<valery@grid.net.ru\>](mailto:valery@grid.net.ru),
2010

## 1. Introduction

This document describes application protocol that is used by [nginx
upload module](upload.ru.html) to implement resumable file uploads. The
first version of the module that supports this protocol is 2.2.0.

<span id="2"></span>

## 2. Purpose

The HTTP implements file uploads according to
[RFC 1867](http://www.ietf.org/rfc/rfc1867.txt). When the request length
is excessively large, the probability that connection will be
interrupted is high. HTTP does not foresee a resumption mechanism. The
goal of the protocol being described is to implement a mechanism of
resumption of interrupted file transfer or suspension of upload upon
user request.

<span id="2.1"></span>

## 2.1. Splitting file into segments

When TCP-connection interrupts abnormaly there is no way to determine
what part of data stream has been succesfully delivered and what hasn't
been delivered. Therefore a client cannot determine what position to
resume from without communicating to server. In order to eliminate
additional communication file is represented as an array of segments of
reasonable length. When TCP-connection interrupts while transmitting
certain segment, client retransmits the whole segment until a positive
reponse will be received from server or maximal number of tries will be
reached. In the protocol being described the client is responsible for
choosing optimal length of a segment.

For tracking the progress of file upload client and server use identical
numbering scheme for each byte of a file. The first byte of a file has
number 0, the last byte has number n-1, where n is the length of file in
bytes.

The order of transmission of a segment is not defined. Client may choose
arbitrary order. However it is recommended to send segments in order
ascention of byte numbers. Moreover, a user agent might decide to send
multiple segments simultaneously using multiple independent connections.
If a client exceeds maximal number of simultaneous connections allowed,
server might return 503 "Service Unavailable" response.

In case of simultaneous transmission it is prohibited to send 2 or more
requests with overlapping ranges within one session. Whenever server
detects simultaneous requests with overlapping ranges it must return an
errorneous response.

<span id="2.2"></span>

## 2.2. Encapsulation

Each segment of a file is encapsulated into a separate HTTP-request. The
method of the request is POST. Each request contains following specific
headers:

| Header              | Function                                                               |
| ------------------- | ---------------------------------------------------------------------- |
| Content-Disposition | `attachment, filename="name of the file being uploaded"`               |
| Content-Type        | mime type of a file being uploaded (must not be `multipart/form-data`) |
| X-Content-Range     | byte range of a segment being uploaded                                 |
| X-Session-ID        | identifier of a session of a file being uploaded (see [2.3](#2.3))     |

`X-Content-Range` and `X-Session-Id` can also be `Content-Range` and `Session-ID`, respectively.

The body of the request must contain a segment of the file,
corresponding to the range that was specified in `X-Content-Range` or
`Content-Range` headers.

Whenever a user agent is not able to determine mime type of a file, it
may use `application/octet-stream`.

<span id="2.3"></span>

## 2.3. Session management

In order to identify requests containing segments of a file, a user
agent sends a unique session identified in headers `X-Session-ID` or
`Session-ID`. User agent is responsible for making session identifiers
unique. Server must be ready to process requests from different
IP-addresses corresponding to a single session.

<span id="2.4"></span>

## 2.4. Acknowledgment

Server acknowledges reception of each segment with a positive response.
Positive responses are: 201 "Created" whenever at the moment of the
response generation not all segments of the file were received or other
2xx and 3xx responses whenever at the moment of the response generation
all segments of the file were received. Server must return positive
response only when all bytes of a segment were successfully saved and
information about which of the byte ranges were received was
successfully updated.

Upon reception of 201 "Created" response client must proceed with
transmission of a next segment. Upon reception of other positive
response codes client must proceed according to their standart
interpretation (see. [RFC 2616](http://www.ietf.org/rfc/rfc2616.txt)).

In each 201 "Created" response server returns a Range header containing
enumeration of all byte ranges of a file that were received at the
moment of the response generation. Server returns identical list of
ranges in response body.

<span id="appa"></span>

## Appendix A: Session examples

### Example 1: Request from client containing the first segment of the file

```http
POST /upload HTTP/1.1
Host: example.com
Content-Length: 51201
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="big.TXT"
X-Content-Range: bytes 0-51200/511920
Session-ID: 1111215056 

<bytes 0-51200>
```

### Example 2: Response to a request containing first segment of a file

```http
HTTP/1.1 201 Created
Date: Thu, 02 Sep 2010 12:54:40 GMT
Content-Length: 14
Connection: close
Range: 0-51200/511920

0-51200/511920 
```

### Example 3: Request from client containing the last segment of the file

```http
POST /upload HTTP/1.1
Host: example.com
Content-Length: 51111
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="big.TXT"
X-Content-Range: bytes 460809-511919/511920
Session-ID: 1111215056

<bytes 460809-511919>
```

### Example 4: Response to a request containing last segment of a file

```http
HTTP/1.1 200 OK
Date: Thu, 02 Sep 2010 12:54:43 GMT
Content-Type: text/html
Connection: close
Content-Length: 2270

<response body>
```
