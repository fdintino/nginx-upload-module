# nginx-upload-module

[![Build Status](https://travis-ci.org/fdintino/nginx-upload-module.svg?branch=master)](https://travis-ci.org/fdintino/nginx-upload-module)
[![codecov](https://codecov.io/gh/fdintino/nginx-upload-module/branch/master/graph/badge.svg)](https://codecov.io/gh/fdintino/nginx-upload-module)

A module for [nginx](https://www.nginx.com/) for handling file uploads using
multipart/form-data encoding ([RFC 1867](http://www.ietf.org/rfc/rfc1867.txt))
and resumable uploads according to
[this](https://github.com/fdintino/nginx-upload-module/blob/master/upload-protocol.md)
protocol.

* [Description](#description)
* [Directives](#directives)
    * [upload_pass](#upload_pass)
    * [upload_resumable](#upload_resumable)
    * [upload_store](#upload_store)
    * [upload_state_store](#upload_state_store)
    * [upload_store_access](#upload_store_access)
    * [upload_set_form_field](#upload_set_form_field)
    * [upload_aggregate_form_field](#upload_aggregate_form_field)
    * [upload_pass_form_field](#upload_pass_form_field)
    * [upload_cleanup](#upload_cleanup)
    * [upload_buffer_size](#upload_buffer_size)
    * [upload_max_part_header_len](#upload_max_part_header_len)
    * [upload_max_file_size](#upload_max_file_size)
    * [upload_limit_rate](#upload_limit_rate)
    * [upload_max_output_body_len](#upload_max_output_body_len)
    * [upload_tame_arrays](#upload_tame_arrays)
    * [upload_pass_args](#upload_pass_args)
* [Example configuration](#example-configuration)
* [License](#license)

## Description

The module parses request body storing all files being uploaded to a
directory specified by [`upload_store`](#upload_store) directive. The
files are then being stripped from body and altered request is then
passed to a location specified by [`upload_pass`](#upload_pass)
directive, thus allowing arbitrary handling of uploaded files. Each of
file fields are being replaced by a set of fields specified by
[`upload_set_form_field`](#upload_set_form_field) directive. The
content of each uploaded file then could be read from a file specified
by $upload_tmp_path variable or the file could be simply moved to
ultimate destination. Removal of output files is controlled by directive
[`upload_cleanup`](#upload_cleanup). If a request has a method other than
POST, the module returns error 405 (Method not allowed). Requests with
such methods could be processed in alternative location via
[`error_page`](http://nginx.org/en/docs/http/ngx_http_core_module.html#error_page)
directive.

## Directives

### upload_pass

**Syntax:** <code><b>upload_pass</b> <i>location</i></code><br>
**Default:** —<br>
**Context:** `server,location`

Specifies location to pass request body to. File fields will be stripped
and replaced by fields, containing necessary information to handle
uploaded files.

### upload_resumable

**Syntax:** <code><b>upload_resumable</b> on | off</code><br>
**Default:** `upload_resumable off`<br>
**Context:** `main,server,location`

Enables resumable uploads.

### upload_store

**Syntax:** <code><b>upload_store</b> <i>directory</i> [<i>level1</i> [<i>level2</i>]] ...</code><br>
**Default:** —<br>
**Context:** `server,location`

Specifies a directory to which output files will be saved to. The
directory could be hashed. In this case all subdirectories should exist
before starting nginx.

### upload_state_store

**Syntax:** <code><b>upload_state_store</b> <i>directory</i> [<i>level1</i> [<i>level2</i>]] ...</code><br>
**Default:** —<br>
**Context:** `server,location`

Specifies a directory that will contain state files for resumable
uploads. The directory could be hashed. In this case all subdirectories
should exist before starting nginx.

### upload_store_access

**Syntax:** <code><b>upload_store_access</b> <i>mode</i></code><br>
**Default:** `upload_store_access user:rw`<br>
**Context:** `server,location`

Specifies access mode which will be used to create output files.

### upload_set_form_field

**Syntax:** <code><b>upload_set_form_field</b> <i>name</i> <i>value</i></code><br>
**Default:** —<br>
**Context:** `server,location`

Specifies a form field(s) to generate for each uploaded file in request
body passed to backend. Both `name` and `value` could contain following
special variables:

  - `$upload_field_name`: the name of original file field
  - `$upload_content_type`: the content type of file uploaded
  - `$upload_file_name`: the original name of the file being uploaded
    with leading path elements in DOS and UNIX notation stripped. I.e.
    "D:\\Documents And Settings\\My Dcouments\\My Pictures\\Picture.jpg"
    will be converted to "Picture.jpg" and "/etc/passwd" will be
    converted to "passwd".
  - `$upload_tmp_path`: the path where the content of original file is
    being stored to. The output file name consists 10 digits and
    generated with the same algorithm as in `proxy_temp_path`
    directive.

These variables are valid only during processing of one part of original
request body.

Usage example:

```nginx
upload_set_form_field $upload_field_name.name "$upload_file_name";
upload_set_form_field $upload_field_name.content_type "$upload_content_type";
upload_set_form_field $upload_field_name.path "$upload_tmp_path";
```

### upload_aggregate_form_field

**Syntax:** <code><b>upload_aggregate_form_field</b> <i>name</i> <i>value</i></code><br>
**Default:** —<br>
**Context:** `server,location`

Specifies a form field(s) containing aggregate attributes to generate
for each uploaded file in request body passed to backend. Both name and
value could contain standard nginx variables, variables from
[upload_set_form_field](#upload_set_form_field) directive and
following additional special variables:

  - `$upload_file_md5`: MD5 checksum of the file
  - `$upload_file_md5_uc`: MD5 checksum of the file in uppercase letters
  - `$upload_file_sha1`: SHA1 checksum of the file
  - `$upload_file_sha1_uc`: SHA1 checksum of the file in uppercase letters
  - `$upload_file_sha256`: SHA256 checksum of the file
  - `$upload_file_sha256_uc`: SHA256 checksum of the file in uppercase letters
  - `$upload_file_sha512`: SHA512 checksum of the file
  - `$upload_file_sha512_uc`: SHA512 checksum of the file in uppercase letters
  - `$upload_file_crc32`: hexdecimal value of CRC32 of the file
  - `$upload_file_size`: size of the file in bytes
  - `$upload_file_number`: ordinal number of file in request body

The value of a field specified by this directive is evaluated after
successful upload of the file, thus these variables are valid only at
the end of processing of one part of original request body.

**Warning:**: variables `$upload_file_md5`, `$upload_file_md5_uc`,
`$upload_file_sha1`, and `$upload_file_sha1_uc` use additional
resources to calculate MD5 and SHA1 checksums.

Usage example:

```nginx
upload_aggregate_form_field $upload_field_name.md5 "$upload_file_md5";
upload_aggregate_form_field $upload_field_name.size "$upload_file_size";

```

### upload_pass_form_field

**Syntax:** <code><b>upload_pass_form_field</b> <i>regex</i></code><br>
**Default:** —<br>
**Context:** `server,location`

Specifies a regex pattern for names of fields which will be passed to
backend from original request body. This directive could be specified
multiple times per location. Field will be passed to backend as soon as
first pattern matches. For PCRE-unaware enviroments this directive
specifies exact name of a field to pass to backend. If directive is
omitted, no fields will be passed to backend from client.

Usage example:

```nginx
upload_pass_form_field "^submit$|^description$";
```

For PCRE-unaware environments:

```nginx
upload_pass_form_field "submit";
upload_pass_form_field "description";

```

### upload_cleanup

**Syntax:** <code><b>upload_cleanup</b> <i>status/range</i> ...</code><br>
**Default:** —<br>
**Context:** `server,location`

Specifies HTTP statuses after generation of which all file successfuly
uploaded in current request will be removed. Used for cleanup after
backend or server failure. Backend may also explicitly signal errornous
status if it doesn't need uploaded files for some reason. HTTP status
must be a numerical value in range 400-599, no leading zeroes are
allowed. Ranges of statuses could be specified with a dash.

Usage example:

```nginx
upload_cleanup 400 404 499 500-505;
```

### upload_buffer_size

**Syntax:** <code><b>upload_buffer_size</b> <i>size</i></code><br>
**Default:** size of memory page in bytes<br>
**Context:** `server,location`

Size in bytes of write buffer which will be used to accumulate file data
and write it to disk. This directive is intended to be used to
compromise memory usage vs. syscall rate.

### upload_max_part_header_len

**Syntax:** <code><b>upload_max_part_header_len</b> <i>size</i></code><br>
**Default:** `512`<br>
**Context:** `server,location`

Specifies maximal length of part header in bytes. Determines the size of
the buffer which will be used to accumulate part headers.

### upload_max_file_size

**Syntax:** <code><b>upload_max_file_size</b> <i>size</i></code><br>
**Default:** `0`<br>
**Context:** `main,server,location`

Specifies maximal size of the file. Files longer than the value of this
directive will be omitted. This directive specifies "soft" limit, in the
sense, that after encountering file longer than specified limit, nginx
will continue to process request body, trying to receive remaining
files. For "hard" limit `client_max_body_size` directive must be
used. The value of zero for this directive specifies that no
restrictions on file size should be applied.

### upload_limit_rate

**Syntax:** <code><b>upload_limit_rate</b> <i>rate</i></code><br>
**Default:** `0`<br>
**Context:** `main,server,location`

Specifies upload rate limit in bytes per second. Zero means rate is
unlimited.

### upload_max_output_body_len

**Syntax:** <code><b>upload_max_output_body_len</b> <i>size</i></code><br>
**Default:** `100k`<br>
**Context:** `main,server,location`

Specifies maximal length of the output body. This prevents piling up of
non-file form fields in memory. Whenever output body overcomes specified
limit error 413 (Request entity too large) will be generated. The value
of zero for this directive specifies that no restrictions on output body
length should be applied.

### upload_tame_arrays

**Syntax:** <code><b>upload_tame_arrays</b> on | off</code><br>
**Default:** `off`<br>
**Context:** `main,server,location`

Specifies whether square brackets in file field names must be dropped
(required for PHP arrays).

### upload_pass_args

**Syntax:** <code><b>upload_pass_args</b> on | off</code><br>
**Default:** `off`<br>
**Context:** `main,server,location`

Enables forwarding of query arguments to location, specified by
[upload_pass](#upload_pass). Ineffective with named locations. Example:

```html
<form action="/upload/?id=5">
<!-- ... -->
```

```nginx
location /upload/ {
    upload_pass /internal_upload/;
    upload_pass_args on;
}

# ...

location /internal_upload/ {
    # ...
    proxy_pass http://backend;
}
```

In this example backend gets request URI "/upload?id=5". In case of
`upload_pass_args off` backend gets "/upload".

## Example configuration

```nginx
server {
    client_max_body_size 100m;
    listen 80;

    # Upload form should be submitted to this location
    location /upload/ {
        # Pass altered request body to this location
        upload_pass @test;

        # Store files to this directory
        # The directory is hashed, subdirectories 0 1 2 3 4 5 6 7 8 9 should exist
        upload_store /tmp 1;

        # Allow uploaded files to be read only by user
        upload_store_access user:r;

        # Set specified fields in request body
        upload_set_form_field $upload_field_name.name "$upload_file_name";
        upload_set_form_field $upload_field_name.content_type "$upload_content_type";
        upload_set_form_field $upload_field_name.path "$upload_tmp_path";

        # Inform backend about hash and size of a file
        upload_aggregate_form_field "$upload_field_name.md5" "$upload_file_md5";
        upload_aggregate_form_field "$upload_field_name.size" "$upload_file_size";

        upload_pass_form_field "^submit$|^description$";

        upload_cleanup 400 404 499 500-505;
    }

    # Pass altered request body to a backend
    location @test {
        proxy_pass http://localhost:8080;
    }
}
```

```html
<form name="upload" method="POST" enctype="multipart/form-data" action="/upload/">
<input type="file" name="file1">
<input type="file" name="file2">
<input type="hidden" name="test" value="value">
<input type="submit" name="submit" value="Upload">
</form>
```

## License

The above-described module is an addition to
[nginx](https://www.nginx.com/) web-server, nevertheless they are
independent products. The license of above-described module is
[BSD](http://en.wikipedia.org/wiki/BSD_license) You should have received
a copy of license along with the source code. By using the materials
from this site you automatically agree to the terms and conditions of
this license. If you don't agree to the terms and conditions of this
license, you must immediately remove from your computer all materials
downloaded from this site.
