use strict;
use warnings;

use File::Basename qw(dirname);

use lib dirname(__FILE__) . "/lib";

use Test::Nginx::Socket tests => 33;
use Test::Nginx::UploadModule;


our $config = <<'_EOC_';
location = /upload/ {
    upload_pass @upstream;
    upload_resumable on;

    upload_set_form_field upload_file_name $upload_file_name;
    upload_set_form_field upload_file_number $upload_file_number;
    upload_set_form_field "upload_field_name" "$upload_field_name";
    upload_set_form_field "upload_content_type" "$upload_content_type";
    upload_set_form_field "upload_tmp_path" "$upload_tmp_path";
    upload_set_form_field "upload_content_range" "$upload_content_range";
    upload_max_file_size 0;
    upload_pass_args on;
    upload_cleanup 400 404 499 500-505;
}
_EOC_

no_long_string();
no_shuffle();
run_tests();

__DATA__
=== TEST 1: single chunk upload
--- config eval: $::config
--- more_headers
X-Content-Range: bytes 0-3/4
Session-ID: 0000000001
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"
--- request eval
qq{POST /upload/
test}
--- error_code: 200
--- response_body eval
qq{upload_content_range = bytes 0-3/4
upload_content_type = text/plain
upload_field_name = file
upload_file_name = test.txt
upload_file_number = 1
upload_tmp_path = ${ENV{TEST_NGINX_UPLOAD_PATH}}/store/1/0000000001
}
--- upload_file_like eval
qr/^test$/

=== TEST 2: multiple chunk uploads
--- http_config eval: $::http_config
--- config eval: $::config
--- more_headers eval
[qq{X-Content-Range: bytes 0-1/4
Session-ID: 0000000002
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"},
qq{X-Content-Range: bytes 2-3/4
Session-ID: 0000000002
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"}]
--- request eval
[["POST /upload/\r\n",
"te"],
["POST /upload/\r\n",
"st"]]
--- error_code eval
[201, 200]
--- response_body eval
["0-1/4", qq{upload_content_range = bytes 2-3/4
upload_content_type = text/plain
upload_field_name = file
upload_file_name = test.txt
upload_file_number = 1
upload_tmp_path = ${ENV{TEST_NGINX_UPLOAD_PATH}}/store/2/0000000002
}]
--- upload_file_like eval
qr/^test$/

=== Test 3: large multiple chunk uploads
--- config eval: $::config
--- more_headers eval
[qq{X-Content-Range: bytes 0-131071/262144
Session-ID: 0000000003
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"},
qq{X-Content-Range: bytes 131072-262143/262144
Session-ID: 0000000003
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"}]
--- request eval
[["POST /upload/\r\n",
"x" x 131072],
["POST /upload/\r\n",
"x" x 131072]]
--- error_code eval
[201, 200]
--- response_body eval
["0-131071/262144", qq{upload_content_range = bytes 131072-262143/262144
upload_content_type = text/plain
upload_field_name = file
upload_file_name = test.txt
upload_file_number = 1
upload_tmp_path = ${ENV{TEST_NGINX_UPLOAD_PATH}}/store/3/0000000003
}]
--- upload_file_like eval
qr/^(??{'x' x 262144})$/

=== Test 4: upload_limit_rate
--- config
location = /upload/ {
    upload_pass @upstream;
    upload_resumable on;
    upload_set_form_field "upload_tmp_path" "$upload_tmp_path";
    upload_max_file_size 0;
    upload_pass_args on;
    upload_cleanup 400 404 499 500-505;
    upload_limit_rate 32768;
}
--- timeout: 5
--- more_headers eval
[qq{X-Content-Range: bytes 0-131071/262144
Session-ID: 0000000004
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"},
qq{X-Content-Range: bytes 131072-262143/262144
Session-ID: 0000000004
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"}]
--- request eval
[["POST /upload/\r\n",
"x" x 131072],
["POST /upload/\r\n",
"x" x 131072]]
--- error_code eval
[201, 200]
--- response_body eval
["0-131071/262144", qq{upload_tmp_path = ${ENV{TEST_NGINX_UPLOAD_PATH}}/store/4/0000000004
}]
--- upload_file_like eval
qr/^(??{'x' x 262144})$/
--- access_log eval
# should have taken 4 seconds, with 1 second possible error
# (Test::Nginx::UploadModule::http_config adds request time to the end of
# the access log)
[qr/[34]\.\d\d\d$/, qr/[34]\.\d\d\d$/]

=== TEST 5: multiple chunk uploads out-of-order
--- config eval: $::config
--- more_headers eval
[qq{X-Content-Range: bytes 131072-262143/262144
Session-ID: 0000000005
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"},
qq{X-Content-Range: bytes 0-131071/262144
Session-ID: 0000000005
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"}]
--- request eval
[["POST /upload/\r\n",
"b" x 131072],
["POST /upload/\r\n",
"a" x 131072]]
--- error_code eval
[201, 200]
--- response_body eval
["131072-262143/262144", qq{upload_content_range = bytes 0-131071/262144
upload_content_type = text/plain
upload_field_name = file
upload_file_name = test.txt
upload_file_number = 1
upload_tmp_path = ${ENV{TEST_NGINX_UPLOAD_PATH}}/store/5/0000000005
}]
--- upload_file_like eval
qr/^(??{'a' x 131072 . 'b' x 131072})$/

=== TEST 6: multipart upload
--- config eval: $::config
--- more_headers
Content-Type: multipart/form-data; boundary=BOUNDARY
--- request eval
"POST /upload/
--BOUNDARY
Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r
Content-Type: text/plain\r
\r
test\r
--BOUNDARY--\r
"
--- error_code: 200
--- response_body eval
qq{upload_content_range = bytes 0-0/0
upload_content_type = text/plain
upload_field_name = file
upload_file_name = test.txt
upload_file_number = 1
upload_tmp_path = ${ENV{TEST_NGINX_UPLOAD_PATH}}/store/8/0000123458
}
--- upload_file_like eval
qr/^test$/

=== TEST 7: multipart upload with quoted boundary and unquoted names
--- config eval: $::config
--- more_headers
Content-Type: multipart/form-data; boundary="BOUNDARY"
--- request eval
"POST /upload/
--BOUNDARY
Content-Disposition: form-data; name=file; filename=test.txt\r
Content-Type: text/plain\r
\r
test\r
--BOUNDARY--\r
"
--- error_code: 200
--- response_body eval
qq{upload_content_range = bytes 0-0/0
upload_content_type = text/plain
upload_field_name = file
upload_file_name = test.txt
upload_file_number = 1
upload_tmp_path = ${ENV{TEST_NGINX_UPLOAD_PATH}}/store/5/0000246915
}
--- upload_file_like eval
qr/^test$/
