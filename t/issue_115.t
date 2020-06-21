use strict;
use warnings;

use File::Basename qw(dirname);

use lib dirname(__FILE__) . "/lib";

use Test::Nginx::Socket tests => 13;
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
X-Content-Range: bytes 0-0/1
Session-ID: 0000000001
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"
--- request eval
qq{POST /upload/
x}
--- no_error_log
[error]
--- error_code: 200
--- response_body eval
qq{upload_content_range = bytes 0-0/1
upload_content_type = text/plain
upload_field_name = file
upload_file_name = test.txt
upload_file_number = 1
upload_tmp_path = ${ENV{TEST_NGINX_UPLOAD_PATH}}/store/1/0000000001
}
--- upload_file_like eval
qr/^x$/

=== TEST 2: multiple single-byte chunk uploads 
--- http_config eval: $::http_config
--- config eval: $::config
--- more_headers eval
[qq{X-Content-Range: bytes 0-0/2
Session-ID: 0000000002
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"},
qq{X-Content-Range: bytes 1-1/2
Session-ID: 0000000002
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"}]
--- request eval
[["POST /upload/\r\n",
"x"],
["POST /upload/\r\n",
"y"]]
--- ignore_response
--- no_error_log eval
["[error]", "[error]"]

=== TEST 3: multiple single-byte chunk uploads success
--- http_config eval: $::http_config
--- config eval: $::config
--- more_headers eval
[qq{X-Content-Range: bytes 0-0/2
Session-ID: 0000000003
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"},
qq{X-Content-Range: bytes 1-1/2
Session-ID: 0000000003
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"}]
--- request eval
[["POST /upload/\r\n",
"x"],
["POST /upload/\r\n",
"y"]]
--- error_code eval
[201, 200]
--- response_body eval
["0-0/2", qq{upload_content_range = bytes 1-1/2
upload_content_type = text/plain
upload_field_name = file
upload_file_name = test.txt
upload_file_number = 1
upload_tmp_path = ${ENV{TEST_NGINX_UPLOAD_PATH}}/store/3/0000000003
}]
--- upload_file_like eval
qr/^xy$/
