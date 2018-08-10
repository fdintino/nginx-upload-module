use strict;
use warnings;

use File::Basename qw(dirname);

use lib dirname(__FILE__) . "/lib";

use Test::Nginx::Socket tests => 13;
use Test::More;
use Test::Nginx::UploadModule;

no_long_string();
no_shuffle();
run_tests();

__DATA__
=== TEST 1: upload_pass_args on should pass GET params
--- config
location /test/ {
    upload_pass /upload/;
    upload_resumable on;
    upload_set_form_field upload_file_name $upload_file_name;
    upload_pass_args on;
}

location /upload/ {
    proxy_pass http://upload_upstream_server;
}
--- more_headers
X-Content-Range: bytes 0-3/4
Session-ID: 1
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"
--- request
POST /test/?foo=bar
test
--- error_code: 200
--- response_body
foo = bar
upload_file_name = test.txt

=== TEST 2: upload_pass_args off should strip GET params
--- config
location /test/ {
    upload_pass /upload/;
    upload_resumable on;
    upload_pass_args off;
    upload_set_form_field upload_file_name $upload_file_name;
}

location /upload/ {
    proxy_pass http://upload_upstream_server;
}
--- more_headers
X-Content-Range: bytes 0-3/4
Session-ID: 2
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"
--- request
POST /test/?foo=bar
test
--- error_code: 200
--- response_body
upload_file_name = test.txt

=== TEST 3: upload_tame_arrays on
--- config
location /upload/ {
    upload_pass @upstream;
    upload_resumable on;
    upload_tame_arrays on;
    upload_set_form_field upload_file_name $upload_file_name;
}
--- more_headers
X-Content-Range: bytes 0-3/4
Session-ID: 3
Content-Type: text/plain
Content-Disposition: form-data; name="file[]"; filename="test.txt"
--- request
POST /upload/
test
--- error_code: 200
--- response_body
upload_file_name = test.txt

=== TEST 4: upload_set_form_field multiple fields
--- config
location /upload/ {
    upload_pass @upstream;
    upload_resumable on;
    upload_set_form_field upload_field_name_and_file_name "$upload_field_name $upload_file_name";
}
--- more_headers
X-Content-Range: bytes 0-3/4
Session-ID: 4
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"
--- request
POST /upload/
test
--- error_code: 200
--- response_body
upload_field_name_and_file_name = file test.txt

=== TEST 5: upload_set_form_field variable key
--- config
location /upload/ {
    upload_pass @upstream;
    upload_resumable on;
    set $form_field_name "upload_file_name";
    upload_set_form_field "$form_field_name" "$upload_file_name";
}
--- more_headers
X-Content-Range: bytes 0-3/4
Session-ID: 5
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"
--- request
POST /upload/
test
--- error_code: 200
--- response_body
upload_file_name = test.txt


=== TEST 6: upload_add_header
--- config
location /upload/ {
    upload_pass @upstream;
    upload_resumable on;
    upload_add_header X-Upload-Filename $upload_file_name;
    upload_set_form_field upload_file_name $upload_file_name;
}
--- more_headers
X-Content-Range: bytes 0-3/4
Session-ID: 3
Content-Type: text/plain
Content-Disposition: form-data; name="file"; filename="test.txt"
--- request
POST /upload/
test
--- error_code: 200
--- raw_response_headers_like: X-Upload-Filename: test\.txt
--- response_body
upload_file_name = test.txt
