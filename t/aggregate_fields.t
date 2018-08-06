use strict;
use warnings;

use File::Basename qw(dirname);

use lib dirname(__FILE__) . "/lib";

use Test::Nginx::Socket tests => 24;
use Test::Nginx::UploadModule;

our $configs = {
    hash_funcs => q[
        location = /upload/ {
            upload_pass @upstream;
            upload_resumable on;
            upload_aggregate_form_field "upload_file_crc32" "$upload_file_crc32";
            upload_aggregate_form_field "upload_file_md5" "$upload_file_md5";
            upload_aggregate_form_field "upload_file_md5_uc" "$upload_file_md5_uc";
            upload_aggregate_form_field "upload_file_sha1" "$upload_file_sha1";
            upload_aggregate_form_field "upload_file_sha1_uc" "$upload_file_sha1_uc";
            upload_aggregate_form_field "upload_file_sha256" "$upload_file_sha256";
            upload_aggregate_form_field "upload_file_sha256_uc" "$upload_file_sha256_uc";
            upload_aggregate_form_field "upload_file_sha512" "$upload_file_sha512";
            upload_aggregate_form_field "upload_file_sha512_uc" "$upload_file_sha512_uc";
            upload_set_form_field "upload_tmp_path" "$upload_tmp_path";
        }
    ],
    simple => q[
        location = /upload/ {
            upload_pass @upstream;
            upload_resumable on;
            upload_aggregate_form_field "upload_file_number" "$upload_file_number";
            upload_aggregate_form_field "upload_file_size" "$upload_file_size";
            upload_set_form_field "upload_tmp_path" "$upload_tmp_path";
        }
    ],
};

our $session_id = 0;

our $requests = {
    single_chunk => {
        headers => sub { join("\n",
            'X-Content-Range: bytes 0-3/4',
            'Session-ID: ' . ++$session_id,
            'Content-Type: text/plain',
            'Content-Disposition: form-data; name="file"; filename="test.txt"');
        },
        body => "POST /upload/\ntest",
    },
    multi_chunk => {
        headers => sub { [
            join("\n",
                'X-Content-Range: bytes 0-131071/262144',
                'Session-ID: ' . ++$session_id,
                'Content-Type: text/plain',
                'Content-Disposition: form-data; name="file"; filename="test.txt"'),
            join("\n",
                'X-Content-Range: bytes 131072-262143/262144',
                'Session-ID: ' . $session_id,
                'Content-Type: text/plain',
                'Content-Disposition: form-data; name="file"; filename="test.txt"'),
        ] },
        body => [
            ["POST /upload/\r\n", "a" x 131072],
            ["POST /upload/\r\n", "b" x 131072],
        ],
    },
    standard => {
        raw_request => sub { join("\r\n",
            "POST /upload/ HTTP/1.1",
            "Host: 127.0.0.1",
            "Connection: Close",
            "Content-Type: multipart/form-data; boundary=------123456789",
            "Content-Length: 262252",
            "",
            "--------123456789",
            "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"",
            "",
            ("a" x 131072) . ("b" x 131072),
            "--------123456789",
            "");
        },
    },
};

no_long_string();
no_shuffle();
run_tests();

__DATA__
=== TEST 1: single chunk upload
--- config eval: $::configs->{simple}
--- more_headers eval: $::requests->{single_chunk}->{headers}->()
--- request eval: $::requests->{single_chunk}->{body}
--- error_code: 200
--- response_body eval
qq{upload_file_number = 1
upload_file_size = 4
upload_tmp_path = ${ENV{TEST_NGINX_UPLOAD_PATH}}/store/$::session_id/$::session_id
}
--- upload_file_like eval
qr/^test$/

=== TEST 2: single chunk upload (http2)
--- config eval: $::configs->{simple}
--- http2
--- skip_nginx
3: < 1.10.0
--- more_headers eval: $::requests->{single_chunk}->{headers}->()
--- request eval: $::requests->{single_chunk}->{body}
--- error_code: 200
--- response_body eval
qq{upload_file_number = 1
upload_file_size = 4
upload_tmp_path = ${ENV{TEST_NGINX_UPLOAD_PATH}}/store/$::session_id/$::session_id
}
--- upload_file_like eval
qr/^test$/

=== TEST 3: multi-chunk uploads
--- config eval: $::configs->{simple}
--- more_headers eval: $::requests->{multi_chunk}->{headers}->()
--- request eval: $::requests->{multi_chunk}->{body}
--- error_code eval
[201, 200]
--- response_body eval
["0-131071/262144", qq{upload_file_number = 1
upload_file_size = 262144
upload_tmp_path = ${ENV{TEST_NGINX_UPLOAD_PATH}}/store/$::session_id/$::session_id
}]
--- upload_file_like eval
qr/^(??{'a' x 131072 . 'b' x 131072})$/

=== TEST 4: multi-chunk uploads (hash funcs)
--- config eval: $::configs->{hash_funcs}
--- more_headers eval: $::requests->{multi_chunk}->{headers}->()
--- request eval: $::requests->{multi_chunk}->{body}
--- error_code eval
[201, 200]
--- response_body eval
["0-131071/262144", qq{upload_file_crc32 = 
upload_file_md5 = 
upload_file_md5_uc = 
upload_file_sha1 = 
upload_file_sha1_uc = 
upload_file_sha256 = 
upload_file_sha256_uc = 
upload_file_sha512 = 
upload_file_sha512_uc = 
upload_tmp_path = ${ENV{TEST_NGINX_UPLOAD_PATH}}/store/$::session_id/$::session_id
}]
--- upload_file_like eval
qr/^(??{'a' x 131072 . 'b' x 131072})$/

=== TEST 5: multi-chunk uploads out of order
--- todo
2: BUG https://github.com/fdintino/nginx-upload-module/issues/106
--- config eval: $::configs->{simple}
--- more_headers eval: [ CORE::reverse @{$::requests->{multi_chunk}->{headers}->()} ]
--- request eval: [ CORE::reverse @{$::requests->{multi_chunk}->{body}}]
--- error_code eval
[201, 200]
--- response_body eval
["131072-262143/262144", qq{upload_file_number = 1
upload_file_size = 262144
upload_tmp_path = ${ENV{TEST_NGINX_UPLOAD_PATH}}/store/$::session_id/$::session_id
}]

=== TEST 6: multipart/form-data
--- config eval: $::configs->{simple}
--- raw_request eval: $::requests->{standard}->{raw_request}->()
--- error_code: 200
--- response_body eval
qq{upload_file_number = 1
upload_file_size = 262144
upload_tmp_path = ${ENV{TEST_NGINX_UPLOAD_PATH}}/store/1/0000000001
}
--- upload_file_like eval
qr/^(??{'a' x 131072 . 'b' x 131072})$/

=== TEST 7: multipart/form-data (hash fields)
--- config eval: $::configs->{hash_funcs}
--- raw_request eval: $::requests->{standard}->{raw_request}->()
--- error_code: 200
--- response_body eval
qq{upload_file_crc32 = db99345e
upload_file_md5 = 01f2c9f3ccdf9c44f733ff443228e66d
upload_file_md5_uc = 01F2C9F3CCDF9C44F733FF443228E66D
upload_file_sha1 = a2eb84a7bee5e2263e9a3cffae44a4a11044bb2e
upload_file_sha1_uc = A2EB84A7BEE5E2263E9A3CFFAE44A4A11044BB2E
upload_file_sha256 = 58a200a96c5ef282be0d02ab6906655513584bf281bef027b842c2e66b1c56c7
upload_file_sha256_uc = 58A200A96C5EF282BE0D02AB6906655513584BF281BEF027B842C2E66B1C56C7
upload_file_sha512 = fa5af601c85900b80f40865a74a71a74ba382b51336543ba72b31d2e0af80867c1862051763ea9309f637b2ad6133b6e170e4f088a2951a3d05d6fe3a5bcd0e9
upload_file_sha512_uc = FA5AF601C85900B80F40865A74A71A74BA382B51336543BA72B31D2E0AF80867C1862051763EA9309F637B2AD6133B6E170E4F088A2951A3D05D6FE3A5BCD0E9
upload_tmp_path = ${ENV{TEST_NGINX_UPLOAD_PATH}}/store/8/0000123458
}
--- upload_file_like eval
qr/^(??{'a' x 131072 . 'b' x 131072})$/
