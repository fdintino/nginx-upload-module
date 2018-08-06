use strict;
use warnings;

use File::Basename qw(dirname);

use lib dirname(__FILE__) . "/lib";

use Test::Nginx::Socket tests => 2;
use Test::More;
use Test::Nginx::UploadModule;

no_long_string();
no_shuffle();
run_tests();

__DATA__
=== TEST 1: OPTIONS request
--- config
location /upload/ {
    upload_pass @upstream;
    upload_resumable on;
    upload_set_form_field "upload_tmp_path" "$upload_tmp_path";
    upload_cleanup 400 404 499 500-505;
}
--- request
OPTIONS /upload/
--- error_code: 200

=== TEST 2: http2 OPTIONS request
--- http2
--- config
location /upload/ {
    upload_pass @upstream;
    upload_resumable on;
    upload_set_form_field "upload_tmp_path" "$upload_tmp_path";
    upload_cleanup 400 404 499 500-505;
}
--- request
OPTIONS /upload/
--- error_code: 200
