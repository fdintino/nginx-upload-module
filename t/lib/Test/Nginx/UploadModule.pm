package Test::Nginx::UploadModule;
use v5.10.1;
use strict;
use warnings;

my $PORT = $ENV{TEST_NGINX_UPSTREAM_PORT} ||= 12345;
$ENV{TEST_NGINX_UPLOAD_PATH} ||= '/tmp/upload';
$ENV{TEST_NGINX_UPLOAD_FILE} = $ENV{TEST_NGINX_UPLOAD_PATH} . "/test_data.txt";


use base 'Exporter';

use Test::Nginx::Socket;
use Test::Nginx::Util qw($RunTestHelper);
use Test::File qw(file_contains_like);
use Test::More;

use File::Path qw(rmtree mkpath);
use Test::Nginx::UploadModule::TestServer;


my ($server_pid, $server);

sub kill_tcp_server() {
    $server->shutdown if defined $server;
    undef $server;
    kill INT => $server_pid if defined $server_pid;
    undef $server_pid;
}

sub make_upload_paths {
    mkpath("${ENV{TEST_NGINX_UPLOAD_PATH}}/stats");
    for (my $i = 0; $i < 10; $i++) {
        mkpath("${ENV{TEST_NGINX_UPLOAD_PATH}}/store/$i");
    }
    open(my $fh, ">", $ENV{TEST_NGINX_UPLOAD_FILE});
    print $fh ('x' x 131072);
    close($fh);
}

add_cleanup_handler(sub {
    kill_tcp_server();
    rmtree($ENV{TEST_NGINX_UPLOAD_PATH});
});

my $OldRunTestHelper = $RunTestHelper;

my @ResponseChecks = ();

my $old_check_response_headers = \&Test::Nginx::Socket::check_response_headers;

sub new_check_response_headers ($$$$$) {
    my ($block, $res, $raw_headers, $dry_run, $req_idx, $need_array) = @_;
    $old_check_response_headers->(@_);
    if (!$dry_run) {
        for my $check (@ResponseChecks) {
            $check->(@_);
        }
    }
}

$RunTestHelper = sub ($$) {
    if (defined $server) {
        $OldRunTestHelper->(@_);
    } else {
        defined (my $pid = fork()) or bail_out "Can't fork: $!";
        if ($pid == 0) {
            $Test::Nginx::Util::InSubprocess = 1;
            if (!defined $server) {
                $server = Test::Nginx::UploadModule::TestServer->new({port=>$PORT});
                $server->run();
                exit 0;
            }
        } else {
            $server_pid = $pid;
            no warnings qw(redefine);
            Test::Nginx::UploadModule::TestServer::wait_for_port($PORT, \&bail_out);
            *Test::Nginx::Socket::check_response_headers = \&new_check_response_headers;

            $OldRunTestHelper->(@_);

            *Test::Nginx::Socket::check_response_headers = &$old_check_response_headers;

            kill_tcp_server();
        }
    }
};

my $default_http_config = <<'_EOC_';
upstream upload_upstream_server {
    server 127.0.0.1:$TEST_NGINX_UPSTREAM_PORT;
}

log_format custom '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" $request_time';
_EOC_


my $default_config = <<'_EOC_';
location @upstream {
    internal;
    proxy_pass http://upload_upstream_server;
}
upload_store $TEST_NGINX_UPLOAD_PATH/store 1;
upload_state_store $TEST_NGINX_UPLOAD_PATH/stats;

access_log $TEST_NGINX_SERVER_ROOT/logs/access.log custom;
_EOC_

# Set default configs, create upload directories, and add extra_tests blocks to @ResponseChecks
add_block_preprocessor(sub {
    my $block = shift;

    make_upload_paths();

    if (!defined $block->http_config) {
        $block->set_value('http_config', $default_http_config);
    } else {
        $block->set_value('http_config', $default_http_config . $block->http_config);
    }
    if (defined $block->config) {
        $block->set_value('config', $default_config . $block->config);
    }
    if (defined $block->extra_tests) {
        if (ref $block->extra_tests ne 'CODE') {
            bail_out('extra_tests should be a subroutine, instead found ' . $block->extra_tests);
        }

        push(@ResponseChecks, $block->extra_tests);
    }
});

# Add 'upload_file_like' block check
add_response_body_check(sub {
    my ($block, $body, $req_idx, $repeated_req_idx, $dry_run) = @_;

    if ($dry_run) {
        return;
    }

    my $num_requests = (ref $block->request eq 'ARRAY') ? scalar @{$block->request} : 1;
    my $final_request = ($req_idx == ($num_requests - 1));
    if ($final_request && defined $block->upload_file_like) {
        my $ref_type = (ref $block->upload_file_like);
        if (ref $block->upload_file_like ne 'Regexp') {
            bail_out("upload_file_like block must be a regex pattern");
        }
        my $test_name = $block->name . " - upload file check";
        if ($body =~ /upload_tmp_path = ([^\n]+)$/) {
            file_contains_like($1, $block->upload_file_like, $test_name);
        } else {
            bail_out("upload_tmp_path information not found in response");
        }
    }
    return $block;
});

1;
