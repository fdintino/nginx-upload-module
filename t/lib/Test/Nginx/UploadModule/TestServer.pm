#!/usr/bin/env perl
use strict;
use warnings;

package File;
{
    sub new {
        my ($class, $opts) = @_;
        return bless {%$opts}, $class;
    }
}

package Test::Nginx::UploadModule::TestServer;
{
use HTTP::Daemon ();
use POSIX 'WNOHANG';
use IO::Socket;
use IO::Select;

use base 'Exporter';

our @EXPORT = qw(wait_for_port);
our @EXPORT_OK = qw(wait_for_port);

local $| = 1;

sub new {
    my ($class, $opts) = @_;
    my $port = $opts->{port} || 12345;
    my $self = {
        opts => {
            port => $port,
        },
    };
    $self->{sock} = HTTP::Daemon->new(
        LocalAddr => 'localhost',
        LocalPort => $self->{opts}->{port},
        ReuseAddr => 1
    ) || die("Could not open socket on port $port: $!");

    return bless $self, $class;
}

sub AUTOLOAD {
    my $self = shift;
    (my $attr = (our $AUTOLOAD)) =~ s/^.*::([^:]+)$/$1/;
    if (@_) {
        $self->{$attr} = shift;
    } else {
        return $self->{$attr};
    }
}


sub trim {
    my $val = shift;
    if (defined $val) {
        $val =~ s|^\s+||s;
        $val =~ s|\s+$||s;
    }
    return $val;
}

sub strip_quotes {
    my $s = shift;
    return ($s =~ /^"(.*?)"$/) ? $1 : $s;
}

sub process_multipart_chunk {
    my ($self, $value, $content_disposition) = @_;
    my %kv;
    if ($content_disposition) {
        (my $disposition = $content_disposition) =~ s/^\s*?form-data\s*?;\s*?(?=\S)//g;
        my @keyvals = map { /^(.*?)=(.*?)$/ && [lc($1), strip_quotes($2)] }
                      map { trim($_) }
                      split(';', $disposition);
        %kv = map {@$_} @keyvals;
    }
    my $kv = \%kv;
    if ($kv->{filename}) {
        $value = File->new({filename => $kv->{filename}, contents => $value});
    }
    return [$kv->{name}, $value];
}

sub process_multipart {
    my ($self, $content, $boundary) = @_;
    my $data = {};
    my $chunk_split = qr/^(.+?)\r\n\r\n(.+)$/s;
    my $strip_dashes = qr/(\r\n)?\-+$/;
    my $chunks = [];
    my @chunks = grep { $_ } map { s/(\r\n)?\-+$//s; s/^\-+\s+$//s; $_ }
                 split(/$boundary/, $content);
    my %data = ();
    for my $chunk (@chunks) {
        my $chunk_data = {headers => {}, body => ''};
        while ($chunk =~ /([\w\-]+)\:\s*(.+?)(?=\r\n)/pgs) {
            $chunk_data->{headers}->{lc $1} = $2;
            ($chunk_data->{value} = $') =~ s/^\r\n\r\n//g;
        }
        my $content_disposition = $chunk_data->{headers}->{'content-disposition'};
        my ($k, $v) = @{$self->process_multipart_chunk($chunk_data->{value}, $content_disposition)};
        $data->{$k} = $v;
    }
    return $data;
}

sub process_body {
    my ($self, $client, $req) = @_;
    my $content = $req->content;
    my $content_type = $req->header('Content-Type');
    my $data = {};
    if ($content_type) {
        if ($content_type =~ /multipart\/form\-data; boundary=(.+?)$/i) {
            my $boundary = quotemeta($1);
            return $self->process_multipart($content, $boundary);
        }
    }
    my $ct_disp = $req->header('Content-Disposition');
    if ($ct_disp) {
        my ($k, $v) = @{$self->process_multipart_chunk($content, $ct_disp)};
        $data->{$k} = $v;
    }
    return $data;
}

sub shutdown {
    my $self = shift;
    if (!defined $self->{sock}) {
        exit 0;
    }
    $self->sock->close;
    kill INT => $self->{forkpid} if defined $self->{forkpid};
    undef $self->{sock};
    exit 0;
}

sub handle_requests {
    my ($self, $client) = @_;
    while (my $req = $client->get_request()) {
        my $response = HTTP::Response->new(200, 'OK');
        $response->header('Content-Type' => 'text/html');

        if ($req->uri->path eq '/shutdown/') {
            $response->content("");
            $client->send_response($response);
            $client->close;
            $self->sock->close;
            undef $client;
            $_[2] = 1;
            exit 0;
        }
        my $data = $self->process_body($client, $req);
        my %query_params = $req->uri->query_form;
        for my $k (keys %query_params) {
            if ($k ne 'headers') {
                $data->{$k} = $query_params{$k};
            }
        }
        my %headers = $req->headers->flatten;
        my @headers = ();
        for my $k (sort keys %headers) {
            my $v = $headers{$k};
            push(@headers, "$k: $v");
        }
        my @fields = ();
        for my $k (sort keys %$data) {
            my $v = $data->{$k};
            if ($v && $v->isa('File')) {
                my $filename = $v->{filename};
                $k .= "(${filename})";
                $v = $v->{contents};
            }
            push(@fields, "$k = $v");
        }
        my $response_str = join("\n", @fields) . "\n";
        $response->content($response_str);
        $client->send_response($response);
    }
}

sub run {
    my $self = shift;
    while ((defined $self->{sock}) && (my $client = $self->sock->accept)) {
        defined (my $pid = fork()) or die("Can't fork: $!");
        if ($pid == 0) {
            $client->close;
            $self->sock->close;
            next;
        }
        my $retval = 0;
        $self->handle_requests($client, $retval);
        $client->close;
        if ($retval == 1) {
            $client->close;
            $self->sock->close;
            undef $client;
            exit 0;
        }
    }
    if (defined $self->sock) {
        $self->sock->close;
    }
}

sub wait_for_port {
    my ($port, $errhandler) = @_;
    if (!defined $errhandler) {
        $errhandler = \&die;
    }
    my $sock;
    eval {
        local $SIG{ALRM} = sub { die('timeout'); };
        alarm(1);
        while (1) {
            $sock = IO::Socket::INET->new(PeerHost=>'127.0.0.1', PeerPort=>$port, Timeout=>1);
            last if $sock;
            select(undef, undef, undef, 0.1);
        }
        alarm(0);
    };
    if ($@ eq 'timeout' || !$sock) {
        $errhandler->("Connecting to test server timed out");
    } elsif ($@) {
        alarm(0);
        $errhandler->($@);
    } elsif ($sock) {
        $sock->close;
    }
}


local $SIG{CHLD} = sub {
    while ((my $child = waitpid(-1, WNOHANG )) > 0) {}
};

}

if (!caller) {
    my $server = __PACKAGE__->new();
    $server->run();
}

1;