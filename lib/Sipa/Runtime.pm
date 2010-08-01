
package Sipa::Runtime;
our $VERSION = '0.0001';

use Moose;
with 'MooseX::Traits';

use Net::Pcap::Easy;
use Data::Dumper;

has 'opt' => (is => 'rw', isa => 'Object');
has 'fh' => (is => 'rw', isa => 'FileHandle');

sub _prepare {
    my $self = shift;
    if ($self->opt->out) {
        open my $fh, '>', $self->opt->out or die $!;
        $self->fh($fh);
    }

    # If we show the body, we don't need to show 'codecs'.
    if ($self->opt->body) {
        $self->opt->codecs(0);
    }
}

sub _print {
    my $self = shift;
    my @out = @_;
    if ($self->opt->out) {
        my $fh = $self->fh;
        print $fh (@out);
    } else {
        print (@out);
    }
}

sub _show_codecs {
    my $self = shift;
    my @data = @{$self->packet};
    for my $line (@data) {
        print (' ' x 16 . '->' . $line . "\n") if $line =~ 'a=rtpmap';
    }
}

sub _check_txts {
    my $self = shift;
    return 0 if $self->opt->txt and $self->packet !~ $self->opt->txt;
    return 1;
}

sub _check_hosts {
    my ($self) = @_;
    return 0 if $self->opt->host and 
        $self->packet_src_host ne $self->opt->host and
            $self->packet_dst_host ne $self->opt->host;
    return 1;
}

sub _verbose {
    my ($self, @info) = @_;
    for my $item (@info) {
        $self->_print (Dumper($item));
    }
}

sub _show_header {
    my $self = shift;
    $self->map_packet_header( sub { $self->_print(join("\n", $_)) });
}

sub _show_body {
    my $self = shift;
}

sub _show () {
    my $self = shift;
    
    my $out = join(':', 
        '**', 
        $self->packet_src_host,  
        $self->packet_src_port
        . ' => ',
        $self->packet_dst_host,
        $self->packet_dst_port
        . ' # ',
        $self->packet_first_line()
        . "\n"
    );
    
    $self->_show_header if $self->opt->header;
    $self->_show_body if $self->opt->body;
    $self->_print($out);
}

sub run {
    my $self = shift;
    
    # validates
    return if !$self->_check_txts or !$self->_check_hosts;
    
    # Info for show
    $self->_show;
    $self->_show_codecs if $self->opt->codecs;

    # introspect and stats.
    $self->inc_calls() if $self->does('Sipa::Role::Stats') 
        and $self->packet_method() eq 'INVITE';

    # more ...
    $self->_verbose if $self->opt->verbose;
};

1;

