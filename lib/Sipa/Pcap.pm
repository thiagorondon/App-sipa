
package Sipa::Pcap;

use Moose;
with 'MooseX::Traits';

use Net::Pcap::Easy;
use Data::Dumper;

has 'opt' => (is => 'rw', isa => 'Object');
has 'fh' => (is => 'rw', isa => 'FileHandle');
has 'spo' => (is => 'rw', isa => 'Str');
has 'first_line' => (is => 'rw', isa => 'Str');

sub _prepare {
    my $self = shift;
    if ($self->opt->out) {
        open my $fh, '>', $self->opt->out or die $!;
        $self->fh($fh);
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
    my @data = split(/\n/, $self->spo);
    for my $line (@data) {
        print (' ' x 16 . '->' . $line . "\n") if $line =~ 'a=rtpmap';
    }
}

sub _check_txts {
    my $self = shift;
    return 0 if $self->opt->txt and $self->spo !~ $self->opt->txt;
    return 1;
}

sub _check_hosts {
    my ($self, $src_host, $dest_host) = @_;
    return 0 if $self->opt->host and 
        $src_host ne $self->opt->host and
            $dest_host ne $self->opt->host;
    return 1;
}

sub _get_method {
    my ($self, $message) = @_;
    return 'INVITE' if $message =~ 'INVITE';
    return '';
}

sub _verbose {
    my ($self, @info) = @_;
    for my $item (@info) {
        $self->_print (Dumper($item));
    }
}

sub _show () {
    my ($self, $ip, $spo) = @_;
    my ($first_line) = split(/\n/, $spo->{data});
    $self->first_line($first_line);
    my $out = join(':', 'SIP', $ip->{src_ip}, $spo->{src_port} . ' -> ',
        $ip->{dest_ip}, $spo->{dest_port}, $first_line . "\n");
    
    $self->_print($out);
}

sub _udp_callback {
    my ($self, $npe, $ether, $ip, $spo) = @_;
    $self->spo($spo->{data});
    
    # validates
    return if !$self->_check_txts;
    return if !$self->_check_hosts($ip->{src_ip}, $ip->{dest_ip});
    
    # Info for show
    $self->_show($ip, $spo);
    $self->_show_codecs if $self->opt->codecs;

    # introspect and stats.
    my $method = $self->_get_method ($self->first_line);
    $self->inc_calls() if $self->does('Sipa::Role::Stats') 
        and $method eq 'INVITE';

    # more ...
    $self->_verbose ($npe, $ether, $ip, $spo) 
        if $self->opt->verbose;
};

sub get {
    my $self = shift;
    $self->_prepare;

    my $npe = Net::Pcap::Easy->new(
        dev     =>  $self->opt->dev,
        filter  =>  $self->opt->filter,
        packet_per_loop => 10,
        bytes_to_capture => 1024,
        timeout_in_ms => 0,
        promiscous => $self->opt->promiscous,
        udp_callback => sub { $self->_udp_callback(@_) } ,
    );

    1 while $npe->loop;
}

1;

