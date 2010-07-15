
package Sipa::Pcap;

use Moose;
with 'MooseX::Traits';

use Net::Pcap::Easy;
use Data::Dumper;

has 'opt' => (is => 'rw', isa => 'Object');
has 'fh' => (is => 'rw', isa => 'FileHandle');
has 'spo' => (is => 'rw', isa => 'ArrayRef', default => sub { [] });
has 'spo_first_line' => (is => 'rw', isa => 'Str');
has 'spo_body' => (is => 'rw', isa => 'Str');
has 'spo_method' =>  (is => 'rw', isa => 'Str', default => '');

has 'spo_header' => (
    traits => ['Array'],
    is => 'ro', 
    isa => 'ArrayRef[Str]',
    default => sub { [] },
    handles => {
        add_spo_header => 'push',
        map_spo_header => 'map',
    }
);

after 'spo' => sub {
    my ($self, $value) = @_;
    my @message = @{$value};
    $self->spo_first_line($message[0]);
    $self->add_spo_header(@message);
    $self->spo_body('boo');
};

after 'spo_first_line' => sub {
    my ($self, $value) = @_;
    $value ||= '';
    $self->spo_method('INVITE') if $value =~ 'INVITE';
};


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

sub _verbose {
    my ($self, @info) = @_;
    for my $item (@info) {
        $self->_print (Dumper($item));
    }
}

sub _show_header {
    my $self = shift;
    $self->map_spo_header( sub { $self->_print(join("\n", $_)) });
}

sub _show_body {
    my $self = shift;
}

sub _show () {
    my ($self, $ip, $spo) = @_;
    my $out = join(':', '**', $ip->{src_ip}, $spo->{src_port} . ' -> ',
        $ip->{dest_ip}, $spo->{dest_port}, $self->spo_first_line() . "\n");
    $self->_show_header if $self->opt->header;
    $self->_show_body if $self->opt->body;
    $self->_print($out);
}

sub _default_callback {
    my ($self, $npe, $ether, $ip, $spo) = @_;
    my @aspo = split(/\n/, $spo->{data});
    $self->spo(\@aspo);
    
    # validates
    return if !$self->_check_txts;
    return if !$self->_check_hosts($ip->{src_ip}, $ip->{dest_ip});
    
    # Info for show
    $self->_show($ip, $spo);
    $self->_show_codecs if $self->opt->codecs;

    # introspect and stats.
    $self->inc_calls() if $self->does('Sipa::Role::Stats') 
        and $self->spo_method() eq 'INVITE';

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
        default_callback => sub { $self->_default_callback(@_) } ,
    );

    1 while $npe->loop;
}

1;

