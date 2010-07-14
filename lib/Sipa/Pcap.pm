
package Sipa::Pcap;

use Moose;
with 'MooseX::Traits';

use Net::Pcap::Easy;
use Data::Dumper;

has 'opt' => (is => 'rw', isa => 'Object');
has 'fh' => (is => 'rw', isa => 'FileHandle');
has 'spo' => (is => 'rw', isa => 'Str');

sub _prepare {
    my $self = shift;
   
    if ($self->opt->out) {
        open my $fh, '>>', $self->opt->out or die $!;
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
    if ($self->opt->txt) {
        return 0 if $self->opt->txt !~ $self->spo;
    }   
    return 1;
}

sub _get_method {
    my $self = shift;
    my $message = shift;
    return 'INVITE' if $message =~ 'INVITE';
    return '';
}

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

        udp_callback => sub {
            my ($npe, $ether, $ip, $spo) = @_;
                $self->spo($spo->{data});
                return if !$self->_check_txts;
 
                $self->_print ("SIP:$ip->{src_ip}:$spo->{src_port} -> ");
                $self->_print ("$ip->{dest_ip}:$spo->{dest_port}");
                
                
                my @data = split(/\n/, $spo->{data});
                my $first_line = $data[0];
                $self->_print (' : ' . $first_line . "\n");

                if ($self->opt->codecs) {
                    $self->_show_codecs;
                }

                my $method = $self->_get_method ($first_line);

                if ($self->does('Sipa::Role::Stats')) {
                    $self->inc_calls() if $method eq 'INVITE';
                }

                if ($self->opt->verbose) {
                    $self->_print ("npe " . "-" x 30 . "\n");
                    $self->_print (Dumper($npe));
                    $self->_print ("ether " . "-" x 30 . "\n");
                    $self->_print (Dumper($ether));
                    $self->_print ("ip " . "-" x 30 . "\n");
                    $self->_print (Dumper($ip));
                    $self->_print ("spo " . "-" x 30 . "\n");
                    $self->_print (Dumper($spo));
                }
        },
    );

    1 while $npe->loop;
}

1;

