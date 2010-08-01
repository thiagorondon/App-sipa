
package Sipa::Role::Pcap;

use Moose::Role;
with 'Sipa::Role::Data';

use Net::Pcap::Easy;

sub _default_callback {
    my ($self, $npe, $ether, $ip, $spo) = @_;
    my @a_spo = split(/\n/, $spo->{data});
    $self->packet(\@a_spo);
    $self->packet_src_host($ip->{src_ip});
    $self->packet_dst_host($ip->{dest_ip});
    $self->packet_src_port($spo->{src_port});
    $self->packet_dst_port($spo->{dest_port});
    $self->run;
};

sub get {
    my $self = shift;
    $self->_prepare;

    my $npe = Net::Pcap::Easy->new(
        dev     =>  $self->opt->dev,
        filter  =>  $self->opt->_filter,
        packet_per_loop => 10,
        bytes_to_capture => 1024,
        timeout_in_ms => 0,
        promiscous => $self->opt->promiscous,
        default_callback => sub { $self->_default_callback(@_) } ,
    );

    1 while $npe->loop;
}

1;

