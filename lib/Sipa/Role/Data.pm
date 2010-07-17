
package Sipa::Role::Data;

use Moose::Role;

has 'packet' => (is => 'rw', isa => 'ArrayRef', default => sub { [] });
has 'packet_first_line' => (is => 'rw', isa => 'Str');
has 'packet_body' => (is => 'rw', isa => 'Str');
has 'packet_method' =>  (is => 'rw', isa => 'Str', default => '');

foreach my $item (qw/packet_src_host packet_src_port packet_dst_host
    packet_dst_port/) {
    has $item => (is => 'rw', isa => 'Str');
}

has 'packet_header' => (
    traits => ['Array'],
    is => 'ro', 
    isa => 'ArrayRef[Str]',
    default => sub { [] },
    handles => {
        add_packet_header => 'push',
        map_packet_header => 'map',
    }
);

after 'packet' => sub {
    my ($self, $value) = @_;
    return if !$value;
    my @message = @{$value};
    $self->packet_first_line($message[0]);
    $self->add_packet_header(@message);
    $self->packet_body('boo');
};

after 'packet_first_line' => sub {
    my ($self, $value) = @_;
    $value ||= '';
    $self->packet_method('INVITE') if $value =~ 'INVITE';
};

1;

