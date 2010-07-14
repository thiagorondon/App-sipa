
package Sipa::Role::Stats;

use Moose::Role;

foreach my $item (qw/calls abandoned completed/) {
    has $item => ( is => 'rw', isa => 'Int', default => 0);
}

sub inc_calls () {
    my $self = shift;
    my $new_value = $self->calls + 1;
    $self->calls($new_value);
}


1;

