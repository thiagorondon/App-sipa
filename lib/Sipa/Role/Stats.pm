
package Sipa::Role::Stats;

use Moose::Role;

foreach my $item (qw/calls abandoned completed/) {
    my $it = "inc_$item";
    has $item => ( 
        traits => ['Counter'],
        is => 'ro', 
        isa => 'Int', 
        default => 0,
        handles => {
            $it => 'inc'
        },
    );
}

1;

