#!/usr/bin/perl

package Sipa::Getopt;

use Moose;
use namespace::autoclean;

with 'MooseX::Getopt';

# With default options
has 'port' => (is => 'rw', isa => 'Int', default => 5060);
has 'dev' => (is => 'rw', isa => 'Str', default => 'eth0');
has 'promiscous' => (is => 'rw', isa => 'Bool', default => 1);

# Bool options
foreach my $item (qw/verbose codecs stats/) {
    has $item => (is => 'rw', isa => 'Bool', default => 0);
}

# Without default options
has 'out' => (is => 'rw', isa => 'Str');
has 'txt' => (is => 'rw', isa => 'Str');

# Read-only and lazy.
has 'filter' => (is => 'ro', isa => 'Str', lazy => 1,
    default =>
        sub {
            my $self = shift;
            join(' ', 'port', $self->port);
        }
    );

__PACKAGE__->meta->make_immutable;

1;

