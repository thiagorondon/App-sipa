#!/usr/bin/perl

package Sipa::Getopt;

use Moose;
use MooseX::Types::NetAddr::IP qw( NetAddrIPv4 );
use namespace::autoclean;

with 'MooseX::Getopt';

# With default options
has 'port' => (
    is => 'rw', 
    isa => 'Int', 
    default => 5060, 
    documentation => 'Default: 5060'
);

has 'dev' => (
    is => 'rw', 
    isa => 'Str', 
    default => 'eth0',
    documentation => 'Default: 5060'
);

has 'promiscous' => (
    is => 'rw', 
    isa => 'Bool', 
    default => 1,
    documentation => 'Default: 1 (True)'
);

# Bool options
foreach my $item (qw/verbose codecs stats header body/) {
    has $item => (
        is => 'rw', 
        isa => 'Bool', 
        default => 0,
        documentation => 'Default: 0 (False)'
    );
}

has 'out' => (
    is => 'rw', 
    isa => 'Str',
    documentation => 'Output file.'
);

has 'txt' => (
    is => 'rw', 
    isa => 'Str',
    documentation => 'Filter this string'
);

# fixme: NetAdddrIPv4
has 'host' => (
    is => 'rw', 
    isa => 'Str',
    documentation => 'Filter this host'
);

# Read-only and lazy.
has '_filter' => (
    is => 'ro', 
    isa => 'Str', 
    lazy => 1,
    default =>
        sub {
            my $self = shift;
            join(' ', 'port', $self->port);
        }
    );

__PACKAGE__->meta->make_immutable;

1;

