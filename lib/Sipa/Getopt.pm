#!/usr/bin/perl

package Sipa::Getopt;

use Moose;
use namespace::autoclean;

with 'MooseX::Getopt';

has 'port' => (is => 'rw', isa => 'Int', default => 5060);
has 'dev' => (is => 'rw', isa => 'Str', default => 'eth0');
has 'promiscous' => (is => 'rw', isa => 'Bool', default => 1);
has 'verbose' => (is => 'rw', isa => 'Bool');
has 'out' => (is => 'rw', isa => 'Str');
has 'codecs' => (is => 'rw', isa => 'Bool');
has 'txt' => (is => 'rw', isa => 'Str');

has 'filter' => (is => 'ro', isa => 'Str', lazy => 1,
    default =>
        sub {
            my $self = shift;
            join(' ', 'port', $self->port);
        }
    );

__PACKAGE__->meta->make_immutable;

1;

