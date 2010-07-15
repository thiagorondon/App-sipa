
use inc::Module::Install;

name 'sipa';
author 'Thiago Rondon <thiago.rondon@gmail.com>';
version '0.0001';
perl_version '5.10.0';
license 'perl';

build_requires 'Test::More';

requires 'MooseX::Types::NetAddr::IP';
requires 'Net::Pcap::Easy';
requires 'MooseX::Getopt';
requires 'MooseX::Traits';
requires 'namespace::autoclean';

WriteAll;

