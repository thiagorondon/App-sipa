
use ExtUtils::MakeMaker;
WriteMakefile(
    NAME => 'App::sipa',
    VERSION_FROM => "lib/Sipa/Runtime.pm",    
    ABSTRACT => 'Yet another sip sniffer',
    PREREQ_PM => {
        'Module::Build' => 0.36,
        'ExtUtils::MakeMaker' => 6.31,
        'ExtUtils::Install' => 1.46,
        'Test::More' => 0.90,
        'MooseX::Types::NetAddr::IP' => 0.03,
        'Net::Pcap::Easy' => 1.3,
        'MooseX::Getopt' => 0.31,
        'MooseX::Traits' => 0.11,
        'namespace::autoclean' => 0.11,
    },
    LICENSE => 'perl',
    EXE_FILES => [ 'bin/sipa' ],
);

