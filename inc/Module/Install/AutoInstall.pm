#line 1 "inc/Module/Install/AutoInstall.pm - /Users/gbarr/Library/Perl/Module/Install/AutoInstall.pm"
# $File: //depot/cpan/Module-Install/lib/Module/Install/AutoInstall.pm $ $Author: autrijus $
# $Revision: #13 $ $Change: 1846 $ $DateTime: 2003/12/31 22:57:12 $ vim: expandtab shiftwidth=4

package Module::Install::AutoInstall;
use Module::Install::Base; @ISA = qw(Module::Install::Base);

sub AutoInstall { $_[0] }

sub run {
    my $self = shift;
    $self->auto_install_now(@_);
}

sub write {
    my $self = shift;
    $self->auto_install(@_);
}

sub auto_install {
    my $self = shift;
    return if $self->{done}++;

# ExtUtils::AutoInstall Bootstrap Code, version 7.
AUTO:{my$p='ExtUtils::AutoInstall';my$v=0.49;$p->VERSION||0>=$v
or+eval"use $p $v;1"or+do{my$e=$ENV{PERL_EXTUTILS_AUTOINSTALL};
(!defined($e)||$e!~m/--(?:default|skip|testonly)/and-t STDIN or
eval"use ExtUtils::MakeMaker;WriteMakefile(PREREQ_PM=>{'$p',$v}
);1"and exit)and print"==> $p $v required. Install it from CP".
"AN? [Y/n] "and<STDIN>!~/^n/i and print"*** Installing $p\n"and
do{if (eval '$>' and lc(`sudo -V`) =~ /version/){system('sudo',
$^X,"-MCPANPLUS","-e","CPANPLUS::install $p");eval"use $p $v;1"
||system('sudo', $^X, "-MCPAN", "-e", "CPAN::install $p")}eval{
require CPANPLUS;CPANPLUS::install$p};eval"use $p $v;1"or eval{
require CPAN;CPAN::install$p};eval"use $p $v;1"||die"*** Please
manually install $p $v from cpan.org first...\n"}}}

    # Flatten array of arrays into a single array
    my @core = map @$_, map @$_, grep ref,
               $self->build_requires, $self->requires;

    while ( @core and @_ > 1 and $_[0] =~ /^-\w+$/ ) {
        push @core, splice(@_, 0, 2);
    }

    ExtUtils::AutoInstall->import(
        (@core ? (-core => \@core) : ()), @_, $self->features
    );

    $self->makemaker_args( ExtUtils::AutoInstall::_make_args() );

    my $class = ref($self);
    $self->postamble(
        "# --- $class section:\n" .
        ExtUtils::AutoInstall::postamble()
    );
}

sub auto_install_now {
    my $self = shift;
    $self->auto_install;
    ExtUtils::AutoInstall::do_install();
}

1;
