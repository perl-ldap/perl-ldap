# The -*- perl -*- script writes the Makefile for perl-ldap
# $Id: Makefile.PL,v 1.7 2001/12/03 16:20:26 gbarr Exp $

use 5.004;
use ExtUtils::MakeMaker;
use Getopt::Std;
use Config;

#--- Configure ---

if (!getopts("hs") || $opt_h) {
  die <<"EDQ";
Usage: perl $0 [-h] [-s] [ MAKEMAKER_ARGS ]
  -h  Display this message
  -s  Install scripts from bin directory
EDQ
}

#--- Distribution section ---

$DISTNAME     = 'perl-ldap';
$VERSION_FROM = 'lib/Net/LDAP.pm';
$AUTHOR       = 'Graham Barr <gbarr@pobox.com>';

($ABSTRACT = <<"EDQ") =~ s/\n/\\n/g;
perl-ldap is a library of modules implementing an LDAP client. The aim
of the perl-ldap project is to implement a very portable LDAP client in
perl by relying on as little compiled code as possible.
EDQ

#--- Check for required modules ---

my $missing = 0;
$| = 1;

sub check_module {
  my($module,$version) = @_;
  print substr("$module ............................",0,30);
  my $ok = eval {
    my $file = $module;
    $file =~ s#::#/#g;
    require $file . ".pm";
    $module->VERSION($version) if defined $version;
    1;
  };
  $missing++ unless $ok;
  $@ =~ s/^(Can't locate \S* in \@INC).*/$1/s;
  print $ok ? "ok\n" : "** FAILED **\n$@\n";
  $ok;
}

print "\nChecking for OPTIONAL modules\n\n";

check_module('URI',1.08) && check_module('URI::ldap',1.10) or print <<"EDQ","\n";
The URI::ldap module is needed ONLY IF you want to parse LDAP URLs
EDQ

check_module('Digest::MD5') or print <<"EDQ","\n";
The Digest::MD5 module is needed ONLY IF intend to use CRAM-MD5 SASL authentication
EDQ

check_module('IO::Socket::SSL') or print <<"EDQ","\n";
The IO::Socket::SSL module is needed ONLY IF you intend to use LDAPS
EDQ

check_module('XML::Parser') or print <<"EDQ","\n";
The XML::Parser module is needed ONLY IF you intend to read/write DSML files
EDQ

check_module('MIME::Base64') or print <<"EDQ","\n";
The MIME::Base64 module is needed ONLY IF you intend to read/write LDIF files
EDQ

print "\n",<<"EDQ","\n" if $missing;
****************************************************************************
You are missing some modules that MAY be needed for some of the features
in perl-ldap to work correctly. Read the above messages and download
any required modules from http://www.perl.com/CPAN
****************************************************************************
EDQ

#--- Write the Makefile ---

my %PL_FILES = map { ($a = $_) =~ s/\.PL// ? ($_,$a) : () } glob('bin/*.PL');

my @ppd;

if ($] >= 5.00503) {
  @ppd = (
    AUTHOR       => $AUTHOR,
    ABSTRACT     => $ABSTRACT,
  );
}

WriteMakefile(
  VERSION_FROM => $VERSION_FROM,
  NAME         => $DISTNAME,
  EXE_FILES    => $opt_s ? [ values %PL_FILES ] : [],
  PL_FILES     => \%PL_FILES,
  clean        => {FILES => 'temp'},
  PREREQ_PM    => { 'Convert::ASN1' => 0.07 },
  @ppd,
);

sub MY::postamble {

<<EOS;

run_mkhtml :
	./mkhtml

run_mkmanf : run_mkhtml
	./mkmanf

distdir : run_mkhtml run_mkmanf

EOS

}

