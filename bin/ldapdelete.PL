# -*- perl -*-

use Config;
use File::Basename qw(&basename &dirname);
use Cwd;

# This forces PL files to create target in same directory as PL file.
# This is so that make depend always knows where to find PL derivatives.
my $origdir = cwd;
chdir dirname($0);
my $script = basename($0, '.PL');
$script .= '.com' if $^O eq 'VMS';

unlink($script);
open OUT, ">$script" or die "open for writing $script: $!";

print OUT <<"!GROK!THIS!";
$Config{startperl}
    eval 'exec $Config{perlpath} -S \$0 \${1+"\$@"}'
	if \$running_under_some_shell && \$running_under_some_shell;
!GROK!THIS!

# In the following, perl variables are not expanded during extraction.

print OUT <<'!NO!SUBS!';
# -*- perl -*-
# Nearly complete clone of Umich ldapdelete program
#
# c.ridd@isode.com
#
# $Id: ldapdelete.PL,v 1.2 2000/07/30 21:03:50 gbarr Exp $
#
# $Log: ldapdelete.PL,v $
# Revision 1.2  2000/07/30 21:03:50  gbarr
# *** empty log message ***
#
# Revision 1.1  1999/01/11 08:38:46  cjr
# Initial revision
#
#

use strict;
use Carp;
use Net::LDAP;
use vars qw($opt_n $opt_v $opt_c $opt_d $opt_D $opt_w $opt_h $opt_p $opt_3);
use Getopt::Std;

die "Usage: $0 [options] dns\
where:\
    dns         Distinguished names of entries to delete\
options:\
    -n          show what would be done but don\'t actually delete\
    -v          run in verbose mode (diagnostics to standard output)\
    -c          continue after any delete errors\
    -d level    set LDAP debugging level to \'level\'\
    -D binddn   bind dn\
    -w passwd   bind passwd (for simple authentication)\
    -h host     ldap server\
    -p port     port on ldap server\
    -3          connect using LDAPv3, otherwise use LDAPv2\n" unless @ARGV;

getopts('nvcd:D:w:h:p:3');

$opt_h = 'nameflow.dante.net' unless $opt_h;

my %newargs;

$newargs{port} = $opt_p if $opt_p;
$newargs{debug} = $opt_d if $opt_d;

dumpargs("new", $opt_h, \%newargs) if ($opt_n || $opt_v);
my $ldap;

unless ($opt_n) {
    $ldap = Net::LDAP->new($opt_h, %newargs) or die $@;
}

#
# Bind as the desired version, falling back if required to v2
#
my %bindargs;
$bindargs{dn} = $opt_D if $opt_D;
$bindargs{password} = $opt_w if $opt_w;
$bindargs{version} = $opt_3 ? 3 : 2;

if ($bindargs{version} == 3) {
    dumpargs("bind", undef, \%bindargs) if ($opt_n || $opt_v);
    unless ($opt_n) {
	$ldap->bind(%bindargs) or $bindargs{version} = 2;
    }
}

if ($bindargs{version} == 2) {
    dumpargs("bind", undef, \%bindargs) if ($opt_n || $opt_v);
    unless ($opt_n) {
	$ldap->bind(%bindargs) or die $@;
    }
}

foreach (@ARGV) {
    if ($opt_n || $opt_v) {
	print "delete('$_')\n";
    }
    unless ($opt_n) {
	$ldap->delete($_) or die $@;
    }
}

if ($opt_n || $opt_v) {
    print "unbind()\n";
}
unless ($opt_n) {
    $ldap->unbind() or die $@;
}

sub dumpargs {
    my ($cmd,$s,$rh) = @_;
    my @t;
    push @t, "'$s'" if $s;
    map {
	my $value = $$rh{$_};
	if (ref($value) eq 'ARRAY') {
	    push @t, "$_ => [" . join(", ", @$value) . "]";
	} else {
	    push @t, "$_ => '$value'";
	}
    } keys(%$rh);
    print "$cmd(", join(", ", @t), ")\n";
}
!NO!SUBS!

close OUT or die "Can't close $script: $!";
chmod 0755, $script or die "Can't reset permissions for $script: $!\n";
exec("$Config{'eunicefix'} $script") if $Config{'eunicefix'} ne ':';
chdir $origdir;
