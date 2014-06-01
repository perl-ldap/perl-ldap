#!perl

use Test::More;
use File::Compare qw(compare_text);

BEGIN { require "t/common.pl" }


plan tests => 9;


require Net::LDAP::LDIF;
require Net::LDAP::Control::ManageDsaIT;
require Net::LDAP::Control::ProxyAuth;

my $infile   = "data/10-in.ldif";
my $outfile1 = "$TEMPDIR/10-out.ldif";
my $cmpfile1 = "data/10-in.ldif";

my $ldifin = Net::LDAP::LDIF->new($infile,"r");
isa_ok($ldifin, Net::LDAP::LDIF, 'input object');

my @entries = ();
while (my $entry = $ldifin->read_entry) {
  push(@entries, $entry);
#  push(@entries, control => \@controls)  if (@controls);
}
is(scalar(@entries), 6, 'entries read');

$ldifin->done;

#use Data::Dumper;
#print STDERR Dumper(@entries);

my $manage = Net::LDAP::Control::ManageDsaIT->new(critical => 1);
isa_ok($manage, Net::LDAP::Control::ManageDsaIT, "control object");

my $auth1 = Net::LDAP::Control::ProxyAuth->new(authzID => 'dn:cn=me,ou=people,o=myorg.com');
isa_ok($auth1, Net::LDAP::Control::ProxyAuth, "control object");

my $auth2 = Net::LDAP::Control::ProxyAuth->new(authzID => 'dn:cn=Hägar,ou=people,o=myorg.com');
isa_ok($auth2, Net::LDAP::Control::ProxyAuth, "control object");

splice(@entries, 2, 0, control => [ $auth1 ]);
splice(@entries, 1, 0, control => [ $manage, $auth2 ]);
push(@entries, control => $manage);

my $manage = $entries[-1];
isa_ok($manage, Net::LDAP::Control::ManageDsaIT, "control object read");

my $ldifout = Net::LDAP::LDIF->new($outfile1, 'w', change => 1);
isa_ok($ldifout, Net::LDAP::LDIF, 'output object');

# write all entres at once
my $x = $ldifout->write_entry(@entries);
ok($x, 'entries written');

$ldifout->done;

ok(!compare_text($cmpfile1,$outfile1), $cmpfile1);

