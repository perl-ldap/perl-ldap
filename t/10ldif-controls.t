#!perl

use Test::More;
use File::Compare qw(compare_text);

BEGIN { require "t/common.pl" }


plan tests => 21;


require Net::LDAP::LDIF;
require Net::LDAP::Control::ManageDsaIT;
require Net::LDAP::Control::ProxyAuth;

my $infile   = "data/10-in.ldif";
my $outfile1 = "$TEMPDIR/10-out.ldif";
my $cmpfile1 = "data/10-in.ldif";

my $ldifin = Net::LDAP::LDIF->new($infile,"r");
isa_ok($ldifin, Net::LDAP::LDIF, 'input object');

my @entries = ();
while (my ($entry, @controls) = $ldifin->read_entry) {
  push(@entries, $entry);
  push(@entries, control => \@controls)  if (@controls);
}
is(scalar(@entries), 12, 'entries read');

$ldifin->done;

map { chomp(my $t = <DATA>); ref($_) ? isa_ok($_, $t, "structure") : is($_, $t, "structure"); } @entries;

isa_ok($entries[0], 'Net::LDAP::Entry', "1st entry");

ok(@{$entries[2]} == 2 and ref($entries[2][0]) eq 'Net::LDAP::Control::ManageDsaIT', "1st entry's control");

ok(@{$entries[2]} == 2 and ref($entries[2][1]) eq 'Net::LDAP::Control::ProxyAuth', "1st entry's control");

ok(@{$entries[-1]} == 1 and ref($entries[-1][0]) eq 'Net::LDAP::Control::ManageDsaIT', "last entry's control");

my $ldifout = Net::LDAP::LDIF->new($outfile1, 'w', change => 1);
isa_ok($ldifout, Net::LDAP::LDIF, 'output object');

# write all entres at once
my $x = $ldifout->write_entry(@entries);
ok($x, 'entries written');

$ldifout->done;

ok(!compare_text($cmpfile1,$outfile1), $cmpfile1);

__DATA__
Net::LDAP::Entry
control
ARRAY
Net::LDAP::Entry
control
ARRAY
Net::LDAP::Entry
Net::LDAP::Entry
Net::LDAP::Entry
Net::LDAP::Entry
control
ARRAY
