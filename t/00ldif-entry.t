#!perl

BEGIN {
  require "t/common.pl";
}


print "1..2\n";

use Net::LDAP::LDIF;

my $infile  = "data/00-in.ldif";
my $outfile = "$TEMPDIR/00-out1.ldif";
my $cmpfile = $infile;

@entry = Net::LDAP::LDIF->new($infile,"r")->read;

Net::LDAP::LDIF->new($outfile,"w")->write(@entry);

print "not " if compare($cmpfile,$outfile);
print "ok 1\n";

$e = $entry[0];

$e->changetype('modify');
$e->delete('objectclass');
$e->delete('o',['UM']);
$e->add('counting',[qw(one two three)]);
$e->replace('telephonenumber' => ['911']);

$outfile = "$TEMPDIR/00-out2.ldif";
$cmpfile = "data/00-cmp2.ldif";

$ldif = Net::LDAP::LDIF->new($outfile,"w");
$ldif->write($e);
$ldif->write_cmd($e);
$ldif->done;
print "not " if compare($cmpfile,$outfile);
print "ok 2\n";
