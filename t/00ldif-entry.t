#!perl

BEGIN {
  require "t/common.pl";
}


print "1..9\n";

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

$e->add('name' => 'Graham Barr');
$e->add('name;en-us' => 'Bob');

print "not " unless join(":",sort $e->attributes) eq "associateddomain:counting:description:l:lastmodifiedby:lastmodifiedtime:name:name;en-us:o:postaladdress:st:streetaddress:telephonenumber";
print "ok 3\n";

print "not " unless join(":",sort $e->attributes(nooptions => 1)) eq "associateddomain:counting:description:l:lastmodifiedby:lastmodifiedtime:name:o:postaladdress:st:streetaddress:telephonenumber";
print "ok 4\n";

$r = $e->get('name');
print "not " unless $r and @$r == 1 and $r->[0] eq 'Graham Barr';
print "ok 5\n";

$r = $e->get('name;en-us');
print "not " unless $r and @$r == 1 and $r->[0] eq 'Bob';
print "ok 6\n";

$r = $e->get('name', alloptions => 1);
print "not " unless $r and  join("*", sort keys %$r) eq "*;en-us";
print "ok 7\n";

print "not " unless $r and $r->{''} and @{$r->{''}} == 1 and $r->{''}[0] eq 'Graham Barr';
print "ok 8\n";

print "not " unless $r and $r->{';en-us'} and @{$r->{';en-us'}} == 1 and $r->{';en-us'}[0] eq 'Bob';
print "ok 9\n";

