#!perl

use Test::More;
use Net::LDAP::LDIF;
use Net::LDAP::Entry;

BEGIN { require "t/common.pl" }

(eval { require LWP::UserAgent } && $HTTP_JPEG_URL && $HTTP_TEXT_URL)
? plan tests => 4
: plan skip_all => 'LWP::UserAgent module not installed or HTTP_JPEG_URL, HTTP_TEXT_URL not set';


my $ldifdata = <<"LDIF";
dn: cn=Sam One,ou=People,o=University of Michigan,c=US
jpegPhoto:< $HTTP_JPEG_URL
objectclass: OpenLDAPperson
cn: Sam One
uid: sam
sn: One
postalAddress:< $HTTP_TEXT_URL
LDIF

open(my $ldifhandle, '<', \$ldifdata);

my $ldif = Net::LDAP::LDIF->new($ldifhandle);
isa_ok($ldif, Net::LDAP::LDIF, "object");

my $entry = $ldif->read_entry;
isa_ok($entry, Net::LDAP::Entry, "entry");

my $photo = $entry->get_value('jpegPhoto');
ok(length($photo), 'jpegPhoto not empty');

my $address = $entry->get_value('postalAddress');
ok(length($address), 'postalAddress not empty');

#print STDERR $entry->dump ."\n";

