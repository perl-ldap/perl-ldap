#!perl

BEGIN {
  require "t/common.pl";
  start_server(version => 3);
}

print "1..2\n";

$ldap = client();
print "ok 1\n";

$dse = $ldap->root_dse or print "not ";
print "ok 2\n";

use Net::LDAP::LDIF;
Net::LDAP::LDIF->new(qw(- w))->write_entry($dse) if $dse;


