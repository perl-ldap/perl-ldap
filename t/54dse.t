#!perl

BEGIN {
  require "t/common.pl";
  start_server(version => 3);
}

print "1..2\n";

$ldap = client();
ok($ldap, "client");

$dse = $ldap->root_dse;
ok($dse, "dse");

use Net::LDAP::LDIF;
Net::LDAP::LDIF->new(qw(- w))->write_entry($dse) if $dse;


