#!perl

BEGIN {
  require "t/common.pl";
  start_server();
}

print "1..44\n";

$ldap = client();
print "ok 1\n";

$mesg = $ldap->bind($MANAGERDN, password => $PASSWD);

print "#",$mesg->code,"\n";
print "not " if $mesg->code;
print "ok 2\n";

print "not " unless $ldif = Net::LDAP::LDIF->new("data/50-in.ldif","r",
				changetype => 'add');
print "ok 3\n";

my $i = 4;
foreach $e ($ldif->read_cmd) {
  print "ok ",$i++,"\n";
  $mesg = $e->update($ldap);
  print "#",$mesg->code,"\n";
  print "not " if $mesg->code;
  print "ok ",$i++,"\n";
}

$mesg = $ldap->search(base => $BASEDN, filter => 'objectclass=*');
  print "#",$mesg->code,"\n";

compare_ldif("50",$mesg,$i);
