#!perl

BEGIN {
  require "t/common.pl";
  start_server();
}

my $i = 4;


print "1..53\n";

$ldap = client();
print "ok 1\n";

$mesg = $ldap->bind($MANAGERDN, password => $PASSWD);

print "not " if $mesg->code;
print "ok 2\n";

print "not " unless $ldif = Net::LDAP::LDIF->new("data/51-in.ldif","r",
				changetype => 'add');
print "ok 3\n";

foreach $e ($ldif->read_cmd) {
  print "ok ",$i++,"\n";
  $mesg = $e->update($ldap);
  if ($mesg->code) {
    $e->dump;
    print "# ",$mesg->code," ",$mesg->error,"\n";
    print "not ";
  }
  print "ok ",$i++,"\n";
}

# now search the database

# Exact searching
$mesg = $ldap->search(base => $BASEDN, filter => 'sn=jensen');
$i += compare_ldif("51a",$i,$mesg,$mesg->sorted);

# Or searching
$mesg = $ldap->search(base => $BASEDN, filter => '(|(objectclass=groupofnames)(sn=jones))');
$i += compare_ldif("51b",$i,$mesg,$mesg->sorted);

# And searching
$mesg = $ldap->search(base => $BASEDN, filter => '(&(objectclass=groupofnames)(cn=A*))');
$i += compare_ldif("51c",$i,$mesg,$mesg->sorted);

# Not searching
$mesg = $ldap->search(base => $BASEDN, filter => '(!(objectclass=person))');
$i += compare_ldif("51d",$i,$mesg,$mesg->sorted);

