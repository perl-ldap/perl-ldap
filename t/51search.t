#!perl

BEGIN {
  require "t/common.pl";
  start_server();
}

my $i = 4;


print "1..15\n";

$ldap = client();
print "ok 1\n";

$mesg = $ldap->bind($MANAGERDN, password => $PASSWD);

print "# ",$mesg->code,": ",$mesg->error,"\nnot " if $mesg->code;
print "ok 2\n";

print "not " unless ldif_populate($ldap, "data/51-in.ldif");
print "ok 3\n";


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

