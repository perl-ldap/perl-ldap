#!perl

BEGIN {
  require "t/common.pl";
  start_server();
}

print "1..7\n";

$ldap = client();
print "ok 1\n";

$mesg = $ldap->bind($MANAGERDN, password => $PASSWD);

print "# ",$mesg->code,": ",$mesg->error,"\nnot " if $mesg->code;
print "ok 2\n";

print "not " unless ldif_populate($ldap, "data/52-in.ldif");
print "ok 3\n";

# load modify LDIF
print "not " unless ldif_populate($ldap, "data/52-mod.ldif", 'modify');
print "ok 4\n";

# now search the database

$mesg = $ldap->search(base => $BASEDN, filter => 'objectclass=*');

compare_ldif("52",5,$mesg,$mesg->sorted);

