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

print "not " unless ldif_populate($ldap, "data/50-in.ldif");
print "ok 3\n";

$mesg = $ldap->search(base => $BASEDN, filter => 'objectclass=*');
print "# ",$mesg->code,": ",$mesg->error,"\nnot " if $mesg->code;
print "ok 4\n";

compare_ldif("50",5,$mesg,$mesg->sorted);
