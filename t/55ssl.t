#!perl

BEGIN {
  require "t/common.pl";
  start_server(version => 3, ssl => 1);
}

print "1..13\n";

$ldap = client();
print "ok 1\n";

$mesg = $ldap->bind($MANAGERDN, password => $PASSWD, version => 3);

print "# ",$mesg->code,": ",$mesg->error,"\nnot " if $mesg->code;
print "ok 2\n";

print "not " unless ldif_populate($ldap, "data/50-in.ldif");
print "ok 3\n";

$mesg = $ldap->start_tls;
print "# ",$mesg->code,": ",$mesg->error,"\nnot " if $mesg->code;
print "ok 4\n";

$mesg = $ldap->start_tls;
print "# ",$mesg->code,": ",$mesg->error,"\nnot " unless $mesg->code;
print "ok 5\n";

$mesg = $ldap->search(base => $BASEDN, filter => 'objectclass=*');
print "# ",$mesg->code,": ",$mesg->error,"\nnot " if $mesg->code;
print "ok 6\n";

compare_ldif("50",7,$mesg,$mesg->sorted);

$ldap = client(ssl => 1) or print "not ";
print "ok 10\n";

$mesg = $ldap->start_tls;
print "# ",$mesg->code,": ",$mesg->error,"\nnot " unless $mesg->code;
print "ok 11\n";

$mesg = $ldap->search(base => $BASEDN, filter => 'objectclass=*');
print "# ",$mesg->code,": ",$mesg->error,"\nnot " if $mesg->code;
print "ok 12\n";

compare_ldif("50",13,$mesg,$mesg->sorted);

