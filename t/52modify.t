#!perl

BEGIN {
  require "t/common.pl";
  start_server();
}

my $i = 4;



print "1..56\n";

$ldap = client();
print "ok 1\n";

$mesg = $ldap->bind($MANAGERDN, password => $PASSWD);

print "not " if $mesg->code;
print "ok 2\n";

print "not " unless $ldif = Net::LDAP::LDIF->new("data/52-in.ldif","r",
				changetype => 'add');
print "ok 3\n";

foreach $e ($ldif->read_cmd) {
  print "ok ",$i++,"\n";
  $mesg = $e->update($ldap);
  if ($mesg->code) {
    print "# ",$mesg->code," ",$mesg->error,"\n";
    print "not ";
  }
  print "ok ",$i++,"\n";
}

# load modify LDIF
print "not " unless $ldif = Net::LDAP::LDIF->new("data/52-mod.ldif","r",
				changetype => 'modify');

foreach $e ($ldif->read_cmd) {
  print "ok ",$i++,"\n";
  $mesg = $e->update($ldap);
  if ($mesg->code) {
    print "# ",$mesg->code," ",$mesg->error,"\n";
    print "not ";
  }
  print "ok ",$i++,"\n";
}

# now search the database

$mesg = $ldap->search(base => $BASEDN, filter => 'objectclass=*');

compare_ldif("52",$i,$mesg,$mesg->sorted);

