#!perl

use Net::LDAP::Util qw(canonical_dn);

# Each line has an opcode and a DN, opcode are
# bad   cacnonical_dn should return undef
# ref   Set new reference DN
# same  Should be the same as the current refdn
# diff  Should be different to the current refdn

my @tests = map { /^\s*(\w\S+)\s+(.*)/ } split(/\n/,<<'EOS');

  bad	OU=Sales+CN=J. Smith,O=Widget Inc.,C=US,

  ref	CN=J. Smith+OU=Sales,O=Widget Inc.,C=US
  same	ou=Sales+cn=J. Smith,O=Widget Inc.,C=US
  same	cn=J. Smith+ou=Sales,O=Widget Inc.,C=US
  same	cn=J.\20Smith+ou=Sales,O=Widget\20Inc.,C=US
  same	OU=Sales+CN=J. Smith;O=Widget Inc.;C=US
  same	OU=Sales + CN=J. Smith,O=Widget Inc.,C=US
  same	OU=Sales+CN=J. Smith , O=Widget Inc. , C=US
  same	OU = Sales+CN =J. Smith,O= Widget Inc.,C=US
  same	OU="Sales"+CN=J. Smith,O=Widget Inc.,C=US
  diff	OU="Sales+CN=J. Smith",O=Widget Inc.,C=US

  bad	cn=J.\20Smith\+ou=Sales,O=Widget\20Inc.,C=US

  ref	CN=Babs Jensen,O=Widget Inc.,C=US
  same	cn=Babs Jensen,o=Widget Inc.,c=US

  # This is here to test a restriction that
  # canonical_dn does not decode BER encoded values
  ref	1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB
  same	1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB
  diff	1.3.6.1.4.1.1466.0=\04\02Hi,O=Test,C=GB

  ref	1.3.6.1.4.1.1466.0=Hi,O=Test,C=GB
  same	oid.1.3.6.1.4.1.1466.0=Hi,O=Test,C=GB
  same	OID.1.3.6.1.4.1.1466.0=Hi,O=Test,C=GB

  ref	CN=Clif Harden+IDNUMBER=a0125589\20,OU=tiPerson,OU=person,O=ti,C=us
  diff	cn=Clif Harden+IDNumber=a0125589,ou=tiPerson,ou=person,o=ti,c=us
  same	cn=Clif Harden+IDNumber=a0125589\ ,ou=tiPerson,ou=person,o=ti,c=us
  same	cn=Clif Harden+IDNumber=a0125589\20 ,ou=tiPerson,ou=person,o=ti,c=us
  same	cn=Clif Harden+IDNumber="a0125589 ",ou=tiPerson,ou=person,o=ti,c=us


  ref   CN=\20\20Graham  Barr\20\20,OU=person,O=vc,C=us
  same  Cn="  Graham  Barr  ",OU=person,O=vc,C=us
  same  cn="  Graham \20Barr\20 ",OU=person,O=vc,C=us


EOS

print "1..", scalar(@tests)>>1, "\n";
my $testno = 0;
my $refdn;
while(my($op,$dn) = splice(@tests,0,2)) {

  if ($op eq 'ref') {
    $refdn=$dn;
    next;
  }

  my $canon = canonical_dn($dn);
  my $failed = 0;

  if ($op eq 'bad') {
    if ($failed = defined $canon) {
      print "'$dn' should not have parsed\n";
    }
  }
  elsif ( $op eq 'same' ) {
    if ($failed = !defined $canon) {
      print "'$dn' failed to parse\n";
    }
    elsif ($failed = $canon ne $refdn) {
      print "'$refdn'\n\ndid not match\n\n'$dn'\n'$canon'\n";
    }
  }
  elsif ($op eq 'diff' ) {
    if ($failed = !defined $canon) {
      print "'$dn' failed to parse\n";
    }
    elsif ($failed = $canon eq $refdn) {
      print "'$refdn'\n\nmatched\n\n'$dn'\n'$canon'\n";
    }
  }
  else {
    $failed = 1;
    warn "Bad opcode $op\n";
  }

  print +($failed ? "not ok " : "ok "),++$testno,"\n";
}
