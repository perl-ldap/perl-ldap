#!perl

use Net::LDAP::Util qw(canonical_dn);

# Each line has an opcode and a DN, opcode are
# bad   cacnonical_dn should return undef
# ref   Set new reference DN
# same  Should be the same as the current refdn
# diff  Should be different to the current refdn

my @tests = map { /^\s*(\S+)\s+(.*)/ } split(/\n/,<<EOS);

  bad	OU=Sales+CN=J. Smith,O=Widget Inc.,C=US,

  ref	OU=Sales+CN=J. Smith,O=Widget Inc.,C=US
  same	ou=Sales+cn=J. Smith,O=Widget Inc.,C=US

  ref	1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB
  diff	1.3.6.1.4.1.1466.0=\04\02Hi,O=Test,C=GB

EOS

print "1..", scalar(@tests)>>1, "\n";
my $testno = 0;
my $refdn;
while(my($op,$dn) = splice(@tests,0,2)) {
  my $canon = canonical_dn($dn);

  if ($op eq 'bad') {
    print "not " if defined $canon;
  }
  elsif ( $op eq 'ref') {
    print "not " if !defined $canon;
    $refdn = $canon;
  }
  elsif ( $op eq 'same' ) {
    print "not " if !defined $canon or $canon ne $refdn;
  }
  elsif ($op eq 'diff' ) {
    print "not " if !defined $canon or $canon eq $refdn;
  }
  else {
    print "not ";
    warn "Bad opcode $op\n";
  }

  print "ok ",++$testno,"\n";
}
