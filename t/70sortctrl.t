#!perl
#
# The attribute given must have unique values over the entries
# returned from the search. This is because this test checks
# that the order of entries returned by 'attr' is the exact
# opposite of '-attr' this is not guaranteed if two entries have
# the same value for attr.
#
# Obviously the filter should be specific enough to ensure that
# a relatively small set of entries is returned
#
# TODO:
#
# This test should be expanded to test sort controls with
# more than one attribute specified.

use Test::More;

BEGIN { require "t/common.pl" }

use Net::LDAP::LDIF;
use Net::LDAP::Control::Sort;
use Net::LDAP::Constant qw(
	LDAP_CONTROL_SORTREQUEST
	LDAP_CONTROL_SORTRESULT
	LDAP_SUCCESS
);


start_server()
? plan tests => 13
: plan skip_all => 'no server';


$ldap = client();
isa_ok($ldap, Net::LDAP, "client");

$rootdse = $ldap->root_dse;
isa_ok($rootdse, Net::LDAP::RootDSE, "root_dse");


SKIP: {
  skip("RootDSE does not offer sort control", 11)
    unless($rootdse->supported_control(LDAP_CONTROL_SORTREQUEST));

  #$mesg = $ldap->start_tls;
  #ok(!$mesg->code, "start_tls: " . $mesg->code . ": " . $mesg->error);

  $mesg = $ldap->bind($MANAGERDN, password => $PASSWD);
  ok(!$mesg->code, "bind: " . $mesg->code . ": " . $mesg->error);

  ok(ldif_populate($ldap, "data/40-in.ldif"), "data/40-in.ldif");
  
  my $sort = Net::LDAP::Control::Sort->new(order => 'cn:2.5.13.3');
  isa_ok($sort, Net::LDAP::Control::Sort, 'sort control object');

  my $mesg = $ldap->search(
	      base	=> $BASEDN,
	      filter	=> '(objectclass=OpenLDAPperson)',
	      control	=> [ $sort ],
	    );
  is($mesg->code, LDAP_SUCCESS, "search: " . $mesg->code . ": " . $mesg->error);

  my ($resp) = $mesg->control( LDAP_CONTROL_SORTRESULT );
  ok($resp, 'LDAP_CONTROL_SORTRESULT response');

  ok($resp && $resp->result == LDAP_SUCCESS , 'LDAP_CONTROL_SORTRESULT success');

  #print "# ",$mesg->count,"\n";

  my $dn1 = join ";", map { $_->dn } $mesg->entries;

  $sort = Net::LDAP::Control::Sort->new(order => "-cn:2.5.13.3");
  isa_ok($sort, Net::LDAP::Control::Sort, 'sort control object (reverse order)');

  $mesg = $ldap->search(
	  base		=> $BASEDN,
	  filter	=> '(objectclass=OpenLDAPperson)',
	  control	=> [ $sort ],
	);
  is($mesg->code, LDAP_SUCCESS, 'search result');

  ($resp) = $mesg->control( LDAP_CONTROL_SORTRESULT );
  ok($resp, 'LDAP_CONTROL_SORTRESULT response');

  ok($resp && $resp->result == LDAP_SUCCESS , 'LDAP_CONTROL_SORTRESULT success');

  #print "# ",$mesg->count,"\n";

  my $dn2 = join ";", map { $_->dn } reverse $mesg->entries;

  is($dn1, $dn2, 'sort order');
}
