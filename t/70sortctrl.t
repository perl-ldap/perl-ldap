#!perl
#
# For this test to run you must defined the following in test.cfg
#   $EXTERNAL_TESTS = 1
#   %sortctrl with the following entries
#     host   => name of ldap server
#     base   => the base for the search
#     filter => the filter for the search
#     order  => the attribute name to order by
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

use vars qw(%sortctrl);

use Test::More tests => 9;

BEGIN { require "t/common.pl" }

use Net::LDAP::LDIF;
use Net::LDAP::Control::Sort;
use Net::LDAP::Constant qw(
	LDAP_CONTROL_SORTREQUEST
	LDAP_CONTROL_SORTRESULT
	LDAP_SUCCESS
);

SKIP: {
  skip('External tests disabled', 9)  unless ($EXTERNAL_TESTS);

  my($host, $base, $filter, $order) = @sortctrl{qw(host base filter order)};

  my $ldap = $host && Net::LDAP->new($host, version => 3);

  skip('Cannot connect to host', 9)  unless ($ldap);

  my $dse  = $ldap && $ldap->root_dse;

  skip('server does not support LDAP_CONTROL_SORTREQUEST', 9)
    unless ($dse and grep { $_ eq LDAP_CONTROL_SORTREQUEST } $dse->get_value('supportedControl'));


  Net::LDAP::LDIF->new(qw(- w))->write_entry($dse);

  my $sort = Net::LDAP::Control::Sort->new(order => $order);
  isa_ok($sort, Net::LDAP::Control::Sort, 'Net::LDAP::Control::Sort object');

  my $mesg = $ldap->search(
	      base	=> $base,
	      control	=> [$sort],
	      filter	=> $filter,
	    );
  is($mesg->code, LDAP_SUCCESS, 'search result');

  my ($resp) = $mesg->control( LDAP_CONTROL_SORTRESULT );
  ok($resp, 'LDAP_CONTROL_SORTRESULT response');

  ok($resp && $resp->result == LDAP_SUCCESS , 'LDAP_CONTROL_SORTRESULT success');

  print "# ",$mesg->count,"\n";

  my $dn1 = join ";", map { $_->dn } $mesg->entries;

  $sort = Net::LDAP::Control::Sort->new(order => "-$order");
  isa_ok($sort, Net::LDAP::Control::Sort, 'Net::LDAP::Control::Sort object (reversse order)');

  $mesg = $ldap->search(
	  base		=> $base,
	  control	=> [$sort],
	  filter	=> $filter,
	);
  is($mesg->code, LDAP_SUCCESS, 'search result');

  ($resp) = $mesg->control( LDAP_CONTROL_SORTRESULT );
  ok($resp, 'LDAP_CONTROL_SORTRESULT response');

  ok($resp && $resp->result == LDAP_SUCCESS , 'LDAP_CONTROL_SORTRESULT success');

  print "# ",$mesg->count,"\n";

  my $dn2 = join ";", map { $_->dn } reverse $mesg->entries;

  is($dn1, $dn2, 'sort order');
}
