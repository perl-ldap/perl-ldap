#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use Net::LDAP::Util qw/ escape_dn_value unescape_dn_value /;

is(escape_dn_value("foo"), "foo", "simple, passthrough test");
is(unescape_dn_value(escape_dn_value("foo")), "foo", "simple, passthrough test, round trip");
is(unescape_dn_value("foo"), "foo", "simple, passthrough test, decoding");

is(escape_dn_value("foo,bar"), 'foo\,bar', "with a comma");
is(unescape_dn_value(escape_dn_value("foo,bar")), 'foo,bar', "with a comma, round trip");
is(unescape_dn_value('foo\,bar'), 'foo,bar', "with a comma, decoding");

my $latin1 = "caf".chr(0xe9);
is(escape_dn_value($latin1), 'caf\C3\A9', 'latin1');
is(unescape_dn_value(escape_dn_value($latin1)), $latin1, 'latin1, round trip');
is(unescape_dn_value('caf\C3\A9'), $latin1, 'latin1, decoding');

my $bad_unicode = "mieow ".chr(0x1F638);
is(escape_dn_value($bad_unicode), 'mieow \F0\9F\98\B8', 'bad unicode');
is(unescape_dn_value(escape_dn_value($bad_unicode)), $bad_unicode, 'bad unicode, round trip');
is(unescape_dn_value('mieow \F0\9F\98\B8'), $bad_unicode, 'bad unicode, decoding');

done_testing();
