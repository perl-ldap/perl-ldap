#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use Net::LDAP::Util qw/ escape_dn_value /;

is(escape_dn_value("foo"), "foo", "simple, passthrough test");
is(escape_dn_value("foo,bar"), 'foo\,bar', "with a comma");

done_testing();
