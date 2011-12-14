#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use Net::LDAP::Util qw/ escape_dn_value /;

is("foo", escape_dn_value("foo"), "simple, passthrough test");

done_testing();
