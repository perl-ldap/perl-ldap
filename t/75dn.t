#!perl
#
#

use Test::More;

use Net::LDAP::DN;

plan tests => 13;

my $entry = Net::LDAP::DN->new('cn=User Name,ou=users,dc=example,dc=net');
my $parent = $entry->parent;
my $users = Net::LDAP::DN->new('ou=users,dc=example,dc=net');
my $base  = Net::LDAP::DN->new('dc=example,dc=net');
my $rdn   = Net::LDAP::DN->new("uid=user");

isa_ok($parent, Net::LDAP::DN, 'isa Net::LDAP::DN');
# of course an entry is equal to itself
is($entry->equal("$entry"), 1, 'equal');

# of course an entry is equal to it's clone
is($entry->equal($entry->clone), 1, 'clone');

is("$users" eq 'OU=users,DC=example,DC=net', 1, 'stringify');

is($parent eq $users, 1, 'overload eq');

isnt($entry eq $users, 1, 'overload eq');

ok($entry->rdn eq 'User Name', 'rdn');

ok($entry->is_subordinate($base) == 1, 'is subordinate');

is(($entry - $base)->pretty("/", sub { ucfirst shift }), 'Users/User Name', 'strip and pretty');

is(($entry & $base) eq $base, 1, 'overload common_base');

is($entry->clone->rename(cn => "Someone Else")->as_string
        eq "CN=Someone Else,OU=users,DC=example,DC=net", 1, 'rename');

is($entry->clone->move($base)->as_string
        eq "CN=User Name,DC=example,DC=net", 1, 'move');

is(($rdn + $users)->as_string
    eq "UID=user,OU=users,DC=example,DC=net", 1, 'append');
1;
