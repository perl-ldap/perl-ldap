#!perl -w

use Test::More tests => 7;
use Net::LDAP::Schema;

my $schema = Net::LDAP::Schema->new( "data/schema.in" ) or die "Cannot open schema";
isa_ok($schema, Net::LDAP::Schema, 'load schema file');

my @atts = $schema->all_attributes();
is(@atts, 55, 'number of attribute types in schema');
print "The schema contains ", scalar @atts, " attributes\n";

my @ocs = $schema->all_objectclasses();
is(@ocs, 22, 'number of object classes in schema');
print "The schema contains ", scalar @ocs, " object classes\n";

@atts = $schema->must( "person" );
is(join(' ', sort map $_->{name}, @atts), join(' ',sort qw(cn sn objectClass)), 'mandatory attributes');
print "The 'person' OC must have these attributes [",
		join( ",", map $_->{name}, @atts ),
		"]\n";

@atts = $schema->may( "mhsOrganizationalUser" );
ok(!@atts, 'optional attributes');
print "The 'mhsOrganizationalUser' OC may have these attributes [",
		join( ",", map $_->{name}, @atts ),
		"]\n";

ok(! defined($schema->attribute('distinguishedName')->{max_length}), 'infinite length attribute type');

is($schema->attribute('userPassword')->{max_length}, 128, 'attribute type max. length');

use Data::Dumper;
print Dumper($schema);

0;
