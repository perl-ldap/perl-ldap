#!perl -w
use Net::LDAP::Schema;

print "1..7\n";

my $schema = Net::LDAP::Schema->new( "data/schema.in" ) or die "Cannot open schema";
print "ok 1\n";

my @atts = sort $schema->attributes();
print "not " unless @atts == 55;
print "ok 2\n";

print "The schema contains ", scalar @atts, " attributes\n";

my @ocs = $schema->objectclasses();
print "not " unless @ocs == 22;
print "ok 3\n";
print "The schema contains ", scalar @ocs, " object classes\n";

@atts = $schema->must( "person" );
print "not " unless join(' ',@atts) eq join(' ',qw(cn sn));
print "ok 4\n";
print "The 'person' OC must have these attributes [",
		join( ",", @atts ),
		"]\n";
@atts = $schema->may( "mhsOrganizationalUser" );
print "not " if @atts;
print "ok 5\n";
print "The 'mhsOrganizationalUser' OC must have these attributes [",
		join( ",", @atts ),
		"]\n";

print "not " if defined $schema->item('distinguishedName','max_length');
print "ok 6\n";

print "not " unless $schema->item('userPassword','max_length') == 128;
print "ok 7\n";
