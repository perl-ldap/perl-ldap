#!perl

use Test::More tests => 8;
use Net::LDAP::LDIF;
use Net::LDAP::Entry;

my $infile = "data/75-in.ldif";

# No comments
my $ldif   = Net::LDAP::LDIF->new($infile, 'r', onerror => 'undef');
ok(defined($ldif), 'Commented LDIF is read (ignoring comments)');
my $entry    = $ldif->read_entry();
my @comments = @{ $entry->comments };
ok(scalar comments == 0, 'LDIF comments ignored');
$ldif->done();

# With comments
$ldif   = Net::LDAP::LDIF->new($infile, 'r', onerror => 'undef', comments => 1);
ok(defined($ldif), 'Commented LDIF is read (with comments)');
$entry    = $ldif->read_entry();
@comments = @{ $entry->comments };
like($comments[0], qr/^# modify 1470032839/, 'Start comment read');
like($comments[ $#comments ], qr/^# end modify 1470032839/, 'Ending comment read');

# Verify folded attribute
$entry = $ldif->read_entry();
is($entry->get_value('foldedAttr'), 'help', 'Read folded attribute');

# Read the last entry
$entry    = $ldif->read_entry();
@comments = @{ $entry->comments };
like($comments[0], qr/^# modify 1470032840/, 'Start comment read (last entry)');
like($comments[ $#comments ], qr/^# end modify 1470032840/, 'Ending comment read (last entry)');

$ldif->done();
