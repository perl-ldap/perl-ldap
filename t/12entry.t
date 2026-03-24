#!/usr/bin/perl
# Offline tests for Net::LDAP::Entry

use strict;
use warnings;
use Test::More;

use Net::LDAP::Entry;

# === constructor ===

# new with no args
{
  my $e = Net::LDAP::Entry->new;
  isa_ok($e, 'Net::LDAP::Entry', 'new() returns Entry object');
  is($e->dn, undef, 'dn is undef for empty entry');
  is_deeply([$e->attributes], [], 'no attributes in empty entry');
  is($e->changetype, 'add', 'default changetype is add');
}

# new with DN
{
  my $e = Net::LDAP::Entry->new('cn=Test,dc=example,dc=com');
  is($e->dn, 'cn=Test,dc=example,dc=com', 'dn set via new()');
}

# new with DN and attributes
{
  my $e = Net::LDAP::Entry->new('cn=Test,dc=example,dc=com',
    cn          => 'Test',
    objectClass => [qw(top person)],
  );
  is($e->dn, 'cn=Test,dc=example,dc=com', 'dn set with attrs');
  is($e->get_value('cn'), 'Test', 'scalar attribute from new()');
  is_deeply([$e->get_value('objectClass')],
            [qw(top person)],
            'multi-valued attribute from new()');
}

# === dn getter/setter ===

{
  my $e = Net::LDAP::Entry->new;
  $e->dn('dc=example,dc=com');
  is($e->dn, 'dc=example,dc=com', 'dn setter works');
  $e->dn('dc=other,dc=com');
  is($e->dn, 'dc=other,dc=com', 'dn can be changed');
}

# === add ===

{
  my $e = Net::LDAP::Entry->new('dc=example,dc=com');
  $e->add(cn => 'Alice');
  is($e->get_value('cn'), 'Alice', 'add scalar value');

  $e->add(mail => ['alice@example.com', 'alice@work.com']);
  is_deeply([$e->get_value('mail')],
            ['alice@example.com', 'alice@work.com'],
            'add array ref values');

  # add to existing attribute
  $e->add(mail => 'alice@home.com');
  is_deeply([$e->get_value('mail')],
            ['alice@example.com', 'alice@work.com', 'alice@home.com'],
            'add appends to existing attribute');
}

# === exists ===

{
  my $e = Net::LDAP::Entry->new('dc=example,dc=com',
    cn => 'Bob',
  );
  ok($e->exists('cn'), 'exists returns true for present attr');
  ok($e->exists('CN'), 'exists is case-insensitive');
  ok(!$e->exists('sn'), 'exists returns false for absent attr');
}

# === get_value ===

{
  my $e = Net::LDAP::Entry->new('dc=example,dc=com',
    cn   => 'Carol',
    mail => [qw(carol@a.com carol@b.com)],
  );

  # scalar context returns first value
  is($e->get_value('cn'), 'Carol', 'get_value scalar context');
  is($e->get_value('mail'), 'carol@a.com', 'get_value scalar returns first');

  # list context returns all values
  is_deeply([$e->get_value('mail')],
            [qw(carol@a.com carol@b.com)],
            'get_value list context');

  # asref option
  my $ref = $e->get_value('mail', asref => 1);
  is(ref $ref, 'ARRAY', 'get_value asref returns arrayref');
  is_deeply($ref, [qw(carol@a.com carol@b.com)], 'asref values correct');

  # case-insensitive
  is($e->get_value('CN'), 'Carol', 'get_value is case-insensitive');

  # nonexistent attribute
  is($e->get_value('sn'), undef, 'get_value returns undef for absent attr');
}

# === get_value with options (nooptions / alloptions) ===

{
  my $e = Net::LDAP::Entry->new('dc=example,dc=com');
  # Simulate attribute with options by direct ASN manipulation
  $e->{asn}{attributes} = [
    { type => 'cn',       vals => ['Carol'] },
    { type => 'cn;lang-en', vals => ['Carol EN'] },
    { type => 'cn;lang-fr', vals => ['Carol FR'] },
  ];
  delete $e->{attrs};  # clear cache

  # nooptions: merge all cn variants
  my @vals = $e->get_value('cn', nooptions => 1);
  is(scalar @vals, 3, 'nooptions collects all cn variants');

  # alloptions: return hash of option suffixes
  my $opts = $e->get_value('cn', alloptions => 1);
  is(ref $opts, 'HASH', 'alloptions returns hashref');
  ok(exists $opts->{''}, 'alloptions has empty-string key for bare cn');
  ok(exists $opts->{';lang-en'}, 'alloptions has ;lang-en key');
  ok(exists $opts->{';lang-fr'}, 'alloptions has ;lang-fr key');
}

# === replace ===

{
  my $e = Net::LDAP::Entry->new('dc=example,dc=com',
    cn   => 'Dave',
    mail => 'dave@example.com',
  );

  $e->replace(cn => 'David');
  is($e->get_value('cn'), 'David', 'replace changes value');

  # replace with array ref
  $e->replace(mail => [qw(david@a.com david@b.com)]);
  is_deeply([$e->get_value('mail')],
            [qw(david@a.com david@b.com)],
            'replace with arrayref');

  # replace with undef removes attribute
  $e->replace(mail => undef);
  ok(!$e->exists('mail'), 'replace with undef removes attribute');

  # replace with empty arrayref removes attribute
  $e->replace(cn => []);
  ok(!$e->exists('cn'), 'replace with empty arrayref removes attribute');
}

# === delete ===

{
  my $e = Net::LDAP::Entry->new('dc=example,dc=com',
    cn          => 'Eve',
    mail        => [qw(eve@a.com eve@b.com eve@c.com)],
    objectClass => [qw(top person)],
  );
  $e->changetype('modify');

  # delete specific values
  $e->delete(mail => ['eve@b.com']);
  is_deeply([$e->get_value('mail')],
            [qw(eve@a.com eve@c.com)],
            'delete specific value removes it');

  # delete entire attribute
  $e->delete(objectClass => undef);
  ok(!$e->exists('objectClass'), 'delete with undef removes attribute');

  # delete with no args sets changetype to delete
  my $e2 = Net::LDAP::Entry->new('dc=example,dc=com', cn => 'Test');
  $e2->delete;
  is($e2->changetype, 'delete', 'delete() with no args sets changetype');
}

# === attributes ===

{
  my $e = Net::LDAP::Entry->new('dc=example,dc=com',
    cn          => 'Frank',
    sn          => 'Smith',
    objectClass => 'person',
  );

  my @attrs = $e->attributes;
  is(scalar @attrs, 3, 'attributes returns correct count');
  # The order should match insertion order
  is($attrs[0], 'cn', 'first attribute');
  is($attrs[1], 'sn', 'second attribute');
  is($attrs[2], 'objectClass', 'third attribute');
}

# === attributes with nooptions ===

{
  my $e = Net::LDAP::Entry->new('dc=example,dc=com');
  $e->{asn}{attributes} = [
    { type => 'cn',         vals => ['Test'] },
    { type => 'cn;lang-en', vals => ['Test EN'] },
    { type => 'sn',         vals => ['Smith'] },
  ];
  delete $e->{attrs};

  my @attrs = $e->attributes(nooptions => 1);
  is_deeply(\@attrs, [qw(cn sn)], 'attributes nooptions deduplicates');
}

# === changetype ===

{
  my $e = Net::LDAP::Entry->new('dc=example,dc=com');
  is($e->changetype, 'add', 'default changetype is add');

  $e->changetype('modify');
  is($e->changetype, 'modify', 'changetype setter works');
}

# === changes tracking ===

{
  my $e = Net::LDAP::Entry->new('dc=example,dc=com',
    cn => 'Grace',
  );
  $e->changetype('modify');

  $e->add(mail => 'grace@example.com');
  $e->replace(cn => 'Gracie');
  $e->delete(mail => undef);

  my @changes = $e->changes;
  is(scalar @changes, 6, 'changes has 3 pairs (6 elements)');
  is($changes[0], 'add',     'first change is add');
  is($changes[2], 'replace', 'second change is replace');
  is($changes[4], 'delete',  'third change is delete');
}

# changes not tracked for changetype 'add'
{
  my $e = Net::LDAP::Entry->new('dc=example,dc=com');
  $e->add(cn => 'Hal');
  $e->add(sn => 'Jones');
  my @changes = $e->changes;
  is(scalar @changes, 0, 'no changes tracked when changetype is add');
}

# === clone ===

{
  my $orig = Net::LDAP::Entry->new('cn=Ivy,dc=example,dc=com',
    cn          => 'Ivy',
    mail        => [qw(ivy@a.com ivy@b.com)],
    objectClass => [qw(top person)],
  );
  $orig->changetype('modify');
  $orig->add(sn => 'Green');

  my $clone = $orig->clone;

  isa_ok($clone, 'Net::LDAP::Entry', 'clone returns Entry');
  is($clone->dn, $orig->dn, 'clone has same dn');
  is_deeply([$clone->get_value('mail')],
            [$orig->get_value('mail')],
            'clone has same attribute values');

  # clone is independent
  $clone->replace(cn => 'Ivana');
  is($orig->get_value('cn'), 'Ivy', 'modifying clone does not affect original');

  # clone preserves changes
  my @changes = $clone->changes;
  is($changes[0], 'add', 'clone preserves changes');
}

# clone independence of array values
{
  my $orig = Net::LDAP::Entry->new('dc=example,dc=com',
    mail => [qw(a@x.com b@x.com)],
  );
  $orig->changetype('modify');
  $orig->add(sn => 'Test');

  my $clone = $orig->clone;

  # modify the clone's change data deeply
  my @orig_changes = $orig->changes;
  my @clone_changes = $clone->changes;
  push @{$clone_changes[1]}, 'extra', ['val'];
  # original should be unaffected
  my @orig_changes2 = $orig->changes;
  is(scalar @{$orig_changes2[1]}, 2, 'clone changes are independent');
}

# === ldif output ===

{
  my $e = Net::LDAP::Entry->new('cn=Test,dc=example,dc=com',
    cn          => 'Test',
    objectClass => [qw(top person)],
  );

  my $ldif = $e->ldif;
  like($ldif, qr/^dn: cn=Test,dc=example,dc=com$/m, 'ldif output has dn');
  like($ldif, qr/^cn: Test$/m, 'ldif output has cn');
  like($ldif, qr/^objectClass: top$/m, 'ldif output has objectClass');
}

# === encode/decode round-trip ===

{
  my $orig = Net::LDAP::Entry->new('cn=Test,dc=example,dc=com',
    cn          => 'Test',
    objectClass => [qw(top person)],
    sn          => 'User',
  );

  my $ber = $orig->encode;
  ok(defined $ber, 'encode produces output');

  my $decoded = Net::LDAP::Entry->new;
  $decoded->decode($ber);
  is($decoded->dn, 'cn=Test,dc=example,dc=com', 'decode restores dn');
  is($decoded->get_value('cn'), 'Test', 'decode restores cn');
  is_deeply([sort $decoded->get_value('objectClass')],
            [qw(person top)],
            'decode restores objectClass');
  is($decoded->changetype, 'modify', 'decoded entry changetype is modify');
}

# === multiple operations sequence ===

{
  my $e = Net::LDAP::Entry->new('uid=jdoe,ou=people,dc=example,dc=com',
    uid         => 'jdoe',
    cn          => 'John Doe',
    mail        => 'jdoe@example.com',
    objectClass => [qw(top inetOrgPerson)],
  );
  $e->changetype('modify');

  $e->add(telephoneNumber => '+1-555-0100');
  $e->replace(mail => [qw(john@example.com jdoe@work.com)]);
  $e->delete(cn => undef);
  $e->add(cn => 'Jonathan Doe');

  ok(!$e->exists('cn') || $e->get_value('cn') eq 'Jonathan Doe',
     'sequence of delete+add works');
  is_deeply([$e->get_value('mail')],
            [qw(john@example.com jdoe@work.com)],
            'replace in sequence works');
  is($e->get_value('telephoneNumber'), '+1-555-0100',
     'add in sequence works');
}

done_testing;
