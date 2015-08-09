#!/usr/bin/perl -w
# convert standard LDAP schema into a format that AD can digest

use Net::LDAP::Schema;
use Net::LDAP::LDIF;
use Net::LDAP::Entry;

sub simplify($);
sub addAUXclass($$@);
sub updateSchemaCache($);

# syntax mappings according to
# * http://msdn.microsoft.com/en-us/library/cc223177.aspx
# * http://msdn.microsoft.com/en-us/library/windows/desktop/aa772375.aspx
my %syntaxMap = (
  # Boolean
  '1.3.6.1.4.1.1466.115.121.1.7'   => { as => '2.5.5.8',  oms =>   '1' },
  # Enumeration
  #'1.3.6.1.4.1.1466.115.121.1.27' => { as => '2.5.5.9',  oms =>  '10' },
  # Integer
  #'1.3.6.1.4.1.1466.115.121.1.27' => { as => '2.5.5.9',  oms =>   '2' },
  # LargeInteger
  '1.3.6.1.4.1.1466.115.121.1.27'  => { as => '2.5.5.16', oms =>  '65' },
  # Object(Access-Point)
  #''                              => { as => '2.5.5.14', oms => '127' },
  # Object(DN-String)
  #''                              => { as => '2.5.5.14', oms => '127' },
  # Object(OR-Name)
  #''                              => { as => '2.5.5.7',  oms => '127' },
  # Object(DN-Binary)
  #''                              => { as => '2.5.5.7',  oms => '127' },
  # Object(DS-DN)
  '1.3.6.1.4.1.1466.115.121.1.12'  => { as => '2.5.5.1',  oms => '127' },
  # Object(Presentation-Address)
  #'1.3.6.1.4.1.1466.115.121.1.43' => { as => '2.5.5.13', oms => '127' },
  # Object(Replica-Link)
  #'1.3.6.1.4.1.1466.115.121.1.5'  => { as => '2.5.5.10', oms => '127' },
  # String(Case)
  #''                              => { as => '2.5.5.3',  oms =>  '27' },
  # String(IA5)
  '1.3.6.1.4.1.1466.115.121.1.26'  => { as => '2.5.5.5',  oms =>  '22' },
  # String(NT-Sec-Desc)
  #''                              => { as => '2.5.5.15', oms =>  '66' },
  # String(Numeric)
  '1.3.6.1.4.1.1466.115.121.1.36'  => { as => '2.5.5.6',  oms =>  '18' },
  # String(Object-Identifier)
  '1.3.6.1.4.1.1466.115.121.1.38'  => { as => '2.5.5.2',  oms =>   '6' },
  # String(Octet)
  '1.3.6.1.4.1.1466.115.121.1.5'   => { as => '2.5.5.10', oms =>   '4' },
  # String(Printable)
  '1.3.6.1.4.1.1466.115.121.1.44'  => { as => '2.5.5.5',  oms =>  '19' },
  # String(Sid)
  #''                              => { as => '2.5.5.17', oms =>   '4' },
  # String(Teletex)
  #''                              => { as => '2.5.5.4',  oms =>  '20' },
  # String(Unicode)
  '1.3.6.1.4.1.1466.115.121.1.15'  => { as => '2.5.5.12', oms =>  '64' },
  # String(UTC-Time)
  '1.3.6.1.4.1.1466.115.121.1.53'  => { as => '2.5.5.11', oms =>  '23' },
  # String(Generalized-Time)
  '1.3.6.1.4.1.1466.115.121.1.24'  => { as => '2.5.5.11', oms =>  '24' },
  # telephoneNumber => String(Unicode)
  '1.3.6.1.4.1.1466.115.121.1.50'  => { as => '2.5.5.12', oms =>  '64' },
  # facsimileTelephoneNumber => String(Unicode)
  '1.3.6.1.4.1.1466.115.121.1.22'  => { as => '2.5.5.12', oms =>  '64' },
  # PostalAddress => String(Unicode)
  '1.3.6.1.4.1.1466.115.121.1.41'  => { as => '2.5.5.12', oms =>  '64' },
  # PresentationAddress => String(Unicode)
  '1.3.6.1.4.1.1466.115.121.1.43'  => { as => '2.5.5.12', oms =>  '64' },
  # DataQualitySyntax => String(Unicode)
  '1.3.6.1.4.1.1466.115.121.1.13'  => { as => '2.5.5.12', oms =>  '64' },
  # OctetString => String(Octet)
  '1.3.6.1.4.1.1466.115.121.1.40'  => { as => '2.5.5.10', oms =>   '4' },
);

# die on errors on the command line
die "Usage: schema2ad [<options>] <schema file> <ldif file>\n"
  if (scalar(@ARGV) != 2);


# parse Schema file
my $schema = Net::LDAP::Schema->new($ARGV[0])
  or die 'Unable to parse schema file '.$ARGV[0]."\n";
my $ldifdata;

# open an "intermediate" file handle pointing to a scalar
open(my $ldifhandle, '>', \$ldifdata)
  or die 'Unable to open Perl scalar as file handle'."\n";

# print header
print $ldifhandle <<EOT;
# ===============================================================================
#  This file should be imported using the following command:
#    ldifde -i -f schema-sync.ldf -v -c DC=X DC=<forest root> -j <directory path>
# ===============================================================================

EOT

# create LDAP pointing to the intermediate file handle
# this is necessary as we want to post-process the generated ldif data
my $ldif = Net::LDAP::LDIF->new($ldifhandle,"w", change => 1, wrap => 0, version => 1)
  or die 'Unable to create LDIF object'."\n";


# loop over all attribute types
# http://msdn.microsoft.com/en-us/library/windows/desktop/ms675578.aspx
foreach my $at ($schema->all_attributes) {
  my $cn = $at->{name};
  my $syntax = $schema->attribute_syntax_oid($cn);

  die "Syntax not known for attribute $cn\n"
    if (!$syntax);

  die "Unknown syntax $syntax for attribute $cn\n"
    if (!exists($syntaxMap{$syntax}));

  my $entry = Net::LDAP::Entry->new('CN='.$cn.',CN=Schema,CN=Configuration,DC=X',
	objectclass => [ qw/top attributeSchema/ ],
	cn => $cn,
	attributeID => $at->{oid},
	attributeSyntax => $syntaxMap{$syntax}->{as},
	adminDisplayName => $cn,
	lDAPDisplayName => simplify($cn),
        oMSyntax => $syntaxMap{$syntax}->{oms});

  $entry->add(isSingleValued => 'TRUE')
    if ($at->{'single-value'});
  $entry->add(rangeLower => 1,
              rangeUpper => $at->{max_length})
    if ($at->{max_length});
  $entry->add(description => $at->{desc},
              adminDescription => $at->{desc})
    if ($at->{desc});

  # set default indexing to "per Container"
  $entry->add(searchFlags => 3);

  $entry->update($ldif);
}

updateSchemaCache($ldif);

# loop over all object classes
# http://msdn.microsoft.com/en-us/library/windows/desktop/ms675579.aspx
foreach my $oc ($schema->all_objectclasses) {
  my $cn = $oc->{name};
  my $entry = Net::LDAP::Entry->new('CN='.$cn.',CN=Schema,CN=Configuration,DC=X',
	objectclass => [ qw/top classSchema/ ],
	cn => $cn,
	# object is writable
	instanceType => 4,
	governsID => $oc->{oid},
	adminDisplayName => $cn,
	# http://msdn.microsoft.com/en-us/library/windows/desktop/ms677964.aspx
	objectClassCategory => $oc->{auxiliary} ? 3 : 1,
	lDAPDisplayName => simplify($cn));

  $entry->add(subClassOf => $oc->{sup})
    if ($oc->{sup});
  $entry->add(description => $oc->{desc},
              adminDescription => $oc->{desc})
    if ($oc->{desc});
  $entry->add(mustContain => [ sort map { simplify($_) } @{$oc->{must}} ])
    if ($oc->{must});
  $entry->add(mayContain => [ sort map { simplify($_) } @{$oc->{may}} ])
    if ($oc->{may});

  $entry->update($ldif);

  updateSchemaCache($ldif);
}

# add freshly created objectclasses to other objectclasses
#addAUXclass($ldif, $structural, @auxiliary);

#updateSchemaCache($ldif);

$ldif->done;

# post-process the ldif data
# http://msdn.microsoft.com/en-us/library/windows/desktop/ms677268.aspx
$ldifdata =~ s/^(changetype:)\s+add$/$1 ntdsSchemaAdd/mg;

# write footer
$ldifdata .= "\n\n# EOF";

# write output file with DOS/Windows line endings
if ($ARGV[1] eq '-') {
  binmode(*STDOUT, ':crlf');
  print $ldifdata;
}
else {
  open(my $outputfile, '>:crlf', $ARGV[1])
    or die 'Unable to create output file '.$ARGV[1]."\n";
  print $outputfile $ldifdata;
  close($outputfile);
}



#### function definitions ####

## simplify attribute / objectclass name to letters and digits only ##
# Synopsis: $simplifiedName = simplify($name)
sub simplify($)
{
  my $str = shift;

  $str =~ s/;.*$//;
  $str =~ s/[^A-Za-z0-9]//g;

  return $str;
}


## add AUXILIARY classes to a STRUCTURAL class ##
# Synopsis: addAUXclass($ldif, $structural, @auxiliary)
sub addAUXclass($$@)
{
  my $ldif = shift;
  my $structural = shift;
  my @auxiliary = @_;

  if ($structural && @auxiliary) {
    my $entry = Net::LDAP::Entry->new('CN='.$structural.',CN=Schema,CN=Configuration,DC=X');

    $entry->changetype('modify');
    $entry->add(auxiliaryClass => \@auxiliary);
  }
}


## trigger updating the schema cache ##
# Synopsis: updateSchemaCache($ldif)
# see: http://msdn.microsoft.com/en-us/library/windows/desktop/ms677976.aspx
sub updateSchemaCache($)
{
  my $ldif = shift;
  my $entry = Net::LDAP::Entry->new('');	# empty DN

  $entry->changetype('modify');
  $entry->add(schemaUpdateNow => 1);

  #DN:
  #changetype: modify
  #add: schemaUpdateNow
  #schemaUpdateNow: 1
  #-

  $entry->update($ldif);
}


## Net::LDAP::Schema extension
package Net::LDAP::Schema;

# get an attribute's syntax's OID taking into account attribute supertype
# based on: Net::LDAP::Schema's attribute_syntax()
sub attribute_syntax_oid
{
    my $self = shift;
    my $attr = shift;
    my $syntax;

    while ($attr) {
        my $elem = $self->attribute( $attr ) or return undef;

        $syntax = $elem->{syntax}  and  return $syntax;

        $attr = ${$elem->{sup} || []}[0];
    }

    return undef;
}


=head1 NAME

schema2ad.pl -- convert standard LDAP schema into a format that AD can digest

=head1 SYNOPSIS

B<schema2ad.pl>
I<schema-file>
I<AD-schema-file>

=head1 DESCRIPTION

schema2ad.pl parses the contents of the schema file I<schema-file>,
converts them to Active Directory / Active Directory Application Mode /
Active Directory Lightweight Directory Service compatible format,
and writes the result to I<AD-schema-file>.

=head1 ARGUMENTS

schema2ad.pl takes two arguments:

=over 4

=item I<schema-file>

Input file in LDIF format containing a schema entry with its I<attributeTypes>
and I<objectClasses> attributes, as e.g. returned by
L<Net::LDAP::Schema's dump()|Net::LDAP::Schema/"dump ( )">
method.

=item I<AD-schema-file>

Output file holding the generated AD compatible schema.

=back

=head1 AUTHOR

Peter Marschall <peter@adpm.de>

=head1 COPYRIGHT & LICENSE

Copyright (c) 2012-2015 Peter Marschall. All rights reserved.
This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut
