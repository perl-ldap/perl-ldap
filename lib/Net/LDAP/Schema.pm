# Copyright (c) 1998-2000 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Schema;

use strict;
use vars qw($VERSION);

$VERSION = "0.05";

#
# Get schema from the server (or read from LDIF) and parse it into 
# data structure
#
sub new {
  my $self = shift;
  my $type = ref($self) || $self;

  my $arg = shift;

  # XXX - Throw error?
  return undef unless $arg;
  
  my $entry;
  if( ref $arg ) {
    $entry = $arg->entry or return undef;
  }
  elsif( -f $arg ) {
    require Net::LDAP::LDIF;
    my $ldif = Net::LDAP::LDIF->new( $arg, "r" );
    $entry = $ldif->read();
    unless( $entry ) {
      warn( "Cannot parse LDIF from file [$arg]" );
      return undef;
    }
  }
  else {
    warn( "Can't load schema" );
    return undef;
  }
  
  my $schema = _parse_schema( $entry );
  $schema->{entry} = $entry;
  bless $schema, $type;
}

#
# Return base entry
#
sub entry {
  $_[0]->{'entry'};
}

#
# Dump as LDIF
#
sub dump {
  my $self = shift;
  my $fh = @_ ? shift : \*STDOUT;
  my $entry = $self->{'entry'} or return;
  require Net::LDAP::LDIF;
  Net::LDAP::LDIF->new($fh,"w", wrap => 0)->write($entry);
  1;
}

#
# Given another Net::LDAP::Schema, merge the contents together.
# XXX - todo
#
sub merge
{
  my $self = shift;
  my $new = shift;

  # Go through structure of 'new', copying code to $self. Take some
  # parameters describing what to do in the event of a clash.
}

#
# The names of all the attributes.
# Or all atts in (one or more) objectclass(es). 
#
sub attributes {
  my $self = shift;
  my @oc = @_;
  my $res = [];

  if( @oc ) {
    push @$res, $self->must( @oc );
    push @$res, $self->may( @oc );
    my %res = map { $_ => 1 } @$res;		# Get uniqueness
    my @res = keys %res;
    $res = \@res;
            }
            else {
    $res = $self->{at} || [];
  }
  return wantarray() ? @$res : $res;
}

# The names of all the object classes

sub objectclasses {
  my $self = shift;
  my $res = $self->{oc};
  return wantarray() ? @$res : $res;
}

# Return all syntaxes

sub syntaxes {
  my $self = shift;
  my $res = $self->{syn};
  return wantarray() ? @$res : $res;
}


sub superclass
{
   my $self = shift;
   my $oc = shift;

   my $oid = $self->is_objectclass( $oc );
   return undef unless $oid;

   my $res = $self->{oid}->{$oid}->{sup};
   return undef unless $res;
   return wantarray() ? @$res : $res;
}

sub must
{
  my $self = shift;
  $self->_must_or_may( "must", @_ );
}

sub may
{
  my $self = shift;
  $self->_must_or_may( "may", @_ );
}

#
# Return must or may attributes for this OC. [As array or array ref]
# return empty array/undef on error
#
sub _must_or_may
{
  my $self = shift;
  my $must_or_may = shift;
  my @oc = shift;
  my %res = ();		# Use hash to get uniqueness
  
  #
  # If called with an entry, get the OC names and continue
  #
  if( UNIVERSAL::isa( $oc[0], "Net::LDAP::Entry" ) ) {
    my $entry = $oc[0];
    @oc = $entry->get( "objectclass" );
  }

  return (wantarray() ? () : undef) unless @oc;

  foreach my $oc ( @oc ) {
    my $oid = $self->is_objectclass( $oc );
    if( $oid ) {
      my $res = $self->{oid}->{$oid}->{$must_or_may};
      %res = map { $_ => 1 } @$res; 	# Add in, getting uniqueness
    }
  }
  my @res = keys %res;

  return wantarray() ? @res : \@res;
}


#
# Return the value of an item, e.g. 'desc'. If item is array ref and we
# are called from array context, return an array, else scalar
#
sub item
{
  my $self = shift;
  my $arg = shift;
  my $item_name = shift;	# May be undef. If so all are returned

  my $oid = $self->name2oid( $arg );
  goto ERROR unless $oid;

  my $item_ref = $self->{oid}->{$oid};
  goto ERROR unless $item_ref;

  my $value = $item_ref->{$item_name};
  goto ERROR unless $value;

  if( ref $value eq "ARRAY" && wantarray() ) {
    return @$value;
  }
  else {
    return $value;
  }

 ERROR:
  return wantarray() ? () : undef;
}

#
# Return a list of items for a particular name or oid
#
# BUG:Dumps internal representation rather than real info. E.g. shows
# the alias/name distinction we create and the 'type' field.
#
sub items
{
  my $self = shift;
  my $arg = shift;

  my $oid = $self->name2oid( $arg );
  goto ERROR unless $oid;

  my $item_ref = $self->{oid}->{$oid};
  goto ERROR unless $item_ref;

  my @items = keys %$item_ref;
  return wantarray() ? @items : \@items;
  
 ERROR:
  return wantarray() ? () : undef;
}

#
# Given a name, alias or oid, return oid or undef. Undef if not known.
#
sub name2oid
{
  my $self = shift;
  my $name = lc shift;
  return undef unless $name;
  return $name if exists $self->{oid}->{$name};	# Already an oid
  my $oid = $self->{name}->{$name} || $self->{aliases}->{$name};
  return $oid;
}

#
# Given an an OID (not a name) return the canonical name. Undef if not
# an OID
#
sub oid2name
{
  my $self = shift;
  my $oid = shift;
  return undef unless $oid;
  return undef unless $self->{oid}->{$oid};
  return $self->{oid}->{$oid}->{name};
}

#
# Given name or oid, return oid or undef if not of appropriate type
#
sub is_attribute
{
  my $self = shift;
  return $self->_is_type( "at", @_ );
}

sub is_objectclass
{
  my $self = shift;
  return $self->_is_type( "oc", @_ );
}

sub is_syntax
{
  my $self = shift;
  return $self->_is_type( "syn", @_ );
}

# --------------------------------------------------
# Internal functions
# --------------------------------------------------

#
# Given a type and a name_or_oid, return true (the oid) if the name_or_oid
# is of the appropriate type. Else return undef.
#
sub _is_type
{
  my $self = shift;
  my $type = shift;
  my $name = shift;
  return undef unless( $type && $name );

  my $oid = $self->name2oid( $name );  
  return undef unless $oid;
  my $hash = $self->{oid}->{$oid};
  return $oid if $hash->{type} eq $type;
  return undef;
}


#
# XXX - TODO - move long comments to POD and write up interface
#
# Data structure is:
#
# $schema (hash ref)
#
# The {oid} piece here is a little redundant since we control the other
# top-level members. We promote the first listed name to be 'canonical' and
# also make up a name for syntaxes (from the description). Thus we always
# have a unique name. This avoids a lot of checking in the access routines.
#
# ->{oid}->{$oid}->{
#			name	=> $canonical_name, (created for syn)
#			aliases	=> list of non. canon names
#			type	=> at/oc/syn
#			desc	=> description
#			must	=> list of can. names of mand. atts [if OC]
#			may	=> list of can. names of opt. atts [if OC]
#			syntax	=> can. name of syntax [if AT]
#			... etc per oid details
#
# These next items are optimisations, to avoid always searching the OID
# lists. Could be removed in theory.
#
# ->{at} = [ list of canonical names of attributes ]
# ->{oc} = [ list of can. names of objectclasses ]
# ->{syn} = [ list of can. names of syntaxes (we make names from descripts) ]
#
# This is used to optimise name => oid lookups (to avoid searching).
# This could be removed or made into a cache to reduce memory usage.
# The names include any aliases.
#
# ->{name}->{ $lower_case_name } = $oid
#

#
# These items have no following arguuments
#
my %flags = map { ($_,1) } qw(
			      single-value
			      obsolete
			      collective
			      no-user-modification
			      abstract
			      structural
			      auxiliary
			      );

sub _parse_item
{
  my $value = shift;
  my( $item_name, $item_value );

  #
  # Items are all of the form:
  # 1 - "ITEM-NAME"				(if item-name is in flags)
  # 2 - "ITEM" VALUE
  # 3 - "ITEM" ( VALUES )
  #
  # Depending exactly on what we are parsing, the BNF in RFC2252 says that
  # we could have any character from "the UTF-8 [9] transformation of a
  # character from ISO10646"
  #
  # Now, shouldn't that include space and quote (which are our delimiters)?
  # And it seems that exchange server is happy to miss out white space, so
  # we work to that. Also try and be forgiving on quoting (i.e. not require it)
  #
  ( $item_name, $value ) = _get_one_word( $value );
  return () unless $item_name;

  $item_name = lc $item_name;

  #
  # Catch flags here
  #
  if( exists $flags{$item_name} ) {
    $item_value = 1;
    return( $item_name, $item_value, $value );
  }

  #
  # Now a bracketed list or one word. No nested brackets.
  # Values optionally seperated by '$'.
  #
  if( $value =~ s/^\s*\(// ) {   	# Strip bracket as well as detecting
    $item_value = [];
    my $one_val;
    while( ! ($value =~ s/^\s*\)// ) ) {       	# Until we hit end bracket
      ( $one_val, $value ) = _get_one_word( $value );
      next if $one_val eq "\$";			# Drop dollars
      push @$item_value, $one_val;
    }
  }
  else {
    #
    # Single value
    #
    ( $item_value, $value ) = _get_one_word( $value );
  }

  return( $item_name, $item_value, $value );
}

#
# 'Word' rules.
#
# - leading commas and w/s are discarded
# - We need to allow a 'word' to be enclosed in single or double quotes.
# - Such quotes may be used to embed w/s in the word
# (mixed quotes are unlikely to work)
# - Such quotes are stripped from the return value
# - A word ends in whitespace or close bracket
# [Note: RFC does not require this but MS Exchange does]
# - an open or close parens is left in the value and dealt with by the caller
# (yuck)
#
# Note: escaped quotes, escaped w/s and mixed quotes aren't supported.
# Life is hard enough.
#
sub _get_one_word
{
  my $value = shift;

#  ( $word, $value ) = $value =~ /^\s*,?\s*["' ]?([^"' ]+)["' ]?\s*,?\s*(.*)$/;
  my $word = "";	# Return value
  my $token;		# Chunk at a time
  my @quotes;

  do {
    ( $token, $value ) = $value =~ /^[\s,]*(["']?[^"'\s()]+["']?[,\s]*)(.*)$/;
    die( "Failed to parse token from value [$value]" ) unless $token;
    $word .= $token;
    @quotes = $word =~ /(["'])/g; 		# broken emacs '"])/;
  }
  while( @quotes &1 );				# Until even num of quotes

  # Clean up word & return
  $word =~ s/^["'\s]*//;
  $word =~ s/['"\s]*$//;
  return ( $word, $value );
}


#
# Given one value of an attribute of type objectclasses, ldapsyntaxes
# or attributetypes - break it into a 'schema entry'
#
sub _parse_value
{
  my $value = shift;
  my $schema_entry;
  my $oid;
  
  $value =~ s/^\s*\(\s*//;		# Be forgiving about leading bracket
  
  #
  # Netscape doesn't always use numeric OIDs. Bad Netscape.
  #
#  ( $oid, $value ) = $value =~ /([0-9.]+)\s+(.*)$/;
  ( $oid, $value ) = _get_one_word( $value );
  $oid = lc $oid;
#  unless( $oid && $oid =~ /^[0-9.]+$/ ) {
#    warn( "Non-numeric OID [$oid]" );
#  }
  return undef unless $oid;
  $schema_entry->{oid} = $oid;

  while( $value ) {
    my ( $item_name, $item_value );
    ( $item_name, $item_value, $value ) = _parse_item( $value );
    $value =~ s/^\s*\)\s*// if $value;	# Eat trailing bracket if it is there
    unless( $item_name ) {
      warn( "Failed to parse item [$value]" );
      next;
    }
    $schema_entry->{$item_name} = $item_value;
  }

  return $schema_entry;
}


#
# Return ref to hash containing schema data - undef on failure
#
sub _parse_schema {
  my $entry = shift;
  my $schema;
  
  return undef unless defined($entry);

  #
  # Map schema attribute names to internal names
  #
  my %type2attr = ( at	=> "attributetypes",
		    oc	=> "objectclasses",
		    syn	=> "ldapsyntaxes",
		    );
  foreach my $type ( qw( syn at oc ) ) {
    my $attr = $type2attr{$type};

    my $vals = $entry->get($attr);

    my @names;
    $schema->{$type} = \@names;		# Save reference to list of names

    next unless $vals;			# Just leave empty ref if nothing

    foreach my $val (@$vals) {
      #
      # We assume that each value can be turned into an OID, a canonical
      # name and a 'schema_entry' which is a hash ref containing the items
      # present in the value.
      #
      my $schema_entry = _parse_value( $val );
      unless( $schema_entry ) {
	warn( "Unable to parse value [$val]" );
	next;
      }
      my $oid = $schema_entry->{oid};

      #
      # We digest the raw parsed schema - throw away if we cannot fix it up
      #
      unless( _fixup_entry( $schema_entry, $type ) ) {
	warn( "Something wrong with schema entry - can't fixup [$val]" );
	next;
      }
      $schema_entry->{type} = $type;			# Remember type

      #
      # In the schema we store:
      #
      # 1 - The schema entry referenced by OID
      # 2 - a list of canonical names of each type
      # 3 - a (lower-cased) canonical name -> OID map
      # 4 - a (lower-cased) alias -> OID map
      #
      $schema->{oid}->{$oid} = $schema_entry;
      my $uc_name = $schema_entry->{name};
      push @names, $uc_name;
      $schema->{name}->{lc $uc_name} = $oid;
      foreach my $alias ( @{$schema_entry->{aliases}} ) {
	$schema->{aliases}->{lc $alias} = $oid;
      }
    }
  }

  #
  # Add in bare syntax entry for any syntaxes which are used but
  # not defined in the returned schema.
  # XXX - todo
  #
#  _fixup_schema( $schema );

  return $schema;
}


#
# Process schema entry - return undef if it is not good
#
sub _fixup_entry
{
  my $schema_entry = shift;
  my $type = shift;

  #
  # Store some items as array refs always, for simpler code
  # Note - 'name' is made scalar later in this function
  #
  foreach my $item_type ( qw( name must may sup ) ) {
    my $item = $schema_entry->{$item_type};
    if( $item && !ref $item ) {
      $schema_entry->{$item_type} = [ $item ];
	}
  }

  #
  # We also do some type-specific transformations. This is ugly...should
  # this be object-based code? Seems overkill.
  #
  my $name;
  if( $type eq "syn" ) {
    #
    # For syntaxes, we munge the desc to a name
    #
    if( exists $schema_entry->{desc} ) {
      $name = $schema_entry->{desc};
      $name =~ s/ +//g;
      $schema_entry->{name} = [ $name ];
    }
  }
  elsif( $type eq "at" ) {
    #
    # Extract the maximum length info if present.
    #
    my $syntax = $schema_entry->{syntax};
    if( $syntax ) {
      my $length;
      ( $syntax, $length ) = split( /[{}]/, $syntax );
      $length ||= 0;		# Length of zero = not specified
      $schema_entry->{max_length} = $length;
      $schema_entry->{syntax} = $syntax;      
    }
  }

  #
  # Force a name if we don't have one
  #
  unless( exists $schema_entry->{name} ) {
    $schema_entry->{name} = [ "$type:$schema_entry->{oid}" ];
  }
  #
  # Now make 'name' be the first listed name, demote the others to aliases
  #
  $name = shift @{$schema_entry->{name}};
  $schema_entry->{aliases} = $schema_entry->{name};  	# Aliases are array
  $schema_entry->{name} = $name;						# Name is scalar

  return 1;		# Entry OK
}


#
# Get the syntax of an attribute
#
sub syntax
{
  my $self = shift;
  my $attr = shift;

  my $oid = $self->is_attribute( $attr );
  return undef unless $oid;

  my $syntax = $self->{oid}->{$oid}->{syntax};
  unless( $syntax ) {
    my @sup = @{$self->{oid}->{$oid}->{sup}};
    $syntax = $self->syntax( $sup[0] );
  }

  return $syntax;
}

#
# Given an OID or name (or alias), return the canonical name
#
sub name
{
  my $self = shift;
  my $arg = shift;
  my $oid = $self->name2oid( $arg );
  return undef unless $oid;
  return $self->oid2name( $oid );
}

1;
