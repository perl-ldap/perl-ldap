# Copyright (c) 1998-2000 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Schema;

use strict;
use vars qw($VERSION);

$VERSION = "0.08";

#
# Get schema from the server (or read from LDIF) and parse it into 
# data structure
#
sub new {
  my $self = shift;
  my $type = ref($self) || $self;
  my $schema = bless {}, $type;

  return $schema unless @_;
  return $schema->parse( shift ) ? $schema : undef;
}

sub parse {
  my $schema = shift;
  my $arg = shift;

  unless ($arg) {
    $schema->{error} = "Bad argument";
    return undef;
  }
  
  %$schema = ();

  my $entry;
  if( ref $arg ) {
    if (UNIVERSAL::isa($arg, 'Net::LDAP::Entry')) {
      $entry = $arg;
    }
    elsif (UNIVERSAL::isa($arg, 'Net::LDAP::Search')) {
      unless ($entry = $arg->entry) {
	$schema->{error} = 'Bad Argument';
	return undef;
      }
    }
    else {
      $schema->{error} = 'Bad Argument';
      return undef;
    }
  }
  elsif( -f $arg ) {
    require Net::LDAP::LDIF;
    my $ldif = Net::LDAP::LDIF->new( $arg, "r" );
    $entry = $ldif->read();
    unless( $entry ) {
      $schema->{error} = "Cannot parse LDIF from file [$arg]";
      return undef;
    }
  }
  else {
    $schema->{error} = "Can't load schema from [$arg]: $!";
    return undef;
  }
  
  eval {
    local $SIG{__DIE__} = sub {};
    _parse_schema( $schema, $entry );
  };

  if ($@) {
    $schema->{error} = $@;
    return undef;
  }

  return $schema;
}

sub error {
  $_[0]->{error};
}

#
# Return base entry
#
sub entry {
  $_[0]->{entry};
}

#
# Dump as LDIF
#
# XXX - We should really dump from the internal structure. That way we can
#       have methods to modify the schema and write a new one -- GMB
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
sub merge {
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
  my %res;

  if( @oc ) {
    @res{ $self->must( @oc ) } = ();
    @res{ $self->may( @oc ) } = ();
  }
  else {
    @res{ @{ $self->{at} } } = () if $self->{at};
  }

  return wantarray ? (keys %res) : [keys %res];
}

# The names of all the object classes

sub objectclasses {
  my $self = shift;
  my $res = $self->{oc};
  return wantarray ? @$res : $res;
}

# Return all syntaxes

sub syntaxes {
  my $self = shift;
  my $res = $self->{syn};
  return wantarray ? @$res : $res;
}


# The names of all the matchingrules

sub matchingrules {
  my $self = shift;
  my $res = $self->{mr};
  return wantarray ? @$res : $res;
}

sub superclass {
   my $self = shift;
   my $oc = shift;

   my $oid = $self->is_objectclass( $oc );
   return undef unless $oid;

   my $res = $self->{oid}->{$oid}->{sup};
   return undef unless $res;
   return wantarray ? @$res : $res;
}

sub must {
  my $self = shift;
  $self->_must_or_may( "must", @_ );
}

sub may {
  my $self = shift;
  $self->_must_or_may( "may", @_ );
}

#
# Return must or may attributes for this OC. [As array or array ref]
# return empty array/undef on error
#
sub _must_or_may {
  my $self = shift;
  my $must_or_may = shift;
  my @oc = shift;
  
  #
  # If called with an entry, get the OC names and continue
  #
  if( UNIVERSAL::isa( $oc[0], "Net::LDAP::Entry" ) ) {
    my $entry = $oc[0];
    @oc = $entry->get_value( "objectclass" );
  }

  return unless @oc;

  my %res;		# Use hash to get uniqueness

  foreach my $oc ( @oc ) {
    my $oid = $self->is_objectclass( $oc );
    if( $oid ) {
      my $res = $self->{oid}->{$oid}->{$must_or_may};
      @res{ @$res } = (); 	# Add in, getting uniqueness
    }
  }

  return wantarray ? (keys %res) : [ keys %res ];
}


#
# Return the value of an item, e.g. 'desc'. If item is array ref and we
# are called from array context, return an array, else scalar
#
sub item {
  my $self = shift;
  my $arg = shift;
  my $item_name = shift;	# May be undef. If so all are returned

  my $oid = $self->name2oid( $arg ) or return;

  my $item_ref = $self->{oid}->{$oid} or return;

  my $value = $item_ref->{$item_name} or return;

  if( ref $value eq "ARRAY" && wantarray ) {
    return @$value;
  }
  else {
    return $value;
  }
}

#
# Return a list of items for a particular name or oid
#
# BUG:Dumps internal representation rather than real info. E.g. shows
# the alias/name distinction we create and the 'type' field.
#
sub items {
  my $self = shift;
  my $arg = shift;

  my $oid = $self->name2oid( $arg ) or return;

  my $item_ref = $self->{oid}->{$oid} or return;

  return wantarray ? (keys %$item_ref) : [keys %$item_ref];
}

#
# Given a name, alias or oid, return oid or undef. Undef if not known.
#
sub name2oid {
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
sub oid2name {
  my $self = shift;
  my $oid = shift;
  return undef unless $oid;
  return undef unless $self->{oid}->{$oid};
  return $self->{oid}->{$oid}->{name};
}

#
# Given name or oid, return oid or undef if not of appropriate type
#
sub is_attribute {
  my $self = shift;
  return $self->_is_type( "at", @_ );
}

sub is_objectclass {
  my $self = shift;
  return $self->_is_type( "oc", @_ );
}

sub is_syntax {
  my $self = shift;
  return $self->_is_type( "syn", @_ );
}

sub is_matchingrule {
  my $self = shift;
  return $self->_is_type( "mr", @_ );
}

# --------------------------------------------------
# Internal functions
# --------------------------------------------------

#
# Given a type and a name_or_oid, return true (the oid) if the name_or_oid
# is of the appropriate type. Else return undef.
#
sub _is_type {
  my $self = shift;
  my $type = shift or return;
  my $name = shift or return;

  my $oid = $self->name2oid( $name ) or return;  
  my $hash = $self->{oid}->{$oid} or return;

  return $hash->{type} eq $type ? $oid : undef;
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
# ->{at}  = [ list of canonical names of attributes ]
# ->{oc}  = [ list of can. names of objectclasses ]
# ->{syn} = [ list of can. names of syntaxes (we make names from descripts) ]
# ->{mr}  = [ list of can. names of matchingrules ]
#
# This is used to optimise name => oid lookups (to avoid searching).
# This could be removed or made into a cache to reduce memory usage.
# The names include any aliases.
#
# ->{name}->{ $lower_case_name } = $oid
#

#
# These items have no following arguments
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

#
# These items can have lists arguments
# (name can too, but we treat it special)
#
my %listops = map { ($_,1) } qw(must may sup);

#
# Map schema attribute names to internal names
#
my %type2attr = ( at	=> "attributetypes",
		  oc	=> "objectclasses",
		  syn	=> "ldapsyntaxes",
		  mr	=> "matchingrules",
		  );

#
# Return ref to hash containing schema data - undef on failure
#

sub _parse_schema {
  my $schema = shift;
  my $entry = shift;
  
  return undef unless defined($entry);

  keys %type2attr; # reset iterator
  while(my($type,$attr) = each %type2attr) {
    my $vals = $entry->get_value($attr, asref => 1);

    my @names;
    $schema->{$type} = \@names;		# Save reference to list of names

    next unless $vals;			# Just leave empty ref if nothing

    foreach my $val (@$vals) {
      #
      # We assume that each value can be turned into an OID, a canonical
      # name and a 'schema_entry' which is a hash ref containing the items
      # present in the value.
      #
      my %schema_entry = ( type => $type, aliases => [] );

      my @tokens;
      push @tokens, $+
        while $val =~ /(?:^|\G)\s*(?:
                       ([()])
                      |
                       ([^"'\s()]+)
                      |
                       "([^"]*)"
                      |
                       '([^']*)'
                      )\s*/xcg;
      die "Cannot parse [$val]" unless @tokens and pos($val) == length($val);

      # remove () from start/end
      shift @tokens if $tokens[0]  eq '(';
      pop   @tokens if $tokens[-1] eq ')';

      # The first token is the OID
      my $oid = $schema_entry{oid} = shift @tokens;

      while(@tokens) {
	my $tag = lc shift @tokens;

	if (exists $flags{$tag}) {
	  $schema_entry{$tag} = 1;
	}
	elsif (@tokens) {
	  if (($schema_entry{$tag} = shift @tokens) eq '(') {
	    my @arr;
	    $schema_entry{$tag} = \@arr;
	    while(1) {
	      my $tmp = shift @tokens;
	      last if $tmp eq ')';
	      push @arr,$tmp unless $tmp eq '$';

              # Drop of end of list ?
	      die "Cannot parse [$val]" unless @tokens;
	    }
	  }

          # Ensure items that can be lists are stored as array refs
	  $schema_entry{$tag} = [ $schema_entry{$tag} ]
	    if exists $listops{$tag} and !ref $schema_entry{$tag};
	}
        else {
          die "Cannot parse [$val]";
        }
      }

      #
      # Extract the maximum length of a syntax
      #
      if ( exists $schema_entry{syntax}) {
	$schema_entry{syntax} =~ s/{(\d+)}//;
	$schema_entry{max_length} = $1 || 0;
      }

      #
      # Force a name if we don't have one
      #
      if (!exists $schema_entry{name}) {
        if (exists $schema_entry{desc}) {
	  ($schema_entry{name} = $schema_entry{desc}) =~ s/\s+//g
        }
        else {
	  $schema_entry{name} = "$type:$schema_entry{oid}"
        }
      }

      #
      # If we have multiple names, make the name be the first and demote the rest to aliases
      #
      $schema_entry{name} = shift @{$schema_entry{aliases} = $schema_entry{name}}
	if ref $schema_entry{name};

      #
      # In the schema we store:
      #
      # 1 - The schema entry referenced by OID
      # 2 - a list of canonical names of each type
      # 3 - a (lower-cased) canonical name -> OID map
      # 4 - a (lower-cased) alias -> OID map
      #
      $schema->{oid}->{$oid} = \%schema_entry;
      my $uc_name = uc $schema_entry{name};
      push @names, $uc_name;
      $schema->{name}->{lc $uc_name} = $oid;
      foreach my $alias ( @{$schema_entry{aliases}} ) {
	$schema->{aliases}->{lc $alias} = $oid;
      }
    }
  }

  $schema->{entry} = $entry;
  return $schema;
}




#
# Get the syntax of an attribute
#
sub syntax {
  my $self = shift;
  my $attr = shift;

  my $oid = $self->is_attribute( $attr ) or return undef;

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
sub name {
  my $self = shift;
  my $arg = shift;
  my $oid = $self->name2oid( $arg ) or return undef;
  return $self->oid2name( $oid );
}

1;
