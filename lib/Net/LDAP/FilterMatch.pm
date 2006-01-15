# ===========================================================================
# Net::LDAP::FilterMatch
# 
# LDAP entry matching
# 
# Hans Klunder <hans.klunder@bigfoot.com>
# Peter Marschall <peter@adpm.de>
#  Copyright (c) 2005-2006.
# 
# See below for documentation.
# 

use Net::LDAP::Filter;
use Net::LDAP::Schema;

package Net::LDAP::Filter;

use strict;
use vars qw(@ISA @EXPORT_OK);

require Exporter;
@ISA       = qw(Exporter);
@EXPORT_OK = qw(filterMatch);
$VERSION   = '0.13';

sub filterMatch($@);
sub _cis_equalityMatch($@);
sub _cis_greaterOrEqual($@);
sub _cis_lessOrEqual($@);
sub _cis_approxMatch($@);
sub _cis_substrings;

sub _caseIgnoreMatch { return _cis_equalityMatch(@_)};
sub _caseIgnoreSubstringsMatch { return _cis_substrings(@_) };

sub match
{
  my $self = shift;
  my $entry = shift;
  my $schema =shift;

  return filterMatch($self, $entry, $schema);
}

# map Ops to schema matches 
my %op2schema = qw(
	equalityMatch  equality
	greaterOrEqual equality
	lessOrEqual	   ordering
	approxMatch	   ordering
	substrings	   substr
);

sub filterMatch($@)
{
  my $filter = shift;
  my $entry = shift;
  my $schema = shift;

  keys(%{$filter}); # re-initialize each() operator
  my ($op, $args) = each(%{$filter});

  # handle combined filters
  if ($op eq 'and') {	# '(&()...)' => fail on 1st mismatch
    foreach my $subfilter (@{$args}) {
      return 0  if (!filterMatch($subfilter, $entry));
    }  
    return 1;	# all matched or '(&)' => succeed
  }  
  if ($op eq 'or') {	# '(|()...)' => succeed on 1st match
    foreach my $subfilter (@{$args}) {
      return 1  if (filterMatch($subfilter, $entry));
    }  
    return 0;	# none matched or '(|)' => fail
  }  
  if ($op eq 'not') {
    return (! filterMatch($args, $entry));
  }  
  if ($op eq 'present') {
    #return 1  if (lc($args) eq 'objectclass');	# "all match" filter
    return ($entry->exists($args));
  }  

  # handle basic filters
  if ($op =~ /^(equalityMatch|greaterOrEqual|lessOrEqual|approxMatch|substrings)/o) {
    my $attr=($op eq 'substrings') ? $args->{'type'} : $args->{'attributeDesc'} ;
    my @values = $entry->get_value($attr);
    my $match;
    
    # approx match is not standardized in schema
    if ($schema and ($op ne 'approxMatch') ){
	     # get matchingrule from schema, be sure that matching subs exist for every MR in your schema
	      $match='_' . $schema->matchingrule_for_attribute( $attr, $op2schema{$op}) or return undef;
    }
    else{
       # fall back on build-in logic
       $match='_cis_' . $op;
    }

    return &$match($args, @values);
  }
  
  return undef;	# all other filters => fail with error
}

sub _cis_equalityMatch($@)
{
my $args=shift;
my $assertion = $args->{'assertionValue'};

  return grep(/^\Q$assertion\E$/i, @_) ? 1 : 0;
}


sub _cis_greaterOrEqual($@)
{
my $args=shift;
my $assertion = $args->{'assertionValue'};

  if (grep(!/^-?\d+$/o, $assertion, @_)) {	# numerical values only => compare numerically
    return (grep { $_ ge $assertion } @_) ? 1 : 0;
  }
  else {
    return (grep { lc($_) >= lc($assertion) } @_) ? 1 : 0;
  }  
}


sub _cis_lessOrEqual($@)
{
my $args=shift;
my $assertion = $args->{'assertionValue'};

  if (grep(!/^-?\d+$/o, $assertion, @_)) {	# numerical values only => compare numerically
    return (grep { $_ le $assertion } @_) ? 1 : 0;
  }
  else {
    return (grep { lc($_) <= lc($assertion) } @_) ? 1 : 0;
  }  
}


sub _cis_approxMatch($@)
{
my $args=shift;
my $assertion = $args->{'assertionValue'};

  # kludge: treat assertion as regex
  $assertion =~ s/\./\\./go;
  $assertion =~ s/\*/.*/go;
  #print "$assertion\n";  

  return grep(/^$assertion$/i, @_) ? 1 : 0;
  # better: by use String::Approx or similar
}


sub _cis_substrings
{
  my $args=shift;
  my $regex = join('.*', map { "\Q$_\E" } map { values %$_ } @{$args->{'substrings'}});

  $regex =  '^'.$regex  if (exists $args->{'substrings'}[0]{initial});
  $regex .= '$'         if (exists $args->{'substrings'}[-1]{final});
      
  #print "RegEx: ".$regex."\n";

  return grep(/$regex/i, @_) ? 1 : 0;
}

1;
  
  
__END__

=head1 NAME

Net::LDAP::FilterMatch - LDAP entry matching

=head1 SYNOPSIS

  use Net::LDAP::Entry;
  use Net::LDAP::Filter;
  use Net::LDAP::FilterMatch;

  my $entry = new Net::LDAP::Entry;
  $entry->dn("cn=dummy entry");
  $entry->add (
   'cn' => 'dummy entry',
   'street' => [ '1 some road','nowhere' ] );
   
  my @filters = (qw/(cn=dummy*)
                 (ou=*)
                 (&(cn=dummy*)(street=*road))
                 (&(cn=dummy*)(!(street=nowhere)))/);


  for (@filters) {
    my $filter = Net::LDAP::Filter->new($_);
    print $_,' : ', $filter->match($entry) ? 'match' : 'no match' ,"\n";
  }

=head1 ABSTRACT

This extension of the class Net::LDAP::Filter provides entry matching
functionality on the Perl side.

Given an entry it will tell whether the entry matches the filter object.

It can be used on its own or as part of a Net::LDAP::Server based LDAP server.

=head1 METHOD

=over 4

=item match ( ENTRY [ ,SCHEMA ] )

Return whether ENTRY matches the filter object. If a schema object is provided, 
the selection of matching algorithms will be derived from schema.

In case of error undef is returned.

=back


=head1 SEE ALSO

L<Net::LDAP::Filter> 

=head1 COPYRIGHT

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHORS

Hans Klunder E<lt>hans.klunder@bigfoot.comE<gt>
Peter Marschall E<lt>peter@adpm.deE<gt>

=cut

# EOF
  
