# Copyright (c) 2011 Peter Marschall <peter@adpm.de>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::MatchedValues;

use Net::LDAP::Control;

our @ISA = qw(Net::LDAP::Control);
our $VERSION = '0.02';

use Net::LDAP::ASN qw(ValuesReturnFilter);
use strict;

sub init {
  my($self) = @_;

  delete $self->{asn};

  unless (exists $self->{value}) {
    $self->{asn} = $self->{matchedValues} || '';
  }

  $self;
}

sub matchedValues {
  my $self = shift;

  if (@_) {
    delete $self->{value};
    return $self->{asn} = shift;
  }
  elsif (exists $self->{value}) {
    my $f = $ValuesReturnFilter->decode($self->{value});
    $self->{asn} ||= Net::LDAP::FilterList::as_string($f)
      if (ref $f);
  }

  $self->{asn};
}

sub value {
  my $self = shift;

  unless (exists $self->{value}) {
    my $f = Net::LDAP::FilterList->new;
    $self->{value} = $ValuesReturnFilter->encode($f)
      if ($f->parse($self->{asn}));
  }

  $self->{value};
}

1;

=head1 NAME

Net::LDAP::Control::MatchedValues - LDAPv3 MatchedValues Control

=head1 SYNOPSIS

 use Net::LDAP;
 use Net::LDAP::Control::MatchedValues;

 $ldap = Net::LDAP->new( "ldap.mydomain.eg" );

 $mv = Net::LDAP::Control::MatchedValues->new( matchedValues => '((sn=Jensen)(sn=Miller))' );

 # return the entries of all people with first name "Babs",
 # but only show the sn if it is "Jensen" or "Miller"
 my $mesg = $ldap->search( base => "o=University of Michigan, c=US",
                           filter => "(givenName=Babs)",
                           attrs => [ qw/sn/ ],
                           control => $mv );

=head1 DESCRIPTION

C<Net::LDAP::Control::MatchedValues> provides an interface for the creation and
manipulation of objects that represent the C<MatchedValues Control> as described
by RFC 3876.

The C<MatchedValues Control>, which only has a meaning with the C<Search> operation,
allows the client to specify criteria that restrict the values of attributes returned.
It has no effect on the number of objects found, but only allows one to restrict the
values of the attributes returned by the search to those matching the criteria.


=head1 CONSTRUCTOR ARGUMENTS

In addition to the constructor arguments described in
L<Net::LDAP::Control> the following are provided.

=over 4

=item matchedValues => VALUESRETURNFILTER

A filter giving the criteria which attribute values shall be returned.

VALUESRETURNFILTER is a sequence of simple filter items of the form
C<< ( <ATTRSPEC> <OP> <VALUE> ) >> surrounded by an additional set of parentheses;
e.g.

=over 4

=item ((personsAge<=29))

Only return the age if is less than 30 ;-)

=item ((cn=*Emergency*)(telephoneNumber=+1*)(telephoneNumber=911))

Only return those values of the cn that contain C<Emergency>,
and phone numbers from North America including the one for emergency calls.

=back

=back


=head1 METHODS

As with L<Net::LDAP::Control> each constructor argument
described above is also available as a method on the object which will
return the current value for the attribute if called without an argument,
and set a new value for the attribute if called with an argument.


=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Control>,
http://www.ietf.org/rfc/rfc3876.txt

=head1 AUTHOR

Peter Marschall E<lt>peter@adpm.deE<gt>

Please report any bugs, or post any suggestions, to the perl-ldap mailing list
E<lt>perl-ldap@perl.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2011 Peter Marschall. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut


package Net::LDAP::FilterList;

use Net::LDAP::Filter;

our @ISA = qw(Net::LDAP::Filter);
our $VERSION = '0.03';

# filter       = "(" 1*item ")"
# item         = simple / present / substring / extensible
# simple       = attr filtertype value
# filtertype   = equal / approx / greater / less
# equal        = "="
# approx       = "~="
# greater      = ">="
# less         = "<="
# extensible   = attr [":" matchingrule] ":=" value
#                / ":" matchingrule ":=" value
# present      = attr "=*"
# substring    = attr "=" [initial] any [final]
# initial      = value
# any          = "*" *(value "*")
# final        = value
# attr         = AttributeDescription from Section 4.1.5 of [1]
# matchingrule = MatchingRuleId from Section 4.1.9 of [1]
# value        = AttributeValue from Section 4.1.6 of [1]
#
# Special Character encodings
# ---------------------------
#    *               \2a, \*
#    (               \28, \(
#    )               \29, \)
#    \               \5c, \\
#    NUL             \00


sub new {
  my $self = shift;
  my $class = ref($self) || $self;

  my $me = bless [], $class;

  if (@_) {
    $me->parse(shift) or
      return undef;
  }
  $me;
}

my $Attr  = '[-;.:\d\w]*[-;\d\w]';

my %Op = qw(
  =   equalityMatch
  ~=  approxMatch
  >=  greaterOrEqual
  <=  lessOrEqual
  :=  extensibleMatch
);

my $ErrStr;

sub parse {
  my $self = shift;
  my $filterlist = shift;

  my @parsed = ();

  undef $ErrStr;

  # a filterlist is required
  if (!defined $filterlist) {
    $ErrStr = "Undefined filterlist";
    return undef;
  }


  # remove surrounding braces ((..)(..)(..)) -> (..)(..)(..)
  $filterlist =~s/^\((\(.*)\)$/$1/;

  while (length($filterlist)) {

    # process (attr op string)
    if ($filterlist =~ s/^\(\s*
                            ($Attr)\s*
                            ([:~<>]?=)
                            ((?:\\.|[^\\()]+)*)
                            \)\s*
                           //xo) {
      my $item = Net::LDAP::Filter::_encode($1, $2, $3);
      return undef  if (!$item);
      push(@parsed, $item);
      next;
    }

    # If we get here then there is an error in the filter string
    # so exit loop with data in $filterlist
    last;
  }

  if (length $filterlist) {
    # If we have anything left in the filter, then there is a problem
    $ErrStr = "Bad filterlist, error before " . substr($filterlist, 0, 20);
    return undef;
  }

  @$self = @parsed;

  $self;
}

sub as_string {
  my $l = shift;

  return '(' . join('', map { Net::LDAP::Filter::_string(%{$_}) } @{$l}) . ')';
}

1;
