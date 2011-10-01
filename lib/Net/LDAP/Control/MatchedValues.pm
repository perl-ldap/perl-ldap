# Copyright (c) 2011 Peter Marschall <peter@adpm.de>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::MatchedValues;

use vars qw(@ISA $VERSION);
use Net::LDAP::Control;

@ISA = qw(Net::LDAP::Control);
$VERSION = "0.01";

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
It has no effect on the number of objects found, but only allows to restrict the
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

my $ErrStr;

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

my %Rop = reverse %Op;

sub errstr { $ErrStr }

# Unescape
#   \xx where xx is a 2-digit hex number
#   \y  where y is one of ( ) \ *
sub _unescape {
  $_[0] =~ s/
	     \\([\da-fA-F]{2}|.)
	    /
	     length($1) == 1
	       ? $1
	       : chr(hex($1))
	    /soxeg;
  $_[0];
}

sub _escape { (my $t = $_[0]) =~ s/([\\\(\)\*\0-\37\177-\377])/sprintf("\\%02x",ord($1))/sge; $t }

sub _encode {
  my($attr,$op,$val) = @_;

  # extensible match
  if ($op eq ':=') {
    # attr must be in the form type:1.2.3.4
    unless ($attr =~ /^([-;\d\w]*)(:(\w+|[.\d]+))?$/) {
      $ErrStr = "Bad attribute $attr";
      return undef;
    }
    my($type,$rule) = ($1,$3);

    return ( {
      extensibleMatch => {
	matchingRule => $rule,
	type         => length($type) ? $type : undef,
	matchValue   => _unescape($val), 
      }
    });
  }


  # special cases: present / substring matches
  if ($op eq '=') {
    # present match
    if ($val eq '*') {
      return ({ present => $attr });
    }

    # if val contains unescaped *, then we have substring match
    elsif ( $val =~ /^(\\.|[^\\*]+)*\*/o ) {

      my $n = [];
      my $type = 'initial';

      while ($val =~ s/^((\\.|[^\\*]+)*)\*//) {
        push(@$n, { $type, _unescape("$1") })         # $1 is readonly, copy it
	  if length($1) or $type eq 'any';

        $type = 'any';
      }

      push(@$n, { 'final', _unescape($val) })
        if length $val;

      return ({
        substrings => {
	  type       => $attr,
	  substrings => $n
        }
      });
    }
  }

  # in all other cases we must have an operator and no un-escaped *'s on the RHS
  return {
    $Op{$op} => {
      attributeDesc => $attr, assertionValue =>  _unescape($val)
    }
  };
}

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
      my $item = _encode($1,$2,$3);
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
    $ErrStr = "Bad filterlist, error before " . substr($filterlist,0,20);
    return undef;
  }

  @$self = @parsed;

  $self;
}

sub print {
  my $self = shift;
  no strict 'refs'; # select may return a GLOB name
  my $fh = @_ ? shift : select;

  print $fh $self->as_string,"\n";
}

sub as_string {
  my $l = shift;

  return '(' . join('', map { _string(%{$_}) } @{$l}) . ')';
}

sub _string {    # prints things of the form (<item>)
  my $str = "";

  for ($_[0]) {
    /^present/ and return "($_[1]=*)";
    /^(equalityMatch|greaterOrEqual|lessOrEqual|approxMatch)/
      and return "(" . $_[1]->{attributeDesc} . $Rop{$1} . _escape($_[1]->{assertionValue})  .")";
    /^substrings/ and do {
      my $str = join("*", "",map { _escape($_) } map { values %$_ } @{$_[1]->{substrings}});
      $str =~ s/^.// if exists $_[1]->{substrings}[0]{initial};
      $str .= '*' unless exists $_[1]->{substrings}[-1]{final};
      return "($_[1]->{type}=$str)";
    };
    /^extensibleMatch/ and do {
      my $str = "(";
      $str .= $_[1]->{type} if defined $_[1]->{type};
      $str .= ":$_[1]->{matchingRule}" if defined $_[1]->{matchingRule};
      $str .= ":=" . _escape($_[1]->{matchValue}) . ")";
      return $str;
    };
  }

  die "Internal error $_[0]";
}

1;
