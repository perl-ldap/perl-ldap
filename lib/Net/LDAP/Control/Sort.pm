# $Id: Sort.pm,v 1.3 2000/05/22 20:59:50 gbarr Exp $
# Copyright (c) 1999-2000 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::Sort;

use vars qw(@ISA $VERSION);

@ISA = qw(Net::LDAP::Control);
$VERSION = "0.01";

use Net::LDAP::ASN qw(SortRequest);
use strict;

sub init {
  my($self) = @_;

  if (exists $self->{value}) {
    $self->value($self->{value});
  }
  elsif (exists $self->{order}) {
    $self->order(ref($self->{order}) ? @{$self->{order}} : $self->{order});
  }

  $self;
}

sub value {
  my $self = shift;

  if (@_) {
    my $value = shift;

    delete $self->{value};
    delete $self->{order};
    delete $self->{error};

    my $asn = $SortRequest->decode($value);

    unless ($asn) {
      $self->{error} = $@;
      return undef;
    }

    $self->{order} = [ map {
      ($_->{reverseOrder} ? "-" : "")
      . $_->{type}
      . (defined($_->{orderingRule}) ? ":$_->{orderingRule}" : "")
    } @{$asn->{order}}];

    return $self->{value} = $value;
  }

  unless (defined $self->{value}) {
    $self->{value} = $SortRequest->encode(
      order => [
	map {
	  /^(-)?([^:]+)(?::(.+))?/;
	  {
	    type => $2,
	    (defined $1 ? (reverseOrder => 1)  : ()), 
	    (defined $3 ? (orderingRule => $3) : ())
	  }
	} @{$self->{order} || []}
      ]
    ) or $self->{error} = $@;
  }

  $self->{value};
}

sub valid { exists shift->{order} }

sub order {
  my $self = shift;

  if (@_) {
    # @_ can either be a list, or a single item.
    # if a single item it can be a string, which needs
    # to be split on spaces, or a reference to a list
    #
    # Each element has three parts
    #  leading - (optional)
    #  an attribute name
    #  :match-rule (optional)

    my @order = (@_ == 1) ? split(/\s+/, $_[0]) : @_;

    delete $self->{'value'};
    delete $self->{order};
    delete $self->{error};

    foreach (@order) {
      next if /^-?[^:]+(?::.+)?$/;

      $self->{error} = "Bad order argument '$_'";
      return;
    }

    $self->{order} = \@order;
  }

  return @{$self->{order}};
}

1;

__END__


=head1 NAME

Net::LDAP::Control::Sort - LDAPv3 sort control object

=head1 SYNOPSIS

 use Net::LDAP::Control::Sort;
 use Net::LDAP::Constant qw(LDAP_CONTROL_SORTRESULT);

 $sort = Net::LDAP::Control::Sort->new(
   order => "cn -phone"
 );

 $mesg = $ldap->search( @args, control => [ $sort ]);

 ($resp) = $mesg->control( LDAP_CONTROL_SORTRESULT );

 print "Results are sorted\n" if $resp and !$resp->result;

=head1 DESCRIPTION

C<Net::LDAP::Control::Sort> is a sub-class of L<Net::LDAP::Control|Net::LDAP::Control>.
It provides a class for manipulating the LDAP sort request control C<1.2.840.113556.1.4.473>

If the server supports sorting, then the response from a search operation will
include a sort result control. This control is handled by L<Net::LDAP::Control::SortResult>.

=head1 CONSTRUCTOR ARGUMENTS

=over 4

=item order

C<order> may be a string or a reference to an array. If it is a string it is split
on whitespace, otherwise the contents of the array is used.

Each element in the array specifies a sorting order as follows

  -attributeType:orderingRule

The leading C<-> is optional, and if present indicates that the sorting order should
be reversed. attributeType is the attribute name to sort by. orderingRule is optional and
indicates the rule to use for the sort and should be valid for the given attributeType.

Any one attributeType should only appear once in the sorting list.

=back


=head1 METHODS

Net::LDAP::Control::Sort provides the following methods in addition to
those defined by L<Net::LDAP::Control|Net::LDAP::Control>

=over 4

=item order [ ORDER ]

ORDER may be a string or a list. If it is a string then it is split on whitespace
and treated as if a list had been passed. See C<order> above for a description
of the format for each element.

If no arguments are passed then a list is returned of the current ordering elements.

=back

=head1 SEE ALSO

L<Net::LDAP|Net::LDAP>,
L<Net::LDAP::Control::SortResult|Net::LDAP::Control::SortResult>,
L<Net::LDAP::Control|Net::LDAP::Control>

=head1 AUTHOR

Graham Barr <gbarr@pobox.com>

Please report any bugs, or post any suggestions, to the perl-ldap mailing list
<perl-ldap-dev@lists.sourceforge.net>

=head1 COPYRIGHT

Copyright (c) 1999-2000 Graham Barr. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=for html <hr>

I<$Id: Sort.pm,v 1.3 2000/05/22 20:59:50 gbarr Exp $>

=cut
