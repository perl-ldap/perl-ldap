# $Id: SortResult.pm,v 1.1 2000/05/03 12:29:20 gbarr Exp $
# Copyright (c) 1999-2000 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::SortResult;

use Net::LDAP::ASN qw(SortResult);

@ISA = qw(Net::LDAP::Control);

sub init {
  my($self) = @_;

  if (exists $self->{value}) {
    $self->{asn} = $SortResult->decode(delete $self->{value});
  }
  else {
    $self->{asn} = { sortResult => delete $self->{result} };
    $self->{asn}{attributeType} = delete $self->{attr} if exists $self->{attr};
  }

  $self;
}

sub value {
  my $self = shift;

  $self->{value} = $SortResult->encode($self->{asn});
}

sub result {
  my $self = shift;

  @_ ? ($self->{asn}{sortResult}=shift)
     : $self->{asn}{sortResult};
}

sub attr {
  my $self = shift;

  @_ ? ($self->{asn}{attributeType}=shift)
     : $self->{asn}{attributeType};
}

1;


__END__


=head1 NAME

Net::LDAP::Control::SortResult - LDAPv3 sort result control object

=head1 SYNOPSIS

 use Net::LDAP::Control::Sort;
 use Net::LDAP::Constant qw( LDAP_CONTROL_SORTRESULT );

 $sort = Net::LDAP::Control::Sort->new(
   order => "cn -age"
 );

 $mesg = $ldap->search( @args, control => [ $sort ]);

 ($resp) = $mesg->control( LDAP_CONTROL_SORTRESULT );

 print "Results are sorted\n" if $resp and !$resp->result;

=head1 DESCRIPTION

C<Net::LDAP::Control::SortResult> is a sub-class of L<Net::LDAP::Control|Net::LDAP::Control>.
It provides a class for manipulating the LDAP sort request control C<1.2.840.113556.1.4.474>

A sort result control will be returned by the server in response to a search with a sort
control. If a sort result control is not returned then the user may assume that the
server does not support sorting and the resutls are not sorted.

=head1 CONSTRUCTOR ARGUMENTS

=over 4

=item result

=item attr


=back


=head1 METHODS

Net::LDAP::Control::SortResult provides the following methods in addition to
those defined by L<Net::LDAP::Control|Net::LDAP::Control>

=over 4

=item result [ RESULT ]

=item attr [ ATTR ]

=back

=head1 RESULT CODES

Possible results from a sort request are listed below. See L<Net::LDAP::Constant> for
a definition of each.

=over 4

=item LDAP_SUCCESS

=item LDAP_OPERATIONS_ERROR

=item LDAP_TIMELIMIT_EXCEEDED

=item LDAP_STRONG_AUTH_REQUIRED

=item LDAP_ADMIN_LIMIT_EXCEEDED

=item LDAP_NO_SUCH_ATTRIBUTE

=item LDAP_INAPPROPRIATE_MATCHING

=item LDAP_INSUFFICIENT_ACCESS

=item LDAP_BUSY

=item LDAP_UNWILLING_TO_PERFORM

=item LDAP_OTHER

=back

=head1 SEE ALSO

L<Net::LDAP|Net::LDAP>,
L<Net::LDAP::Control::Sort|Net::LDAP::Control::Sort>,
L<Net::LDAP::Control|Net::LDAP::Control>

=head1 AUTHOR

Graham Barr <gbarr@pobox.com>

Please report any bugs, or post any suggestions, to the perl-ldap mailing list
<perl-ldap@mail.med.cornell.edu>

=head1 COPYRIGHT

Copyright (c) 1999-2000 Graham Barr. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=for html <hr>

I<$Id: SortResult.pm,v 1.1 2000/05/03 12:29:20 gbarr Exp $>

=cut
