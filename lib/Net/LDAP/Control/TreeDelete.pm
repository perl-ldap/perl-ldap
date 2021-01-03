# Copyright (c) 2020 Peter Marschall <peter@adpm.de>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::TreeDelete;

use Net::LDAP::Control;

our @ISA = qw(Net::LDAP::Control);
our $VERSION = '0.01';

use strict;

sub init {
  my($self) = @_;

  delete $self->{asn};
  delete $self->{value};

  $self;
}

# make sure value does not get set
sub value {
  undef;
}

1;

__END__

=head1 NAME

Net::LDAP::Control::TreeDelete - LDAPv3 Tree Delete control object

=head1 SYNOPSIS

 use Net::LDAP;
 use Net::LDAP::Control::TreeDelete;

 $ldap = Net::LDAP->new( "ldap.mydomain.eg" );

 $treedel = Net::LDAP::Control::TreeDelete->new( critical => 1 );

 $msg = $ldap->delete( 'o=University of Michigan,c=US',
                       control  => [ $treedel ] );

 die "error: ",$msg->code(),": ",$msg->error()  if ($msg->code());


=head1 DESCRIPTION

C<Net::LDAP::Control::TreeDelete> provides an interface for the creation
and manipulation of objects that represent the C<TreeDelete> control as
described by L<draft-armijo-ldap-treedelete-02.txt|https://tools.ietf.org/html/draft-armijo-ldap-treedelete-02>

It allows the client to delete an entire subtree.

The control is appropriate for LDAP delete operations [RFC4511] only,
and inappropriate for all other operations.

Its criticality may be TRUE or FALSE; it has no value.

There is no corresponding response control.

=head1 CONSTRUCTOR ARGUMENTS

Since the C<TreeDelete> control does not have any values, only the
constructor arguments described in L<Net::LDAP::Control> are
supported

=head1 METHODS

As there are no additional values in the control, only the
methods in L<Net::LDAP::Control> are available for
C<Net::LDAP::Control::TreeDelete> objects.

=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Control>,

=head1 AUTHOR

Peter Marschall E<lt>peter@adpm.deE<gt>.

Please report any bugs, or post any suggestions, to the perl-ldap
mailing list E<lt>perl-ldap@perl.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2020 Peter Marschall. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut

