# Copyright (c) 2021 Peter Marschall <peter@adpm.de>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::NoOp;

use Net::LDAP::Control;

our @ISA = qw(Net::LDAP::Control);
our $VERSION = '0.01';

use strict;

sub init {
  my($self) = @_;

  delete $self->{asn};
  delete $self->{value};

  # criticality must be set !
  $self->{critical} = 1;

  $self;
}

# make sure value does not get set
sub value {
  undef;
}

# make sure criticality remains TRUE
sub critical {
  1;
}

1;

__END__

=head1 NAME

Net::LDAP::Control::NoOp - LDAPv3 Tree Delete control object

=head1 SYNOPSIS

 use Net::LDAP;
 use Net::LDAP::Control::NoOp;

 $ldap = Net::LDAP->new( "ldap.mydomain.eg" );

 $noop = Net::LDAP::Control::NoOp->new();

 $msg = $ldap->modify( 'cn=Barbara Jensen, o=University of Michigan, c=US',
                       control  => [ $noop ] );

 die "error: ",$msg->code(),": ",$msg->error()  if ($msg->code());


=head1 DESCRIPTION

C<Net::LDAP::Control::NoOp> provides an interface for the creation
and manipulation of objects that represent the C<No-Op> control as
described by L<draft-zeilenga-ldap-noop-01.txt|https://tools.ietf.org/html/draft-zeilenga-ldap-noop-01>.

The control, which has no corresponding response control,
is appropriate for all LDAP update requests, including
L<add|Net::LDAP/add>, L<delete|Net::LDAP/delete>,
L<modify|Net::LDAP/modify>, and L<moddn|Net::LDAP/moddn>.

Its criticality is always C<TRUE>; it has no value.

The presence of the C<No-Op> control in an operation request message
disables the normal effect of the operation;
i.e. the server will do all processing necessary to perform the
operation but not actually update the directory.

=head1 CONSTRUCTOR ARGUMENTS

Since the C<NoOp> control does not have any values, only the
constructor arguments described in L<Net::LDAP::Control> are
supported

=head1 METHODS

As there are no additional values in the control, only the
methods in L<Net::LDAP::Control> are available for
C<Net::LDAP::Control::NoOp> objects.

=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Control>,

=head1 AUTHOR

Peter Marschall E<lt>peter@adpm.deE<gt>.

Please report any bugs, or post any suggestions, to the perl-ldap
mailing list E<lt>perl-ldap@perl.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2021 Peter Marschall. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut

