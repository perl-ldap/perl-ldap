# Copyright (c) 2014 Peter Marschall <peter@adpm.de>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::DontUseCopy;

use Net::LDAP::Control;

our @ISA = qw(Net::LDAP::Control);
our $VERSION = '0.01';

use strict;

sub init {
  my($self) = @_;

  delete $self->{asn};
  delete $self->{value};

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

Net::LDAP::Control::DontUseCopy - LDAPv3 Don't Use Copy control object

=head1 SYNOPSIS

 use Net::LDAP;
 use Net::LDAP::Control::DontUseCopy;

 $ldap = Net::LDAP->new( "ldap.mydomain.eg" );

 $nocopy = Net::LDAP::Control::DontUseCopy->new( critical => 1 );

 $msg = $ldap->search( base => 'o=University of Michigan,c=US',
                       filter => '(cn=Barbara Jensen)'
                       control  => [ $nocopy ] );

 die "error: ",$msg->code(),": ",$msg->error()  if ($msg->code());


=head1 DESCRIPTION

C<Net::LDAP::Control::DontUseCopy> provides an interface for the creation
and manipulation of objects that represent the C<DontUseCopy> control as
described by RFC 6171.

It allows the the client to specify that copied information should not be used
in providing the service.

The control is appropriate for LDAP search and compare operations [RFC4511]
and inappropriate for all other oeprations.

Its criticality must be TRUE; it has no value.

There is no corresponding response control.

=head1 CONSTRUCTOR ARGUMENTS

Since the C<DontUseCopy> control does not have any values only the
constructor arguments described in L<Net::LDAP::Control> are
supported

=head1 METHODS

As there are no additional values in the control only the
methods in L<Net::LDAP::Control> are available for
C<Net::LDAP::Control::DontUseCopy> objects.

=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Control>,

=head1 AUTHOR

Peter Marschall E<lt>peter@adpm.deE<gt>.

Please report any bugs, or post any suggestions, to the perl-ldap
mailing list E<lt>perl-ldap@perl.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2014 Peter Marschall. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut

