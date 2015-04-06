# Copyright (c) 2013 Peter Marschall <peter@adpm.de>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::Relax;

use Net::LDAP::Control;

our @ISA = qw(Net::LDAP::Control);
our $VERSION = '0.03';

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

Net::LDAP::Control::Relax - LDAPv3 Relax control object

=head1 SYNOPSIS

 use Net::LDAP;
 use Net::LDAP::Control::Relax;

 $ldap = Net::LDAP->new( "ldap.mydomain.eg" );

 $relax = Net::LDAP::Control::Relax->new();

 $msg = $ldap->modify( 'dc=sub,dc=mydomain,dc=eg",
                       changes => [
                         replace => { modifyTimestamp => '19700101000000Z' } ],
                       control  => [ $relax ] );

 die "error: ",$msg->code(),": ",$msg->error()  if ($msg->code());


=head1 DESCRIPTION

C<Net::LDAP::Control::Relax> provides an interface for the creation
and manipulation of objects that represent the C<Relax> control as
described by draft-zeilenga-ldap-relax-03.txt

The presence of the Relax control in an LDAP update request
indicates the server temporarily relax X.500 model constraints
during performance of the directory update.

The control is appropriate for all LDAP update requests, including
add, delete, modify, and modifyDN (rename) [RFC4511].

Its criticality is always set to TRUE, and no value.

There is no corresponding response control.

=head1 CONSTRUCTOR ARGUMENTS

Since the C<Relax> control does not have any values only the
constructor arguments described in L<Net::LDAP::Control> are
supported

=head1 METHODS

As there are no additional values in the control only the
methods in L<Net::LDAP::Control> are available for
C<Net::LDAP::Control::Relax> objects.

=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Control>,

=head1 AUTHOR

Peter Marschall E<lt>peter@adpm.deE<gt>.

Please report any bugs, or post any suggestions, to the perl-ldap
mailing list E<lt>perl-ldap@perl.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2013 Peter Marschall. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut

