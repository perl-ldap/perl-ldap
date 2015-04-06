# Copyright (c) 2004 Peter Marschall <peter@adpm.de>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::ManageDsaIT;

use Net::LDAP::Control;

our @ISA = qw(Net::LDAP::Control);
our $VERSION = '0.04';

use strict;

sub init {
  my($self) = @_;

  delete $self->{asn};
  delete $self->{value};

  $self;
}

sub value {
  undef;
}

1;

__END__

=head1 NAME

Net::LDAP::Control::ManageDsaIT - LDAPv3 Manage DSA-IT control object

=head1 SYNOPSIS

 use Net::LDAP;
 use Net::LDAP::Control::ManageDsaIT;

 $ldap = Net::LDAP->new( "ldap.mydomain.eg" );

 $manage = Net::LDAP::Control::ManageDsaIT->new( critical => 1 );

 $msg = $ldap->modify( 'dc=sub,dc=mydomain,dc=eg",
                       changes => [
                         delete => { ref => 'ldap://ldap2/dc=sub,dc=mydom,dc=eg' },
                         add => { ref => 'ldap://ldap3/dc=sub,dc=mydom,dc=eg' } ],
                       control  => [ $manage ] );

 die "error: ",$msg->code(),": ",$msg->error()  if ($msg->code());


=head1 DESCRIPTION

C<Net::LDAP::Control::ManageDsaIT> provides an interface for the creation
and manipulation of objects that represent the C<ManageDsaIT> control as
described by RFC 3296.

It allows the manipulation of referral and other special objects as normal
entries.

The control is appropriate for LDAP search, compare and all update requests,
including add, delete, modify, and modifyDN (rename) [RFC4511].

Its criticality may be TRUE or FALSE; it has no value.

=head1 CONSTRUCTOR ARGUMENTS

Since the C<ManageDsaIT> control does not have any values only the
constructor arguments described in L<Net::LDAP::Control> are
supported

=head1 METHODS

As there are no additional values in the control only the
methods in L<Net::LDAP::Control> are available for
C<Net::LDAP::Control::ManageDsaIT> objects.

=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Control>,

=head1 AUTHOR

Peter Marschall E<lt>peter@adpm.deE<gt>.

Please report any bugs, or post any suggestions, to the perl-ldap
mailing list E<lt>perl-ldap@perl.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2004 Peter Marschall. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut

