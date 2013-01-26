package Net::LDAP::Extension::Refresh;
require Net::LDAP::Extension;

our @ISA = qw(Net::LDAP::Extension);
our $VERSION = '0.03';

use Convert::ASN1;

my $refreshReq = Convert::ASN1->new;
$refreshReq->prepare(q<SEQUENCE {
                     entryName    [0] OCTET STRING, -- originally: LDAPDN
                     requestTtl   [1] INTEGER
                     }>);

my $refreshResp = Convert::ASN1->new;
$refreshResp->prepare(q<SEQUENCE {
                      responseTtl [0] INTEGER
                      }>);

sub Net::LDAP::refresh {
  my $ldap = shift;
  my %opt = @_;

  my $res = $ldap->extension (
    name => '1.3.6.1.4.1.1466.101.119.1',
    value => $refreshReq->encode(\%opt),
    ($opt{control} ? (control => $opt{control}) : ())
  );

  bless $res;
}

sub get_ttl {
  my $self = shift;
  my $out = $refreshResp->decode($self->response);
  $out->{responseTtl};
}
1;

__END__

=head1 NAME

Net::LDAP::Extension::Refresh - LDAPv3 Refresh extension object (RFC 2589)

=head1 SYNOPSIS

 use Net::LDAP;
 use Net::LDAP::Extension::Refresh;

 $ldap = Net::LDAP->new('localhost');
 $ldap->bind('cn=admin,dc=example,dc=com', password => 'password');

 $mesg = $ldap->refresh(entryName => 'cn=dynamic,dc=example,dc=com',
        requestTtl => 100);
 die "error :", $mesg->code(), ": ", $mesg->error()  if ($mesg->code());
 print "TTL changed to ", $mesg->get_ttl(), "\n";

=head1 DESCRIPTION

C<Net::LDAP::Extension::Refresh> implements the C<Refresh> extended LDAPv3
operation as described in RFC 2589

It implements no object by itself but extends the L<Net::LDAP> object
by another method:

=head1 METHODS

=over 4

=item refresh ( OPTIONS )

Send a refresh operation for an object.

OPTIONS is a list of key/value pairs. The following keys are recognized:

=over 4

=item entryName

This option contains the object to refresh. It must be a DN.

=item requestTtl

This option contains the TTL in seconds requested. The server may choose to
set another value as stated in RFC 2589

=back

=item get_ttl ( )

Return the TTL set by the server during the previous C<refresh> call.

This method is a method of the L<Net::LDAP::Message> response object
returned in reply to C<refresh()> in case the C<refresh()> call succeeded.

=back

=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Extension>

=head1 AUTHOR

Etienne Bagnoud E<lt>etienne.bagnoud@irovision.chE<gt>
Adapted from Graham Barr L<Net::LDAP::Extension::SetPassword>
Documentation adapted from Peter Marschall L<Net::LDAP::Extension::SetPassword>

Please report any bugs, or post any suggestions, to the perl-ldap
mailing list E<lt>perl-ldap@perl.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2010 Etienne Bagnoud. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut

