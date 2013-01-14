
package Net::LDAP::Extension::Cancel;

require Net::LDAP::Extension;

our @ISA = qw(Net::LDAP::Extension);
our $VERSION = '0.02';

use Convert::ASN1;

my $cancelReq = Convert::ASN1->new;
$cancelReq->prepare(q<SEQUENCE {
                     cancelID    INTEGER	-- originally: MessageID
                    }>);

sub Net::LDAP::cancel {
  my $ldap = shift;
  my $op = shift;
  my %opt = @_;

  my $res = $ldap->extension (
    name => '1.3.6.1.1.8',
    value => $cancelReq->encode({ cancelID => ref($op) ? $op->mesg_id : $op }),
    ($opt{control} ? (control => $opt{control}) : ())
  );

  bless $res;
}

1;

__END__

=head1 NAME

Net::LDAP::Extension::Cancel - LDAP Cancel Operation

=head1 SYNOPSIS

 use Net::LDAP;
 use Net::LDAP::Constant qw(LDAP_SUCCESS LDAP_CANCELED)
 use Net::LDAP::Extension::Cancel;

 $ldap = Net::LDAP->new( 'ldap.mydomain.eg' );

 $ldap->bind('cn=Joe User,cn=People,dc=example,dc=com',
             password => 'secret');

 $search = $ldap->search(
                        base     => 'c=US',
                        filter   => '(&(sn=Barr) (o=Texas Instruments))',
                        callback => \&process_entry, # Call this sub for each entry
                      );

 $mesg = $ldap->cancel($search);

 die "error :", $mesg->code(), ": ", $mesg->error()
   if ($mesg->code() != LDAP_CANCELED && mesg->code() != LDAP_SUCCESS);

=head1 DESCRIPTION

C<Net::LDAP::Extension::Cancel> implements the C<Cancel>
extended LDAPv3 operation as described in RFC 3909.

The C<Cancel> extended operation is very similar to the C<Abandon>
standard operation, and has the same call signature.
Unlike the C<Abandon> operation, it has a response which provides
an indication of its outcome.

It implements no object by itself but extends the L<Net::LDAP> object
by another method:

=head1 METHODS

=over 4

=item cancel ( OPERATION, OPTIONS )

Cancel an outstanding operation. C<OPERATION> may be a number or an
object which is a sub-class of L<Net::LDAP::Message>, returned from a
previous method call.

OPTIONS is a list of key/value pairs. The following keys are recognized:

=over 4

=item control => CONTROL

=item control => [ CONTROL, .. ]

Control(s) to be passed to the operation.

=back


=back

=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Extension>

=head1 AUTHOR

Peter Marschall <peter@adpm.de>.

Please report any bugs, or post any suggestions, to the perl-ldap
mailing list E<lt>perl-ldap@perl.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2011 Peter Marschall. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut

