# Copyright (c) 2000-2003 Chris Ridd <chris.ridd@isode.com> and
# Graham Barr <gbarr@pobox.com>. All rights reserved.  This program is
# free software; you can redistribute it and/or modify it under the
# same terms as Perl itself.

package Net::LDAPS;
@Net::LDAPS::ISA = ( 'Net::LDAP' );
$Net::LDAPS::VERSION = "0.05";

use strict;
use Net::LDAP;

sub new {
  shift->SUPER::new(@_, scheme => 'ldaps');
}

1;

__END__

=head1 NAME

Net::LDAPS - use LDAP over an SSL connection

=head1 SYNOPSIS

 use Net::LDAPS;

 $ldaps = new Net::LDAPS('myhost.example.com',
                         port => '10000',
                         verify => 'require',
                         capath => '/usr/local/cacerts/');

=head1 DESCRIPTION

Communicate using the LDAP protocol to a directory server using a
potentially encrypted (SSL) network connection.

This class is a subclass of Net::LDAP so all the normal Net::LDAP
methods can be used with a Net::LDAPS object; see the documentation
for Net::LDAP to find out how to query a directory server using the
LDAP protocol.

Note that the use of LDAPS is not recommended, because it is not
described by any IETF documents. Instead, you should consider using
LDAPv3 with the TLS extension defined in RFC 2830. This will give you
the same functionality as LDAPS, but using recognized standards.
Unfortunately servers may support LDAPS but not the TLS extension. See
L<Net::LDAP/start_tls>.

=head1 CONSTRUCTOR

=over 4

=item new ( HOST [, OPTIONS ] )

Create a new connection. HOST is the hostname to contact. OPTIONS is a
number of key/value pairs - additional keys to those understood by
Net::LDAP::new are:

=over 4

=item verify

How to verify the server's certificate, either 'none' (the server may
provide a certificate but it will not be checked - this may mean you
are be connected to the wrong server), 'optional' (verify if the
server offers a certificate), or 'require' (the server must provide a
certificate, and it must be valid.) If you set verify to optional or
require, you must also set either cafile or capath. The most secure
option is 'require'.

=item sslversion

This defines the version of the SSL/TLS protocol to use. Defaults to
'sslv2/3', other possible values are 'sslv2', 'sslv3', and 'tlsv1'.

=item ciphers

Specify which subset of cipher suites are permissible for this
connection, using the standard OpenSSL string format. The default
value for ciphers is 'ALL', which permits all ciphers, even those that
don't encrypt!

=item clientcert

=item clientkey

=item keydecrypt

If you want to use the client to offer a certificate to the server for
SSL authentication (which is not the same as for the LDAP Bind
operation) then set clientcert to the user's certificate file, and
clientkey to the user's private key file. These files B<must> be in
PEM format.

If the private key is encrypted (highly recommended!) then set
keydecrypt to a reference to a subroutine that returns the decrypting
key. For example:

 $ldaps = new Net::LDAPS('myhost.example.com',
                         port => '636',
                         verify => 'require',
                         clientcert => 'mycert.pem',
                         clientkey => 'mykey.pem',
                         keydecrypt => sub { 'secret'; },
                         capath => '/usr/local/cacerts/');

=item capath

=item cafile

When verifying the server's certificate, either set capath to the
pathname of the directory containing CA certificates, or set cafile to
the filename containing the certificate of the CA who signed the
server's certificate. These certificates B<must> all be in PEM format.

The directory in 'capath' must contain certificates named using the
hash value of the certificates' subject names. To generate these
names, use OpenSSL like this in Unix:

    ln -s cacert.pem `openssl x509 -hash -noout < cacert.pem`.0

(assuming that the certificate of the CA is in cacert.pem.)

=back

=back

=head1 ADDITIONAL METHODS

=over 4

=item cipher

Returns the cipher mode being used by the connection, in the string
format used by OpenSSL.

=item certificate

Returns an X509_Certificate object containing the server's
certificate. See the IO::Socket::SSL documentation for information
about this class.

For example, to get the subject name (in a peculiar OpenSSL-specific
format, different from RFC 1779 and RFC 2253) from the server's
certificate, do this:

    print "Subject DN: " . $ldaps->certificate->subject_name . "\n";

=back

=head1 SEE ALSO

L<Net::LDAP>,
L<IO::Socket::SSL>

=head1 BUGS

You cannot have more than one LDAPS connection at any one time, due to
restrictions in the underlying Net::SSLeay code.

=head1 AUTHOR

Chris Ridd E<lt>chris.ridd@isode.comE<gt>

=head1 COPYRIGHT

Copyright (c) 2000-2003, Chris Ridd and Graham Barr. All rights reserved. This
library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

