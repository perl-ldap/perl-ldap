# Copyright (c) 2003 Derrik Pates <dpates@dsdk12.net> and Graham Barr
# <gbarr@pobox.com>. All rights reserved.  This program is free
# software; you can redistribute it and/or modify it under the same
# terms as Perl itself.

package Net::LDAPI;
@Net::LDAPI::ISA = ( 'Net::LDAP' );
$Net::LDAPI::VERSION = "0.02";

use strict;
use Net::LDAP;

sub new {
  shift->SUPER::new(@_, scheme => 'ldapi');
}

1;

__END__

=head1 NAME

Net::LDAPI - use LDAP over a UNIX domain socket

=head1 SYNOPSIS

 use Net::LDAPI;

 $ldaps = new Net::LDAPI('/var/lib/ldapi');

=head1 DESCRIPTION

Communicate using the LDAP protocol to a directory server using a
UNIX domain socket.

This class is a subclass of Net::LDAP so all the normal Net::LDAP
methods can be used with a Net::LDAPI object; see the documentation
for Net::LDAP to find out how to query a directory server using the
LDAP protocol.

=head1 CONSTRUCTOR

=over 4

=item new ( [SOCKPATH] )

Create a new connection. SOCKPATH can optionally be specified, to specify
the location of the UNIX domain socket to connect to. By default, the
domain socket path is '/var/lib/ldapi'. This is OpenLDAP-specific.

=back

=head1 SEE ALSO

L<Net::LDAP>,
L<IO::Socket::UNIX>

=head1 BUGS

None yet.

=head1 AUTHOR

Derrik Pates E<lt>dpates@dsdk12.netE<gt>

=head1 COPYRIGHT

Original code Copyright (c) 2003, Derrik Pates and Graham Barr. All
rights reserved. This library is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

=cut
