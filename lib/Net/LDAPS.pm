# Copyright (c) 2000 Chris Ridd <chris.ridd@messagingdirect.com> and
# Graham Barr <gbarr@pobox.com>. All rights reserved.  This program is
# free software; you can redistribute it and/or modify it under the
# same terms as Perl itself.

package Net::LDAPS;
@Net::LDAPS::ISA = ( 'Net::LDAP' );
$Net::LDAPS::VERSION = "0.02";

use strict;
use Net::LDAP;
use Net::LDAP::ASN qw(LDAPResponse);
use Convert::ASN1 qw(asn_read);
use IO::Socket::SSL;

sub _options {
    my %r;
    while (@_) {
	my ($k, $v) = splice(@_, 0, 2);
	$r{$k} = $v;
    }
    \%r;
}

# Different OpenSSL verify modes.
my %verify = qw(none 0 optional 1 require 3);

sub new {
  my $self = shift;
  my $type = ref($self) || $self;
  my $host = shift if @_ % 2;
  my $arg  = _options(@_);
  my $verify = 0;
  my ($clientcert,$clientkey);
  
  if (exists $arg->{'verify'}) {
      my $v = lc $arg->{'verify'};
      $verify = 0 + (exists $verify{$v} ? $verify{$v} : $verify);
  }
  if (exists $arg->{'clientcert'}) {
      $clientcert = $arg->{'clientcert'};
      if (exists $arg->{'clientkey'}) {
	  $clientkey = $arg->{'clientkey'};
      } else {
	  die "Setting client public key but not client private key";
      }
  }
  my $obj  = bless {}, $type;

  my $sock = IO::Socket::SSL->new(
				  PeerAddr => $host,
				  PeerPort => $arg->{'port'} || '636',
				  Proto    => 'tcp',
				  Timeout  => defined $arg->{'timeout'}
				  ? $arg->{'timeout'}
				  : 120,
				  SSL_verify_mode => $verify,
				  SSL_cipher_list => defined $arg->{'ciphers'}
				  ? $arg->{'ciphers'}
				  : 'ALL',
				  SSL_use_cert => $clientcert ? 1 : 0,
				  SSL_cert_file => $clientcert,
				  SSL_key_file => $clientcert
				  ? $clientkey : undef,
				  SSL_ca_file => exists $arg->{'cafile'}
				  ? $arg->{'cafile'} : undef,
				  SSL_ca_path => exists $arg->{'capath'}
				  ? $arg->{'capath'} : undef,
				 ) or return;

  $sock->autoflush(1);

  $obj->{'net_ldap_socket'}  = $sock;
  $obj->{'net_ldap_host'}    = $host;
  $obj->{'net_ldap_resp'}    = {};
  $obj->{'net_ldap_debug'}   = $arg->{'debug'} || 0;
  $obj->{'net_ldap_version'} = $arg->{'version'} || $Net::LDAP::LDAP_VERSION;
  $obj->{'net_ldap_async'}   = $arg->{'async'} ? 1 : 0;

  $obj;
}

sub cipher {
    $_[0]->{'net_ldap_socket'}->get_cipher;
}

sub certificate {
    $_[0]->{'net_ldap_socket'}->get_peer_certificate;
}

# Override a Net::LDAP method because IO::Socket::SSL doesn't support the
# socket methods (ie send) that Net::LDAP uses.

sub _sendmesg {
  my $ldap = shift;
  my $mesg = shift;

  my $debug;
  if ($debug = $ldap->debug) {
    require Convert::ASN1::Debug;
    print STDERR "$ldap sending:\n";

    Convert::ASN1::asn_hexdump(*STDERR, $mesg->pdu)
      if $debug & 1;

    Convert::ASN1::asn_dump(*STDERR, $mesg->pdu)
      if $debug & 4;
  }

  syswrite($ldap->socket, $mesg->pdu, length($mesg->pdu))
    or return $mesg->set_error(Net::LDAP::LDAP_LOCAL_ERROR,"$!");

  # for CLDAP, here we need to recode when we were sent
  # so that we can perform timeouts and resends

  my $mid = $mesg->mesg_id;

  unless ($mesg->done) { # may not have a response

    $ldap->{net_ldap_mesg}->{$mid} = $mesg;

    unless ($ldap->async) {
      my $err = $ldap->sync($mid);
      $mesg->set_error($err,$@) if $err;
    }
  }
  $mesg;
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

=head1 CONSTRUCTOR

=over 4

=item new ( HOST [, OPTIONS ] )

Create a new connection. HOST is the hostname to contact. OPTIONS is a
number of key/value pairs - additional keys to those understood by
Net::LDAP::new are:

=over 4

=item verify

How to verify the server's certificate, either 'none' (the server may
provide a cert but don't verify it - this may mean you are be
connected to the wrong server), 'optional' (verify if the server
offers a cert), or 'require' (the server must provide a cert, and it
must be valid.) If you set verify to optional or require, you must
also set either cafile or capath.

=item ciphers

Specify which subset of cipher suites are permissible for this
connection, using the standard OpenSSL string format. The default value
for ciphers is 'ALL', which permits all ciphers.

=item clientcert

=item clientkey

If you want to use the client to offer a certificate to the server for
SSL authentication (which is not the same as for the LDAP Bind
operation) then set clientcert to the user's certificate file, and
clientkey to the user's private key file.

=item capath

=item cafile

When verifying the server's certificate, either set capath to the
pathname of the directory containing CA certificates, or set cafile to
the filename containing the certificate of the CA who signed the
server's certificate.

The directory in 'capath' must contain certificates named using the
hash value of themselves. To generate these names, use OpenSSL thusly:

    ln -s cacert.pem `openssl x509 -hash -nout < cacert.pem`.0

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

L<Net::LDAP|Net::LDAP>,
L<IO::Socket::SSL|IO::Socket::SSL>

=head1 BUGS

Several apparently bogus warnings are emitted when initializing the
two underlying modules used by Net::LDAPS, namely IO::Socket::SSL and
Net::SSLeay. To avoid these, don't initialize via 'use Net::LDAPS' and
instead try initializing Net::LDAPS like this:

    BEGIN {
        # Turn off all warnings etc whilst initializing
        # IO::Socket::SSL and Net::SSLeay.
        local $^W = 0;
        no strict;
        require Net::SSLeay;
        # The /dev/urandom is a device on Linux that returns
        # random data.
        Net::SSLeay::randomize('/dev/urandom');
        require Net::LDAPS;
    }

=head1 AUTHOR

Chris Ridd <chris.ridd@messagingdirect.com>

=head1 COPYRIGHT

Copyright (c) 2000, Chris Ridd and Graham Barr. All rights reserved. This
library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

