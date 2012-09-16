package LWP::Protocol::ldapi;

use strict ;
use base 'LWP::Protocol::ldap' ;

1;

__END__

=head1 NAME

LWP::Protocol::ldapi - Provide LDAPI support for LWP::UserAgent

=head1 SYNOPSIS

  use LWP::UserAgent;
  use MIME::Base64;

  $ua = LWP::UserAgent->new();
  $res = $ua->get('ldapi:///' .
                  'o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)',
                  Authorization => 'Basic '.encode_Base64('cn=John Doe:secret')):

=head1 DESCRIPTION

The LWP::Protocol::ldapi module provides support for using I<ldapi> schemed
URLs with LWP.  This module is a plug-in to the LWP protocol handling, so
you don't use it directly.

=head1 SEE ALSO

L<LWP::Protocol::ldap>, L<LWP::Protocol::ldaps>

=head1 COPYRIGHT

Copyright (c) 2012 Peter Marschall. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.
