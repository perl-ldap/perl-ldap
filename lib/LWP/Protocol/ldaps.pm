package LWP::Protocol::ldaps;

use strict ;
use base 'LWP::Protocol::ldap' ;

1;

__END__

=head1 NAME

LWP::Protocol::ldaps - Provide LDAPS support for LWP::UserAgent

=head1 SYNOPSIS

  use LWP::UserAgent;

  $ua = LWP::UserAgent->new();
  $res = $ua->get('ldaps://ldap.example.com/' .
                  'o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)',
                  Accept => 'text/ldif'):

=head1 DESCRIPTION

The LWP::Protocol::ldaps module provides support for using I<ldaps> schemed
URLs with LWP.  This module is a plug-in to the LWP protocol handling, so
you don't use it directly.

=head1 SEE ALSO

L<LWP::Protocol::ldap>, L<LWP::Protocol::ldapi>

=head1 COPYRIGHT

Copyright (c) 2012 Peter Marschall. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.
