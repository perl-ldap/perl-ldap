# Copyright (c) 2008 Peter Marschall <peter@adpm.de>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::PostRead;

use Net::LDAP::Control::PreRead;

our @ISA = qw(Net::LDAP::Control::PreRead);
our $VERSION = '0.03';

1;


__END__

=head1 NAME

Net::LDAP::Control::PostRead - LDAPv3 Post-Read control object

=head1 SYNOPSIS

 use Net::LDAP;
 use Net::LDAP::Control::PostRead;
 use Net::LDAP::Constant qw( LDAP_CONTROL_POSTREAD LDAP_SUCCESS );

 $ldap = Net::LDAP->new( "ldap.mydomain.eg" );

 $postread = Net::LDAP::Control::PostRead->new( attrs => [ qw/givenName/ ] );

 my $mesg = $ldap->modify( "cn=Barbara Jensen, o=University of Michigan, c=US",
                           replace => { givenName => "Babs" },
			   control => $postread );

 if ($mesg->code eq LDAP_SUCCESS) {
   my ($afterwards) = $mesg->control( LDAP_CONTROL_PREREAD );
   my $entry = $afterwards ? $afterwards->entry() : undef;

   if ($entry) {
     print "givenName changed to '" .
           join("', '", $entry->get_value(givenName") .
           "' to 'Babs'\n");
   }
 }


=head1 DESCRIPTION

C<Net::LDAP::Control::PostRead> provides an interface for the creation and
manipulation of objects that represent the C<Post-Read Controls> as described
by RFC 4527.

In modification operations, the C<Post-Read request control> indicates to the
server that a copy of the modified entry after the update is to be returned.
After the successful completion of the operation, the accompanying C<Post-Read
response control> allows one to retrieve the updated value from the server's response.

One use case of this control may be to obtain values of operational attributes,
such as the C<entryUUID> and C<modifyTimestamp> attributes, updated by the server
as part of the update operation.


=head1 CONSTRUCTOR ARGUMENTS

In addition to the constructor arguments described in
L<Net::LDAP::Control> the following are provided.

=over 4

=item attrs => [ ATTR, ... ]

A list of attributes to be returned in the entry returned in the response control.

If absent, all attributes are returned.

Operational attributes may be included in the list by explicitly asking for them
or by using special C<"+"> feature (provided the server supports this feature).

=back


=head1 METHODS

As with L<Net::LDAP::Control> each constructor argument
described above is also available as a method on the object which will
return the current value for the attribute if called without an argument,
and set a new value for the attribute if called with an argument.

In addition to these methods, the control also supports the following method:

=over 4

=item entry ()

Returns the entry from the response control in the response message
to the LDAP request that contained the request control.

The result is either a Net::LDAP::Entry object or undefined.

=back


=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Control>,
http://www.ietf.org/rfc/rfc4527.txt

=head1 AUTHOR

Peter Marschall E<lt>peter@adpm.deE<gt>

Please report any bugs, or post any suggestions, to the perl-ldap mailing list
E<lt>perl-ldap@perl.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2008,2011 Peter Marschall. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut

