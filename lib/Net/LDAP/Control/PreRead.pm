# Copyright (c) 2008 Peter Marschall <peter@adpm.de>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::PreRead;

use Net::LDAP::Control;

our @ISA = qw(Net::LDAP::Control);
our $VERSION = '0.04';

use Net::LDAP::ASN qw(AttributeSelection SearchResultEntry);
use Net::LDAP::Entry;
use strict;

# use some kind of hack here:
# - calling the control without args means: response,
# - giving an argument: means: request
sub init {
  my($self) = @_;

  delete $self->{asn};

  unless (exists $self->{value}) {
    $self->{asn} = $self->{attrs} || [];
  }

  $self;
}

sub attrs {
  my $self = shift;

  $self->{asn} ||= $AttributeSelection->decode($self->{value});
  if (@_) {
    delete $self->{value};
    return $self->{asn} = [ @_ ];
  }

  $self->{asn};
}

sub entry {
  my $self = shift;
  my %opt = @_;
  my $entry;

  if ($self->{value}) {
    my $data = $SearchResultEntry->decode($self->{value});

    $entry = Net::LDAP::Entry->new;
    $entry->decode($data, raw => $opt{raw} || $self->{raw});
  }

  $entry;
}

sub value {
  my $self = shift;

  exists $self->{value}
    ? $self->{value}
    : $self->{value} = $AttributeSelection->encode($self->{asn});
}

1;


__END__

=head1 NAME

Net::LDAP::Control::PreRead - LDAPv3 Pre-Read control object

=head1 SYNOPSIS

 use Net::LDAP;
 use Net::LDAP::Control::PreRead;
 use Net::LDAP::Constant qw( LDAP_CONTROL_PREREAD LDAP_SUCCESS );

 $ldap = Net::LDAP->new( "ldap.mydomain.eg" );

 $preread = Net::LDAP::Control::PreRead->new( attrs => [ qw/givenName/ ] );

 my $mesg = $ldap->modify( "cn=Barbara Jensen, o=University of Michigan, c=US",
                           replace => { givenName => "Babs" },
			   control => $preread );

 if ($mesg->code eq LDAP_SUCCESS) {
   my ($previous) = $mesg->control( LDAP_CONTROL_PREREAD );
   my $entry = $previous ? $previous->entry() : undef;

   if ($entry) {
     print "givenName changed from '" .
           join("', '", $entry->get_value(givenName") .
           "' to 'Babs'\n");
   }
 }


=head1 DESCRIPTION

C<Net::LDAP::Control::PreRead> provides an interface for the creation and
manipulation of objects that represent the C<Pre-Read Controls> as described
by RFC 4527.

In modification operations, the C<Pre-Read request control> indicates to the
server that a copy of the original entry before the update is to be returned.
After the successful completion of the operation, the accompanying C<Pre-Read
response control> allows one to retrieve the original value from the server's response.

One use case of this control may be to obtain replaced or deleted
values of modified attributes or a copy of the entry being deleted.


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

