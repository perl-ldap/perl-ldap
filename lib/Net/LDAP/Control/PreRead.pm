# Copyright (c) 2008 Peter Marschall <peter@adpm.de>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::PreRead;

use vars qw(@ISA $VERSION);
use Net::LDAP::Control;

@ISA = qw(Net::LDAP::Control);
$VERSION = "0.01";

use Net::LDAP::ASN qw(AttributeDescriptionList prSearchResultEntry);
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

  $self->{asn} ||= $AttributeDescriptionList->decode($self->{value});
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
    my $data = $prSearchResultEntry->decode($self->{value});

    $entry = Net::LDAP::Entry->new;
    $entry->decode($data, raw => $opt{raw} || $self->{raw});
  }

  $entry;
}

sub value {
  my $self = shift;

  exists $self->{value}
    ? $self->{value}
    : $self->{value} = $AttributeDescriptionList->encode($self->{asn});
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

 $preread = Net::LDAP::Control::Paged->new( attrs => [ qw/givenName/ ] );

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
manipulation of objects that represent the C<Pre-Read Control> as described
by RFC 4527.

=head1 CONSTRUCTOR ARGUMENTS

In addition to the constructor arguments described in
L<Net::LDAP::Control> the following are provided.

=over 4

=item attrs => [ ATTR, ... ]

A list of attributes to be returned in the entry returned in the response control.

If absent, all attributes are returned.

Operational attributes may be included in the list by explicitely asking for them
or by using special C<"+"> feature (provided the server supports this feature).

=back

=head1 METHODS

As with L<Net::LDAP::Control> each constructor argument
described above is also avaliable as a method on the object which will
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

Copyright (c) 2008 Peter Marschall. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut

