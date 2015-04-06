# Copyright (c) 2001-2004 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::ProxyAuth;

use Net::LDAP::Control;

our @ISA = qw(Net::LDAP::Control);
our $VERSION = '1.09';

use Net::LDAP::Constant qw(LDAP_CONTROL_PROXYAUTHORIZATION);
use Net::LDAP::ASN qw(proxyAuthValue);
use strict;

sub LDAP_CONTROL_PROXYAUTHORIZATION_OLD { '2.16.840.1.113730.3.4.12'; }

sub init {
  my($self) = @_;

  delete $self->{asn};

  if (defined($self->{proxyDN})) {
    $self->{type} = LDAP_CONTROL_PROXYAUTHORIZATION_OLD;

    $self->{asn} = { proxyDN => $self->{proxyDN} || '' }
      unless (exists $self->{value});
  }
  else {
    $self->{value} = $self->{authzID} || ''
      unless (exists $self->{value});
  }

  # criticality must be set !
  $self->{critical} = 1;

  $self;
}


sub proxyDN {
  my $self = shift;

  if (@_) {
    delete $self->{value};

    $self->{type} = LDAP_CONTROL_PROXYAUTHORIZATION_OLD;
    return $self->{asn}{proxyDN} = shift || '';
  }
  elsif ($self->{type} eq LDAP_CONTROL_PROXYAUTHORIZATION) {
    $self->{error} = 'Illegal query method: use authzID()';
    return undef;
  }
  else {
    $self->{asn} ||= $proxyAuthValue->decode($self->{value});
  }

  $self->{asn}{proxyDN};
}


sub authzID {
  my $self = shift;

  if (@_) {
    delete $self->{value};

    $self->{type} = LDAP_CONTROL_PROXYAUTHORIZATION;
    return $self->{authzID} = shift || '';
  }
  elsif ($self->{type} eq LDAP_CONTROL_PROXYAUTHORIZATION_OLD) {
    $self->{error} = 'Illegal query method: use proxyDN()';
    return undef;
  }
  else {
    $self->{authzID} ||= $self->{value};
  }

  $self->{authzID};
}


sub value {
  my $self = shift;

  unless (exists $self->{value}) {
    $self->{value} = ($self->{type} eq LDAP_CONTROL_PROXYAUTHORIZATION_OLD)
		     ? $proxyAuthValue->encode($self->{asn})
                     : $self->{authzID} || '';
  }

  return $self->{value};
}

# make sure criticality remains TRUE
sub critical {
  1;
}

1;

__END__

=head1 NAME

Net::LDAP::Control::ProxyAuth - LDAPv3 Proxy Authorization control object

=head1 SYNOPSIS

 use Net::LDAP;
 use Net::LDAP::Control::ProxyAuth;

 $ldap = Net::LDAP->new( "ldap.mydomain.eg" );

 $auth = Net::LDAP::Control::ProxyAuth->new( authzID => 'dn:cn=me,ou=people,o=myorg.com' );

 @args = ( base     => "cn=subnets,cn=sites,cn=configuration,$BASE_DN",
	   scope    => "subtree",
	   filter   => "(objectClass=subnet)",
	   callback => \&process_entry, # Call this sub for each entry
	   control  => [ $auth ],
 );

 while (1) {
   # Perform search
   my $mesg = $ldap->search( @args );

   # Only continue on LDAP_SUCCESS
   $mesg->code and last;

 }


=head1 DESCRIPTION

C<Net::LDAP::Control::ProxyAuth> provides an interface for the creation and manipulation
of objects that represent the C<Proxy Authorization Control> as described by RFC 4370.

It allows a client to be bound to an LDAP server with its own identity, but to perform
operations on behalf of another user, the C<authzID>.

With the exception of any extension that causes a change in authentication,
authorization or data confidentiality, a single C<Proxy Authorization Control>
may be included in any search, compare, modify, add, delete, or moddn or
extended operation.

As required by the RFC, the criticality of this control is automatically set to
TRUE in order to protect clients from submitting requests with other identities
that they intend to.


=head1 CONSTRUCTOR ARGUMENTS

In addition to the constructor arguments described in
L<Net::LDAP::Control> the following are provided.

=over 4

=item authzID

The authzID that is required. This is the identity we are requesting operations to use.

=item proxyDN

In early versions of the drafts to RFC 4370, draft-weltman-ldapv3-proxy-XX.txt,
the value in the control and thus the constructor argument was a DN and was called C<proxyDN>.
It served the same purpose as C<authzID> in recent versions of C<proxyAuthorization> control.

=back

B<Please note:>
Unfortunately the OID and the encoding or the C<Proxy Authorization Control>
changed significantly between early versions of draft-weltman-ldapv3-proxy-XX.txt
and the final RFC.
Net::LDAP::Control::ProxyAuth tries to cope with that situation and changes
the OID and encoding used depending on the constructor argument.

With C<proxyDN> as constructor argument the old OID and encoding are used,
while with C<authzID> as constructor argument the new OID and encoding are used.
Using this logic servers supporting either OID can be handled correctly.

=head1 METHODS

As with L<Net::LDAP::Control> each constructor argument
described above is also available as a method on the object which will
return the current value for the attribute if called without an argument,
and set a new value for the attribute if called with an argument.

=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Control>,

=head1 AUTHORS

Olivier Dubois, Swift sa/nv based on Net::LDAP::Control::Page from
Graham Barr E<lt>gbarr@pobox.comE<gt>.
Peter Marschall E<lt>peter@adpm.deE<gt> added authzID extensions
based on ideas from Graham Barr E<lt>gbarr@pobox.comE<gt>.

Please report any bugs, or post any suggestions, to the perl-ldap
mailing list E<lt>perl-ldap@perl.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2001-2004 Graham Barr. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut

