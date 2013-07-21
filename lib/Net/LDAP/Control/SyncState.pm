# Copyright (c) 2008 Mathieu Parent <math.parent@gmail.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::SyncState;

use Net::LDAP::Control;

our @ISA = qw(Net::LDAP::Control);
our $VERSION = '0.04';

use Net::LDAP::ASN qw(syncStateValue);
use strict;

sub init {
  my($self) = @_;

  if (exists $self->{value}) {
    $self->{asn} = $syncStateValue->decode(delete $self->{value});
  } else {
    $self->{asn} = {
      state => $self->{state} || '',
      entryUUID => $self->{entryUUID} || '',
      cookie => defined($self->{cookie}) ? $self->{cookie} : '',
    };
  }

  $self;
}

sub state {
  my $self = shift;
  $self->{asn} ||= $syncStateValue->decode($self->{value});
  if (@_) {
    delete $self->{value};
    return $self->{asn}{state} = shift || 0;
  }
  $self->{asn}{state};
}

sub entryUUID {
  my $self = shift;
  $self->{asn} ||= $syncStateValue->decode($self->{value});
  if (@_) {
    delete $self->{value};
    return $self->{asn}{entryUUID} = shift || 0;
  }
  $self->{asn}{entryUUID};
}

sub cookie {
  my $self = shift;
  $self->{asn} ||= $syncStateValue->decode($self->{value});
  if (@_) {
    delete $self->{value};
    return $self->{asn}{cookie} = shift || 0;
  }
  $self->{asn}{cookie};
}

sub value {
  my $self = shift;

  exists $self->{value}
    ? $self->{value}
    : $self->{value} = $syncStateValue->encode($self->{asn});
}

1;


__END__

=head1 NAME

Net::LDAP::Control::SyncState - LDAPv3 Sync State control object

=head1 SYNOPSIS

See L<Net::LDAP::Control::SyncRequest>

=head1 DESCRIPTION

C<Net::LDAP::Control::SyncState> provides an interface for the creation and
manipulation of objects that represent the C<Sync State Control> as described
by RFC 4533.

=head1 CONSTRUCTOR ARGUMENTS

In addition to the constructor arguments described in
L<Net::LDAP::Control> the following are provided.

=over 4

=item state

=item entryUUID

=item cookie

=back

=head1 METHODS

As with L<Net::LDAP::Control> each constructor argument
described above is also available as a method on the object which will
return the current value for the attribute if called without an argument,
and set a new value for the attribute if called with an argument.

=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Control>,
L<Net::LDAP::Control::SyncRequest>,
L<Net::LDAP::Control::SyncDone>,
http://www.ietf.org/rfc/rfc4533.txt

=head1 AUTHOR

Mathieu Parent E<lt>math.parent@gmail.comE<gt>

Please report any bugs, or post any suggestions, to the perl-ldap mailing list
E<lt>perl-ldap@perl.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2008 Mathieu Parent. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut

