# Copyright (c) 2008 Mathieu Parent <math.parent@gmail.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::SyncDone;

use Net::LDAP::Control;

our @ISA = qw(Net::LDAP::Control);
our $VERSION = '0.03';

use Net::LDAP::ASN qw(syncDoneValue);
use strict;

sub init {
  my($self) = @_;

  if (exists $self->{value}) {
    $self->{asn} = $syncDoneValue->decode(delete $self->{value});
  } else {
    $self->{asn} = {
      cookie => defined($self->{cookie}) ? $self->{cookie} : '',
      refreshDeletes   => $self->{refreshDeletes} || '0',
    };
  }

  $self;
}

sub cookie {
  my $self = shift;
  $self->{asn} ||= $syncDoneValue->decode($self->{value});
  if (@_) {
    delete $self->{value};
    return $self->{asn}{cookie} = defined($_[0]) ? $_[0] : '';
  }
  $self->{asn}{cookie};
}

sub refreshDeletes {
  my $self = shift;
  $self->{asn} ||= $syncDoneValue->decode($self->{value});
  if (@_) {
    delete $self->{value};
    return $self->{asn}{refreshDeletes} = shift || 0;
  }
  $self->{asn}{refreshDeletes};
}

sub value {
  my $self = shift;

  exists $self->{value}
    ? $self->{value}
    : $self->{value} = $syncDoneValue->encode($self->{asn});
}

1;


__END__

=head1 NAME

Net::LDAP::Control::SyncDone - LDAPv3 Sync Done control object

=head1 SYNOPSIS

See L<Net::LDAP::Control::SyncRequest>

=head1 DESCRIPTION

C<Net::LDAP::Control::SyncDone> provides an interface for the creation and
manipulation of objects that represent the C<Sync Request Control> as described
by RFC 4533.

=head1 CONSTRUCTOR ARGUMENTS

In addition to the constructor arguments described in
L<Net::LDAP::Control> the following are provided.

=over 4

=item cookie

=item refreshDeletes

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
L<Net::LDAP::Control::SyncState>,
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

