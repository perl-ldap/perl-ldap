package Net::LDAP::Extra::AD;

use strict;

use Encode;
use Exporter qw(import);
use Net::LDAP::RootDSE;

our $VERSION = '0.04';
our @EXPORT = qw(is_AD is_ADAM reset_ADpassword change_ADpassword);


sub is_AD {
  my $self = shift;
  my $rootdse = $self->root_dse(attrs => [ qw/supportedCapabilities/ ])
    or return undef;

  return (grep { $_ eq '1.2.840.113556.1.4.800' } $rootdse->get_value('supportedCapabilities'))
         ? 1 : 0;
}

sub is_ADAM {
  my $self = shift;
  my $rootdse = $self->root_dse(attrs => [ qw/supportedCapabilities/ ])
    or return undef;

  return (grep { $_ eq '1.2.840.113556.1.4.1851' } $rootdse->get_value('supportedCapabilities'))
         ? 1 : 0;
}

sub reset_ADpassword {
  my ($self, $dn, $newpw, %opt) = @_;
  my %attrs;

  $attrs{unicodePwd} = encode('utf16le', '"'.decode('utf8', $newpw).'"');
  $attrs{pwdLastSet} = 0  if ($opt{force_change});

  $self->modify($dn, replace => \%attrs);
}

sub change_ADpassword {
  my ($self, $dn, $oldpw, $newpw) = @_;

  $oldpw = encode('utf16le', '"'.decode('utf8', $oldpw).'"');
  $newpw = encode('utf16le', '"'.decode('utf8', $newpw).'"');

  $self->modify($dn, changes => [ delete => [ unicodePwd => $oldpw ],
                                  add    => [ unicodePwd => $newpw ] ]);
}

1;

__END__

=head1 NAME

Net::LDAP::Extra::AD -- AD convenience methods

=head1 SYNOPSIS

  use Net::LDAP::Extra qw(AD);

  $ldap = Net::LDAP->new( ... );

  ...

  if ($ldap->is_AD || $ldap->is_ADAM) {
    $ldap->change_ADpassword($dn, $old_password, $new_password);
  }

=head1 DESCRIPTION

Net::LDAP::Extra::AD tries to spare users the necessity to
reinvent the wheel again and again in order to correctly encode
password strings so that they can be used in AD password change
operations.

To do so, it provides the following methods:

=head1 METHODS

=over 4

=item is_AD ( )

Tell if the LDAP server queried is an Active Directory Domain Controller.

As the check is done by querying the root DSE of the directory,
it works without being bound to the directory.

=item is_ADAM ( )

Tell if the LDAP server queried is running AD LDS
(Active Directory Lightweight Directory Services),
previously known as ADAM (Active Directoy Application Mode).

As the check is done by querying the root DSE of the directory,
it works without being bound to the directory.

=item change_ADpassword ( DN, OLD_PASSWORD, NEW_PASSWORD )

Change the password of the account given by I<DN> from
its old value I<OLD_PASSWORD> to the new value I<NEW_PASSWORD>.

This method requires encrypted connections.

=item reset_ADpassword ( DN, NEW_PASSWORD, OPTIONS )

Reset the password of the account given by I<DN> to the value
given in I<NEW_PASSWORD>.
OPTIONS is a list of key/value pairs. The following keys are recognized:

=over 4

=item force_change

If TRUE, the affected user is required to change the
password at next login.

=back

For this method to work, the caller needs to be bound to AD with
sufficient permissions, and the connection needs to be encrypted.

=back

=head1 AUTHOR

Peter Marschall E<lt>peter@adpm.de<gt>

=head1 COPYRIGHT

Copyright (c) 2012 Peter Marschall. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

