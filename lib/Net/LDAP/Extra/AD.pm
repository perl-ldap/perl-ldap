package Net::LDAP::Extra::AD;

use strict;
use vars qw($VERSION @EXPORT);
use Encode;
use Exporter qw(import);

$VERSION = "0.01";
@EXPORT = qw(reset_ADpassword change_ADpassword);


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

  $self->modify($dn, changes => [ delete => { unicodePwd => $oldpw },
                                  add    => { unicodePwd => $newpw } ]);
}

1;

__END__

=head1 NAME

Net::LDAP::Extra:AD -- AD convenience methods

=head1 SYNOPSIS

  use Net::LDAP::Extra qw(AD);

  $ldap = Net::LDAP->new( ... );

  ...

  $ldap->change_ADpassword($dn, $old_password, $new_password);

=head1 DESCRIPTION

Net::LDAP::Extra::AD tries to spare users the necessity to
reinvent the wheel again and again in order to correctly encode
password strings so that they can be used in AD password change
operations.

To do so, it provides the following methods:

=head1 METHODS

=over 4

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

