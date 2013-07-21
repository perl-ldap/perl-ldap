# Copyright (c) 2008 Chris Ridd <chris.ridd@isode.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::PasswordPolicy;

use Net::LDAP::Control;

our @ISA = qw(Net::LDAP::Control);
our $VERSION = '0.04';

use Net::LDAP::ASN qw(ppControlResponse);
use strict;

sub init {
  my($self) = @_;

  delete $self->{asn};

  unless (exists $self->{value}) {
    $self->{asn} = \my %asn;
    if (defined($self->{time_before_expiration})) {
      $asn{warning}{timeBeforeExpiration} = defined($self->{time_before_expiration});
    }
    elsif (defined($self->{grace_authentications_remaining})) {
      $asn{warning}{graceAuthNsRemaining} = $self->{time_before_expiration};
    }
    if (defined($self->{pp_error})) {
      $asn{error} = $self->{pp_error};
    }
  }

  $self;
}

sub time_before_expiration {
  my $self = shift;
  $self->{asn} ||= $ppControlResponse->decode($self->{value});
  if (@_) {
    delete $self->{value};
    my $time = shift;
    if (defined $time) {
      $self->{asn}{warning} = { timeBeforeExpiration => $time };
    }
    elsif (my $warning = $self->{asn}{warning}) {
      if (exists $warning->{timeBeforeExpiration}) {
        delete $self->{asn}{warning};
      }
    }
    return $time;
  }
  my $warning = $self->{asn}{warning};
  $warning && $warning->{timeBeforeExpiration};
}

sub grace_authentications_remaining {
  my $self = shift;
  $self->{asn} ||= $ppControlResponse->decode($self->{value});
  if (@_) {
    delete $self->{value};
    my $remaining = shift;
    if (defined $remaining) {
      $self->{asn}{warning} = { graceAuthNsRemaining => $remaining };
    }
    elsif (my $warning = $self->{asn}{warning}) {
      if (exists $warning->{graceAuthNsRemaining}) {
        delete $self->{asn}{warning};
      }
    }
    return $remaining;
  }
  my $warning = $self->{asn}{warning};
  $warning && $warning->{graceAuthNsRemaining};
}

sub pp_error {
  my $self = shift;
  $self->{asn} ||= $ppControlResponse->decode($self->{value});
  if (@_) {
    delete $self->{value};
    return $self->{asn}{error} = shift;
  }
  $self->{asn}{error};
}

sub value {
  my $self = shift;
  return $self->{value}  if exists $self->{value};
  my $asn = $self->{asn};
  # Return undef if all optional values are missing
  return undef  unless $asn and (defined $asn->{error} or $asn->{warning});
  $self->{value} = $ppControlResponse->encode($self->{asn});
}

1;

__END__

=head1 NAME

Net::LDAP::Control::PasswordPolicy - LDAPv3 Password Policy control object

=head1 SYNOPSIS

 use Net::LDAP;
 use Net::LDAP::Control::PasswordPolicy;
 use Net::LDAP::Constant qw( LDAP_CONTROL_PASSWORDPOLICY );

 $ldap = Net::LDAP->new( "ldap.example.com" );

 $pp = Net::LDAP::Control::PasswordPolicy->new;

 $mesg = $ldap->bind( "cn=Bob Smith,dc=example,dc=com",
                      password => "secret",
                      control => [ $pp ] );

 # Get password policy response
 my($resp)  = $mesg->control( LDAP_CONTROL_PASSWORDPOLICY );

 if (defined($resp)) {
   my $v = $resp->pp_error;
   print "Password policy error $v\n"  if defined $v;
   $v = $resp->time_before_expiration;
   print "Password expires in $v second(s)\n"  if defined $v;
 }

=head1 DESCRIPTION

C<Net::LDAP::Control::PasswordPolicy> provides an interface for the
creation and manipulation of objects that represent
C<PasswordPolicyRequest>s and C<PasswordPolicyResponse>s as described by
draft-behera-password-policy-09.

This control can be passed to most operations, including the bind.

=head1 CONSTRUCTOR ARGUMENTS

There are no constructor arguments other than those provided by
L<Net::LDAP::Control>.

=head1 METHODS

=over 4

=item time_before_expiration

If defined, this is an integer value holding the time left in seconds
before the account's password will expire.

=item grace_authentications_remaining

If defined, this is an integer value holding the number of
authentication requests allowed before the account is locked.

=item pp_error

If defined, this contains a more detailed error code for the account.
See L<Net::LDAP::Constant> for definitions of each.
Values can include:

=over 4

=item LDAP_PP_PASSWORD_EXPIRED

=item LDAP_PP_ACCOUNT_LOCKED

=item LDAP_PP_CHANGE_AFTER_RESET

=item LDAP_PP_PASSWORD_MOD_NOT_ALLOWED

=item LDAP_PP_MUST_SUPPLY_OLD_PASSWORD

=item LDAP_PP_INSUFFICIENT_PASSWORD_QUALITY

=item LDAP_PP_PASSWORD_TOO_SHORT

=item LDAP_PP_PASSWORD_TOO_YOUNG

=item LDAP_PP_PASSWORD_IN_HISTORY

=back

=back

=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Control>,
L<Net::LDAP::Constant>,
draft-behera-ldap-password-policy-09.txt

=head1 AUTHOR

Chris Ridd E<lt>chris.ridd@isode.comE<gt>

Please report any bugs, or post any suggestions, to the perl-ldap
mailing list E<lt>perl-ldap@perl.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2008 Chris Ridd. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut

