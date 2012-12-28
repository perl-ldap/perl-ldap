# Copyright (c) 2008 Mathieu Parent <math.parent@gmail.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::SyncRequest;

use Net::LDAP::Control;

our @ISA = qw(Net::LDAP::Control);
our $VERSION = '0.03';

use Net::LDAP::ASN qw(syncRequestValue);
use strict;

sub init {
  my($self) = @_;

  delete $self->{asn};

  unless (exists $self->{value}) {
    $self->{asn} = {
      mode => $self->{mode} || '1',
      cookie => $self->{cookie} || undef,
      reloadHint   => $self->{reloadHint} || '0',
    };
  }

  $self;
}

sub mode {
  my $self = shift;
  $self->{asn} ||= $syncRequestValue->decode($self->{value});
  if (@_) {
    delete $self->{value};
    return $self->{asn}{mode} = shift || 0;
  }
  $self->{asn}{mode};
}

sub cookie {
  my $self = shift;
  $self->{asn} ||= $syncRequestValue->decode($self->{value});
  if (@_) {
    delete $self->{value};
    return $self->{asn}{cookie} = shift || 0;
  }
  $self->{asn}{cookie};
}

sub reloadHint {
  my $self = shift;
  $self->{asn} ||= $syncRequestValue->decode($self->{value});
  if (@_) {
    delete $self->{value};
    return $self->{asn}{reloadHint} = shift || 0;
  }
  $self->{asn}{reloadHint};
}

sub value {
  my $self = shift;
  return $self->{value}  if exists $self->{value};
  $self->{value} = $syncRequestValue->encode($self->{asn});
}

1;


__END__

=head1 NAME

Net::LDAP::Control::SyncRequest - LDAPv3 Sync Request control object

=head1 SYNOPSIS

 use Net::LDAP;
 use Net::LDAP::Control::SyncRequest;
 use Net::LDAP::Constant qw(
  LDAP_SYNC_REFRESH_ONLY
  LDAP_SYNC_REFRESH_AND_PERSIST
  LDAP_SUCCESS );

 $ldap = Net::LDAP->new( "ldap.mydomain.eg" );

 $req = Net::LDAP::Control::SyncRequest->new( mode => LDAP_SYNC_REFRESH_ONLY );
 my $mesg = $ldap->search(base=> 'dc=mydomain,dc='eg',
                          scope    => 'sub',
                          control  => [ $req ],
                          callback => \&searchCallback, # call for each entry
                          filter   => "(objectClass=*)",
                          attrs    => [ '*']);
 sub searchCallback {
   my $message = shift;
   my $entry = shift;
   my @controls = $message->control;

   if ($controls[0]->isa('Net::LDAP::Control::SyncState')) {
     print "Received Sync State Control\n";
     print $entry->dn()."\n";
     print 'State: '.$controls[0]->state."\n".', entryUUID: '.$controls[0]->entryUUID.', cookie: '.$controls[0]->cookie;
   } elsif ($controls[0]->isa('Net::LDAP::Control::SyncDone')) {
     print "Received Sync Done Control\n";
     print 'Cookie: '.$controls[0]->cookie.', refreshDeletes: '.$controls[0]->refreshDeletes;
   }
 }

=head1 DESCRIPTION

C<Net::LDAP::Control::SyncRequest> provides an interface for the creation and
manipulation of objects that represent the C<Sync Request Control> as described
by RFC 4533.

=head1 CONSTRUCTOR ARGUMENTS

In addition to the constructor arguments described in
L<Net::LDAP::Control> the following are provided.

=over 4

=item mode

=item cookie

=item reloadHint

=back

=head1 METHODS

As with L<Net::LDAP::Control> each constructor argument
described above is also available as a method on the object which will
return the current value for the attribute if called without an argument,
and set a new value for the attribute if called with an argument.

=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Control>,
L<Net::LDAP::Control::SyncState>,
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

