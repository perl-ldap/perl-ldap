# Copyright (c) 2008 Mathieu Parent <math.parent@gmail.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Intermediate::SyncInfo;

use vars qw(@ISA $VERSION);
use Net::LDAP::Intermediate;

@ISA = qw(Net::LDAP::Intermediate);
$VERSION = "0.01";

use Net::LDAP::ASN qw(syncInfoValue);
use strict;

# use some kind of hack here:
# - calling the control without args means: response,
# - giving an argument: means: request
sub init {
  my($self) = @_;

  delete $self->{asn};

  unless (exists $self->{responseValue}) {
    $self->{asn} = {
      newcookie => $self->{newcookie} || '',
    };
  }

  $self;
}

sub newcookie {
  my $self = shift;
  $self->{asn} ||= $syncInfoValue->decode($self->{responseValue});
  if (@_) {
    delete $self->{responseValue};
    return $self->{asn}{newcookie} = shift || 0;
  }
  $self->{asn}{cookie};
}

sub responseValue {
  my $self = shift;

  exists $self->{responseValue}
    ? $self->{responseValue}
    : $self->{responseValue} = $syncInfoValue->encode($self->{asn});
}

1;


__END__

=head1 NAME

Net::LDAP::Intermediate::SyncInfo - LDAPv3 Sync Info Message object

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

   if($controls[0]->isa('Net::LDAP::Control::SyncState')) {
     print "Received Sync State Control\n";
     print $entry->dn()."\n";
     print 'State: '.$controls[0]->state."\n".', entryUUID: '.$controls[0]->entryUUID.', cookie: '.$controls[0]->cookie;
   } elsif($controls[0]->isa('Net::LDAP::Control::SyncDone')) {
     print "Received Sync Done Control\n";
     print 'Cookie: '.$controls[0]->cookie.', refreshDeletes: '.$controls[0]->refreshDeletes;
   }
 }

=head1 DESCRIPTION

C<Net::LDAP::Intermediate::SyncInfo> provides an interface for the creation and
manipulation of objects that represent the C<Sync Info Message> as described
by RFC 4533.

=head1 CONSTRUCTOR ARGUMENTS

In addition to the constructor arguments described in
L<Net::LDAP::Intermediate> the following are provided.

=over 4

=item TODO

=back

=head1 METHODS

As with L<Net::LDAP::Intermediate> each constructor argument
described above is also avaliable as a method on the object which will
return the current value for the attribute if called without an argument,
and set a new value for the attribute if called with an argument.

=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Intermediate>,
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

