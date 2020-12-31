# Copyright (c) 2020 Peter Marschall <peter@adpm.de>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::Subentries;

use Net::LDAP::Control;

our @ISA = qw(Net::LDAP::Control);
our $VERSION = '0.01';

use Net::LDAP::ASN qw(SubentriesValue);
use strict;

sub init {
  my($self) = @_;

  delete $self->{asn};

  unless (exists $self->{value}) {
    $self->{asn} = {
      visibility   => $self->{visibility} || 0,
    };
  }

  $self;
}

sub visibility {
  my $self = shift;

  $self->{asn} ||= $SubentriesValue->decode($self->{value});
  if (@_) {
    delete $self->{value};
    return $self->{asn}{visibility} = shift || 0;
  }

  $self->{asn}{visibility};
}

sub value {
  my $self = shift;

  exists $self->{value}
    ? $self->{value}
    : $self->{value} = $SubentriesValue->encode($self->{asn});
}

1;


__END__

=head1 NAME

Net::LDAP::Control::Subentries - LDAPv3 Subentries control object

=head1 SYNOPSIS

 use Net::LDAP;
 use Net::LDAP::Control::Subentries;

 $ldap = Net::LDAP->new( "ldap.mydomain.eg" );

 $subentries = Net::LDAP::Control::Subentries->new( visibility => 1 );

 $msg = $ldap->search( base => 'dc=sub,dc=mydomain,dc=eg",
                       filter => '(objectclass=*)',
                       attrs => [ qw/1.1/ ],
                       control => [ $subentries ] );

 die "error: ",$msg->code(),": ",$msg->error()  if ($msg->code());


=head1 DESCRIPTION

C<Net::LDAP::Control::Subentries> provides an interface for the creation
and manipulation of objects that represent the C<Subentries> control as
described by RFC 3672.

This control, for which no corresponding response control exists, is
appropriate for L<LDAP search|Net::LDAP/search> operations only.

In absence of this control, subentries are visible only to
L<LDAP search|Net::LDAP/search> requests with C<< scope => 'base' >>,
but not to searches with any other C<scope> value.

=head1 CONSTRUCTOR ARGUMENTS

In addition to the constructor arguments described in
L<Net::LDAP::Control> the following are provided:

=over 4

=item visibility

A Boolean value indicating the visibility of subentries or regular entries.

The value C<TRUE> indicates that subentries are visible and normal entries
are not; the value C<FALSE> indicates that normal entries are visible
and subentries are not.

=back

=head1 METHODS

As with L<Net::LDAP::Control> each constructor argument
described above is also available as a method on the object which will
return the current value for the attribute if called without an argument,
and set a new value for the attribute if called with an argument.

=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Control>,

=head1 AUTHOR

Peter Marschall E<lt>peter@adpm.deE<gt>.

Please report any bugs, or post any suggestions, to the perl-ldap
mailing list E<lt>perl-ldap@perl.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2020 Peter Marschall. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut
