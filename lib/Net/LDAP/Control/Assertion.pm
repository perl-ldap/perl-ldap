# Copyright (c) 2011 Peter Marschall <peter@adpm.de>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::Assertion;

use Net::LDAP::Control;

our @ISA = qw(Net::LDAP::Control);
our $VERSION = '0.02';

use Net::LDAP::Filter;
use Net::LDAP::ASN qw(Filter);
use strict;

sub init {
  my($self) = @_;

  delete $self->{asn};

  unless (exists $self->{value}) {
    $self->{asn} = $self->{assertion} || '';
  }

  $self;
}

sub assertion {
  my $self = shift;

  if (@_) {
    delete $self->{value};
    return $self->{asn} = shift;
  }
  elsif (exists $self->{value}) {
    my $f = $Filter->decode($self->{value});
    $self->{asn} ||= Net::LDAP::Filter::as_string($f)
      if (ref $f);
  }

  $self->{asn};
}

sub value {
  my $self = shift;

  unless (exists $self->{value}) {
    my $f = Net::LDAP::Filter->new;
    $self->{value} = $Filter->encode($f)
      if ($f->parse($self->{asn}));
  }

  $self->{value};
}

1;


__END__

=head1 NAME

Net::LDAP::Control::Assertion - LDAPv3 Assertion Control

=head1 SYNOPSIS

 use Net::LDAP;
 use Net::LDAP::Control::Assertion;

 $ldap = Net::LDAP->new( "ldap.mydomain.eg" );

 $assert = Net::LDAP::Control::Assertion->new( assertion => '(sn=Jensen)' );

 my $mesg = $ldap->modify( "cn=Barbara Jensen, o=University of Michigan, c=US",
                           replace => { givenName => "Babs" },
			   control => $assert );


=head1 DESCRIPTION

C<Net::LDAP::Control::Assertion> provides an interface for the creation and
manipulation of objects that represent the C<Assertion Control> as described
by RFC 4528.

The C<Assertion Control> allows the client to specify a condition, an assertion,
that must be TRUE for the operation to be processed normally.
Otherwise, the operation is not performed.
For instance, the control can be used with the Modify operation to perform
atomic "test and set" and "test and clear" operations.

The control is appropriate for both LDAP interrogation and update operations,
including Add, Compare, Delete, Modify, ModifyDN (rename), and Search.


=head1 CONSTRUCTOR ARGUMENTS

In addition to the constructor arguments described in
L<Net::LDAP::Control> the following are provided.

=over 4

=item assertion => FILTER

A filter specifying the assertion that must evaluate to TRUE in order to make the
operation process normally.

=back


=head1 METHODS

As with L<Net::LDAP::Control> each constructor argument
described above is also available as a method on the object which will
return the current value for the attribute if called without an argument,
and set a new value for the attribute if called with an argument.


=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Control>,
http://www.ietf.org/rfc/rfc4528.txt

=head1 AUTHOR

Peter Marschall E<lt>peter@adpm.deE<gt>

Please report any bugs, or post any suggestions, to the perl-ldap mailing list
E<lt>perl-ldap@perl.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2011 Peter Marschall. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut

