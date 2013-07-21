# Copyright (c) 2008 Mathieu Parent <math.parent@gmail.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Intermediate;

use strict;

use Net::LDAP::Constant qw(
  LDAP_SYNC_INFO
);

our $VERSION = '0.04';

my %Class2ResponseName = (

  'Net::LDAP::Intermediate::SyncInfo'		=> LDAP_SYNC_INFO,
);

my %ResponseName2Class = reverse %Class2ResponseName;

sub register {
  my($class, $responseName) = @_;

  require Carp and Carp::croak("$responseName is already registered to $ResponseName2Class{$responseName}")
    if exists $ResponseName2Class{$responseName} and $ResponseName2Class{$responseName} ne $class;

  require Carp and Carp::croak("$class is already registered to $Class2ResponseName{$class}")
    if exists $Class2ResponseName{$class} and $Class2ResponseName{$class} ne $responseName;

  $ResponseName2Class{$responseName} = $class;
  $Class2ResponseName{$class} = $responseName;
}

sub new {
  my $self = shift;
  my $class  = ref($self) || $self;
  my $responseName  = (@_ & 1) ? shift : undef;
  my %args = @_;

  $args{responseName} ||= $responseName || $Class2ResponseName{$class} || '';

  unless ($args{responseName} =~ /^\d+(?:\.\d+)+$/) {
    $args{error} = 'Invalid responseName';
    return bless \%args;
  }

  if ($class eq __PACKAGE__ and exists $ResponseName2Class{$args{responseName}}) {
    $class = $ResponseName2Class{$args{responseName}};
    eval "require $class"  or die $@;
  }

  delete $args{error};

  bless(\%args, $class)->init;
}


sub from_asn {
  my $self = shift;
  my $asn = shift;
  my $class = ref($self) || $self;

  if ($class eq __PACKAGE__ and exists $ResponseName2Class{$asn->{responseName}}) {
    $class = $ResponseName2Class{$asn->{responseName}};
    eval "require $class"  or die $@;
  }

  delete $asn->{error};

  bless($asn, $class)->init;
}

sub to_asn {
  my $self = shift;
  $self->responseValue; # Ensure value is there
  $self;
}

sub responseName  { shift->{responseName} }

sub responseValue    {
  my $self = shift;
  $self->{responseValue} = shift  if @_;
  $self->{responseValue} || undef
}

sub valid { ! exists shift->{error} }
sub error { shift->{error} }
sub init  { shift }

1;

__END__


=head1 NAME

Net::LDAP::Intermediate - LDAPv3 intermediate response object base class

=head1 SYNOPSIS

 use Net::LDAP::Intermediate;

=head1 DESCRIPTION

C<Net::LDAP::Intermediate> is a base-class for LDAPv3 intermediate response objects.

=cut

##
## Need more blurb in here about intermediate responses
##

=head1 CONSTRUCTORS

=over 4

=item new ( ARGS )

ARGS is a list of name/value pairs, valid arguments are:

=over 4

=item responseName

A dotted-decimal representation of an OBJECT IDENTIFIER which
uniquely identifies the intermediate response. This prevents conflicts between
intermediate response names.

=item responseValue

Optional information associated with the intermediate response. It's format is specific
to the particular intermediate response.

=back

=item from_asn ( ASN )

ASN is a HASH reference, normally extracted from a PDU. It will contain
a C<responseName> element and optionally C<responseValue> element. On
return ASN will be blessed into a package. If C<responseName> is a registered
OID, then ASN will be blessed into the registered package, if not then ASN
will be blessed into Net::LDAP::Intermediate.

This constructor is used internally by Net::LDAP and assumes that HASH
passed contains a valid intermediate response. It should be used with B<caution>.

=back

=head1 METHODS

In addition to the methods listed below, each of the named parameters
to C<new> is also available as a method. C<responseName> will return the OID of
the intermediate response object. C<responseValue> is set/get methods and will
return the current value for each attribute if called without arguments,
but may also be called with arguments to set new values.

=over 4

=item error ()

If there has been an error returns a description of the error, otherwise it will
return C<undef>

=item init ()

C<init> will be called as the last step in both constructors. What it does will depend
on the sub-class. It must always return the object.

=item register ( OID )

C<register> is provided for sub-class implementors. It should be called as a class method
on a sub-class of Net::LDAP::Intermediate with the OID that the class will handle. Net::LDAP::Intermediate
will remember this class and OID pair and use it in the following
situations.

=over 4

=item *

C<new> is called as a class method on the Net::LDAP::Intermediate package and OID is passed
as the responseName. The returned object will be blessed into the package that registered
the OID.

=item *

C<new> is called as a class method on a registered package and the C<responseName> is not
specified. The C<responseName> will be set to the OID registered by that package.

=item *

C<from_asn> is called to construct an object from ASN. The returned object will be
blessed into the package which was registered to handle the OID in the ASN.

=back

=item ( to_asn )

Returns a structure suitable for passing to Convert::ASN1 for
encoding. This method will be called by L<Net::LDAP> when the
intermediate response is used.

The base class implementation of this method will call the C<responseValue> method
without arguments to allow a sub-class to encode it's value. Sub-classes
should not need to override this method.

=item valid ()

Returns true if the object is valid and can be encoded. The default implementation
for this method is to return TRUE if there is no error, but sub-classes may override that.

=back

=head1 SEE ALSO

L<Net::LDAP>
L<Net::LDAP::Extension>
L<Net::LDAP::Search>
L<Net::LDAP::Intermediate::SyncInfo>

=head1 AUTHOR

Mathieu Parent E<lt>math.parent@gmail.comE<gt>

Please report any bugs, or post any suggestions, to the perl-ldap mailing list
E<lt>perl-ldap@perl.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2008 Mathieu Parent. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut
