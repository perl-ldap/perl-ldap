# $Id: Control.pm,v 1.3 2000/05/22 20:59:50 gbarr Exp $
# Copyright (c) 1999-2000 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control;

use Net::LDAP::Constant qw(/^LDAP_CONTROL/);
use vars qw($VERSION);

$VERSION = "0.03";

my %Pkg2Type = (

  Net::LDAP::Control::Sort 		=> LDAP_CONTROL_SORTREQUEST,
  Net::LDAP::Control::SortResult 	=> LDAP_CONTROL_SORTRESULT,

  Net::LDAP::Control::VLV		=> LDAP_CONTROL_VLVREQUEST,
  Net::LDAP::Control::VLVResponse	=> LDAP_CONTROL_VLVRESPONSE,     

  Net::LDAP::Control::Paged		=> LDAP_CONTROL_PAGED,

  #LDAP_CONTROL_MANAGEDSAIT
  #LDAP_CONTROL_PERSISTENTSEARCH
  #LDAP_CONTROL_ENTRYCHANGE
  #
  #LDAP_CONTROL_PWEXPIRED
  #LDAP_CONTROL_PWEXPIRING
  #
  #LDAP_CONTROL_REFERRALS
);

my %Type2Pkg = reverse %Pkg2Type;

sub register {
  my($class,$oid) = @_;
  $Type2Pkg{$oid} = $class;
  $Pkg2Type{$class} = $oid;
}

sub new {
  my $self = shift;
  my $pkg  = ref($self) || $self;
  my $oid  = (@_ & 1) ? shift : undef;
  my %args = @_;

  $args{'type'} ||= $oid || $Pkg2Type{$pkg} || '';

  unless ($args{type} =~ /^\d+(?:\.\d+)+$/) {
    $args{error} = 'Invalid OID';
    return bless \%args;
  }

  if ($pkg eq __PACKAGE__ && exists $Type2Pkg{$args{type}}) {
    $pkg = $Type2Pkg{$args{type}};
    eval "require $pkg";
  }

  delete $args{error};

  bless(\%args, $pkg)->init;
}


sub from_asn {
  my $self = shift;
  my $asn = shift;
  my $class = ref($self) || $self;

  $class = $Resgistry{$asn->{type}}
    if ($class eq __PACKAGE__ && exists $Resgistry{$asn->{type}});

  delete $asn->{error};
 
  bless($asn, $class)->init;
}

sub to_asn {
  my $self = shift;
  $self->value; # Ensure value is there
  $self->{critical} = 0 unless exists $self->{critical};
  $self;
}

sub type     { shift->{type} }
sub critical { shift->{critical} || 0 }
sub value    { shift->{value} || undef }
sub valid { ! exists shift->{error} }
sub error { shift->{error} }
sub init  { shift }

1;

__END__


=head1 NAME

Net::LDAP::Control - LDAPv3 control object base class

=head1 SYNOPSIS

 use Net::LDAP::Control;

 $ctrl = Net::LDAP::Control->new(
   type     => "1.2.3.4",
   value    => "help",
   critical => 0
 );

 $mesg = $ldap->search( @args, control => [ $ctrl ]);

=head1 DESCRIPTION

C<Net::LDAP::Control> is a base-class for LDAPv3 control objects.

=head1 CONSTRUCTORS

=over 4

=item new ARGS

=over 4

=item type

=item value

=item critical

=back

=item from_asn HASHREF

=back

=head1 METHODS

Net::LDAP::Control provides the following methods in the base class.

=over 4

=item init

init will be called as the last step in both contructors. What it does will depend
on the sub-class. It must always return the object.

=item error

Returns true if there has been an error.

=item valid

Returns true if the object is valid and can be encoded.

=item type [ OID ]

=item value [ VALUE ]

=item critical [ CRITICAL ]

=item to_asn

Returns the asn structure for encoding. This method will be called by L<Net::LDAP|Net::LDAP>
when the control is used. The base class implementaion of this method will call the C<value>
method without arguments to allow a sub-class to encode it's value. Sub-classes should not need
to override this method.

=back

=head1 SEE ALSO

L<Net::LDAP|Net::LDAP>

=head1 AUTHOR

Graham Barr <gbarr@pobox.com>

Please report any bugs, or post any suggestions, to the perl-ldap mailing list
<perl-ldap-dev@lists.sourceforge.net>

=head1 COPYRIGHT

Copyright (c) 1999-2000 Graham Barr. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=for html <hr>

I<$Id: Control.pm,v 1.3 2000/05/22 20:59:50 gbarr Exp $>

=cut
