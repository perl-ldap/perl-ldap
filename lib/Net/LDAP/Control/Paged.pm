# $Id: Paged.pm,v 1.2 2000/05/22 20:59:50 gbarr Exp $
# Copyright (c) 2000 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::Paged;

use vars qw(@ISA $VERSION);

@ISA = qw(Net::LDAP::Control);
$VERSION = "0.01";

use Net::LDAP::ASN qw(realSearchControlValue);
use strict;

sub init {
  my($self) = @_;

  delete $self->{asn};

  unless (exists $self->{value}) {
    $self->{asn} = {
      size   => $self->{size} || 0,
      cookie => defined($self->{cookie}) ? $self->{cookie} : ''
    };
  }

  $self;
}

sub cookie {
  my $self = shift;
  $self->{asn} ||= $realSearchControlValue->decode($self->{value});
  if (@_) {
    delete $self->{value};
    return $self->{asn}{cookie} = defined($_[0]) ? $_[0] : '';
  }
  $self->{asn}{cookie};
}

sub size {
  my $self = shift;
  $self->{asn} ||= $realSearchControlValue->decode($self->{value});
  if (@_) {
    delete $self->{value};
    return $self->{asn}{size} = shift || 0;
  }
  $self->{asn}{size};
}

sub value {
  my $self = shift;

  exists $self->{value}
    ? $self->{value}
    : $self->{value} = $realSearchControlValue->encode($self->{asn});
}

1;

