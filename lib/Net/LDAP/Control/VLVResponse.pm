# Copyright (c) 2000 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::VLVResponse;

use vars qw(@ISA $VERSION);

@ISA = qw(Net::LDAP::Control);
$VERSION = "0.01";

use Net::LDAP::ASN qw(VirtualListViewResponse);
use strict;

sub init {
  my($self) = @_;

  if (exists $self->{value}) {
    $self->value($self->{value});
  }
  else {
    my $asn = $self->{asn} = {};

    $asn->{contentCount} = $self->{content} || 0;
    $asn->{afterCount}  = $self->{position} || 0;
    if (exists $self->{assert}) {
      $asn->{assertionValue} = $self->{assert};
    }
    else {
      $asn->{byoffset} = {
 	offset => $self->{offset} || 0,
	contentCount => $self->{content} || 0
      };
    }
  }

  $self;
}


sub target {
  my $self = shift;
  if (@_) {
    delete $self->{value};
    return $self->{asn}{targetPosition} = shift;
  }
  $self->{asn}{targetPosition};
}

sub content {
  my $self = shift;
  if (@_) {
    delete $self->{value};
    return $self->{asn}{contentCount} = shift;
  }
  $self->{asn}{contentCount};
}

sub result {
  my $self = shift;
  if (@_) {
    delete $self->{value};
    return $self->{asn}{virtualListViewResult} = shift;
  }
  $self->{asn}{virtualListViewResult};
}

sub context {
  my $self = shift;
  if (@_) {
    delete $self->{value};
    return $self->{asn}{context} = shift;
  }
  $self->{asn}{context};
}

sub value {
  my $self = shift;

  if (@_) {
    unless ($self->{asn} = $VirtualListViewResponse->decode($_[0])) {
      delete $self->{value};
      return undef;
    }
    $self->{value} = shift;
  }

  exists $self->{value}
    ? $self->{value}
    : $self->{value} = $VirtualListViewResponse->encode($self->{asn});
}

1;

