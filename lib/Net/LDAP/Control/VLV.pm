# $Id: VLV.pm,v 1.2 2000/05/22 20:59:50 gbarr Exp $
# Copyright (c) 2000 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::VLV;

use vars qw(@ISA $VERSION);

@ISA = qw(Net::LDAP::Control);
$VERSION = "0.01";

use Net::LDAP::ASN qw(VirtualListViewRequest);
use strict;

sub init {
  my($self) = @_;

  # VLVREQUEST should always have a critical of true
  $self->{'critical'} = 1 unless exists $self->{'critical'};

  if (exists $self->{value}) {
    $self->value($self->{value});
  }
  else {
    my $asn = $self->{asn} = {};

    $asn->{beforeCount} = $self->{before} || 0;
    $asn->{afterCount}  = $self->{after} || 0;
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

sub before {
  my $self = shift;
  if (@_) {
    delete $self->{value};
    return $self->{asn}{beforeCount} = shift;
  }
  $self->{asn}{beforeCount};
}

sub after  {
  my $self = shift;
  if (@_) {
    delete $self->{value};
    return $self->{asn}{afterCount} = shift;
  }
  $self->{asn}{afterCount};
}

sub content {
  my $self = shift;
  if (@_) {
    delete $self->{value};
    if (exists $self->{asn}{assertionValue}) {
      delete $self->{asn}{assertionValue};
      $self->{asn}{byoffset} = { offset => 0 };
    }
    return $self->{asn}{byoffset}{contentCount} = shift;
  }
  exists $self->{asn}{byoffset} and $self->{asn}{byoffset}{contentCount};
}

sub assert {
  my $self = shift;
  if (@_) {
    delete $self->{value};
    delete $self->{asn}{byoffset};
    return $self->{asn}{assertionValue} = shift;
  }
  exists $self->{asn}{assertionValue} and $self->{asn}{assertionValue};
}

sub context {
  my $self = shift;
  if (@_) {
    delete $self->{value};
    return $self->{asn}{contextID} = shift;
  }
  $self->{asn}{contextID};
}

# Update self with values from a response

sub response {
  my $self = shift;
  my $resp = shift;
  
  my $asn = $self->{asn};

  $asn->{contextID} = $resp->context;
  $asn->{byoffset} = {
    offset => $resp->target,
    contentCount => $resp->content
  };
  delete $asn->{assertionValue};

  1;  
}

sub offset {
  my $self = shift;
  if (@_) {
    delete $self->{value};
    if (exists $self->{asn}{assertionValue}) {
      delete $self->{asn}{assertionValue};
      $self->{asn}{byoffset} = { contentCount => 0 };
    }
    return $self->{asn}{byoffset}{offset} = shift;
  }
  exists $self->{asn}{byoffset} and $self->{asn}{byoffset}{offset};
}

sub value {
  my $self = shift;

  if (@_) {
    unless ($self->{asn} = $VirtualListViewRequest->decode($_[0])) {
      delete $self->{value};
      return undef;
    }
    $self->{value} = shift;
  }

  exists $self->{value}
    ? $self->{value}
    : $self->{value} = $VirtualListViewRequest->encode($self->{asn});
}


1;

__END__


##
## These are not finished
##

sub up {
  my $self = shift;
  my $n = shift or return;
  my $asn = $self->{asn};

  return unless exists $asn->{byoffset};

  if (($asn->{byoffset}{offset} -= $n) < 1) {
    $asn->{byoffset}{offset} = 1;
  }
  if (($asn->{byoffset}{offset} - $asn->{beforeCount}) < 1) {
  }

}

sub down {
  my $self = shift;
  my $n = shift or return;
  my $asn = $self->{asn};

  return unless exists $asn->{byoffset};
}

sub page_up {
  my $self = shift;
  my $asn = $self->{asn};
  $self->up( $asn->{beforeCount} + $asn->{afterCount} + 1);
}

sub page_down {
  my $self = shift;
  my $asn = $self->{asn};
  $self->down( $asn->{beforeCount} + $asn->{afterCount} + 1);
}

1;

