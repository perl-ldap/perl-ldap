# Copyright (c) 1998 Graham Barr <gbarr@pobox.com> and 2001 Chris Ridd
# <chris.ridd@messagingdirect.com>.  All rights reserved.  This program
# is free software; you can redistribute it and/or modify it under the
# same terms as Perl itself.

package Authen::SASL::EXTERNAL;

use vars qw(@ISA $VERSION);
use strict;

$VERSION = "0.01";

@ISA = qw(Authen::SASL);

sub init {
  my $self = shift;
  my $opt = shift;
  $self->SUPER::init($opt);
  $self;
}

sub name { "EXTERNAL" }

sub response {
  "";
}

sub encode {
  $_[0]->user;
}

1;
