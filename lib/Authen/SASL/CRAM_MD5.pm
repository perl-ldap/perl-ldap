# Copyright (c) 1998 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Authen::SASL::CRAM_MD5;

use vars qw(@ISA $VERSION);
use Digest::HMAC_MD5 qw(hmac_md5_hex);
use strict;

$VERSION = "0.32";

@ISA = qw(Authen::SASL);

sub init {
  my $self = shift;
  my $opt = shift;
  $self->SUPER::init($opt);
  $self->{'response'} = defined $opt->{'password'}
                ? $opt->{'password'}
                : defined $opt->{'response'}
                    ? $opt->{'response'}
                    : undef;
  $self;
}

sub name { "CRAM-MD5" }

sub response {
  my $self   = shift;
  my $string = shift;
  defined $self->{'response'} ? $self->{'response'} : "";
}

sub encode {
  $_[0]->user . " " . hmac_md5_hex($_[1],$_[2]);
}

1;
