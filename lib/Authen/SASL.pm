# Copyright (c) 1998 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Authen::SASL;

use strict;
use vars qw($VERSION);

$VERSION = "0.11";

sub new {
  my $pkg = shift;
  my $type = shift;
  my %opt = @_;
  $pkg .= "::" . $type;
  $pkg =~ s/-/_/g;
  eval "require $pkg" or die;
  my $self = bless {}, $pkg;

  $self->init(\%opt);
}

sub init {
  %{$_[0]} = (%{$_[0]},%{$_[1]});
  $_[0];
}

sub name {
  my $name = ref($_[0]) || $_[0];
  $name =~ s/.*:://;
  $name =~ s/_/-/g;
  uc($name);
}

sub user {
  my $self = shift;
  my $user = $self->{'user'};
  $self->{'user'} = "$_[0]" if @_;
  $user;
}

sub challenge {
  my $self = shift;
  my $string = shift;
  my $resp = $self->response($string);
  $self->encode($string,$resp);
}

sub initial {
  my $self = shift;
  my $initial = $self->{'initial'};
  $self->{'initial'} = shift if @_;
  $initial;
}

1;
