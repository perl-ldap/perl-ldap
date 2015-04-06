# Copyright (c) 1998-2004 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Extension;

our @ISA = qw(Net::LDAP::Message);
our $VERSION = '1.04';

#fetch the response name
sub response_name {
  my $self = shift;

  $self->sync  unless exists $self->{resultCode};

  exists $self->{responseName}
    ? $self->{responseName}
    : undef;
}

# fetch the response value
sub response {
  my $self = shift;

  $self->sync  unless exists $self->{resultCode};

  exists $self->{responseValue}
    ? $self->{responseValue}
    : undef;
}

1;
