# Copyright (c) 1997-2004 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Entry;

use strict;
use Net::LDAP::ASN qw(LDAPEntry);
use Net::LDAP::Constant qw(LDAP_LOCAL_ERROR LDAP_OTHER);

use constant CHECK_UTF8 => $] > 5.007;

BEGIN {
  require Encode
    if (CHECK_UTF8);
}

our $VERSION = '0.25';

sub new {
  my $self = shift;
  my $type = ref($self) || $self;

  my $entry = bless { changetype => 'add', changes => [] }, $type;

  @_ and $entry->dn( shift );
  @_ and $entry->add( @_ );

  return $entry;
}

sub clone {
  my $self  = shift;
  my $clone = $self->new();

  $clone->dn($self->dn());
  foreach ($self->attributes()) {
    $clone->add($_ => [$self->get_value($_)]);
  }

  $clone->{changetype} = $self->{changetype};
  my @changes = @{$self->{changes}};
  while (my($action, $cmd) = splice(@changes, 0, 2)) {
    my @new_cmd;
    my @cmd = @$cmd;
    while (my($type, $val) = splice(@cmd, 0, 2)) {
      push @new_cmd, $type, [ @$val ];
    }
    push @{$clone->{changes}}, $action, \@new_cmd;
  }

  $clone;
}

# Build attrs cache, created when needed

sub _build_attrs {
  +{ map { (lc($_->{type}), $_->{vals}) }  @{$_[0]->{asn}{attributes}} };
}

# If we are passed an ASN structure we really do nothing

sub decode {
  my $self = shift;
  my $result = ref($_[0]) ? shift : $LDAPEntry->decode(shift)
    or return;
  my %arg = @_;

  %{$self} = ( asn => $result, changetype => 'modify', changes => []);

  if (CHECK_UTF8 && $arg{raw}) {
    $result->{objectName} = Encode::decode_utf8($result->{objectName})
      if ('dn' !~ /$arg{raw}/);

    foreach my $elem (@{$self->{asn}{attributes}}) {
      map { $_ = Encode::decode_utf8($_) } @{$elem->{vals}}
        if ($elem->{type} !~ /$arg{raw}/);
    }
  }

  $self;
}



sub encode {
  $LDAPEntry->encode( shift->{asn} );
}


sub dn {
  my $self = shift;
  @_ ? ($self->{asn}{objectName} = shift) : $self->{asn}{objectName};
}

sub get_attribute {
  require Carp;
  Carp::carp('->get_attribute deprecated, use ->get_value')  if $^W;
  shift->get_value(@_, asref => !wantarray);
}

sub get {
  require Carp;
  Carp::carp('->get deprecated, use ->get_value')  if $^W;
  shift->get_value(@_, asref => !wantarray);
}


sub exists {
  my $self = shift;
  my $type = lc(shift);
  my $attrs = $self->{attrs} ||= _build_attrs($self);

  exists $attrs->{$type};
}

sub get_value {
  my $self = shift;
  my $type = lc(shift);
  my %opt  = @_;

  if ($opt{alloptions}) {
    my %ret = map {
                $_->{type} =~ /^\Q$type\E((?:;.*)?)$/i ? (lc($1), $_->{vals}) : ()
              } @{$self->{asn}{attributes}};
    return %ret ? \%ret : undef;
  }

  my $attrs = $self->{attrs} ||= _build_attrs($self);
  my $attr  = $attrs->{$type} or return;

  return $opt{asref}
	  ? $attr
	  : wantarray
	    ? @{$attr}
	    : $attr->[0];
}


sub changetype {

  my $self = shift;
  return $self->{changetype}  unless @_;
  $self->{changes} = [];
  $self->{changetype} = shift;
  return $self;
}



sub add {
  my $self  = shift;
  my $cmd   = $self->{changetype} eq 'modify' ? [] : undef;
  my $attrs = $self->{attrs} ||= _build_attrs($self);

  while (my($type, $val) = splice(@_, 0, 2)) {
    my $lc_type = lc $type;

    push @{$self->{asn}{attributes}}, { type => $type, vals => ($attrs->{$lc_type}=[])}
      unless exists $attrs->{$lc_type};

    push @{$attrs->{$lc_type}}, ref($val) ? @$val : $val;

    push @$cmd, $type, [ ref($val) ? @$val : $val ]
      if $cmd;

  }

  push(@{$self->{changes}}, 'add', $cmd)  if $cmd;

  return $self;
}


sub replace {
  my $self  = shift;
  my $cmd   = $self->{changetype} eq 'modify' ? [] : undef;
  my $attrs = $self->{attrs} ||= _build_attrs($self);

  while (my($type, $val) = splice(@_, 0, 2)) {
    my $lc_type = lc $type;

    if (defined($val) and (!ref($val) or @$val)) {

      push @{$self->{asn}{attributes}}, { type => $type, vals => ($attrs->{$lc_type}=[])}
	unless exists $attrs->{$lc_type};

      @{$attrs->{$lc_type}} = ref($val) ? @$val : ($val);

      push @$cmd, $type, [ ref($val) ? @$val : $val ]
	if $cmd;

    }
    else {
      delete $attrs->{$lc_type};

      @{$self->{asn}{attributes}}
	= grep { $lc_type ne lc($_->{type}) } @{$self->{asn}{attributes}};

      push @$cmd, $type, []
	if $cmd;

    }
  }

  push(@{$self->{changes}}, 'replace', $cmd)  if $cmd;

  return $self;
}


sub delete {
  my $self = shift;

  unless (@_) {
    $self->changetype('delete');
    return;
  }

  my $cmd = $self->{changetype} eq 'modify' ? [] : undef;
  my $attrs = $self->{attrs} ||= _build_attrs($self);

  while (my($type, $val) = splice(@_, 0, 2)) {
    my $lc_type = lc $type;

    if (defined($val) and (!ref($val) or @$val)) {
      my %values;
      @values{(ref($val) ? @$val : $val)} = ();

      unless (@{$attrs->{$lc_type}}
              = grep { !exists $values{$_} } @{$attrs->{$lc_type}})
      {
	delete $attrs->{$lc_type};
	@{$self->{asn}{attributes}}
	  = grep { $lc_type ne lc($_->{type}) } @{$self->{asn}{attributes}};
      }

      push @$cmd, $type, [ ref($val) ? @$val : $val ]
	if $cmd;
    }
    else {
      delete $attrs->{$lc_type};

      @{$self->{asn}{attributes}}
	= grep { $lc_type ne lc($_->{type}) } @{$self->{asn}{attributes}};

      push @$cmd, $type, []  if $cmd;
    }
  }

  push(@{$self->{changes}}, 'delete', $cmd)  if $cmd;

  return $self;
}


sub update {
  my $self = shift;
  my $target = shift;	# a Net::LDAP or a Net::LDAP::LDIF object
  my %opt = @_;
  my $mesg;
  my $user_cb = delete $opt{callback};
  my $cb = sub { $self->changetype('modify')  unless $_[0]->code;
                 $user_cb->(@_)  if $user_cb };

  if (ref($target) && UNIVERSAL::isa($target, 'Net::LDAP')) {
    if ($self->{changetype} eq 'add') {
      $mesg = $target->add($self, callback => $cb, %opt);
    }
    elsif ($self->{changetype} eq 'delete') {
      $mesg = $target->delete($self, callback => $cb, %opt);
    }
    elsif ($self->{changetype} =~ /modr?dn/o) {
      my @args = (newrdn => $self->get_value('newrdn') || undef,
                  deleteoldrdn => $self->get_value('deleteoldrdn') || undef);
      my $newsuperior = $self->get_value('newsuperior');
      push(@args, newsuperior => $newsuperior)  if $newsuperior;
      $mesg = $target->moddn($self, @args, callback => $cb, %opt);
    }
    elsif (@{$self->{changes}}) {
      $mesg = $target->modify($self, changes => $self->{changes}, callback => $cb, %opt);
    }
    else {
      require Net::LDAP::Message;
      $mesg = Net::LDAP::Message->new( $target );
      $mesg->set_error(LDAP_LOCAL_ERROR, 'No attributes to update');
    }
  }
  elsif (ref($target) && UNIVERSAL::isa($target, 'Net::LDAP::LDIF')) {
    require Net::LDAP::Message;
    $target->write_entry($self, %opt);
    $mesg = Net::LDAP::Message::Dummy->new();
    $mesg->set_error(LDAP_OTHER, $target->error())
      if ($target->error());
  }

  return $mesg;
}

sub ldif {
  my $self = shift;
  my %opt = @_;

  require Net::LDAP::LDIF;
  open(my $fh, '>', \my $buffer);
  my $change = exists $opt{change} ? $opt{change} : $self->changes ? 1 : 0;
  my $ldif = Net::LDAP::LDIF->new($fh, 'w', change => $change);
  $ldif->write_entry($self);
  return $buffer;
}

# Just for debugging

sub dump {
  my $self = shift;
  no strict 'refs'; # select may return a GLOB name
  my $fh = @_ ? shift : select;

  my $asn = $self->{asn};
  print $fh '-' x 72, "\n";
  print $fh 'dn:', $asn->{objectName}, "\n\n"  if $asn->{objectName};

  my $l = 0;

  for (keys %{ $self->{attrs} ||= _build_attrs($self) }) {
    $l = length  if length > $l;
  }

  my $spc = "\n  " . ' ' x $l;

  foreach my $attr (@{$asn->{attributes}}) {
    my $val = $attr->{vals};
    printf $fh "%${l}s: ", $attr->{type};
    my $i = 0;
    foreach my $v (@$val) {
      print $fh $spc  if $i++;
      print $fh $v;
    }
    print $fh "\n";
  }
}

sub attributes {
  my $self = shift;
  my %opt  = @_;

  if ($opt{nooptions}) {
    my %done;
    return map {
      $_->{type} =~ /^([^;]+)/;
      $done{lc $1}++ ? () : ($1);
    } @{$self->{asn}{attributes}};
  }
  else {
    return map { $_->{type} } @{$self->{asn}{attributes}};
  }
}

sub asn {
  shift->{asn}
}

sub changes {
  my $ref = shift->{changes};
  $ref ? @$ref : ();
}

1;
