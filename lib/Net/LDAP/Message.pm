# Copyright (c) 1997-2004 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Message;

use Net::LDAP::Constant qw(LDAP_SUCCESS LDAP_COMPARE_TRUE LDAP_COMPARE_FALSE);
use Net::LDAP::ASN qw(LDAPRequest);
use strict;

our $VERSION = '1.12';

my $MsgID = 0;

# We do this here so when we add threading we can lock it
sub NewMesgID {
  $MsgID = 1  if ++$MsgID > 65535;
  $MsgID;
}

sub new {
  my $self   = shift;
  my $type   = ref($self) || $self;
  my $parent = shift->inner;
  my $arg    = shift;

  $self = bless {
    parent   => $parent,
    mesgid   => NewMesgID(),
    callback => $arg->{callback} || undef,
    raw      => $arg->{raw} || undef,
  }, $type;

  $self;
}

sub code {
  my $self = shift;

  $self->sync  unless exists $self->{resultCode};

  exists $self->{resultCode}
    ? $self->{resultCode}
    : undef
}

sub done {
  my $self = shift;

  exists $self->{resultCode};
}

sub dn {
  my $self = shift;

  $self->sync  unless exists $self->{resultCode};

  exists $self->{matchedDN}
    ? $self->{matchedDN}
    : undef
}

sub referrals {
  my $self = shift;

  $self->sync  unless exists $self->{resultCode};

  exists $self->{referral}
    ? @{$self->{referral}}
    : ();
}

sub server_error {
  my $self = shift;

  $self->sync  unless exists $self->{resultCode};

  exists $self->{errorMessage}
    ? $self->{errorMessage}
    : undef
}

sub error {
  my $self = shift;
  my $return;

  unless ($return = $self->server_error) {
    require Net::LDAP::Util and
    $return = Net::LDAP::Util::ldap_error_desc( $self->code );
  }

  $return;
}

sub set_error {
  my $self = shift;
  ($self->{resultCode}, $self->{errorMessage}) = ($_[0]+0, "$_[1]");
  $self->{callback}->($self)
    if (defined $self->{callback});
  $self;
}

sub error_name {
  require Net::LDAP::Util;
  Net::LDAP::Util::ldap_error_name(shift->code);
}

sub error_text {
  require Net::LDAP::Util;
  Net::LDAP::Util::ldap_error_text(shift->code);
}

sub error_desc {
  require Net::LDAP::Util;
  Net::LDAP::Util::ldap_error_desc(shift->code);
}

sub sync {
  my $self = shift;
  my $ldap = $self->{parent};
  my $err;

  until(exists $self->{resultCode}) {
    $err = $ldap->sync($self->mesg_id)  or next;
    $self->set_error($err, 'Protocol Error')
      unless exists $self->{resultCode};
    return $err;
  }

  LDAP_SUCCESS;
}


sub decode { # $self, $pdu, $control
  my $self = shift;
  my $result = shift;
  my $data = (values %{$result->{protocolOp}})[0];

  @{$self}{keys %$data} = values %$data;

  @{$self}{qw(controls ctrl_hash)} = ($result->{controls}, undef);

  # free up memory as we have a result so we will not need to re-send it
  delete $self->{pdu};

  if ($data = delete $result->{protocolOp}{intermediateResponse}) {

    my $intermediate = Net::LDAP::Intermediate->from_asn($data);

    if (defined $self->{callback}) {
      $self->{callback}->($self, $intermediate);
    } else {
      push(@{$self->{intermediate} ||= []}, $intermediate);
    }

    return $self;
  } else {
    # tell our LDAP client to forget us as this message has now completed
    # all communications with the server
    $self->parent->_forgetmesg($self);
  }

  $self->{callback}->($self)
    if (defined $self->{callback});

  $self;
}


sub abandon {
  my $self = shift;

  return  if exists $self->{resultCode}; # already complete

  my $ldap = $self->{parent};

  $ldap->abandon($self->{mesgid});
}

sub saslref {
  my $self = shift;

  $self->sync  unless exists $self->{resultCode};

  exists $self->{sasl}
    ? $self->{sasl}
    : undef
}


sub encode {
  my $self = shift;

  $self->{pdu} = $LDAPRequest->encode(@_, messageID => $self->{mesgid})
    or return;
  1;
}

sub control {
  my $self = shift;

  if ($self->{controls}) {
    require Net::LDAP::Control;
    my $hash = $self->{ctrl_hash} = {};
    foreach my $asn (@{delete $self->{controls}}) {
      my $ctrl = Net::LDAP::Control->from_asn($asn);
      $ctrl->{raw} = $self->{parent}->{raw}
        if ($self->{parent});
      push @{$hash->{$ctrl->type} ||= []}, $ctrl;
    }
  }

  my $ctrl_hash = $self->{ctrl_hash}
    or return;

  my @oid = @_ ? @_ : keys %$ctrl_hash;
  my @control = map {@$_} grep $_, @{$ctrl_hash}{@oid}
    or return;

  # return a list, so in a scalar context we do not just get array length
  return @control[0 .. $#control];
}

sub pdu      {  shift->{pdu}      }
sub callback {  shift->{callback} }
sub parent   {  shift->{parent}->outer   }
sub mesg_id  {  shift->{mesgid}   }
sub is_error {  shift->code       }

##
##
##


@Net::LDAP::Add::ISA     = qw(Net::LDAP::Message);
@Net::LDAP::Delete::ISA  = qw(Net::LDAP::Message);
@Net::LDAP::Modify::ISA  = qw(Net::LDAP::Message);
@Net::LDAP::ModDN::ISA   = qw(Net::LDAP::Message);
@Net::LDAP::Compare::ISA = qw(Net::LDAP::Message);
@Net::LDAP::Unbind::ISA  = qw(Net::LDAP::Message::Dummy);
@Net::LDAP::Abandon::ISA = qw(Net::LDAP::Message::Dummy);

sub Net::LDAP::Compare::is_error {
  my $mesg = shift;
  my $code = $mesg->code;
  $code != LDAP_COMPARE_FALSE and $code != LDAP_COMPARE_TRUE
}

{
  package Net::LDAP::Message::Dummy;
  our @ISA = qw(Net::LDAP::Message);
  use Net::LDAP::Constant qw(LDAP_SUCCESS);

  sub new {
    my $self   = shift;
    my $type   = ref($self) || $self;

    $self = bless {
      mesgid   => Net::LDAP::Message::NewMesgID(),
    }, $type;

    $self;
  }

  sub sync    { shift }
  sub decode  { shift }
  sub abandon { shift }
  sub code { shift->{resultCode} || LDAP_SUCCESS }
  sub error { shift->{errorMessage} || '' }
  sub dn { '' }
  sub done { 1 }
}

1;
