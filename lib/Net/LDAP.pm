# Copyright (c) 1997-2000 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP;

use strict;
use IO::Socket;
use IO::Select;
use vars qw($VERSION $LDAP_VERSION);
use Convert::ASN1 qw(asn_read);
use Net::LDAP::Message;
use Net::LDAP::ASN qw(LDAPResponse);
use Net::LDAP::Constant qw(LDAP_SUCCESS
			   LDAP_OPERATIONS_ERROR
			   LDAP_DECODING_ERROR
			   LDAP_PROTOCOL_ERROR
			   LDAP_ENCODING_ERROR
			   LDAP_FILTER_ERROR
			   LDAP_LOCAL_ERROR
			   LDAP_PARAM_ERROR
			   LDAP_INAPPROPRIATE_AUTH
			);

$VERSION = 0.21;

$LDAP_VERSION = 2;      # default LDAP protocol version

sub import {
    shift;
    unshift @_, 'Net::LDAP::Constant';
    require Net::LDAP::Constant;
    goto &{Net::LDAP::Constant->can('import')};
}

sub _options {
  my %ret = @_;
  my $once = 0;
  for my $v (grep { /^-/ } keys %ret) {
    require Carp;
    $once++ or Carp::carp("depricated use of leading - for options");
    $ret{substr($v,1)} = $ret{$v};
  }

  $ret{control} = [ map { (ref($_) =~ /[^A-Z]/) ? $_->to_asn : $_ } 
		      ref($ret{control}) eq 'ARRAY'
			? @{$ret{control}}
			: $ret{control}
                  ]
    if exists $ret{control};

  \%ret;
}

sub _dn_options {
  unshift @_, 'dn' if @_ & 1;
  &_options;
}

sub _err_msg {
  my $mesg = shift;
  my $errstr = $mesg->dn || '';
  $errstr .= ": " if $errstr;
  $errstr . $mesg->error;
}

my %onerror = (
  'die'   => sub {
		require Carp;
		Carp::croak(_err_msg(@_))
	     },
  'warn'  => sub { require Carp; Carp::carp(_err_msg(@_)); $_[0] },
  'undef' => sub { require Carp; Carp::carp(_err_msg(@_)) if $^W; undef },
);

sub _error {
  my ($ldap, $mesg) = splice(@_,0,2);

  $mesg->set_error(@_);
  $ldap->{net_ldap_onerror} && !$ldap->{net_ldap_async}
    ? scalar &{$ldap->{net_ldap_onerror}}($mesg)
    : $mesg;
}

sub new {
  my $self = shift;
  my $type = ref($self) || $self;
  my $host = shift if @_ % 2;
  my $arg  = &_options;
  my $obj  = bless {}, $type;

  my $sock = IO::Socket::INET->new(
               PeerAddr => $host,
               PeerPort => $arg->{port} || '389',
               Proto    => 'tcp',
               Timeout  => defined $arg->{timeout}
                             ? $arg->{timeout}
                             : 120
             ) or return;

  $sock->autoflush(1);

  $obj->{net_ldap_socket}  = $sock;
  $obj->{net_ldap_host}    = $host;
  $obj->{net_ldap_resp}    = {};
  $obj->{net_ldap_version} = $arg->{version} || $LDAP_VERSION;
  $obj->{net_ldap_async}   = $arg->{async} ? 1 : 0;

  if (defined(my $onerr = $arg->{onerror})) {
    $onerr = $onerror{$onerr} if exists $onerror{$onerr};
    $obj->{net_ldap_onerror} = $onerr;
  }

  $obj->debug($arg->{debug} || 0 );

  $obj;
}

sub message {
  my $ldap = shift;
  shift->new($ldap, @_);
}

sub async {
  my $ldap = shift;

  @_
    ? ($ldap->{'net_ldap_async'},$ldap->{'net_ldap_async'} = shift)[0]
    : $ldap->{'net_ldap_async'};
}

sub debug {
  my $ldap = shift;

  require Convert::ASN1::Debug if $_[0];

  @_
    ? ($ldap->{net_ldap_debug},$ldap->{net_ldap_debug} = shift)[0]
    : $ldap->{net_ldap_debug};
}

sub socket {
  $_[0]->{net_ldap_socket};
}


sub unbind {
  my $ldap = shift;
  my $arg  = &_options;

  my $mesg = $ldap->message('Net::LDAP::Unbind' => $arg);

  $mesg->encode(
    unbindRequest => 1,
    controls      => $arg->{control}
  ) or return _error($ldap, $mesg,LDAP_ENCODING_ERROR,"$@");

  $ldap->_sendmesg($mesg);
}


sub ldapbind {
  require Carp;
  Carp::carp("->ldapbind deprecated, use ->bind") if $^W;
  goto &bind;
}


my %ptype = qw(
  password        simple
  krb41password   krbv41
  krb42password   krbv42
  kerberos41      krbv41
  kerberos42      krbv42
  sasl            sasl
  noauth          anon
  anonymous       anon
);

sub bind {
  my $ldap = shift;
  my $acnt = @_;
  my $arg  = &_dn_options;

  require Net::LDAP::Bind;
  my $mesg = $ldap->message('Net::LDAP::Bind' => $arg);

  $ldap->version($arg->{version})
    if exists $arg->{version};

  my $dn = $arg->{dn} || '';

  my %stash = (
    name    => ref($dn) ? $dn->dn : $dn,
    version => $ldap->version,
  );

  my($auth_type,$passwd) = $acnt ? () : (simple => '');

  keys %ptype; # Reset iterator
  while(my($param,$type) = each %ptype) {
    if (exists $arg->{$param}) {
      ($auth_type,$passwd) = $type eq 'anon' ? (simple => '') : ($type,$arg->{$param});
      return _error($ldap, $mesg, LDAP_INAPPROPRIATE_AUTH, "No password, did you mean noauth or anonymous ?")
        if $type eq 'simple' and $passwd eq '';
      last;
    }
  }

  return _error($ldap, $mesg, LDAP_INAPPROPRIATE_AUTH, "No AUTH supplied")
    unless $auth_type;

  if ($auth_type eq 'sasl') {
#    if ($version < 3) {
#      # FIXME: Need V3 for SASL
#    }

    my $sasl = $passwd;
    # Tell the SASL object our user identifier
    $sasl->user("dn: $dn");

    $passwd = {
      mechanism   => $sasl->name,
      credentials => $sasl->initial
    };

    # Save data, we will need it later
    $mesg->_sasl_info($stash{name},$arg->{control},$sasl);
  }

  $stash{authentication} = { $auth_type => $passwd };

  $mesg->encode(
    bindRequest => \%stash,
    controls    => $arg->{control}
  ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR,"$@");

  $ldap->_sendmesg($mesg);
}


my %scope = qw(base  0 one    1 single 1 sub    2 subtree 2);
my %deref = qw(never 0 search 1 find   2 always 3);

sub search {
  my $ldap = shift;
  my $arg  = &_options;

  require Net::LDAP::Search;

  my $mesg = $ldap->message('Net::LDAP::Search' => $arg);

  my $base = $arg->{base} || '';
  my $filter;

  unless (ref ($filter = $arg->{filter})) {
    require Net::LDAP::Filter;
    my $f = Net::LDAP::Filter->new;
    $f->parse($filter)
      or return _error($ldap, $mesg, LDAP_PARAM_ERROR,"Bad filter");
    $filter = $f;
  }

  my %stash = (
    baseObject   => ref($base) ? $base->dn : $base,
    scope        => 2,
    derefAliases => 2,
    sizeLimit    => $arg->{sizelimit} || 0,
    timeLimit    => $arg->{timelimit} || 0,
    typesOnly    => $arg->{typesonly} || $arg->{attrsonly} || 0,
    filter       => $filter,
    attributes   => $arg->{attrs} || []
  );

  if (exists $arg->{scope}) {
    my $sc = lc $arg->{scope};
    $stash{scope} = 0 + (exists $scope{$sc} ? $scope{$sc} : $sc);
  }

  if (exists $arg->{deref}) {
    my $dr = lc $arg->{deref};
    $stash{derefAliases} = 0 + (exists $deref{$dr} ? $deref{$dr} : $dr);
  }

  $mesg->encode(
    searchRequest => \%stash,
    controls => $arg->{control}
  ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR,"$@");

  $ldap->_sendmesg($mesg);
}


sub add {
  my $ldap = shift;
  my $arg  = &_dn_options;

  my $mesg = $ldap->message('Net::LDAP::Add' => $arg);

  my $entry = $arg->{dn}
    or return _error($ldap, $mesg, LDAP_PARAM_ERROR,"No DN specified");

  unless (ref $entry) {
    require Net::LDAP::Entry;
    $entry = Net::LDAP::Entry->new;
    $entry->dn($arg->{dn});
    $entry->add(@{$arg->{attrs} || $arg->{attr} || []});
  }

  $mesg->encode(
    addRequest => $entry->asn,
    controls   => $arg->{control}
  ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR,"$@");

  $ldap->_sendmesg($mesg);
}


my %opcode = ( 'add' => 0, 'delete' => 1, 'replace' => 2);

sub modify {
  my $ldap = shift;
  my $arg  = &_dn_options;

  my $mesg = $ldap->message('Net::LDAP::Modify' => $arg);

  exists $arg->{dn}
    or return _error($ldap, $mesg, LDAP_PARAM_ERROR,"No DN specified");

  my @ops;
  my $opcode;
  my $op;

  if (exists $arg->{changes}) {
    my $chg;
    my $opcode;
    my $j = 0;
    while($j < @{$arg->{changes}}) {
      return _error($ldap, $mesg, LDAP_PARAM_ERROR,"Bad change type '" . $arg->{changes}[--$j] . "'")
       unless defined($opcode = $opcode{$arg->{changes}[$j++]});
      
      $chg = $arg->{changes}[$j++];
      if (ref($chg)) {
	my $i = 0;
	while ($i < @$chg) {
          push @ops, {
	    operation => $opcode,
	    modification => {
	      type => $chg->[$i],
	      vals => ref($chg->[$i+1]) ? $chg->[$i+1] : [$chg->[$i+1]]
	    }
	  };
	  $i += 2;
	}
      }
    }
  }
  else {
    foreach $op (qw(add delete replace)) {
      next unless exists $arg->{$op};
      my $opt = $arg->{$op};
      my $opcode = $opcode{$op};
      my($k,$v);

      if (ref($opt) eq 'HASH') {
	while (($k,$v) = each %$opt) {
          push @ops, {
	    operation => $opcode,
	    modification => {
	      type => $k,
	      vals => ref($v) ? $v : [$v]
	    }
	  };
	}
      }
      elsif (ref($opt) eq 'ARRAY') {
	$k = 0;
	while ($k < @{$opt}) {
          my $attr = ${$opt}[$k++];
          my $val = $opcode == 1 ? [] : ${$opt}[$k++];
          push @ops, {
	    operation => $opcode,
	    modification => {
	      type => $attr,
	      vals => $val
	    }
	  };
	}
      }
      else {
	push @ops, {
	  operation => $opcode,
	  modification => {
	    type => $opt,
	    vals => []
	  }
	};
      }
    }
  }

  my $dn;

  $mesg->encode(
    modifyRequest => {
      object => ref($dn = $arg->{dn}) ? $dn->dn : $dn,
      modification => \@ops
    },
    controls => $arg->{control}
  )
    or return _error($ldap, $mesg, LDAP_ENCODING_ERROR,"$@");

  $ldap->_sendmesg($mesg);
}

sub delete {
  my $ldap = shift;
  my $arg  = &_dn_options;

  my $mesg = $ldap->message('Net::LDAP::Delete' => $arg);
  my $dn;

  $mesg->encode(
    delRequest => ref($dn = $arg->{dn}) ? $dn->dn : $dn,
    controls   => $arg->{control}
  ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR,"$@");

  $ldap->_sendmesg($mesg);
}

sub moddn {
  my $ldap = shift;
  my $arg  = &_dn_options;
  my $del  = $arg->{deleteoldrdn} || $arg->{'delete'} || 0;
  my $newsup = $arg->{newsuperior};

  my $mesg = $ldap->message('Net::LDAP::ModDN' => $arg);

  exists $arg->{dn}
    or return _error($ldap, $mesg, LDAP_PARAM_ERROR,"No DN specified");

  my $new  = $arg->{newrdn} || $arg->{'new'}
    or return _error($ldap, $mesg, LDAP_PARAM_ERROR,"No NewRDN specified");

  my $dn;

  $mesg->encode(
    modDNRequest => {
      entry        => ref($dn = $arg->{dn}) ? $dn->dn : $dn,
      newrdn       => ref($new) ? $new->dn : $new,
      deleteoldrdn => $del,
      newSuperior  => ref($newsup) ? $newsup->dn : $newsup,
    },
    controls => $arg->{control}
  ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR,"$@");

  $ldap->_sendmesg($mesg);
}

# now maps to the V3/X.500(93) modifydn map
sub modrdn { goto &moddn }

sub compare {
  my $ldap  = shift;
  my $arg   = &_dn_options;

  my $mesg = $ldap->message('Net::LDAP::Compare' => $arg);

  my $dn = $arg->{dn}
    or return _error($ldap, $mesg, LDAP_PARAM_ERROR,"No DN specified");

  my $attr = exists $arg->{attr}
		? $arg->{attr}
		: exists $arg->{attrs} #compat
		   ? $arg->{attrs}[0]
		   : "";

  my $value = exists $arg->{value}
		? $arg->{value}
		: exists $arg->{attrs} #compat
		   ? $arg->{attrs}[1]
		   : "";


  $mesg->encode(
    compareRequest => {
      entry => ref($dn) ? $dn->dn : $dn,
      ava   => {
	attributeDesc  => $attr,
	assertionValue => $value
      }
    },
    controls => $arg->{control}
  ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR,"$@");

  $ldap->_sendmesg($mesg);
}

sub abandon {
  my $ldap = shift;
  unshift @_,'id' if @_ & 1;
  my $arg = &_options;

  my $id = $arg->{id};

  my $mesg = $ldap->message('Net::LDAP::Abandon' => $arg);

  $mesg->encode(
    abandonRequest => ref($id) ? $id->mesg_id : $id,
    controls       => $arg->{control}
  ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR,"$@");

  $ldap->_sendmesg($mesg);
}

sub extension {
  my $ldap = shift;
  my $arg  = &_options;
  my $oid  = $arg->{name};

  return if ($ldap->version < 3);

  require Net::LDAP::Extension;

  my $mesg = $ldap->message('Net::LDAP::Extension' => $arg);

  $mesg->encode(
    extendedRequest => {
      requestName  => $oid,
      requestValue => (exists $arg->{value} ? $arg->{value} : undef)
    },
    controls => $arg->{control}
  ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR,"$@");

  $ldap->_sendmesg($mesg);
}

sub sync {
  my $ldap = shift;
  my $mid  = shift;
  my $table = $ldap->{net_ldap_mesg};
  my $err = LDAP_SUCCESS;

  $mid = $mid->mesg_id if ref($mid);
  while (defined($mid) ? exists $table->{$mid} : %$table) {
    last if $err = $ldap->_recvresp($mid);
  }

  $err;
}

sub _sendmesg {
  my $ldap = shift;
  my $mesg = shift;

  my $debug;
  if ($debug = $ldap->debug) {
    require Convert::ASN1::Debug;
    print STDERR "$ldap sending:\n";

    Convert::ASN1::asn_hexdump(*STDERR, $mesg->pdu)
      if $debug & 1;

    Convert::ASN1::asn_dump(*STDERR, $mesg->pdu)
      if $debug & 4;
  }

  send($ldap->socket, $mesg->pdu, 0)
    or return _error($ldap, $mesg, LDAP_LOCAL_ERROR,"$!");

  # for CLDAP, here we need to recode when we were sent
  # so that we can perform timeouts and resends

  my $mid  = $mesg->mesg_id;
  my $sync = not $ldap->async;

  unless ($mesg->done) { # may not have a responce

    $ldap->{net_ldap_mesg}->{$mid} = $mesg;

    if ($sync) {
      my $err = $ldap->sync($mid);
      return _error($ldap, $mesg, $err,$@) if $err;
    }
  }

  $sync && $ldap->{net_ldap_onerror} && $mesg->is_error
    ? scalar &{$ldap->{net_ldap_onerror}}($mesg)
    : $mesg;
}

sub _recvresp {
  my $ldap = shift;
  my $what = shift;
  my $sock = $ldap->socket;
  my $sel = IO::Select->new($sock);
  my $ready;

  for( $ready = 1 ; $ready ; $ready = $sel->can_read(0)) {
    my $pdu;
    asn_read($sock, $pdu)
      or return LDAP_OPERATIONS_ERROR;

    my $debug;
    if ($debug = $ldap->debug) {
      require Convert::ASN1::Debug;
      print STDERR "$ldap received:\n";

      Convert::ASN1::asn_hexdump(\*STDERR,$pdu)
	if $debug & 2;

      Convert::ASN1::asn_dump(\*STDERR,$pdu)
	if $debug & 8;
    }

    my $result = $LDAPResponse->decode($pdu)
      or return LDAP_DECODING_ERROR;

    my $mid = $result->{messageID};

    my $mesg = $ldap->{net_ldap_mesg}->{$mid} or
      return LDAP_PROTOCOL_ERROR;

    $mesg->decode($result) or
      return $mesg->code;

    last if defined $what && $what == $mid;
  }

  # FIXME: in CLDAP here we need to check if any message has timed out
  # and if so do we resend it or what

  return LDAP_SUCCESS;
}

sub _forgetmesg {
  my $ldap = shift;
  my $mesg = shift;

  my $mid = $mesg->mesg_id;

  delete $ldap->{net_ldap_mesg}->{$mid};
}

#Mark Wilcox 3-20-2000
#now accepts named parameters
#dn => "dn of subschema entry"

sub schema {
  require Net::LDAP::Schema;
  my $self = shift;
  my %arg = @_;
  my $base;
  my $mesg;

  if (exists $arg{'dn'}) {
    $base = $arg{'dn'};
  }
  else {
    my $root = $self->root_dse
      or return undef;

    $base = $root->get_value('subschemasubentry') || 'cn=schema';
  }

  $mesg = $self->search(
    base   => $base,
    scope  => 'base',
    filter => '(objectClass=*)',
  );

  $mesg->code
    ? undef
    : Net::LDAP::Schema->new($mesg->entry);
}

sub root_dse {
  my $ldap = shift;
  my $mesg;
  
  unless ($ldap->{net_ldap_rootdse}) {
    $mesg = $ldap->search(
      base   => "",
      scope  => 'base',
      filter => "(objectClass=*)",
    );
    $ldap->{net_ldap_rootdse} = $mesg->entry;
  }

  return $ldap->{net_ldap_rootdse};
}

# what version are we talking?
sub version {
  my $ldap = shift;

  @_
    ? ($ldap->{net_ldap_version},$ldap->{net_ldap_version} = shift)[0]
    : $ldap->{net_ldap_version};
}

1;

