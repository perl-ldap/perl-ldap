# Copyright (c) 1997-2000 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::LDIF;

use strict;
use SelectSaver;
require Net::LDAP::Entry;
use vars qw($VERSION);

$VERSION = "0.05";

my %mode = qw(w > r < a >>);

sub new {
  my $pkg = shift;
  my $file = shift || "-";
  my $mode = shift || "r";
  my %opt = @_;
  my $fh;
  my $opened_fh = 0;
  
  if (ref($file)) {
    $fh = $file;
  }
  else {
    if ($file eq "-") {
      if ($mode eq "w") {
        ($file,$fh) = ("STDOUT",\*STDOUT);
      }
      else {
        ($file,$fh) = ("STDIN",\*STDIN);
      }
    }
    else {
      require Symbol;
      $fh = Symbol::gensym();
      my $open = ($mode{$mode} || "<") . $file;
      open($fh,$open) or return;
      $opened_fh = 1;
    }
  }

  my $self = {
    changetype => "modify",
    modify => 'add',
    wrap => 78,
    %opt,
    fh   => $fh,
    file => "$file",
    opened_fh => $opened_fh,
  };

  bless $self, $pkg;
}

sub _read_one {
  my $self = shift;
  my @ldif;
  
  {
    local $/ = "";
    my $fh = $self->{'fh'};
    my $ln = scalar <$fh>;
    return unless defined($ln);
    $ln =~ s/\n //sg;
    chomp($ln);
    chomp(@ldif = split(/^/, $ln));
  }
  shift @ldif if @ldif && $ldif[0] !~ /\D/;

  return unless @ldif > 1 && $ldif[0] =~ s/^dn:(:?) //;

  my $dn = shift @ldif;

  if (length($1)) {
    require MIME::Base64;
    $dn = MIME::Base64::decode($dn);
  }

  my @attr;
  my $last = "";
  my $vals = [];
  my $line;
  my $attr;
  foreach $line (@ldif) {
    $line =~ s/^([-;\w]+):\s*// && ($attr = $1) or next;

    if ($line =~ s/^:\s*//) {
      require MIME::Base64;
      $line = MIME::Base64::decode($line);
    }

    if ($attr eq $last) {
      push @$vals, $line;
      next;
    }
    else {
      $vals = [$line];
      push(@attr,$last=$attr,$vals);
    }
  }
  my $entry = Net::LDAP::Entry->new;
  $entry->dn($dn);
  $entry->add(@attr);
  $entry;
}

sub read {
  my $self = shift;

  return unless $self->{'fh'};
  return _read_one($self) unless wantarray;

  my($entry, @entries);
  push(@entries,$entry) while $entry = _read_one($self);

  return @entries;
}

sub _wrap {
  if($_[1] > 40) {
    my $pos = $_[1];
    while($pos < length($_[0])) {
      substr($_[0],$pos,0) = "\n ";
      $pos += $_[1]+1;
    }
  }
  $_[0];
}

sub _write_attr {
  my($attr,$val,$wrap) = @_;
  my $v;
  foreach $v (@$val) {
    my $ln = $attr;
    if ($v =~ /(^[ :]|[\x00-\x1f\x7f-\xff])/) {
      require MIME::Base64;
      $ln .= ":: " . MIME::Base64::encode($v,"");
    }
    else {
      $ln .= ": " . $v;
    }
    print _wrap($ln,$wrap),"\n";
  }
}

sub _write_attrs {
  my($entry,$wrap) = @_;
  my $attr;
  foreach $attr ($entry->attributes) {
    my $val = $entry->get_value($attr, asref => 1);
    _write_attr($attr,$val,$wrap);
  }
}

sub write {
  my $self = shift;
  my $entry;
  my $wrap = int($self->{'wrap'});
  local($\,$,); # output field and record separators

  return unless $self->{'fh'};
  my $saver = SelectSaver->new($self->{'fh'});
  
  my $fh = $self->{'fh'};
  foreach $entry (@_) {
    print "\n" if tell($self->{'fh'});
    my $dn = $entry->dn;

    if ($dn =~ /(^[ :]|[\x00-\x1f\x7f-\xff])/) {
      require MIME::Base64;
      $dn = "dn:: " . MIME::Base64::encode($dn,"");
    }
    else {
      $dn = "dn: " . $dn;
    }

    print _wrap($dn,$wrap),"\n";
    _write_attrs($entry,$wrap);
  }

  1;
}

sub read_cmd {
  my $self = shift;

  return unless $self->{'fh'};
  return _read_one_cmd($self) unless wantarray;

  my($entry, @entries);
  push(@entries,$entry) while $entry = _read_one_cmd($self);

  return @entries;
}

sub _read_one_cmd {
  my $self = shift;

  my @ldif;

  {
    local $/ = "";
    my $fh = $self->{'fh'};
    my $ln = scalar <$fh>;
    return unless defined $ln;
    $ln =~ s/\n //sg;
    chomp($ln);
    chomp(@ldif = split(/^/, $ln));
  }
  shift @ldif if @ldif && $ldif[0] !~ /\D/;
  return unless @ldif > 1 && $ldif[0] =~ s/^dn:(:?) //;

  my $dn = shift @ldif;

  if (length($1)) {
    require MIME::Base64;
    $dn = MIME::Base64::decode($dn);
  }

  my $entry = Net::LDAP::Entry->new;
  $entry->dn($dn);

  my $line;
  my $changetype = $ldif[0] =~ s/^changetype:\s*//
	? shift(@ldif) : $self->{'changetype'};

  $entry->changetype($changetype);

  return $entry if ($changetype eq "delete");

  return unless @ldif; # Bad LDIF

  while(@ldif) {
    my $modify = $self->{'modify'};
    my $modattr;
    my $lastattr;
    if($changetype eq "modify") {
      (my $tmp = shift @ldif) =~ s/^(add|delete|replace):\s*(\w+)//
	or return; # Bad LDIF
      $lastattr = $modattr = $2;
      $modify  = $1;
    }
    my @values;
    while(@ldif) {
      my $line = shift @ldif;
      my $attr;

      if ($line eq "-") {
        $entry->$modify($lastattr, \@values)
	  if defined $lastattr;
        undef $lastattr;
	@values = ();
	last;
      }

      $line =~ s/^(\w+):\s*//;
      $attr = $1;      

      if(defined($modattr)) {
        warn "bad LDIF" unless $attr eq $modattr;
      }

      if(!defined($lastattr) || $lastattr ne $attr) {
        $entry->$modify($lastattr, \@values)
	  if defined $lastattr;
        $lastattr = $attr;
	@values = ($line);
	next;
      }
      push @values, $line;
    }
    $entry->$modify($lastattr, \@values)
      if defined $lastattr;
    
  }
  $entry;
}

sub write_cmd {
  my $self = shift;
  my $entry;
  my $wrap = int($self->{'wrap'});

  return unless $self->{'fh'};
  my $saver = SelectSaver->new($self->{'fh'});
  
  foreach $entry (grep { defined } @_) {
    my $type = $entry->changetype;
    my $dn = "dn: " . $entry->dn;

    print "\n" if tell($self->{'fh'});
    print _wrap($dn,$wrap),"\n","changetype: ",$type,"\n";

    if ($type eq 'delete') {
      next;
    }
    elsif ($type eq 'add') {
      _write_attrs($entry,$wrap);
      next;
    }

    my $change;
    my $first = 0;
    foreach $change ($entry->changes) {
      unless (ref($change)) {
        $type = $change;
	next;
      }
      print "-\n" if $first++;
      my $i = 0;
      while ($i < @$change) {
        my $attr = $change->[$i++];
        my $val = $change->[$i++];
	print $type,": ",$attr,"\n";
	_write_attr($attr,$val,$wrap);
      }
    }
  }
}

sub done {
  my $self = shift;
  my $fh = $self->{'fh'};
  close $fh if $fh && $self->{'opened_fh'};
  delete $self->{'fh'};
  1;
}

sub DESTROY {
    my $self = shift;
    $self->done();
}

1;
