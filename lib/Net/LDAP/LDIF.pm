# Copyright (c) 1997-2008 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::LDIF;

use strict;
require Net::LDAP::Entry;

use constant CHECK_UTF8 => $] > 5.007;

BEGIN {
  require Encode
    if (CHECK_UTF8);
}

our $VERSION = '0.26';

# allow the letters r,w,a as mode letters
my %modes = qw(r <  r+ +<  w >  w+ +>  a >>  a+ +>>);

sub new {
  my $pkg = shift;
  my $file = shift || '-';
  my $mode = @_ % 2 ? shift || 'r' : 'r';
  my %opt = @_;
  my $fh;
  my $opened_fh = 0;

  # harmonize mode
  $mode = $modes{$mode}
    if (defined($modes{$mode}));

  if (ref($file)) {
    $fh = $file;
  }
  else {
    if ($file eq '-') {
      ($file,$fh) = ($mode eq '<')
                    ? ('STDIN', \*STDIN)
                    : ('STDOUT',\*STDOUT);

      if ($mode =~ /(:.*$)/) {
        my $layer = $1;
        binmode($file, $layer);
      }
    }
    else {
      $opened_fh = ($file =~ /^\| | \|$/x)
                   ? open($fh, $file)
                   : open($fh, $mode, $file);
      return  unless ($opened_fh);
    }
  }

  # Default the encoding of DNs to 'none' unless the user specifies
  $opt{encode} = 'none'  unless (exists $opt{encode});

  # Default the error handling to die
  $opt{onerror} = 'die'  unless (exists $opt{onerror});

  # sanitize options
  $opt{lowercase} ||= 0;
  $opt{change} ||= 0;
  $opt{sort} ||= 0;
  $opt{version} ||= 0;

  my $self = {
    changetype => 'modify',
    modify => 'add',
    wrap => 78,
    %opt,
    fh   => $fh,
    file => "$file",
    opened_fh => $opened_fh,
    _eof => 0,
    write_count => ($mode =~ /^\s*\+?>>/ and tell($fh) > 0) ? 1 : 0,
  };

  bless $self, $pkg;
}

sub _read_lines {
  my $self = shift;
  my $fh = $self->{fh};
  my @ldif = ();
  my $entry = '';
  my $in_comment = 0;
  my $entry_completed = 0;
  my $ln;

  return @ldif  if ($self->eof());

  while (defined($ln = $self->{_buffered_line} || scalar <$fh>)) {
    delete($self->{_buffered_line});
    if ($ln =~ /^#/o) {		# ignore 1st line of comments
      $in_comment = 1;
    }
    else {
      if ($ln =~ /^[ \t]/o) {	# append wrapped line (if not in a comment)
        $entry .= $ln  if (!$in_comment);
      }
      else {
        $in_comment = 0;
        if ($ln =~ /^\r?\n$/o) {
          # ignore empty line on start of entry
          # empty line at non-empty entry indicate entry completion
          $entry_completed++  if (length($entry));
	}
        else {
	  if ($entry_completed) {
	    $self->{_buffered_line} = $ln;
	    last;
	  }
	  else {
            # append non-empty line
            $entry .= $ln;
	  }
        }
      }
    }
  }
  $self->eof(1)  if (!defined($ln));
  $self->{_current_lines} = $entry;
  $entry =~ s/\r?\n //sgo;	# un-wrap wrapped lines
  $entry =~ s/\r?\n\t/ /sgo;	# OpenLDAP extension !!!
  @ldif = split(/^/, $entry);
  map { s/\r?\n$//; } @ldif;

  @ldif;
}


# read attribute value from URL
sub _read_url_attribute {
  my $self = shift;
  my $url = shift;
  my @ldif = @_;
  my $line;

  if ($url =~ s/^file:(?:\/\/)?//) {
    open(my $fh, '<', $url)
      or  return $self->_error("can't open $url: $!", @ldif);

    binmode($fh);
    { # slurp in whole file at once
      local $/;
      $line = <$fh>;
    }
    close($fh);
  }
  elsif ($url =~ /^(https?|ftp|gopher|news:)/ and
         eval { require LWP::UserAgent; }) {
    my $ua = LWP::UserAgent->new();
    my $response = $ua->get($url);

    return $self->_error("can't get data from $url: $!", @ldif)
      if (!$response->is_success);

    $line = $response->decoded_content();

    return $self->error("decoding data from $url failed: $@", @ldif)
      if (!defined($line));
  }
  else {
    return $self->_error('unsupported URL type', @ldif);
  }

  $line;
}


# read attribute value (decode it based in its type)
sub _read_attribute_value {
  my $self = shift;
  my $type = shift;
  my $value = shift;
  my @ldif = @_;

  # Base64-encoded value: decode it
  if ($type && $type eq ':') {
    require MIME::Base64;
    $value = MIME::Base64::decode($value);
  }
  # URL value: read from URL
  elsif ($type && $type eq '<' and $value =~ s/^(.*?)\s*$/$1/) {
    $value = $self->_read_url_attribute($value, @ldif);
    return  if (!defined($value));
  }

  $value;
}


# _read_one() is deprecated and will be removed
# in a future version
*_read_one = \&_read_entry;

sub _read_entry {
  my $self = shift;
  my @ldif;
  $self->_clear_error();

  @ldif = $self->_read_lines;

  unless (@ldif) {	# empty records are errors if not at eof
    $self->_error('illegal empty LDIF entry')  if (!$self->eof());
    return;
  }

  if (@ldif and $ldif[0] =~ /^version:\s+(\d+)/) {
    $self->{version} = $1;
    shift @ldif;
    return $self->_read_entry
      unless (@ldif);
  }

  if (@ldif < 1) {
     return $self->_error('LDIF entry is not valid', @ldif);
  }
  elsif ($ldif[0] !~ /^dn::? */) {
     return $self->_error('First line of LDIF entry does not begin with "dn:"', @ldif);
  }

  my $dn = shift @ldif;
  my $xattr = $1  if ($dn =~ s/^dn:(:?) *//);

  $dn = $self->_read_attribute_value($xattr, $dn, @ldif);

  my $entry = Net::LDAP::Entry->new;
  $dn = Encode::decode_utf8($dn)
    if (CHECK_UTF8 && $self->{raw} && ('dn' !~ /$self->{raw}/));
  $entry->dn($dn);

  my @controls = ();

  # optional control: line => change record
  while (@ldif && ($ldif[0] =~ /^control:\s*/)) {
    my $control = shift(@ldif);

    if ($control =~ /^control:\s*(\d+(?:\.\d+)*)(?:\s+(true|false))?(?:\s*\:(.*))?$/) {
      my($oid,$critical,$value) = ($1,$2,$3);

      $critical = ($critical && $critical =~ /true/) ? 1 : 0;

      if (defined($value)) {
        my $type = $1  if ($value =~ s/^([\<\:])\s*//);

        $value =~ s/^\s*//;

        if ($type) {
          $value = $self->_read_attribute_value($type, $value, @ldif);
          return $self->_error('Illegal value in control line given', @ldif)
            if !defined($value);
        }
      }

      require Net::LDAP::Control;
      my $ctrl = Net::LDAP::Control->new(type     => $oid,
                                         value    => $value,
                                         critical => $critical);

      push(@controls, $ctrl);

      return $self->_error('Illegally formatted control line given', @ldif)
        if (!@ldif);
    }
    else {
      return $self->_error('Illegally formatted control line given', @ldif);
    }
  }

  # LDIF change record
  if ((scalar @ldif) && ($ldif[0] =~ /^changetype:\s*/)) {
    my $changetype = $ldif[0] =~ s/^changetype:\s*//
        ? shift(@ldif) : $self->{changetype};
    $entry->changetype($changetype);

    if ($changetype eq 'delete') {
      return $self->_error('LDIF "delete" entry is not valid', @ldif)
        if (@ldif);
      return $entry;
    }

    return $self->_error('LDAP entry is not valid', @ldif)
      unless (@ldif);

    while (@ldif) {
      my $action = $self->{modify};
      my $modattr;
      my $lastattr;
      my @values;

      if ($changetype eq 'modify') {
        unless ((my $tmp = shift @ldif) =~ s/^(add|delete|replace|increment):\s*([-;\w]+)//) {
          return $self->_error('LDAP entry is not valid', @ldif);
        }
        $lastattr = $modattr = $2;
        $action = $1;
      }

      while (@ldif) {
        my $line = shift @ldif;

        if ($line eq '-') {
          return $self->_error('LDAP entry is not valid', @ldif)
            if (!defined($modattr) || !defined($lastattr));

          last;
        }

        if ($line =~ /^([-;\w]+):([\<\:]?)\s*(.*)$/o) {
          my ($attr,$xattr,$val) = ($1,$2,$3);

          return $self->_error('LDAP entry is not valid', @ldif)
            if (defined($modattr) && $attr ne $modattr);

          $val = $self->_read_attribute_value($xattr, $val, $line)
            if ($xattr);
          return  if !defined($val);

          $val = Encode::decode_utf8($val)
            if (CHECK_UTF8 && $self->{raw} && ($attr !~ /$self->{raw}/));

          if (!defined($lastattr) || $lastattr ne $attr) {
            $entry->$action($lastattr => \@values)
              if (defined $lastattr);

            $lastattr = $attr;
            @values = ();
          }
          push(@values, $val);
        }
        else {
          return $self->_error('LDAP entry is not valid', @ldif);
        }
      }
      $entry->$action($lastattr => \@values)
        if (defined $lastattr);
    }
  }
  # content record (i.e. no 'changetype' line; implicitly treated as 'add')
  else {
    my $last = '';
    my @values;

    return $self->_error('Controls only allowed with LDIF change entries', @ldif)
      if (@controls);

    foreach my $line (@ldif) {
      if ($line =~ /^([-;\w]+):([\<\:]?)\s*(.*)$/o) {
        my($attr,$xattr,$val) = ($1,$2,$3);

        $last = $attr  if (!$last);

        $val = $self->_read_attribute_value($xattr, $val, $line)
          if ($xattr);
        return  if !defined($val);

        $val = Encode::decode_utf8($val)
          if (CHECK_UTF8 && $self->{raw} && ($attr !~ /$self->{raw}/));

        if ($attr ne $last) {
          $entry->add($last => \@values);
          @values = ();
          $last = $attr;
        }
        push(@values, $val);
      }
      else {
        return $self->_error("illegal LDIF line '$line'", @ldif);
      }
    }
    $entry->add($last => \@values);
  }

  $self->{_current_entry} = $entry;

  $entry;
}

sub read_entry {
  my $self = shift;

  return $self->_error('LDIF file handle not valid')
    unless ($self->{fh});

  $self->_read_entry();
}

# read() is deprecated and will be removed
# in a future version
sub read {
  my $self = shift;

  return $self->read_entry()  unless wantarray;

  my($entry, @entries);
  push(@entries, $entry)  while ($entry = $self->read_entry);

  @entries;
}

sub eof {
  my $self = shift;
  my $eof = shift;

  $self->{_eof} = $eof
    if ($eof);

  $self->{_eof};
}

sub _wrap {
  my $len = int($_[1]);	# needs to be >= 2 to avoid division by zero
  return $_[0]  if (length($_[0]) <= $len or $len <= 40);
  use integer;
  my $l2 = $len - 1;
  my $x = (length($_[0]) - $len) / $l2;
  my $extra = (length($_[0]) == ($l2 * $x + $len)) ? '' : 'a*';
  join("\n ", unpack("a$len" . "a$l2" x $x . $extra, $_[0]));
}

sub _write_attr {
  my($self, $attr, $val) = @_;
  my $lower = $self->{lowercase};
  my $fh = $self->{fh};
  my $res = 1;	# result value

  foreach my $v (@$val) {
    my $ln = $lower ? lc $attr : $attr;

    $v = Encode::encode_utf8($v)
      if (CHECK_UTF8 and Encode::is_utf8($v));

    if ($v =~ /(^[ :<]|[\x00-\x1f\x7f-\xff]| $)/) {
      require MIME::Base64;
      $ln .= ':: ' . MIME::Base64::encode($v, '');
    }
    else {
      $ln .= ': ' . $v;
    }
    $res &&= print $fh _wrap($ln, $self->{wrap}), "\n";
  }
  $res;
}

# helper function to compare attribute names (sort objectClass first)
sub _cmpAttrs {
  ($a =~ /^objectclass$/io)
  ? -1 : (($b =~ /^objectclass$/io) ? 1 : ($a cmp $b));
}

sub _write_attrs {
  my($self, $entry) = @_;
  my @attributes = $entry->attributes();
  my $res = 1;	# result value

  @attributes = sort _cmpAttrs @attributes  if ($self->{sort});

  foreach my $attr (@attributes) {
    my $val = $entry->get_value($attr, asref => 1);
    $res &&= $self->_write_attr($attr, $val);
  }
  $res;
}

sub _write_controls {
  my($self, @ctrls) = @_;
  my $res = 1;
  my $fh = $self->{fh};

  require Net::LDAP::Control;

  foreach my $ctrl (@ctrls) {
    my $ln = 'control: ' . $ctrl->type . ($ctrl->critical ? ' true' : ' false');
    my $v = $ctrl->value;

    if (defined($v)) {
      $v = Encode::encode_utf8($v)
        if (CHECK_UTF8 and Encode::is_utf8($v));

      if ($v =~ /(^[ :<]|[\x00-\x1f\x7f-\xff]| $)/) {
        require MIME::Base64;
        $v = MIME::Base64::encode($v, '');
        $ln .= ':';	# indicate Base64-encoding of $v
      }

      $ln .= ': ' . $v;
    }
    $res &&= print $fh _wrap($ln, $self->{wrap}), "\n";
  }
  $res;
}

sub _write_dn {
  my($self, $dn) = @_;
  my $encode = $self->{encode};
  my $fh = $self->{fh};

  $dn = Encode::encode_utf8($dn)
    if (CHECK_UTF8 and Encode::is_utf8($dn));

  if ($dn =~ /^[ :<]|[\x00-\x1f\x7f-\xff]/) {
    if ($encode =~ /canonical/i) {
      require Net::LDAP::Util;
      $dn = Net::LDAP::Util::canonical_dn($dn, mbcescape => 1);
      # Canonicalizer won't fix leading spaces, colons or less-thans, which
      # are special in LDIF, so we fix those up here.
      $dn =~ s/^([ :<])/\\$1/;
      $dn = "dn: $dn";
    }
    elsif ($encode =~ /base64/i) {
      require MIME::Base64;
      $dn = 'dn:: ' . MIME::Base64::encode($dn, '');
    }
    else {
      $dn = "dn: $dn";
    }
  }
  else {
    $dn = "dn: $dn";
  }
  print $fh _wrap($dn, $self->{wrap}), "\n";
}

# write() is deprecated and will be removed
# in a future version
sub write {
  my $self = shift;

  $self->_write_entry(0, @_);
}

sub write_entry {
  my $self = shift;

  $self->_write_entry($self->{change}, @_);
}

sub write_version {
  my $self = shift;
  my $fh = $self->{fh};
  my $res = 1;

  $res &&= print $fh "version: $self->{version}\n"
    if ($self->{version} && !$self->{version_written}++);

  return $res;
}

# internal helper: write entry in different format depending on 1st arg
sub _write_entry {
  my $self = shift;
  my $change = shift;
  my $res = 1;	# result value
  my @args = ();

  return $self->_error('LDIF file handle not valid')
    unless ($self->{fh});

  # parse list of entries optionally interspersed with lists of option pairs
  # each option-pair list belongs to the preceding entry
  #  e.g. $entry1, control => $ctrl1, $entry2, $entry3, control => [ $ctrl3a, $ctrl3b ], ...
  foreach my $elem (@_) {
    if (ref($elem)) {
      if (scalar(@args) % 2) {    # odd number of args: $entry + optional args
        $res &&= $self->_write_one($change, @args);
        @args = ();
      }
    }
    elsif (!@args) {	# 1st arg needs to be an N:L:E object
      $self->_error("Entry '$elem' is not a valid Net::LDAP::Entry object.");
      $res = 0;
      @args = ();
      next;	# try to re-sync
    }

    push(@args, $elem);
  }

  if (scalar(@args) % 2) {
    $res &&= $self->_write_one($change, @args);
  }
  elsif (@args) {
    $self->error("Illegal argument list passed");
    $res = 0;
  }

  $self->_error($!)  if (!$res && $!);

  $res;
}

# internal helper to write exactly one entry
sub _write_one
{
  my $self = shift;
  my $change = shift;
  my $entry = shift;
  my %opt = @_;
  my $fh = $self->{fh};
  my $res = 1;	# result value
  local($\, $,); # output field and record separators

  if ($change) {
    my @changes = $entry->changes;
    my $type = $entry->changetype;

    # Skip entry if there is nothing to write
    return $res  if ($type eq 'modify' and !@changes);

    $res &&= $self->write_version()  unless ($self->{write_count}++);
    $res &&= print $fh "\n";
    $res &&= $self->_write_dn($entry->dn);

    $res &&= $self->_write_controls(ref($opt{control}) eq 'ARRAY'
                                    ? @{$opt{control}}
                                    : ( $opt{control} ))
      if ($opt{control});

    $res &&= print $fh "changetype: $type\n";

    if ($type eq 'delete') {
      return $res;
    }
    elsif ($type eq 'add') {
      $res &&= $self->_write_attrs($entry);
      return $res;
    }
    elsif ($type =~ /modr?dn/o) {
      my $deleteoldrdn = $entry->get_value('deleteoldrdn') || 0;
      $res &&= $self->_write_attr('newrdn', $entry->get_value('newrdn', asref => 1));
      $res &&= print $fh 'deleteoldrdn: ', $deleteoldrdn, "\n";
      my $ns = $entry->get_value('newsuperior', asref => 1);
      $res &&= $self->_write_attr('newsuperior', $ns)  if (defined $ns);
      return $res;
    }

    my $dash = 0;
    # changetype: modify
    while (my($action,$attrs) = splice(@changes, 0, 2)) {
      my @attrs = @$attrs;

      while (my($attr,$val) = splice(@attrs, 0, 2)) {
        $res &&= print $fh "-\n"  if (!$self->{version} && $dash++);
        $res &&= print $fh "$action: $attr\n";
        $res &&= $self->_write_attr($attr, $val);
        $res &&= print $fh "-\n"  if ($self->{version});
      }
    }
  }
  else {
    $res &&= $self->write_version()  unless ($self->{write_count}++);
    $res &&= print $fh "\n";
    $res &&= $self->_write_dn($entry->dn);
    $res &&= $self->_write_attrs($entry);
  }

  $res;
}

# read_cmd() is deprecated in favor of read_entry()
# and will be removed in a future version
sub read_cmd {
  my $self = shift;

  return $self->read_entry()  unless wantarray;

  my($entry, @entries);
  push(@entries, $entry)  while ($entry = $self->read_entry);

  @entries;
}

# _read_one_cmd() is deprecated in favor of _read_one()
# and will be removed in a future version
*_read_one_cmd = \&_read_entry;

# write_cmd() is deprecated in favor of write_entry()
# and will be removed in a future version
sub write_cmd {
  my $self = shift;

  $self->_write_entry(1, @_);
}

sub done {
  my $self = shift;
  my $res = 1;	# result value

  if ($self->{fh}) {
    if ($self->{opened_fh}) {
      $res = close($self->{fh});
      undef $self->{opened_fh};
    }
    delete $self->{fh};
  }
  $res;
}

sub handle {
  my $self = shift;

  return $self->{fh};
}

my %onerror = (
  die   => sub {
                my $self = shift;
                require Carp;
                $self->done;
                Carp::croak($self->error(@_));
             },
  warn  => sub {
                my $self = shift;
                require Carp;
                Carp::carp($self->error(@_));
             },
  undef => sub {
                my $self = shift;
                require Carp;
                Carp::carp($self->error(@_))  if ($^W);
             },
);

sub _error {
  my ($self, $errmsg, @errlines) = @_;
  $self->{_err_msg} = $errmsg;
  $self->{_err_lines} = join("\n", @errlines);

  scalar &{ $onerror{ $self->{onerror} } }($self, $self->{_err_msg})
    if ($self->{onerror});

  return;
}

sub _clear_error {
  my $self = shift;

  undef $self->{_err_msg};
  undef $self->{_err_lines};
}

sub error {
  my $self = shift;
  $self->{_err_msg};
}

sub error_lines {
  my $self = shift;
  $self->{_err_lines};
}

sub current_entry {
  my $self = shift;
  $self->{_current_entry};
}

sub current_lines {
  my $self = shift;
  $self->{_current_lines};
}

sub version {
  my $self = shift;
  return $self->{version}  unless (@_);
  $self->{version} = shift || 0;
}

sub next_lines {
  my $self = shift;
  $self->{_next_lines};
}

sub DESTROY {
  my $self = shift;
  $self->done();
}

1;
