# Copyright (c) 1999-2000 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Util;

=head1 NAME

Net::LDAP::Util - Utility functions

=head1 SYNOPSIS

  use Net::LDAP::Util qw(ldap_error_text);

=head1 DESCRIPTION

B<Net::LDAP::Util> is a collection of utility functions for use with
the L<Net::LDAP|Net::LDAP> modules.

=head1 FUNCTIONS

=over 4

=cut

use vars qw($VERSION);
require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(
  ldap_error_name
  ldap_error_text
);
$VERSION = "0.03";

=item ldap_error_name ( NUM )

Returns the name corresponding with the error number passed in. If the
error is not known the a string in the form C<"LDAP error code %d(0x%02X)">
is returned.

=cut

my %error;
sub ldap_error_name {
  my $code = 0+ shift;
  require Net::LDAP::Constant;
  unless(%error) {
    while(($var,$glob) = each %{'Net::LDAP::Constant::'}) {
     next unless $var =~ /^LDAP_/ && defined(&{$glob});
      $error{ &{$glob}() } = $var;
    }
  }
  $error{$code} || sprintf("LDAP error code %d(0x%02X)",$code,$code);
}

=item ldap_error_text ( NUM )

Returns the text from the POD description for the given error. If the
error code given is unknown then C<undef> is returned.

=cut

sub ldap_error_text {
  my $name = ldap_error_name(shift);
  my $text;
  if($name =~ /^LDAP_/) {
    my $pod = $INC{'Net/LDAP/Constant.pm'};
    substr($pod,-3) = ".pod";
    local *F;
    open(F,$pod) or return;
    local $/ = "";
    local $_;
    my $len = length($name);
    my $indent = 0;
    while(<F>) {
      if(substr($_,0,11) eq "=item LDAP_") {
        last if defined $text;
	$text = "" if /^=item $name\b/;
      }
      elsif(defined $text && /^=(\S+)/) {
        $indent = 1 if $1 eq "over";
        $indent = 0 if $1 eq "back";
	$text .= " * " if $1 eq "item";
      }
      elsif(defined $text) {
        if($indent) {
          s/\n(?=.)/\n   /sog;
	}
        $text .= $_;
      }
    }
    close(F);
    $text =~ s/\n+\Z/\n/ if defined $text;
  }
  $text;
}

=back

=head1 AUTHOR

Graham Barr <gbarr@pobox.com>

=head1 COPYRIGHT

Copyright (c) 1999-2000 Graham Barr. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=for html <hr>

I<$Id: Util.pm,v 1.2 2000/05/22 20:59:50 gbarr Exp $>

=cut

1;
