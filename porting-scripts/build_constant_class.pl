#!/usr/bin/perl
use warnings;
use strict;

local $_;
my @array;
while (<>) {
  last  if /^=cut/;
  my $protocol_const = /^=head2 Protocol Constants/ ... /^=head2/;
  next  unless /^=item\s+(LDAP_\S+)\s+\((.*)\)/;
  my ($name, $value);
  if ($protocol_const) {
    ($name, $value) = ($1, $2);
    push @array, "$value => $name,\n";	
  } else {
      ($name, $value) = ($1, "\"$2\"");
  }
  print "constant $name is export = $value\n";
}

print "\n";
print for @array;
