#!/usr/bin/perl -w
#
# recursive-ldap-delete.pl
#
# Mike Jackson <mj@sci.fi>
#

use strict;
use Net::LDAP;

my $server      = "localhost";
my $binddn      = "cn=directory manager";
my $bindpasswd  = "foobar";
my $base        = "dc=bigcorp,dc=com";
my $delbranch   = "ou=users,$base";             # branch to remove

my $ldap        = Net::LDAP->new( $server ) or die "$@";
$ldap->bind( $binddn, password => $bindpasswd, version => 3 );
my $result      = $ldap->search( base   => $delbranch,
                                 filter => "(objectclass=*)" );

my @dnlist;
my $entry;
foreach $entry ( $result->all_entries ) { push @dnlist, $entry->dn }

# explode dn into an array and push
# arrays to indexed hash of arrays
my %HoL;
my $i   = 0;
for ( @dnlist ) {
    s/,$base//;
    $HoL{$i} = [ split(",", $_) ];
    $i++;
}

# sorted descending by number of members (leaf nodes last)
foreach my $key ( sort { @{$HoL{$b}} <=> @{$HoL{$a}} } keys %HoL ) {
        my $dn = join(",", @{ $HoL{$key} }).",$base";
        $ldap->delete($dn);
}

$entry->update ( $ldap );
$ldap->unbind;
