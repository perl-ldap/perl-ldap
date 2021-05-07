#! /usr/bin/perl

=head1 NAME

ldifsort.pl - Sorts an LDIF file by the specified key attribute. The sorted
version is written to standard output.

=head1 DESCRIPTION

Sorts an LDIF file by the specified key attribute.

=head1 SYNOPSIS

ldifsort.pl B<-k keyattr> [B<-acdhn>] file.ldif

=over 4

=item B<-k>

Specifies the key attribute for making sort comparisons. If 'dn' is
specified, sorting is done by the full DN string, which can be composed of
different attributes for different entries.

=item B<-a>

Specifies that attributes within a given entry should also be sorted. This
has the side effect of removing all comments and line continuations in the
LDIF file.

=item B<-c>

Specifies case-insensitive comparisons on the key attribute. This is the
default behavior if 'dn' is passed as the argument to B<-k>.

=item B<-d>

Specifies that the key attribute is a DN. Comparisons are done on a
DN-normalized version of attribute values. This is the default
behavior if 'dn' is passed as the argument to B<-k>.

=item B<-h>

When the key attribute is a DN, sorts hierarchically superior values before
subordinate values. For example, dc=example,dc=com is sorted before
cn=test,dc=example,dc=com.

=item B<-r>

When hierarchically sorting according to DN, reverse sort entries where
changetype: delete. This is useful for sorting diffed ldifs for import
with ldapmodify as childs have to be deleted before parent nodes.

=item B<-n>

Specifies numeric comparisons on the key attribute. Otherwise string
comparisons are done.

=back


=head1 AUTHOR

Kartik Subbarao E<lt>subbarao@computer.orgE<gt>

=cut


use Net::LDAP::Util qw(canonical_dn);
use MIME::Base64;
use Getopt::Std;

use strict;

my %args;
getopts("k:acdhrn", \%args);

my $keyattr = $args{k};
my $sortattrs = $args{a};
my $ciscmp = $args{c};
my $ldiffile = $ARGV[0];
my $sorthier = $args{h};

die "usage: $0 -k keyattr [-acdhrn] ldiffile\n"
	unless $keyattr && $ldiffile;

$/ = "";

open(LDIFH, $ldiffile) || die "$ldiffile: $!\n";

my $pos = 0;
my @valuepos;
while (<LDIFH>) {
	my $value;
	my $changetype = "unknown";
	1 while s/^($keyattr:.*)?\n /$1/im; # Handle line continuations
    if (/^changetype: (.*)$/im) {
        $changetype = lc($1);
    }
	if (/^$keyattr(::?) (.*)$/im) {
		$value = $2;
		$value = decode_base64($value) if $1 eq '::';
	}
	$value = lc($value) if $ciscmp;
	# To simplify hierarchical sorting, replace escaped commas in the sort key
	# with dash (the next ASCII character)
	$value =~ s/\\,/-/g if $args{h};
	push @valuepos, [ $value, $pos, $changetype ];
	$pos = tell;
}

sub cmpattr { $a->[0] cmp $b->[0] }
sub cmpattrnum { $a->[0] <=> $b->[0] }
my %canonicaldns;
sub cmpdn {
	my $cadn = ($canonicaldns{$a->[0]} ||= lc(canonical_dn($a->[0])));
	my $cbdn = ($canonicaldns{$b->[0]} ||= lc(canonical_dn($b->[0])));
	if ($args{h} && $cadn ne $cbdn) {
		# Sort superior entries before subordinate entries
		while (substr($cadn,-1,1) eq substr($cbdn,-1,1)) { chop($cadn, $cbdn) }
		$cadn =~ s/^.*,(?=.)//; $cbdn =~ s/^.*,(?=.)//;
	}
	# reverse sort order if hierarchical sorting and delete entries for modify ldifs
	if ($args{h} && $args{r}) {
		if ($a->[2] ne $b->[2]) {
                	# order of operations: "add", "delete", "modify"; cmp does that :)
                	return $a->[2] cmp $b->[2];
        	} elsif ($a->[2] eq "delete") {
                	# deletes are sorted in reverse (children are deleted before parent)
                	return $cbdn cmp $cadn;
        	}
	}
	return $cadn cmp $cbdn;
}

my $cmpfunc;
if ($args{d} || lc($keyattr) eq 'dn') { $cmpfunc = \&cmpdn }
elsif ($args{n}) { $cmpfunc = \&cmpattrnum }
else { $cmpfunc = \&cmpattr; }

my @sorted;
@sorted = sort $cmpfunc @valuepos;

foreach my $valuepos (@sorted) {
	seek(LDIFH, $valuepos->[1], 0);
	my $entry = <LDIFH>;
	if ($sortattrs) {
		$entry =~ s/\n //mg; # collapse line continuations
		my @lines = grep(!/^#/, split(/\n/, $entry));
		my $dn = shift(@lines);
		print "$dn\n", join("\n", sort @lines), "\n\n";
	}
	else {
		print $entry;
		print "\n" if $entry !~ /\n\n$/;
	}
}
