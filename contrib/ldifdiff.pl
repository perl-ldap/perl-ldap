#! /usr/bin/perl
# $Id: ldifdiff.pl,v 1.2 2002/11/03 01:47:45 kartik_subbarao Exp $

=head1 NAME

ldifdiff.pl -- Generates LDIF change diff between two sorted LDIF files.

=head1 DESCRIPTION

ldifdiff.pl takes as input two sorted LDIF files, source and target, and 
generates on standard output the LDIF changes needed to transform the target 
into the source.

=head1 SYNOPSIS

ldifdiff.pl B<-k keyattr> [B<-a attr1,attr2,...>] [B<-c attr1,attr2,...>] B<sourcefile> B<targetfile>

=head1 OPTIONS

=over 4

=item B<-k> keyattr

Specifies the key attribute to use when comparing source and target entries. 
Entries in both LDIF files must be sorted by this attribute for comparisons to 
be meaningful. F<ldifsort.pl> can be used to sort LDIF files by a given 
attribute.

=item B<-a attr1,attr2,...>

(Optional) Specifies a list of attributes to consider when comparing
source and target entries. By default, all attributes are considered.

=item B<-c attr1,attr2,...>

(Optional) Compare values of the specified attributes case-insensitively. By 
default, comparisons are case-sensitive. 

=item B<sourcefile>

Specifies the source LDIF file.

=item B<targetfile>

Specifies the target LDIF file.

=back

=cut

use Net::LDAP;
use Net::LDAP::LDIF;
use Net::LDAP::Util qw(canonical_dn);
use Getopt::Std;

use strict;

my %args;
getopts("a:c:k:", \%args);

my $keyattr = $args{k};
my @sourceattrs = split(/,/, $args{a});
my %ciscmp = (objectclass => 1, manager => 1, owner => 1, uniquemember => 1);
foreach (split(/,/, $args{c})) { $ciscmp{$_} = 1 }


my ($sourcefile, $targetfile);
$sourcefile = shift; $targetfile = shift;

die "usage: $0 -k keyattr [-a attr1,attr2,...] sourcefile targetfile\n"
	unless $keyattr && $sourcefile && $targetfile;

my $source = Net::LDAP::LDIF->new($sourcefile)
	or die "Can't open LDIF file $sourcefile\n: $!\n";

my $target = Net::LDAP::LDIF->new($targetfile)
	or die "Can't open LDIF file $targetfile: $!\n";

my $ldifout = Net::LDAP::LDIF->new('-', 'w');
$ldifout->{change} = 1;
$ldifout->{wrap} = 78;

diff($source, $target);
exit;


# Gets the relative distinguished name (RDN) attribute
sub rdnattr { ($_[0]->dn =~ /^(.*?)=/)[0] }

# Gets the relative distinguished name (RDN) value
sub rdnval { my $rv = ($_[0]->dn =~ /=(.*)/)[0]; $rv =~ s/(?<!\\),.*//; $rv }

sub cmpEntries
{ 
    my ($a, $b) = @_;

    if ($keyattr =~ /^dn$/i) { 
		return lc(canonical_dn($a->dn)) cmp lc(canonical_dn($b->dn))
	}
    else { return $a->get_value($keyattr) cmp $b->get_value($keyattr) }
}


# Diffs two LDIF data sources
sub diff
{ 
	my ($source, $target) = @_;
	my ($sourceentry, $targetentry, $incr_source, $incr_target, @ldifchanges);

	$sourceentry = $source->read_entry();
	$targetentry = $target->read_entry();

	while () {
		# End of all data
		last if !$sourceentry && !$targetentry;

		# End of source data, but more target data. Delete.
		if (!$sourceentry && $targetentry) {
			$targetentry->delete;
			$ldifout->write_entry($targetentry);
			$incr_target = 1, next;
		}

		# End of target data, but more data in source. Add.
		if ($sourceentry && !$targetentry) {
			$ldifout->write_entry($sourceentry);
            $incr_source = 1, next;
		}

		# Check if the current source entry has a higher sort position than 
		# the current target. If so, we interpret this to mean that the 
		# target entry no longer exists on the source. Issue a delete to LDAP.
		if (cmpEntries($sourceentry, $targetentry) > 0) {
			$targetentry->delete;
			$ldifout->write_entry($targetentry);
            $incr_target = 1, next;
		}

		# Check if the current target entry has a higher sort position than 
		# the current source entry. If so, we interpret this to mean that the
		# source entry doesn't exist on the target. Issue an add to LDAP.
		if (cmpEntries($targetentry, $sourceentry) > 0) {
			$ldifout->write_entry($sourceentry);
            $incr_source = 1, next;
		}

		# When we get here, we're dealing with the same person in $sourceentry
		# and $targetentry. Compare the data and generate the update.

		# If a modRDN is necessary, it needs to happen before other mods
		if (lc(canonical_dn($sourceentry->dn)) 
		 ne lc(canonical_dn($targetentry->dn))) {
			my $rdnattr = rdnattr($sourceentry);
			my $rdnval = rdnval($sourceentry);

			$targetentry->{changetype} = 'modrdn';
			$targetentry->add(newrdn => "$rdnattr=$rdnval",
							  deleteoldrdn => '1');
			$ldifout->write_entry($targetentry);
			$targetentry->delete('newrdn');
			$targetentry->delete('deleteoldrdn');
			delete($targetentry->{changetype});
			
			$targetentry->dn($sourceentry->dn);
			$targetentry->{$rdnattr} = $sourceentry->{$rdnattr}
				if $sourceentry->exists($rdnattr);

		}

		# Check for differences and generate LDIF as appropriate
		updateFromEntry($sourceentry, $targetentry, @sourceattrs);
		$ldifout->write_entry($targetentry) if @{$targetentry->{changes}};
		$incr_source = 1, $incr_target = 1, next;

    } continue {
		if ($incr_source) {
			$sourceentry = $source->read_entry(); $incr_source = 0;
		}
		if ($incr_target) {
			$targetentry = $target->read_entry(); $incr_target = 0;
		}
    }
}

# Generate LDIF to update $target with information in $source.
# Optionally restrict the set of attributes to consider.
sub updateFromEntry
{
	my ($source, $target, @attrs) = @_;
	my ($attr, $val, $ldifstr);

	my %sharedattrs = (objectclass => 1);

	unless (@attrs) {
		# add all source entry attributes
		@attrs = $source->attributes;
		# add any other attributes we haven't seen from the target entry
		foreach my $tattr ($target->attributes) { 
			push(@attrs, $tattr) unless grep(/^$tattr$/i, @attrs) 
		}
	}

	$target->{changetype} = 'modify';

	foreach $attr (@attrs) {
		my $lcattr = lc $attr;
		next if $lcattr eq 'dn'; # Can't handle modrdn here

		# Build lists of unique values in the source and target, to
		# speed up comparisons.
		my @sourcevals = $source->get_value($attr);
		my @targetvals = $target->get_value($attr);
		my (%sourceuniqvals, %targetuniqvals);
		if ($ciscmp{$lcattr}) {
			@sourceuniqvals{map { lc($_) } @sourcevals} = ();
			@targetuniqvals{map { lc($_) } @targetvals} = ();
		}
		else {
			@sourceuniqvals{@sourcevals} = ();
			@targetuniqvals{@targetvals} = ();
		}
		foreach my $val (keys %sourceuniqvals) {
			if (exists $targetuniqvals{$val}) {
				delete $sourceuniqvals{$val};
				delete $targetuniqvals{$val};
			}
		}

		# Move on if there are no differences
		next unless keys(%sourceuniqvals) || keys(%targetuniqvals);

		# Make changes as appropriate
		if ($sharedattrs{$lcattr}) {
			# For 'shared' attributes (e.g. objectclass) where $source may not 
			# be a sole authoritative source, we issue separate delete and 
			# add modifications instead of a single replace.
			$target->delete($attr => [ keys(%targetuniqvals) ])
				if keys(%targetuniqvals);
			$target->add($attr => [ keys(%sourceuniqvals) ])
				if keys(%sourceuniqvals);
		}
		else {
			# Issue a replace or delete as needed
			if (@sourcevals) { $target->replace($attr => [ @sourcevals ]) }
			else { $target->delete($attr) }
		}
	}

	# Get rid of the "changetype: modify" if there were no changes
	delete($target->{changetype}) unless @{$target->{changes}};
}


=back

=head1 AUTHOR

Kartik Subbarao E<lt>subbarao@computer.orgE<gt>

=cut

