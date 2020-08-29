#!perl

use Test::More;

use Net::LDAP::Util qw(:time);

# Each line consists of a OPCDODE, a RESULT, DATETIME, and a EXPECTED
# where
# - OPCDODE is a TESTCASE followed by a RESULT sepaated by a colon
# - TESTCASE is the check to be performed: one of
#     g2t   generalizedTime_to_time
#     t2g   time_to_generalizedTime
# - RESULT is the expected result, one of:
#     yes   TESTCASE succeeds and matches EXPECTED
#     no    TESTCASE succeeds, but may not match EXPECTED
#     fail  TESTCASE failures
# - DATETIME is a date-time combination to be checked.
#   Depending on TESTCASE it may be either a string in LDAP's generalizedTime
#   format or a UNIX time string denoting the seconds since the epoch,
#   optionally extended by sub-second parts as decimal fractions
# - EXPECTED is the expected value on successful conversion

# To keep the order of tests, @tests is an array of ($filterstring => @ops) tuples
my @tests = map { /^(g2t|t2g):(\w+)\s+(\S+)\s+(\S+)/ &&  [ $1, $2, $3, $4 ] }
                grep(/^(:?g2t|t2g):\w+\s+\S+\s+\S+/, <DATA>);

# The elements of the @testcases array are the TESTCASE prefixes described above
my %testcases = ( g2t => "generalizedTime_to_time",
                  t2g => "time_to_generalizedTime" );


# calculate number of tests:
($] >= 5.012)
? plan tests =>  scalar(@tests) 	# @tests is a list of tests
: plan skip_all => 'Perl version too old';


foreach my $elem (@tests) {
  my ($testcase, $result, $datetime, $expected) = @{$elem};
  my $function = $testcases{$testcase};
  my $got = &$function($datetime);

  foreach ($result) {
    /fail/  &&  ok(!defined($got), "$function('$datetime') should fail");
    /no/   &&   is(defined($got), $expected, "$function('$datetime') should succeed");
    /yes/   &&  is($got, $expected, "$function('$datetime') should yield $expected");
  }
}


__DATA__

## generalizedTime -> time
g2t:yes		19691231235958.9Z		-1.1
g2t:yes		19691231235959Z			-1
g2t:yes		19691231235959.9Z		-0.1
g2t:yes		19700101000000Z			0
g2t:yes		19700101000000.1Z		0.1
g2t:yes		19700101000001Z			1
g2t:yes		19700101000001.1Z		1.1

# "abbreviated" formats
gt2:yes		196912312253.9Z			-3966
gt2:yes		196912312254Z			-3960
gt2:yes		1969123122.9Z			-3960
g2t:yes		1969123123Z			-3600
g2t:yes		1970010100Z			0
g2t:yes		1970010101Z			3600
gt2:yes		1970010101.1Z			3960
gt2:yes		197001010106Z			3960
gt2:yes		197001010106.1Z			3966

# formats with offsets
g2t:yes		19700101000000+0130		-5400
g2t:yes		19700101000000+01		-3600
g2t:yes		19700101000000-01		3600
g2t:yes		19700101000000-0130		5400

## time -> generalizedTime
t2g:yes		-1.1				19691231235958.9Z
t2g:yes		-1				19691231235959Z
t2g:yes		-0.1				19691231235959.9Z
t2g:yes		0				19700101000000Z
t2g:yes		0.1				19700101000000.1Z
t2g:yes		1				19700101000001Z
t2g:yes		1.1				19700101000001.1Z
t2g:yes		-33358996800			09121123120000Z


# illegally formatted generalizedTimes
g2t:fail	9999				?
g2t:fail	2013Z				?
g2t:fail	201303Z				?
g2t:fail	20130315Z			?
g2t:fail	20130315000000+1		?
g2t:fail	20130315000000+115		?

# wrong date: 2013 is/was no leap year
g2t:fail	20130229000000Z			?
# wrong date: gap between Julian & Gregorian calendar - this really should fail
#g2t:yes		15821013000000Z			-12219552000
# wrong date: second out of range
g2t:fail	20130315000060Z			?
# wrong date: minute out of range
g2t:fail	20130315006000Z			?
# wrong date: hour out of range
g2t:fail	20130315240000Z			?
# wrong date: day out of range
g2t:fail	20130100000000Z			?
g2t:fail	20131232000000Z			?
# wrong date: month out of range
g2t:fail	20130029000000Z			?
g2t:fail	20131329000000Z			?
# wrong date: year out of range
g2t:fail	-01230101000000Z		?
g2t:fail	123450101000000Z		?
# wrong date: year not supported by Time::Local
g2t:fail	09991259235959Z			?
g2t:fail	09121123120000Z			-33358996800


# EOF
