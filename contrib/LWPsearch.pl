#!/usr/bin/perl -w

use open OUT => ':utf8';

use LWP::UserAgent;
use MIME::Base64;
use Getopt::Long;

# option variables
my $user     = '';
my $password = '';
my $format   = '';

# get options
my $result = GetOptions('u|user=s'     => \$user,
                        'p|password=s' => \$password,
                        'f|format=s'   => \$format);

# die on errors on the command line
die "Usage: LWPsearch [<options>] <LDAP-URL>\n" .
    "  where <options> are:\n" .
    "    -f  --format {dsml|html|json|ldif}  output format\n" .
    "    -u  --user <username>       user name (DN) to logon to LDAP server\n" .
    "    -p  --password <password>   password to logon to LDAP server\n"
  if (!$result || scalar(@ARGV) != 1 || ($format && $format !~ /^(dsml|json|ldif|html)$/));

# create a user agent object
my $ua = LWP::UserAgent->new;
$ua->agent("LWPsearch");

# add headers as requested
my %headers = ();

$headers{Accept} = "text/$format"
  if ($format);

$headers{Authorization} = 'Basic '.encode_base64("$user:$password")
  if ($user);

# pass GET request to the user agent and get a response back
my $res = $ua->get($ARGV[0], %headers);

# check the outcome of the response
if ($res->is_success) {
    print $res->content;
}
else {
    print $res->status_line, ($res->content) ? ' ('.$res->content.')' : '', "\n";
}

=head1 NAME

LWPsearch.pl -- perform LDAP search using LWP mechanisms

=head1 SYNOPSIS

B<LWPsearch.pl>
[B<-f|--format> {C<dsml>|C<html>|C<json>|C<ldif>}]
[B<-u|--user> I<user>]
[B<-p|--password> I<password>]
B<LDAP-URL>

=head1 DESCRIPTION

LWPsearch.pl parses the LDAP URL given on the command line using the
methods provided by C<LWP::Protocol::ldap> message, connects to the
LDAP server given in the URL, and performs the search described in the URL.

If user and password are given, they are used to do a simple bind before the search.

The output depends on the option B<-f|--format>.

=head1 OPTIONS

=over 4

=item B<-f|--format> {C<dsml>|C<html>|C<json>|C<ldif>}

Specifies the output format to use.

For the format C<json> to work, the Perl module C<JSON> needs to be installed.

=item B<-u|--user>  I<user>

Specifies the user to log on to the LDAP server.
The I<user> must be a DN.

=item B<-p|--password> I<password>

Specifies the password with which the I<user> logs on to the LDAP server.

=back

=head1 ARGUMENTS

LWPsearch.pl only takes one argument.

B<LDAP-URL>, an LDAP URL as described in L<RFC 4516|http://tools.ietf.org/html/rfc4516>.

=head1 AUTHOR

Peter Marschall <peter@adpm.de>

=head1 COPYRIGHT & LICENSE

Copyright (c) 2012 Peter Marschall All rights reserved.
This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

