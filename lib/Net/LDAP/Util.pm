# Copyright (c) 1999-2004 Graham Barr <gbarr@pobox.com> and
# Norbert Klasen <norbert.klasen@daasi.de> All Rights Reserved.
# This program is free software; you can redistribute it and/or modify
# it under the same terms as Perl itself.

package Net::LDAP::Util;

=head1 NAME

Net::LDAP::Util - Utility functions

=head1 SYNOPSIS

  use Net::LDAP::Util qw(ldap_error_text
                         ldap_error_name
                         ldap_error_desc
                        );

  $mesg = $ldap->search( .... );

  die "Error ",ldap_error_name($mesg)  if $mesg->code;

=head1 DESCRIPTION

B<Net::LDAP::Util> is a collection of utility functions for use with
the L<Net::LDAP> modules.

=head1 FUNCTIONS

=over 4

=cut

require Exporter;
require Net::LDAP::Constant;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(
  ldap_error_name
  ldap_error_text
  ldap_error_desc
  canonical_dn
  ldap_explode_dn
  escape_filter_value
  unescape_filter_value
  escape_dn_value
  unescape_dn_value
  ldap_url_parse
  generalizedTime_to_time
  time_to_generalizedTime
);
our %EXPORT_TAGS = (
	error	=> [ qw(ldap_error_name ldap_error_text ldap_error_desc) ],
	filter	=> [ qw(escape_filter_value unescape_filter_value) ],
	dn    	=> [ qw(canonical_dn ldap_explode_dn
	                escape_dn_value unescape_dn_value) ],
	escape 	=> [ qw(escape_filter_value unescape_filter_value
	                escape_dn_value unescape_dn_value) ],
	url   	=> [ qw(ldap_url_parse) ],
	time	=> [ qw(generalizedTime_to_time time_to_generalizedTime) ],
);

our $VERSION = '0.19';

=item ldap_error_name ( ERR )

Returns the name corresponding with ERR. ERR can either be an LDAP
error number, or a C<Net::LDAP::Message> object containing an error
code. If the error is not known the a string in the form C<"LDAP error
code %d(0x%02X)"> is returned.

=cut

# Defined in Constant.pm

=item ldap_error_text ( ERR )

Returns the text from the POD description for the given error. ERR can
either be an LDAP error code, or a C<Net::LDAP::Message> object
containing an LDAP error code. If the error code given is unknown then
C<undef> is returned.

=cut

# Defined in Constant.pm

=item ldap_error_desc ( ERR )

Returns a short text description of the error. ERR can either be an
LDAP error code or a C<Net::LDAP::Message> object containing an LDAP
error code.

=cut

my @err2desc = (
  'Success',                                             # 0x00 LDAP_SUCCESS
  'Operations error',                                    # 0x01 LDAP_OPERATIONS_ERROR
  'Protocol error',                                      # 0x02 LDAP_PROTOCOL_ERROR
  'Timelimit exceeded',                                  # 0x03 LDAP_TIMELIMIT_EXCEEDED
  'Sizelimit exceeded',                                  # 0x04 LDAP_SIZELIMIT_EXCEEDED
  'Compare false',                                       # 0x05 LDAP_COMPARE_FALSE
  'Compare true',                                        # 0x06 LDAP_COMPARE_TRUE
  'Strong authentication not supported',                 # 0x07 LDAP_STRONG_AUTH_NOT_SUPPORTED
  'Strong authentication required',                      # 0x08 LDAP_STRONG_AUTH_REQUIRED
  'Partial results and referral received',               # 0x09 LDAP_PARTIAL_RESULTS
  'Referral received',                                   # 0x0a LDAP_REFERRAL
  'Admin limit exceeded',                                # 0x0b LDAP_ADMIN_LIMIT_EXCEEDED
  'Critical extension not available',                    # 0x0c LDAP_UNAVAILABLE_CRITICAL_EXT
  'Confidentiality required',                            # 0x0d LDAP_CONFIDENTIALITY_REQUIRED
  'SASL bind in progress',                               # 0x0e LDAP_SASL_BIND_IN_PROGRESS
  undef,
  'No such attribute',                                   # 0x10 LDAP_NO_SUCH_ATTRIBUTE
  'Undefined attribute type',                            # 0x11 LDAP_UNDEFINED_TYPE
  'Inappropriate matching',                              # 0x12 LDAP_INAPPROPRIATE_MATCHING
  'Constraint violation',                                # 0x13 LDAP_CONSTRAINT_VIOLATION
  'Type or value exists',                                # 0x14 LDAP_TYPE_OR_VALUE_EXISTS
  'Invalid syntax',                                      # 0x15 LDAP_INVALID_SYNTAX
  undef,
  undef,
  undef,
  undef,
  undef,
  undef,
  undef,
  undef,
  undef,
  undef,
  'No such object',                                      # 0x20 LDAP_NO_SUCH_OBJECT
  'Alias problem',                                       # 0x21 LDAP_ALIAS_PROBLEM
  'Invalid DN syntax',                                   # 0x22 LDAP_INVALID_DN_SYNTAX
  'Object is a leaf',                                    # 0x23 LDAP_IS_LEAF
  'Alias dereferencing problem',                         # 0x24 LDAP_ALIAS_DEREF_PROBLEM
  undef,
  undef,
  undef,
  undef,
  undef,
  undef,
  undef,
  undef,
  undef,
  undef,
  'Proxy authorization failure',                         # 0x2F LDAP_PROXY_AUTHZ_FAILURE
  'Inappropriate authentication',                        # 0x30 LDAP_INAPPROPRIATE_AUTH
  'Invalid credentials',                                 # 0x31 LDAP_INVALID_CREDENTIALS
  'Insufficient access',                                 # 0x32 LDAP_INSUFFICIENT_ACCESS
  'DSA is busy',                                         # 0x33 LDAP_BUSY
  'DSA is unavailable',                                  # 0x34 LDAP_UNAVAILABLE
  'DSA is unwilling to perform',                         # 0x35 LDAP_UNWILLING_TO_PERFORM
  'Loop detected',                                       # 0x36 LDAP_LOOP_DETECT
  undef,
  undef,
  undef,
  undef,
  undef,
  'Sort control missing',                                # 0x3C LDAP_SORT_CONTROL_MISSING
  'Index range error',                                   # 0x3D LDAP_INDEX_RANGE_ERROR
  undef,
  undef,
  'Naming violation',                                    # 0x40 LDAP_NAMING_VIOLATION
  'Object class violation',                              # 0x41 LDAP_OBJECT_CLASS_VIOLATION
  'Operation not allowed on nonleaf',                    # 0x42 LDAP_NOT_ALLOWED_ON_NONLEAF
  'Operation not allowed on RDN',                        # 0x43 LDAP_NOT_ALLOWED_ON_RDN
  'Already exists',                                      # 0x44 LDAP_ALREADY_EXISTS
  'Cannot modify object class',                          # 0x45 LDAP_NO_OBJECT_CLASS_MODS
  'Results too large',                                   # 0x46 LDAP_RESULTS_TOO_LARGE
  'Affects multiple servers',                            # 0x47 LDAP_AFFECTS_MULTIPLE_DSAS
  undef,
  undef,
  undef,
  undef,
  'VLV error',                                           # 0x4C LDAP_VLV_ERROR
  undef,
  undef,
  undef,
  'Unknown error',                                       # 0x50 LDAP_OTHER
  'Can\'t contact LDAP server',                           # 0x51 LDAP_SERVER_DOWN
  'Local error',                                         # 0x52 LDAP_LOCAL_ERROR
  'Encoding error',                                      # 0x53 LDAP_ENCODING_ERROR
  'Decoding error',                                      # 0x54 LDAP_DECODING_ERROR
  'Timed out',                                           # 0x55 LDAP_TIMEOUT
  'Unknown authentication method',                       # 0x56 LDAP_AUTH_UNKNOWN
  'Bad search filter',                                   # 0x57 LDAP_FILTER_ERROR
  'Canceled',                                            # 0x58 LDAP_USER_CANCELED
  'Bad parameter to an ldap routine',                    # 0x59 LDAP_PARAM_ERROR
  'Out of memory',                                       # 0x5a LDAP_NO_MEMORY
  'Can\'t connect to the LDAP server',                    # 0x5b LDAP_CONNECT_ERROR
  'Not supported by this version of the LDAP protocol',  # 0x5c LDAP_NOT_SUPPORTED
  'Requested LDAP control not found',                    # 0x5d LDAP_CONTROL_NOT_FOUND
  'No results returned',                                 # 0x5e LDAP_NO_RESULTS_RETURNED
  'More results to return',                              # 0x5f LDAP_MORE_RESULTS_TO_RETURN
  'Client detected loop',                                # 0x60 LDAP_CLIENT_LOOP
  'Referral hop limit exceeded',                         # 0x61 LDAP_REFERRAL_LIMIT_EXCEEDED
);

sub ldap_error_desc {
  my $code = (ref($_[0]) ? $_[0]->code : $_[0]);
  $err2desc[$code] || sprintf('LDAP error code %d(0x%02X)', $code, $code);
}





=item canonical_dn ( DN [ , OPTIONS ] )

Returns the given B<DN> in a canonical form. Returns undef if B<DN> is
not a valid Distinguished Name. (Note: The empty string "" is a valid DN.)
B<DN> can either be a string or reference to an array of hashes as returned by
ldap_explode_dn, which is useful when constructing a DN.

It performs the following operations on the given B<DN>:

=over 4

=item *

Removes the leading 'OID.' characters if the type is an OID instead
of a name.

=item *

Escapes all RFC 4514 special characters (",", "+", """, "\", "E<lt>",
"E<gt>", ";", "#", "=", " "), slashes ("/"), and any other character
where the ASCII code is E<lt> 32 as \hexpair.

=item *

Converts all leading and trailing spaces in values to be \20.

=item *

If an RDN contains multiple parts, the parts are re-ordered so that
the attribute type names are in alphabetical order.

=back

B<OPTIONS> is a list of name/value pairs, valid options are:

=over 4

=item casefold

Controls case folding of attribute type names. Attribute values are not
affected by this option. The default is to uppercase. Valid values are:

=over 4

=item lower

Lowercase attribute type names.

=item upper

Uppercase attribute type names. This is the default.

=item none

Do not change attribute type names.

=back

=item mbcescape

If TRUE, characters that are encoded as a multi-octet UTF-8 sequence
will be escaped as \(hexpair){2,*}.

=item reverse

If TRUE, the RDN sequence is reversed.

=item separator

Separator to use between RDNs. Defaults to comma (',').

=back

=cut

sub canonical_dn($%) {
  my ($dn, %opt) = @_;

  return $dn  unless defined $dn and $dn ne '';

  # create array of hash representation
  my $rdns = ref($dn) eq 'ARRAY'
		? $dn
		: ldap_explode_dn( $dn, casefold => $opt{casefold} || 'upper')
    or return undef; #error condition

  # assign specified or default separator value
  my $separator = $opt{separator} || ',';

  # flatten all RDNs into strings
  my @flatrdns =
    map {
      my $rdn = $_;
      my @types = sort keys %$rdn;
      join('+',
        map {
          my $val = $rdn->{$_};

          if ( ref($val) ) {
            $val = '#' . unpack('H*', $$val);
          } else {
            #escape insecure characters and optionally MBCs
            if ( $opt{mbcescape} ) {
              $val =~ s/([\x00-\x1f\/\\",=+<>#;\x7f-\xff])/
                sprintf('\\%02x', ord($1))/xeg;
            } else {
              $val =~ s/([\x00-\x1f\/\\",=+<>#;])/
                sprintf('\\%02x', ord($1))/xeg;
            }
            #escape leading and trailing whitespace
            $val =~ s/(^\s+|\s+$)/
              '\\20' x length $1/xeg;
            #compact multiple spaces
            $val =~ s/\s+/ /g;
          }

          # case fold attribute type and create return value
          if ( !$opt{casefold} || $opt{casefold} eq 'upper' ) {
            (uc $_)."=$val";
          } elsif ( $opt{casefold} eq 'lower' ) {
            (lc $_)."=$val";
          } else {
            "$_=$val";
          }
        } @types);
    } @$rdns;

  # join RDNs into string, optionally reversing order
  $opt{reverse}
    ? join($separator, reverse @flatrdns)
    : join($separator, @flatrdns);
}


=item ldap_explode_dn ( DN [ , OPTIONS ] )

Explodes the given B<DN> into an array of hashes and returns a reference to this
array. Returns undef if B<DN> is not a valid Distinguished Name.

A Distinguished Name is a sequence of Relative Distinguished Names (RDNs), which
themselves are sets of Attributes. For each RDN a hash is constructed with the
attribute type names as keys and the attribute values as corresponding values.
These hashes are then stored in an array in the order in which they appear
in the DN.

For example, the DN 'OU=Sales+CN=J. Smith,DC=example,DC=net' is exploded to:
 [
   {
     'OU' =E<gt> 'Sales',
     'CN' =E<gt> 'J. Smith'
   },
   {
     'DC' =E<gt> 'example'
   },
   {
     'DC' =E<gt> 'net'
   }
 ]

(RFC4514 string) DNs might also contain values, which are the bytes of the
BER encoding of the X.500 AttributeValue rather than some LDAP string syntax.
These values are hex-encoded and prefixed with a #. To distinguish such BER
values, ldap_explode_dn uses references to the actual values,
e.g. '1.3.6.1.4.1.1466.0=#04024869,DC=example,DC=com' is exploded to:
 [
   {
     '1.3.6.1.4.1.1466.0' =E<gt> "\004\002Hi"
   },
   {
     'DC' =E<gt> 'example'
   },
   {
     'DC' =E<gt> 'com'
   }
 ];

It also performs the following operations on the given DN:

=over 4

=item *

Unescape "\" followed by ",", "+", """, "\", "E<lt>", "E<gt>", ";",
"#", "=", " ", or a hexpair and strings beginning with "#".

=item *

Removes the leading 'OID.' characters if the type is an OID instead
of a name.

=back

B<OPTIONS> is a list of name/value pairs, valid options are:

=over 4

=item casefold

Controls case folding of attribute types names. Attribute values are not
affected by this option. The default is to uppercase. Valid values are:

=over 4

=item lower

Lowercase attribute types names.

=item upper

Uppercase attribute type names. This is the default.

=item none

Do not change attribute type names.

=back

=item reverse

If TRUE, the RDN sequence is reversed.

=back

=cut

sub ldap_explode_dn($%) {
  my ($dn, %opt) = @_;
  return undef  unless defined $dn;
  return []  if $dn eq '';

  my $pair = qr/\\(?:[\\"+,;<> #=]|[0-9A-F]{2})/i;

  my (@dn, %rdn);
  while (
  $dn =~ /\G(?:
    \s*
    ((?i)[A-Z][-A-Z0-9]*|(?:oid\.)?\d+(?:\.\d+)*)	# attribute type
    \s*
    =
    [ ]*
    (							# attribute value
      (?:(?:[^\x00 "\#+,;<>\\\x80-\xBF]|$pair)		# string
         (?:(?:[^\x00"+,;<>\\]|$pair)*
            (?:[^\x00 "+,;<>\\]|$pair))?)?
      |
      \#(?:[0-9a-fA-F]{2})+				# hex string
      |
      "(?:[^\\"]+|$pair)*"				# "-quoted string, only for v2
    )
    [ ]*
    (?:([;,+])\s*(?=\S)|$)				# separator
    )\s*/gcx)
  {
    my($type, $val, $sep) = ($1, $2, $3);

    $type =~ s/^oid\.//i;	#remove leading "oid."

    if ( !$opt{casefold} || $opt{casefold} eq 'upper' ) {
      $type = uc $type;
    } elsif ( $opt{casefold} eq 'lower' ) {
      $type = lc($type);
    }

    if ( $val =~ s/^#// ) {
      # decode hex-encoded BER value
      my $tmp = pack('H*', $val);
      $val = \$tmp;
    } else {
      # remove quotes
      $val =~ s/^"(.*)"$/$1/;
      # unescape characters
      $val =~ s/\\([\\ ",=+<>#;]|[0-9a-fA-F]{2})
           /length($1)==1 ? $1 : chr(hex($1))
           /xeg;
    }

    $rdn{$type} = $val;

    unless (defined $sep and $sep eq '+') {
      if ( $opt{reverse} ) {
        unshift @dn, { %rdn };
      } else {
        push @dn, { %rdn };
      }
      %rdn = ();
    }
  }

  length($dn) == (pos($dn)||0)
    ? \@dn
    : undef;
}


=item escape_filter_value ( VALUES )

Escapes the given B<VALUES> according to RFC 4515 so that they
can be safely used in LDAP filters.

Any control characters with an ASCII code E<lt> 32 as well as the
characters with special meaning in LDAP filters "*", "(", ")",
and "\" the backslash are converted into the representation
of a backslash followed by two hex digits representing the
hexadecimal value of the character.

Returns the converted list in list mode and the first element
in scalar mode.

=cut

## convert a list of values into its LDAP filter encoding ##
# Synopsis:  @escaped = escape_filter_value(@values)
sub escape_filter_value(@)
{
my @values = @_;

  map { $_ =~ s/([\x00-\x1F\*\(\)\\])/'\\'.unpack('H2', $1)/oge; } @values;

  return(wantarray ? @values : $values[0]);
}


=item unescape_filter_value ( VALUES )

Undoes the conversion done by B<escape_filter_value()>.

Converts any sequences of a backslash followed by two hex digits
into the corresponding character.

Returns the converted list in list mode and the first element
in scalar mode.

=cut

## convert a list of values from its LDAP filter encoding ##
# Synopsis:  @values = unescape_filter_value(@escaped)
sub unescape_filter_value(@)
{
my @values = @_;

  map { $_ =~ s/\\([0-9a-fA-F]{2})/pack('H2', $1)/oge; } @values;

  return(wantarray ? @values : $values[0]);
}


=item escape_dn_value ( VALUES )

Escapes the given B<VALUES> according to RFC 4514 so that they
can be safely used in LDAP DNs.

The characters ",", "+", """, "\", "E<lt>", "E<gt>", ";", "#", "=" with
a special meaning in section 2.4 of RFC 4514 are preceded by a backslash.
Control characters with an ASCII code E<lt> 32 are represented
as \hexpair.
Finally all leading and trailing spaces are converted to
sequences of \20.

Returns the converted list in list mode and the first element
in scalar mode.

=cut

## convert a list of values into its DN encoding ##
# Synopsis:  @escaped = escape_dn_value(@values)
sub escape_dn_value(@)
{
my @values = @_;

  map { $_ =~ s/([\\",=+<>#;])/\\$1/og;
        $_ =~ s/([\x00-\x1F])/'\\'.unpack('H2', $1)/oge;
        $_ =~ s/(^ +| +$)/'\\20' x length($1)/oge; } @values;

  return(wantarray ? @values : $values[0]);
}


=item unescape_dn_value ( VALUES )

Undoes the conversion done by B<escape_dn_value()>.

Any escape sequence starting with a backslash - hexpair or
special character - will be transformed back to the
corresponding character.

Returns the converted list in list mode and the first element
in scalar mode.

=cut

## convert a list of values from its LDAP filter encoding ##
# Synopsis:  @values = unescape_dn_value(@escaped)
sub unescape_dn_value(@)
{
my @values = @_;

  map { $_ =~ s/\\([\\",=+<>#;]|[0-9a-fA-F]{2})
               /(length($1)==1) ? $1 : pack('H2', $1)
               /ogex; } @values;

  return(wantarray ? @values : $values[0]);
}


=item ldap_url_parse ( LDAP-URL [, OPTIONS ] )

Parse an B<LDAP-URL> conforming to RFC 4516 into a hash containing its elements.

For easy cooperation with LDAP queries, the hash keys for the elements
used in LDAP search operations are named after the parameters to
L<Net::LDAP/search>.

In extension to RFC 4516, the socket path for URLs with the scheme C<ldapi>
will be stored in the hash key named C<path>.

If any element is omitted, the result depends on the setting of the option
C<defaults>.

B<OPTIONS> is a list of key/value pairs with the following keys recognized:

=over 4

=item defaults

A Boolean option that determines whether default values according to RFC 4516
shall be returned for missing URL elements.

If set to TRUE, default values are returned, with C<ldap_url_parse>
using the following defaults in extension to RFC 4516.

=over 4

=item *

The default port for C<ldaps> URLs is C<636>.

=item *

The default path for C<ldapi> URLs is the contents of the environment variable
C<LDAPI_SOCK>. If that is not defined or empty, then C</var/run/ldapi> is used.

This is consistent with the behaviour of L<Net::LDAP/new>.

=item *

The default C<host> name for C<ldap> and C<ldaps> URLs is C<localhost>.

=back

When set to FALSE, no default values are used.

This leaves all keys in the resulting hash undefined where the corresponding
URL element is empty.

To distinguish between an empty base DN and an undefined base DN,
C<ldap_url_parse> uses the slash between the host:port resp. path
part of the URL and the base DN part of the URL.
With the slash present, the hash key C<base> is set to the empty string,
without it, it is left undefined.

Leaving away the C<defaults> option entirely is equivalent to setting it to TRUE.

=back

Returns the hash in list mode, or the reference to the hash in scalar mode.

=cut

## parse an LDAP URL into its various elements
# Synopsis: {$elementref,%elements} = ldap_url_parse($url)
sub ldap_url_parse($@)
{
my $url = shift;
my %opt = @_;

  eval { require URI };
  return  if ($@);

  my $uri = URI->new($url);
  return  unless ($uri && ref($uri) =~ /^URI::ldap[is]?$/);

  $opt{defaults} = 1  unless (exists($opt{defaults}));

  my %elements = ( scheme => $uri->scheme );

  $uri = $uri->canonical;	# canonical form
  $url = $uri->as_string;	# normalize

  if ($elements{scheme} eq 'ldapi') {
    $elements{path} = $uri->un_path || $ENV{LDAPI_SOCK} || '/var/run/ldapi'
      if ($opt{defaults} || $uri->un_path);
  }
  else {
    $elements{host} = $uri->host || 'localhost'
      if ($opt{defaults} || $uri->host);

    $elements{port} = $uri->port || ($elements{scheme} eq 'ldaps' ? 636 : 389)
      if ($opt{defaults} || $uri->port);
  }

  $elements{base}       = $uri->dn
      if ($opt{defaults} || $uri->dn || $url =~ m{^ldap[is]?://[^/]*/});

  $elements{attrs}      = [ $uri->attributes ]
      if ($opt{defaults} || $uri->attributes);

  $elements{scope}      = $uri->scope
      if ($opt{defaults} || $uri->_scope);

  $elements{filter}     = $uri->filter
      if ($opt{defaults} || $uri->_filter);

  $elements{extensions} = [ $uri->extensions ]
      if ($opt{defaults} || $uri->extensions);

  #return _error($ldap, $mesg, LDAP_LOCAL_ERROR, "unhandled critical URL extension")
  #  if (grep(/^!/, keys(%extns)));

  return wantarray ? %elements : \%elements;
}


=item generalizedTime_to_time ( GENERALIZEDTIME )

Convert the generalizedTime string B<GENERALIZEDTIME>, which is expected
to match the template C<YYYYmmddHH[MM[SS]][(./,)d...](Z|(+/-)HH[MM])>
to a floating point number compatible with UNIX time
(i.e. the integral part of the number is a UNIX time).

Returns an extended UNIX time or C<undef> on error.

Times in years smaller than 1000 will lead to C<undef> being returned.
This restriction is a direct effect of the year value interpretation rules
in Time::Local.

B<Note:> this function depends on Perl's implementation of time and Time::Local.
See L<Time::Local/Limits of time_t>, L<Time::Local/Negative Epoch Values>, and
L<perlport/gmtime> for restrictions in older versions of Perl.

=cut

sub generalizedTime_to_time($)
{
my $generalizedTime = shift;

  if ($generalizedTime =~ /^\s*(\d{4})(\d{2})(\d{2})
                               (\d{2})(?:(\d{2})(\d{2})?)?
                               (?:[.,](\d+))?\s*(Z|[+-]\d{2}(?:\d{2})?)\s*$/x) {
    my ($year,$month,$day,$hour,$min,$sec,$dec,$offset) = ($1,$2,$3,$4,$5,$6,$7,$8);

    # Time::Local's timegm() interpret years strangely
    if ($year >= 1000) {
      $dec = defined($dec) ? "0.$dec" : 0;

      # decimals in case of missing minutes / seconds - see RFC 4517
      if (!defined($min)) {
        $min = 0;

        if ($dec) {
          $min = int(60 * $dec);
          $dec = sprintf('%.4f', 60 * $dec - $min);
        }
      }
      if (!defined($sec)) {
        $sec = 0;

        if ($dec) {
          $sec = int(60 * $dec);
          $dec = sprintf('%.2f', 60 * $dec - $sec);
        }
      }

      eval { require Time::Local; };
      unless ($@) {
        my $time;

        eval { $time = Time::Local::timegm($sec,$min,$hour,$day,$month-1,$year); };
        unless ($@) {
          if ($offset =~ /^([+-])(\d{2})(\d{2})?$/) {
            my ($direction,$hourdelta,$mindelta) = ($1,$2,$3);

            $mindelta = 0  if (!$mindelta);
            $time += ($direction eq '-')
                     ? 3600 * $hourdelta + 60 * $mindelta
                     : -3600 * $hourdelta - 60 * $mindelta;
          }

          # make decimal part directional
          if ($dec != 0) {
            my $sign = '';

            if ($time < 0) {
              $dec = 1 - $dec;
              $time++; 
              $sign = '-'  if ($time == 0);
            }
            $dec =~ s/^0\.//;
            $time = "${sign}${time}.${dec}";
          }

          return $time;
        }
      }
    }
  }

  return undef;
}


=item time_to_generalizedTime ( TIME [, OPTIONS ] )

Convert the UNIX time B<TIME> to a generalizedTime string.

In extension to UNIX times, B<TIME> may be a floating point number,
the decimal part will be used for the resulting generalizedTime.

B<OPTIONS> is a list of key/value pairs. The following keys are recognized:

=over 4

=item AD

Take care of an ActiveDirectory peculiarity to always require decimals.

=back

Returns the generalizedTime string, or C<undef> on error.

Times before BC or after year 9999 result in C<undef>
as they cannot be represented in the generalizedTime format.

B<Note:> this function depends on Perl's implementation of gmtime.
See L<Time::Local/Limits of time_t>, L<Time::Local/Negative Epoch Values>, and
L<perlport/gmtime> for restrictions in older versions of Perl.

=cut

sub time_to_generalizedTime($;@)
{
my $arg = shift;
my %opt = @_;

  if ($arg =~ /^(\-?)(\d*)(?:[.,](\d*))?$/) {
    my ($sign, $time, $dec) = ($1, $2, $3);

    $dec = defined($dec) ? "0.$dec" : 0;

    # decimal part of time is directional: make sure to have it positive
    if ($sign) {
      if ($dec != 0) {
        $time++;
        $dec = 1 - $dec;
      }
      $time = -$time;
    }

    my ($sec,$min,$hour,$mday,$month,$year,$wday,$yday,$isdst) = gmtime(int($time));

    # generalizedTime requires 4-digit year without sign
    return undef  if ($year < -1900 || $year > 8099);

    $dec =~ s/^0?\.(\d*?)0*$/$1/;

    return sprintf("%04d%02d%02d%02d%02d%02d%sZ",
                   $year+1900, $month+1, $mday, $hour, $min, $sec,
                   # AD peculiarity: if there are no decimals, add .0 as decimals
                   ($dec ? ('.'.$dec) : ($opt{AD} ? '.0' : '')));
  }

  return undef;
}


=back


=head1 AUTHOR

Graham Barr E<lt>gbarr@pobox.comE<gt>

=head1 COPYRIGHT

Copyright (c) 1999-2004 Graham Barr. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

ldap_explode_dn and canonical_dn also

(c) 2002 Norbert Klasen, norbert.klasen@daasi.de, All Rights Reserved.

=cut

1;
