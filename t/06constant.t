#!perl -w

BEGIN {
  for (1,2) { require Net::LDAP::Constant; }
}

use Net::LDAP::Util qw(ldap_error_name);;

my @constant = qw(
  LDAP_SUCCESS
  LDAP_OPERATIONS_ERROR
  LDAP_PROTOCOL_ERROR
  LDAP_TIMELIMIT_EXCEEDED
  LDAP_SIZELIMIT_EXCEEDED
  LDAP_COMPARE_FALSE
  LDAP_COMPARE_TRUE
  LDAP_STRONG_AUTH_NOT_SUPPORTED
  LDAP_STRONG_AUTH_REQUIRED
  LDAP_PARTIAL_RESULTS
  LDAP_REFERRAL
  LDAP_ADMIN_LIMIT_EXCEEDED
  LDAP_UNAVAILABLE_CRITICAL_EXT
  LDAP_CONFIDENTIALITY_REQUIRED
  LDAP_SASL_BIND_IN_PROGRESS
  15
  LDAP_NO_SUCH_ATTRIBUTE
  LDAP_UNDEFINED_TYPE
  LDAP_INAPPROPRIATE_MATCHING
  LDAP_CONSTRAINT_VIOLATION
  LDAP_TYPE_OR_VALUE_EXISTS
  LDAP_INVALID_SYNTAX
  22
  23
  24
  25
  26
  27
  28
  29
  30
  31
  LDAP_NO_SUCH_OBJECT
  LDAP_ALIAS_PROBLEM
  LDAP_INVALID_DN_SYNTAX
  LDAP_IS_LEAF
  LDAP_ALIAS_DEREF_PROBLEM
  37
  38
  39
  40
  41
  42
  43
  44
  45
  56
  57
  LDAP_INAPPROPRIATE_AUTH
  LDAP_INVALID_CREDENTIALS
  LDAP_INSUFFICIENT_ACCESS
  LDAP_BUSY
  LDAP_UNAVAILABLE
  LDAP_UNWILLING_TO_PERFORM
  LDAP_LOOP_DETECT
  55
  56
  57
  58
  59
  LDAP_SORT_CONTROL_MISSING
  LDAP_INDEX_RANGE_ERROR
  62
  63
  LDAP_NAMING_VIOLATION
  LDAP_OBJECT_CLASS_VIOLATION
  LDAP_NOT_ALLOWED_ON_NONLEAF
  LDAP_NOT_ALLOWED_ON_RDN
  LDAP_ALREADY_EXISTS
  LDAP_NO_OBJECT_CLASS_MODS
  LDAP_RESULTS_TOO_LARGE
  LDAP_AFFECTS_MULTIPLE_DSAS
  72
  73
  74
  75
  LDAP_VLV_ERROR
  77
  78
  79
  LDAP_OTHER
  LDAP_SERVER_DOWN
  LDAP_LOCAL_ERROR
  LDAP_ENCODING_ERROR
  LDAP_DECODING_ERROR
  LDAP_TIMEOUT
  LDAP_AUTH_UNKNOWN
  LDAP_FILTER_ERROR
  LDAP_USER_CANCELED
  LDAP_PARAM_ERROR
  LDAP_NO_MEMORY
  LDAP_CONNECT_ERROR
  LDAP_NOT_SUPPORTED
  LDAP_CONTROL_NOT_FOUND
  LDAP_NO_RESULTS_RETURNED
  LDAP_MORE_RESULTS_TO_RETURN
  LDAP_CLIENT_LOOP
  LDAP_REFERRAL_LIMIT_EXCEEDED
);

print "1..", scalar(@constant),"\n";
my $i = 0;
while(my $const = $constant[$i]) {
  my $name = ldap_error_name($i);
  $const = sprintf("LDAP error code %d(0x%02X)",$i,$i) unless $const =~ /\D/;
  print "not " if !$name or $name ne $const;
  ++$i;
  print "ok $i  # $name $const\n";
}
