# Copyright (c) 1998-2009 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Constant;

our $VERSION = '0.23';

use Exporter qw(import);

my @err2name;

local $_;
while (<DATA>) {
  last  if /^=cut/;
  my $protocol_const = /^=head2 Protocol Constants/ ... /^=head2/;
  next  unless /^=item\s+(LDAP_\S+)\s+\((.*)\)/;
  my ($name, $value) = ($1, $2);
  *{$name} = sub () { $value };
  push @EXPORT_OK, $name;
  $err2name[$value] = $name  if $protocol_const;
}


# These subs are really in Net::LDAP::Util, but need to access <DATA>
# so its easier for them to be here.


sub Net::LDAP::Util::ldap_error_name {
  my $code = 0 + (ref($_[0]) ? $_[0]->code : $_[0]);

  $err2name[$code] || sprintf('LDAP error code %d(0x%02X)', $code, $code);
}


sub Net::LDAP::Util::ldap_error_text {
  my $code = 0 + (ref($_[0]) ? $_[0]->code : $_[0]);
  my $text;

  seek(DATA, 0, 0);
  local $/=''; # paragraph mode
  local $_;
  my $n = -1;
  while (<DATA>) {
    last  if /^=head2/ and ++$n;
    last  if /^=cut/;
    next  if $n;
    if (/^=item\s+(LDAP_\S+)\s+\((\d+)\)/) {
      last  if defined $text;
      $text = ''  if $2 == $code;
    }
    elsif (defined $text) {
      $text .= $_;
    }
  }

  if (defined $text) {
    # Do some cleanup. Really should use a proper pod parser here.

    $text =~ s/^=item\s+\*\s+/ * /msg;
    $text =~ s/^=(over\s*\d*|back)//msg;
    $text =~ s/ +\n//g;
    $text =~ s/\n\n+/\n\n/g;
    $text =~ s/\n+\Z/\n/  if defined $text;
  }

  return $text;
}

1;

__DATA__

=head1 NAME

Net::LDAP::Constant - Constants for use with Net::LDAP

=head1 SYNOPSIS

 use Net::LDAP qw(LDAP_SUCCESS LDAP_PROTOCOL_ERROR);

=head1 DESCRIPTION

B<Net::LDAP::Constant> exports constant subroutines for the following LDAP
error codes.

=head2 Protocol Constants

=over 4

=item LDAP_SUCCESS (0)

Operation completed without error

=item LDAP_OPERATIONS_ERROR (1)

Server encountered an internal error

=item LDAP_PROTOCOL_ERROR (2)

Unrecognized version number or incorrect PDU structure

=item LDAP_TIMELIMIT_EXCEEDED (3)

The time limit on a search operation has been exceeded

=item LDAP_SIZELIMIT_EXCEEDED (4)

The maximum number of search results to return has been exceeded.

=item LDAP_COMPARE_FALSE (5)

This code is returned when a compare request completes and the attribute value
given is not in the entry specified

=item LDAP_COMPARE_TRUE (6)

This code is returned when a compare request completes and the attribute value
given is in the entry specified

=item LDAP_AUTH_METHOD_NOT_SUPPORTED (7)

Unrecognized SASL mechanism name

=item LDAP_STRONG_AUTH_NOT_SUPPORTED (7)

Unrecognized SASL mechanism name

=item LDAP_STRONG_AUTH_REQUIRED (8)

The server requires authentication be performed with a SASL mechanism

=item LDAP_PARTIAL_RESULTS (9)

Returned to version 2 clients when a referral is returned. The response
will contain a list of URLs for other servers.

=item LDAP_REFERRAL (10)

The server is referring the client to another server. The response will
contain a list of URLs

=item LDAP_ADMIN_LIMIT_EXCEEDED (11)

The server has exceed the maximum number of entries to search while gathering
a list of search result candidates

=item LDAP_UNAVAILABLE_CRITICAL_EXT (12)

A control or matching rule specified in the request is not supported by
the server

=item LDAP_CONFIDENTIALITY_REQUIRED (13)

This result code is returned when confidentiality is required to perform
a given operation

=item LDAP_SASL_BIND_IN_PROGRESS (14)

The server requires the client to send a new bind request, with the same SASL
mechanism, to continue the authentication process

=item LDAP_NO_SUCH_ATTRIBUTE (16)

The request referenced an attribute that does not exist

=item LDAP_UNDEFINED_TYPE (17)

The request contains an undefined attribute type

=item LDAP_INAPPROPRIATE_MATCHING (18)

An extensible matching rule in the given filter does not apply to the specified
attribute

=item LDAP_CONSTRAINT_VIOLATION (19)

The request contains a value which does not meet with certain constraints.
This result can be returned as a consequence of

=over 4

=item *

The request was to add or modify a user password, and the password fails to
meet the criteria the server is configured to check. This could be that the
password is too short, or a recognizable word (e.g. it matches one of the
attributes in the users entry) or it matches a previous password used by
the same user.

=item *

The request is a bind request to a user account that has been locked

=back

=item LDAP_TYPE_OR_VALUE_EXISTS (20)

The request attempted to add an attribute type or value that already exists

=item LDAP_INVALID_SYNTAX (21)

Some part of the request contained an invalid syntax. It could be a search
with an invalid filter or a request to modify the schema and the given
schema has a bad syntax.

=item LDAP_NO_SUCH_OBJECT (32)

The server cannot find an object specified in the request

=item LDAP_ALIAS_PROBLEM (33)

Server encountered a problem while attempting to dereference an alias

=item LDAP_INVALID_DN_SYNTAX (34)

The request contained an invalid DN

=item LDAP_IS_LEAF (35)

The specified entry is a leaf entry

=item LDAP_ALIAS_DEREF_PROBLEM (36)

Server encountered a problem while attempting to dereference an alias

=item LDAP_PROXY_AUTHZ_FAILURE (47)

The user bound is not authorized to assume the requested identity.

=item LDAP_INAPPROPRIATE_AUTH (48)

The server requires the client which had attempted to bind anonymously or
without supplying credentials to provide some form of credentials

=item LDAP_INVALID_CREDENTIALS (49)

The wrong password was supplied or the SASL credentials could not be processed

=item LDAP_INSUFFICIENT_ACCESS (50)

The client does not have sufficient access to perform the requested
operation

=item LDAP_BUSY (51)

The server is too busy to perform requested operation

=item LDAP_UNAVAILABLE (52)

The server in unavailable to perform the request, or the server is
shutting down

=item LDAP_UNWILLING_TO_PERFORM (53)

The server is unwilling to perform the requested operation

=item LDAP_LOOP_DETECT (54)

The server was unable to perform the request due to an internal loop detected

=item LDAP_SORT_CONTROL_MISSING (60)

The search contained a "virtual list view" control, but not a server-side
sorting control, which is required when a "virtual list view" is given.

=item LDAP_INDEX_RANGE_ERROR (61)

The search contained a control for a "virtual list view" and the results
exceeded the range specified by the requested offsets.

=item LDAP_NAMING_VIOLATION (64)

The request violates the structure of the DIT

=item LDAP_OBJECT_CLASS_VIOLATION (65)

The request specifies a change to an existing entry or the addition of a new
entry that does not comply with the servers schema

=item LDAP_NOT_ALLOWED_ON_NONLEAF (66)

The requested operation is not allowed on an entry that has child entries

=item LDAP_NOT_ALLOWED_ON_RDN (67)

The requested operation ill affect the RDN of the entry

=item LDAP_ALREADY_EXISTS (68)

The client attempted to add an entry that already exists. This can occur as
a result of

=over 4

=item *

An add request was submitted with a DN that already exists

=item *

A modify DN requested was submitted, where the requested new DN already exists

=item *

The request is adding an attribute to the schema and an attribute with the
given OID or name already exists

=back

=item LDAP_NO_OBJECT_CLASS_MODS (69)

Request attempt to modify the object class of an entry that should not be
modified

=item LDAP_RESULTS_TOO_LARGE (70)

The results of the request are to large

=item LDAP_AFFECTS_MULTIPLE_DSAS (71)

The requested operation needs to be performed on multiple servers where
the requested operation is not permitted

=item LDAP_VLV_ERROR (76)

A VLV error has occurred

=item LDAP_OTHER (80)

An unknown error has occurred

=item LDAP_SERVER_DOWN (81)

C<Net::LDAP> cannot establish a connection or the connection has been lost

=item LDAP_LOCAL_ERROR (82)

An error occurred in C<Net::LDAP>

=item LDAP_ENCODING_ERROR (83)

C<Net::LDAP> encountered an error while encoding the request packet that would
have been sent to the server

=item LDAP_DECODING_ERROR (84)

C<Net::LDAP> encountered an error while decoding a response packet from
the server.

=item LDAP_TIMEOUT (85)

C<Net::LDAP> timeout while waiting for a response from the server

=item LDAP_AUTH_UNKNOWN (86)

The method of authentication requested in a bind request is unknown to
the server

=item LDAP_FILTER_ERROR (87)

An error occurred while encoding the given search filter.

=item LDAP_USER_CANCELED (88)

The user canceled the operation

=item LDAP_PARAM_ERROR (89)

An invalid parameter was specified

=item LDAP_NO_MEMORY (90)

Out of memory error

=item LDAP_CONNECT_ERROR (91)

A connection to the server could not be established

=item LDAP_NOT_SUPPORTED (92)

An attempt has been made to use a feature not supported by Net::LDAP

=item LDAP_CONTROL_NOT_FOUND (93)

The controls required to perform the requested operation were not
found.

=item LDAP_NO_RESULTS_RETURNED (94)

No results were returned from the server.

=item LDAP_MORE_RESULTS_TO_RETURN (95)

There are more results in the chain of results.

=item LDAP_CLIENT_LOOP (96)

A loop has been detected. For example when following referrals.

=item LDAP_REFERRAL_LIMIT_EXCEEDED (97)

The referral hop limit has been exceeded.

=item LDAP_CANCELED (118)

Operation was canceled

=item LDAP_NO_SUCH_OPERATION (119)

Server has no knowledge of the operation requested for cancellation

=item LDAP_TOO_LATE (120)

Too late to cancel the outstanding operation

=item LDAP_CANNOT_CANCEL (121)

The identified operation does not support cancellation or
the cancel operation cannot be performed

=item LDAP_ASSERTION_FAILED (122)

An assertion control given in the LDAP operation evaluated to false
causing the operation to not be performed.

=item LDAP_SYNC_REFRESH_REQUIRED (4096)

Refresh Required.

=back

=head2 Control OIDs

=over 4

=item LDAP_CONTROL_SORTREQUEST (1.2.840.113556.1.4.473)

=item LDAP_CONTROL_SORTRESULT (1.2.840.113556.1.4.474)

=item LDAP_CONTROL_SORTRESPONSE (1.2.840.113556.1.4.474)

=item LDAP_CONTROL_VLVREQUEST (2.16.840.1.113730.3.4.9)

=item LDAP_CONTROL_VLVRESPONSE (2.16.840.1.113730.3.4.10)

=item LDAP_CONTROL_PROXYAUTHORIZATION (2.16.840.1.113730.3.4.18)

=item LDAP_CONTROL_PROXYAUTHENTICATION (2.16.840.1.113730.3.4.18)

=item LDAP_CONTROL_PAGED (1.2.840.113556.1.4.319)

=item LDAP_CONTROL_TREE_DELETE (1.2.840.113556.1.4.805)

=item LDAP_CONTROL_MATCHEDVALS (1.2.826.0.1.3344810.2.2)

=item LDAP_CONTROL_MATCHEDVALUES (1.2.826.0.1.3344810.2.3)

=item LDAP_CONTROL_MANAGEDSAIT (2.16.840.1.113730.3.4.2)

=item LDAP_CONTROL_PERSISTENTSEARCH (2.16.840.1.113730.3.4.3)

=item LDAP_CONTROL_ENTRYCHANGE (2.16.840.1.113730.3.4.7)

=item LDAP_CONTROL_PWEXPIRED (2.16.840.1.113730.3.4.4)

=item LDAP_CONTROL_PWEXPIRING (2.16.840.1.113730.3.4.5)

=item LDAP_CONTROL_REFERRALS (1.2.840.113556.1.4.616)

=item LDAP_CONTROL_RELAX (1.3.6.1.4.1.4203.666.5.12)

=item LDAP_CONTROL_PASSWORDPOLICY (1.3.6.1.4.1.42.2.27.8.5.1)

=item LDAP_CONTROL_PERMISSIVEMODIFY (1.2.840.113556.1.4.1413)

=item LDAP_CONTROL_PREREAD (1.3.6.1.1.13.1)

=item LDAP_CONTROL_POSTREAD (1.3.6.1.1.13.2)

=item LDAP_CONTROL_ASSERTION (1.3.6.1.1.12)

=item LDAP_CONTROL_DONTUSECOPY (1.3.6.1.1.22)

=item LDAP_CONTROL_NOOP (1.3.6.1.4.1.4203.666.5.2)

=item LDAP_CONTROL_SYNC (1.3.6.1.4.1.4203.1.9.1.1)

=item LDAP_CONTROL_SYNC_STATE (1.3.6.1.4.1.4203.1.9.1.2)

=item LDAP_CONTROL_SYNC_DONE (1.3.6.1.4.1.4203.1.9.1.3)

=item LDAP_SYNC_INFO (1.3.6.1.4.1.4203.1.9.1.4)

=back

=head2 Control constants

=over 4

=item LDAP_PP_PASSWORD_EXPIRED (0) [LDAP_CONTROL_PASSWORDPOLICY]

The account's password has expired.

=item LDAP_PP_ACCOUNT_LOCKED (1) [LDAP_CONTROL_PASSWORDPOLICY]

The account is locked.

=item LDAP_PP_CHANGE_AFTER_RESET (2) [LDAP_CONTROL_PASSWORDPOLICY]

The account's password has been reset and now must be changed.

=item LDAP_PP_PASSWORD_MOD_NOT_ALLOWED (3) [LDAP_CONTROL_PASSWORDPOLICY]

The account's password may not be modified.

=item LDAP_PP_MUST_SUPPLY_OLD_PASSWORD (4) [LDAP_CONTROL_PASSWORDPOLICY]

The old password must also be supplied when setting a new password.

=item LDAP_PP_INSUFFICIENT_PASSWORD_QUALITY (5) [LDAP_CONTROL_PASSWORDPOLICY]

The new password was not of sufficient quality.

=item LDAP_PP_PASSWORD_TOO_SHORT (6) [LDAP_CONTROL_PASSWORDPOLICY]

The new password was too short.

=item LDAP_PP_PASSWORD_TOO_YOUNG (7) [LDAP_CONTROL_PASSWORDPOLICY]

The previous password was changed too recently.

=item LDAP_PP_PASSWORD_IN_HISTORY (8) [LDAP_CONTROL_PASSWORDPOLICY]

The new password was used too recently.

=item LDAP_SYNC_NONE (0) [LDAP_CONTROL_SYNC]

=item LDAP_SYNC_REFRESH_ONLY (1) [LDAP_CONTROL_SYNC]

=item LDAP_SYNC_RESERVED (2) [LDAP_CONTROL_SYNC]

=item LDAP_SYNC_REFRESH_AND_PERSIST (3) [LDAP_CONTROL_SYNC]

=item LDAP_SYNC_REFRESH_PRESENTS (0) [LDAP_SYNC_INFO]

=item LDAP_SYNC_REFRESH_DELETES (1) [LDAP_SYNC_INFO]

=item LDAP_TAG_SYNC_NEW_COOKIE (0x80) [LDAP_SYNC_INFO]

=item LDAP_TAG_SYNC_REFRESH_DELETE (0xa1) [LDAP_SYNC_INFO]

=item LDAP_TAG_SYNC_REFRESH_PRESENT (0xa2) [LDAP_SYNC_INFO]

=item LDAP_TAG_SYNC_ID_SET (0xa3) [LDAP_SYNC_INFO]

=item LDAP_TAG_SYNC_COOKIE (0x04) [LDAP_SYNC_INFO]

=item LDAP_TAG_REFRESHDELETES (0x01) [LDAP_SYNC_INFO]

=item LDAP_TAG_REFRESHDONE (0x01) [LDAP_SYNC_INFO]

=item LDAP_TAG_RELOAD_HINT (0x01) [LDAP_CONTROL_SYNC]

=item LDAP_SYNC_PRESENT (0) [LDAP_CONTROL_SYNC_STATE]

=item LDAP_SYNC_ADD (1) [LDAP_CONTROL_SYNC_STATE]

=item LDAP_SYNC_MODIFY (2) [LDAP_CONTROL_SYNC_STATE]

=item LDAP_SYNC_DELETE (3) [LDAP_CONTROL_SYNC_STATE]

=back

=head2 Extension OIDs

B<Net::LDAP::Constant> exports constant subroutines for the following LDAP
extension OIDs.

=over 4

=item LDAP_NOTICE_OF_DISCONNECTION (1.3.6.1.4.1.1466.20036)

Indicates that the server is about to close the connection due to an error (RFC 4511)

=item LDAP_EXTENSION_START_TLS (1.3.6.1.4.1.1466.20037)

Indicates if the server supports the Start TLS extension (RFC 4513)

=item LDAP_EXTENSION_PASSWORD_MODIFY (1.3.6.1.4.1.4203.1.11.1)

Indicates that the server supports the Password Modify extension (RFC 3062)

=item LDAP_EXTENSION_WHO_AM_I (1.3.6.1.4.1.4203.1.11.3)

Indicates that the server supports the "Who am I?" extension (RFC 4532)

=item LDAP_EXTENSION_REFRESH (1.3.6.1.4.1.1466.101.119.1)

Indicates that the server supports the Refresh extension (RFC 2589)

=item LDAP_EXTENSION_CANCEL (1.3.6.1.1.8)

Indicates the server supports the Cancel extension (RFC 3909)

=back

=head3 Novell eDirectory Extension OIDs

=over 4

=item LDAP_EXTENSION_NDSTOLDAP (2.16.840.1.113719.1.27.100.2)

=item LDAP_EXTENSION_SPLIT_PARTITION (2.16.840.1.113719.1.27.100.3)

=item LDAP_EXTENSION_MERGE_PARTITION (2.16.840.1.113719.1.27.100.5)

=item LDAP_EXTENSION_ADD_REPLICA (2.16.840.1.113719.1.27.100.7)

=item LDAP_EXTENSION_REFRESH_LDAP_SERVER (2.16.840.1.113719.1.27.100.9)

=item LDAP_EXTENSION_REMOVE_REPLICA (2.16.840.1.113719.1.27.100.11)

=item LDAP_EXTENSION_PARTITION_ENTRY_COUNT (2.16.840.1.113719.1.27.100.13)

=item LDAP_EXTENSION_CHANGE_REPLICA_TYPE (2.16.840.1.113719.1.27.100.15)

=item LDAP_EXTENSION_GET_REPLICA_INFO (2.16.840.1.113719.1.27.100.17)

=item LDAP_EXTENSION_LIST_REPLICAS (2.16.840.1.113719.1.27.100.19)

=item LDAP_EXTENSION_RECEIVE_ALL_UPDATES (2.16.840.1.113719.1.27.100.21)

=item LDAP_EXTENSION_SEND_ALL_UPDATES (2.16.840.1.113719.1.27.100.23)

=item LDAP_EXTENSION_REQUEST_PARTITIONSYNC (2.16.840.1.113719.1.27.100.25)

=item LDAP_EXTENSION_REQUEST_SCHEMASYNC (2.16.840.1.113719.1.27.100.27)

=item LDAP_EXTENSION_ABORT_PARTITION_OPERATION (2.16.840.1.113719.1.27.100.29)

=item LDAP_EXTENSION_GET_BINDDN (2.16.840.1.113719.1.27.100.31)

=item LDAP_EXTENSION_GET_EFFECTIVE_PRIVILEGES (2.16.840.1.113719.1.27.100.33)

=item LDAP_EXTENSION_SET_REPLICATION_FILTER (2.16.840.1.113719.1.27.100.35)

=item LDAP_EXTENSION_GET_REPLICATION_FILTER (2.16.840.1.113719.1.27.100.37)

=item LDAP_EXTENSION_CREATE_ORPHAN_PARTITION (2.16.840.1.113719.1.27.100.39)

=item LDAP_EXTENSION_REMOVE_ORPHAN_PARTITION (2.16.840.1.113719.1.27.100.41)

=item LDAP_EXTENSION_TRIGGER_BACKLINKER (2.16.840.1.113719.1.27.100.43)

=item LDAP_EXTENSION_TRIGGER_DRLPROCESS (2.16.840.1.113719.1.27.100.45)

=item LDAP_EXTENSION_TRIGGER_JANITOR (2.16.840.1.113719.1.27.100.47)

=item LDAP_EXTENSION_TRIGGER_LIMBER (2.16.840.1.113719.1.27.100.49)

=item LDAP_EXTENSION_TRIGGER_SKULKER (2.16.840.1.113719.1.27.100.51)

=item LDAP_EXTENSION_TRIGGER_SCHEMASYNC (2.16.840.1.113719.1.27.100.53)

=item LDAP_EXTENSION_TRIGGER_PARTITIONPURGE (2.16.840.1.113719.1.27.100.55)

=item LDAP_EXTENSION_MONITOR_EVENTS (2.16.840.1.113719.1.27.100.79)

=item LDAP_EXTENSION_EVENT_NOTIFICATION (2.16.840.1.113719.1.27.100.81)

=item LDAP_EXTENSION_FILTERED_EVENT_MONITOR (2.16.840.1.113719.1.27.100.84)

=item LDAP_EXTENSION_LDAPBACKUP (2.16.840.1.113719.1.27.100.96)

=item LDAP_EXTENSION_LDAPRESTORE (2.16.840.1.113719.1.27.100.98)

=item LDAP_EXTENSION_GET_EFFECTIVE_LIST_PRIVILEGES (2.16.840.1.113719.1.27.100.103)

=item LDAP_EXTENSION_CREATE_GROUPING (2.16.840.1.113719.1.27.103.1)

=item LDAP_EXTENSION_END_GROUPING (2.16.840.1.113719.1.27.103.2)

=item LDAP_EXTENSION_NMAS_PUT_LOGIN_CONFIGURATION (2.16.840.1.113719.1.39.42.100.1)

=item LDAP_EXTENSION_NMAS_GET_LOGIN_CONFIGURATION (2.16.840.1.113719.1.39.42.100.3)

=item LDAP_EXTENSION_NMAS_DELETE_LOGIN_CONFIGURATION (2.16.840.1.113719.1.39.42.100.5)

=item LDAP_EXTENSION_NMAS_PUT_LOGIN_SECRET (2.16.840.1.113719.1.39.42.100.7)

=item LDAP_EXTENSION_NMAS_DELETE_LOGIN_SECRET (2.16.840.1.113719.1.39.42.100.9)

=item LDAP_EXTENSION_NMAS_SET_PASSWORD (2.16.840.1.113719.1.39.42.100.11)

=item LDAP_EXTENSION_NMAS_GET_PASSWORD (2.16.840.1.113719.1.39.42.100.13)

=item LDAP_EXTENSION_NMAS_DELETE_PASSWORD (2.16.840.1.113719.1.39.42.100.15)

=item LDAP_EXTENSION_NMAS_PASSWORD_POLICYCHECK (2.16.840.1.113719.1.39.42.100.17)

=item LDAP_EXTENSION_NMAS_GET_PASSWORD_POLICY_INFO (2.16.840.1.113719.1.39.42.100.19)

=item LDAP_EXTENSION_NMAS_CHANGE_PASSWORD (2.16.840.1.113719.1.39.42.100.21)

=item LDAP_EXTENSION_NMAS_GAMS (2.16.840.1.113719.1.39.42.100.23)

=item LDAP_EXTENSION_NMAS_MANAGEMENT (2.16.840.1.113719.1.39.42.100.25)

=item LDAP_EXTENSION_START_FRAMED_PROTOCOL (2.16.840.1.113719.1.142.100.1)

=item LDAP_EXTENSION_END_FRAMED_PROTOCOL (2.16.840.1.113719.1.142.100.4)

=item LDAP_EXTENSION_LBURP_OPERATION (2.16.840.1.113719.1.142.100.6)

=back

=head2 Feature OIDs

B<Net::LDAP::Constant> exports constant subroutines for the following LDAP
feature OIDs.

=over 4

=item LDAP_FEATURE_ALL_OPATTS (1.3.6.1.4.1.4203.1.5.1)

Indicates if the server allows C<+> for returning all operational attributes
(RFC 3673)

=item LDAP_FEATURE_OBJECTCLASS_ATTRS (1.3.6.1.4.1.4203.1.5.2)

Indicates that the server allows C<@I<objectclass>> for returning all
attributes used to represent a particular class of object (RFC 4529)

=item LDAP_FEATURE_ABSOLUTE_FILTERS (1.3.6.1.4.1.4203.1.5.3)

Indicates that the server supports C<(&)> for the absolute I<True> filter,
and C<(|)> for the absolute I<False> filter (RFC 4526).

=item LDAP_FEATURE_LANGUAGE_TAG_OPTIONS (1.3.6.1.4.1.4203.1.5.4)

Indicates the server supports language tag options of the form
C<lang-I<language-tag>> with attributes (RFC 3866)

=item LDAP_FEATURE_LANGUAGE_RANGE_OPTIONS (1.3.6.1.4.1.4203.1.5.5)

Indicates that the server supports language tag range options (RFC 3866)

=item LDAP_FEATURE_MODIFY_INCREMENT (1.3.6.1.1.14)

Indicates if the server supports the Modify Increment extension (RFC 4525)

=back

=head2 Active Directory Capability OIDs

The following constants are specific to Microsoft Active Directory.
They serve to denote capabilities via the non-standard attribute
C<supportedCapabilities> in the Root DSE.

=over 4

=item LDAP_CAP_ACTIVE_DIRECTORY (1.2.840.113556.1.4.800)

Indicates that the LDAP server is running Active Directory
and is running as AD DS.

=item LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG (1.2.840.113556.1.4.1791)

Indicates that the LDAP server on the DC is capable of signing and sealing
on an NTLM authenticated connection, and that the server is capable of
performing subsequent binds on a signed or sealed connection.

=item LDAP_CAP_ACTIVE_DIRECTORY_V51 (1.2.840.113556.1.4.1670)

On an Active Directory DC operating as AD DS, the presence of this capability
indicates that the LDAP server is running at least the Windows 2003.

On an Active Directory DC operating as AD LDS, the presence of this capability
indicates that the LDAP server is running at least the Windows 2008.

=item LDAP_CAP_ACTIVE_DIRECTORY_ADAM (1.2.840.113556.1.4.1851)

Indicates that the LDAP server is running Active Directory as AD LDS.

=item LDAP_CAP_ACTIVE_DIRECTORY_ADAM_DIGEST (1.2.840.113556.1.4.1880)

Indicates on a DC operating as AD LDS,
that the DC accepts DIGEST-MD5 binds for AD LDS security principals.

=item LDAP_CAP_ACTIVE_DIRECTORY_PARTIAL_SECRETS (1.2.840.113556.1.4.1920)

Indicates that the Active Directory DC operating as AD DS, is an RODC.

=item LDAP_CAP_ACTIVE_DIRECTORY_V60 (1.2.840.113556.1.4.1935)

Indicates that the LDAP server is running at least the Windows 2008.

=item LDAP_CAP_ACTIVE_DIRECTORY_V61_R2 (1.2.840.113556.1.4.2080)

Indicates that the LDAP server is running at least the Windows 2008 R2.

=item LDAP_CAP_ACTIVE_DIRECTORY_W8 (1.2.840.113556.1.4.2237)

Indicates that the LDAP server is running at least the Windows 2012.

=back

=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Message>

=head1 AUTHOR

Graham Barr E<lt>gbarr@pobox.comE<gt>

Please report any bugs, or post any suggestions, to the perl-ldap mailing list
E<lt>perl-ldap@perl.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 1998-2009 Graham Barr. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut

