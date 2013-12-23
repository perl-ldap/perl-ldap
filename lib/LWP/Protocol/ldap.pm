# Copyright (c) 1998-2004 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package LWP::Protocol::ldap;

use Carp ();

use HTTP::Status qw(HTTP_OK HTTP_BAD_REQUEST HTTP_INTERNAL_SERVER_ERROR HTTP_NOT_IMPLEMENTED);
use HTTP::Negotiate ();
use HTTP::Response ();
use LWP::MediaTypes ();
require LWP::Protocol;

our @ISA = qw(LWP::Protocol);
our $VERSION = '1.25';

use strict;
eval {
  require Net::LDAP;
};
my $init_failed = $@ ? $@ : undef;

sub request {
  my($self, $request, $proxy, $arg, $size, $timeout) = @_;

  $size = 4096  unless $size;

  LWP::Debug::trace('()')  if defined &LWP::Debug::trace;

  # check proxy
  if (defined $proxy) {
    return $self->_error(HTTP_BAD_REQUEST,
                         'You can not proxy through the ldap');
  }

  my $url = $request->url;
  my $scheme   = $url->scheme;
  my $userinfo = $url->can('userinfo') ? $url->userinfo : '';
  my $dn       = $url->dn;
  my @attrs    = $url->attributes;
  my $scope    = $url->scope || 'base';
  my $filter   = $url->filter;

  # check scheme
  if ($scheme !~ /^ldap[si]?$/) {
    return $self->_error(HTTP_INTERNAL_SERVER_ERROR,
                         "LWP::Protocol::ldap::request called for '$scheme'");
  }

  # check method
  my $method = $request->method;

  unless ($method =~ /^(?:GET|HEAD)$/) {
    return $self->_error(HTTP_NOT_IMPLEMENTED,
                         "Library does not allow method $method for '$scheme:' URLs");
  }

  if ($init_failed) {
    return $self->_error(HTTP_INTERNAL_SERVER_ERROR,
                         $init_failed);
  }

  my ($user, $password) = defined($userinfo) ? split(/:/, $userinfo, 2) : ();
  my %extn     = $url->extensions;
  my $tls     = exists($extn{'x-tls'}) ? 1 : 0;
  my $format = lc($extn{'x-format'} || 'html');
  my $mime_type = 'text/'.$format;

  # analyse HTTP headers
  if (my $accept = $request->header('Accept')) {
    if ($accept =~ m!\b((?:text|application|xml)/(?:x-)?dsml)\b!) { $mime_type = $1; $format = 'dsml'; };
    if ($accept =~ m!\b(text/(?:x-)?ldif)\b!)                     { $mime_type = $1; $format = 'ldif'; };
    if ($accept =~ m!\b((?:text|application)/json)\b!)            { $mime_type = $1; $format = 'json'; };
  }

  if (!$user) {
    if (my $authorization = $request->header('Authorization')) {
      # we only accept Basic authorization for now
      if ($authorization =~ /^Basic\s+([A-Z0-9+\/=]+)$/i) {
        require MIME::Base64;
        ($user, $password) = split(/:/, MIME::Base64::decode($1), 2);
      }
    }
  }

  # connect to LDAP server
  my $ldap = new Net::LDAP($url->as_string);
  if (!$ldap) {
    return $self->_error(HTTP_BAD_REQUEST,
                         'Connection to LDAP server failed', "$@");
  }

  # optional: startTLS
  if ($tls && $scheme ne 'ldaps') {
    my $mesg = $ldap->start_tls();

    return $self->_ldap_error($mesg)  if ($mesg->code);
  }

  # optional: simple bind
  if ($user) {
    my $mesg = $ldap->bind($user, password => $password);

    return $self->_ldap_error($mesg)  if ($mesg->code);
  }

  # do the search
  my %opts = ( scope => $scope );
  $opts{base}   = $dn      if $dn;
  $opts{filter} = $filter  if $filter;
  $opts{attrs}  = \@attrs  if @attrs;

  my $mesg = $ldap->search(%opts);

  return $self->_ldap_error($mesg)  if ($mesg->code);

  # Create an initial response object
  my $response = HTTP::Response->new(HTTP_OK, 'Document follows');
  $response->request($request);

  # return data in the format requested
  my $content = '';

  if ($format eq 'ldif') {
    require Net::LDAP::LDIF;

    open(my $fh, '>', \$content);
    my $ldif = Net::LDAP::LDIF->new($fh, 'w', version => 1);

    while (my $entry = $mesg->shift_entry) {
      $ldif->write_entry($entry);
    }
    $ldif->done;
    close($fh);
  }
  elsif ($format eq 'dsml') {
    require Net::LDAP::DSML;

    open(my $fh, '>', \$content);
    my $dsml = Net::LDAP::DSML->new(output => $fh, pretty_print => 1);

    $dsml->start_dsml();
    while (my $entry = $mesg->shift_entry) {
      $dsml->write_entry($entry);
    }
    $dsml->end_dsml();
    close($fh);
  }
  elsif ($format eq 'json') {
    require JSON;

    my $entry;
    my %objects;

    for (my $index = 0 ; $entry = $mesg->entry($index); $index++) {
      my $dn = $entry->dn;

      $objects{$dn} = {};
      foreach my $attr (sort($entry->attributes)) {
        $objects{$dn}{$attr} = $entry->get_value($attr, asref => 1);
      }
    }

    $content = JSON::to_json(\%objects, {pretty => 1, utf8 => 1});
  }
  else {
    my $entry;
    my $index;

    $content = "<head><title>Directory Search Results</title></head>\n<body>";

    for ($index = 0 ; $entry = $mesg->entry($index); $index++) {
      $content .= $index ? qq{<tr><th colspan="2"><hr>&nbsp</tr>\n} : '<table>';

      $content .= qq{<tr><th colspan="2">} . $entry->dn . "</th></tr>\n";

      foreach my $attr ($entry->attributes) {
        my $vals = $entry->get_value($attr, asref => 1);

        $content .= q{<tr><td align="right" valign="top"};
        $content .= q{ rowspan="} . scalar(@$vals) . q{"}
          if (@$vals > 1);
        $content .= '>' . $attr  . "&nbsp</td>\n";

        my $j = 0;
        foreach my $val (@$vals) {
	  $val = qq!<a href="$val">$val</a>!  if $val =~ /^https?:/;
	  $val = qq!<a href="mailto:$val">$val</a>!  if $val =~ /^[-\w]+\@[-.\w]+$/;
          $content .= "<tr>"  if $j++;
          $content .= "<td>" . $val . "</td></tr>\n";
        }
      }
    }

    $content .= '</table>'  if $index;
    $content .= '<hr>';
    $content .= $index ? sprintf('%s Match%s found', $index, $index>1 ? 'es' : '')
		       : '<b>No Matches found</b>';
    $content .= "</body>\n";
  }
  $response->header('Content-Type' => $mime_type.'; charset=utf-8');
  $response->header('Content-Length', length($content));
  $response = $self->collect_once($arg, $response, $content)
    if ($method ne 'HEAD');

  $ldap->unbind;

  $response;
}

sub _ldap_error
{
  my($self, $mesg) = @_;

  $self->_error(HTTP_BAD_REQUEST,
                'LDAP return code '.$mesg->code, $mesg->error);
}

sub _error
{
  my($self, $code, $message, $content) = @_;
  my $res = HTTP::Response->new($code, $message);

  if ($content) {
    $res->content_type('text/plain');
    $res->content($content);
  }

  $res;
}

1;

__END__

=head1 NAME

LWP::Protocol::ldap - Provide LDAP support for LWP::UserAgent

=head1 SYNOPSIS

  use LWP::UserAgent;

  $ua = LWP::UserAgent->new();
  $res = $ua->get('ldap://ldap.example.com/' .
                  'o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)',
                   Accept => 'text/json'):

=head1 DESCRIPTION

The LWP::Protocol::ldap module provides support for using I<ldap> schemed
URLs following RFC 4516 with LWP.  This module is a plug-in to the LWP
protocol handling, so you don't use it directly.

In addition to being used with LDAP URIs, LWP::Protocol::ldap also acts
as the base class for its sibling modules LWP::Protocol::ldaps
and LWP::Protocol::ldapi.

=head2 Features

=head3 HTTP methods supported

LWP::Protocol::ldap implements the HTTP I<GET> and I<HEAD> methods.
They are mapped to the LDAP L<search|Net::LDAP/search> operation,

=head3 Response format

Depending on the HTTP I<Accept> header provided by the user agent,
LWP::Protocol::ldap can answer the requests in one of the following
formats:

=over 4

=item DSML

When the HTTP I<Accept> header contains the C<text/dsml> MIME type,
the response is sent as DSMLv1.

=item JSON

When the HTTP I<Accept> header contains the C<text/json> MIME type,
the response is sent as JSON.
For this to work the I<JSON> Perl module needs to be installed.

=item LDIF

When the HTTP I<Accept> header contains the C<text/ldif> MIME type,
the response is sent in LDIFv1 format.

=item HTML

In case no HTTP I<Accept> header has been sent or none of the above
MIME types can be detected, and the I<x-format> extension has not been provided
either, the response is sent using HTML markup in a 2-column table format
(roughly modeled on LDIF).

=back

As an alternative to sending an HTTP I<Accept> header, LWP::Protocol::ldap
also accepts the C<x-format> extension

Example:

 ldap://ldap.example.com/o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)?x-format=dsml

=head3 TLS support

For I<ldap> and I<ldapi> URIs, the module implements the C<x-tls> extension
that switches the LDAP connection to TLS using a call of the
L<start_tls|Net::LDAP/start_tls> method.

Example:

 ldap://ldap.example.com/o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)?x-tls=1

Note:
In the above example, ideally giving C<x-tls> should be sufficient,
but unfortunately the parser in URI::ldap has a little flaw.

=head3 Authorization

Usually the connection is done anonymously, but if the HTTP I<Authorization>
header is provided with credentials for HTTP Basic authorization,
the credentials given in that header will be used to do a simple
bind to the LDAP server.


=head1 SEE ALSO

L<LWP::Protocol::ldaps>, L<LWP::Protocol::ldapi>

=head1 COPYRIGHT

Copyright (c) 1998-2004 Graham Barr, 2012 Peter Marschall.
All rights reserved.  This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.
