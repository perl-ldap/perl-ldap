#!/usr/bin/perl
# Test the sslargs option for _SSL_context_init_args

use strict;
use warnings;
use Test::More tests => 6;

use Net::LDAP;

# _SSL_context_init_args is not exported, call it via full name
my @args;

# Test 1: without sslargs, SSL_hostname should not be present
@args = Net::LDAP::_SSL_context_init_args({ sslserver => 'example.com' });
my %h = @args;
ok(!exists $h{SSL_hostname}, 'SSL_hostname absent without sslargs');

# Test 2: sslargs with SSL_hostname => '' to disable SNI
@args = Net::LDAP::_SSL_context_init_args({
  sslserver => 'example.com',
  sslargs   => { SSL_hostname => '' },
});
%h = @args;
is($h{SSL_hostname}, '', 'SSL_hostname set to empty string via sslargs');

# Test 3: sslargs can override SSL_verify_mode
@args = Net::LDAP::_SSL_context_init_args({
  sslserver => 'example.com',
  verify    => 'none',
  sslargs   => { SSL_verify_mode => 3 },
});
%h = @args;
is($h{SSL_verify_mode}, 3, 'sslargs overrides SSL_verify_mode');

# Test 4: sslargs with non-hashref is ignored
@args = Net::LDAP::_SSL_context_init_args({
  sslserver => 'example.com',
  sslargs   => 'not a hash',
});
%h = @args;
ok(!exists $h{SSL_hostname}, 'non-hashref sslargs is ignored');

# Test 5: sslargs can pass arbitrary SSL options
@args = Net::LDAP::_SSL_context_init_args({
  sslserver => 'example.com',
  sslargs   => { SSL_alpn_protocols => ['h2'] },
});
%h = @args;
is_deeply($h{SSL_alpn_protocols}, ['h2'], 'arbitrary SSL option passed through');

# Test 6: empty sslargs hash is harmless
@args = Net::LDAP::_SSL_context_init_args({
  sslserver => 'example.com',
  sslargs   => {},
});
%h = @args;
is($h{SSL_verify_mode}, 0, 'empty sslargs does not break defaults');
