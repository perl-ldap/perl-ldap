#!perl

use Test::More;

BEGIN { require "t/common.pl" }


start_server()
? plan tests => 3
: plan skip_all => 'no server';


$ldap = client();
ok($ldap, 'client with IPv4/IPv6 auto-selection' .
   ($ldap ? (', bound to ' . $ldap->{net_ldap_socket}->peerhost) : ''));

$ldap = client(inet4 => 1);
ok($ldap, 'client with IPv4' .
   ($ldap ? (', bound to ' . $ldap->{net_ldap_socket}->peerhost) : ''));


SKIP: {
  skip('No IPv6 capable IO::Socket module installed', 1)
    unless (eval { require IO::Socket::INET6; } or
            eval { require IO::Socket::IP; IO::Socket::IP->VERSION(0.20); });

  $ldap = client(inet6 => 1);
  ok($ldap, 'client with IPv6' .
     ($ldap ? (', bound to ' . $ldap->{net_ldap_socket}->peerhost) : ''));
}
