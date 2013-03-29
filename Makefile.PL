# -*- perl -*-

use inc::Module::Install;

perl_version    5.008001;

name		'perl-ldap';
module_name	'Net::LDAP';
abstract	'LDAP client library';
version_from	'lib/Net/LDAP.pm';
author		'Graham Barr <gbarr@cpan.org>';
license		'perl';

resources
	homepage    => 'http://ldap.perl.org/',
	repository  => 'https://github.com/perl-ldap/perl-ldap',
	bugtracker  => 'https://rt.cpan.org/Public/Dist/Display.html?Name=perl-ldap',
	MailingList => 'http://lists.cpan.org/showlist.cgi?name=perl-ldap',
	ListArchive => 'http://perl.markmail.org/search/list:perl-ldap';

check_nmake;	# check and download nmake.exe for Win32

requires	'Convert::ASN1' => 0.20;

test_requires	'Test::More';
test_requires	'File::Basename';
test_requires	'File::Compare';
test_requires	'File::Path';
test_requires	'IO::File';

features
        'IPv6 support' => [
		-default => 0,
                'IO::Socket::INET6' => 0,
        ],
	'LDAPS support' => [
		-default => 0,
		'IO::Socket::SSL' => 1.26,
	],
	'Read/Write LDIF files' => [
		-default => 0,
		'MIME::Base64'  => 0,		# core module since Perl 5.7.3
	],
	'SASL authentication' => [
		-default => 0,
		'Authen::SASL'  => '2.00',
		recommends 'Digest::MD5',	# for DIGEST-MD5 SASL mech, core since Perl 5.7.3
		recommends 'Digest::HMAC_MD5',	# for CRAM-MD5 SASL mech
		recommends 'GSSAPI',		# for GSSAPI SASL mech
	],
	'LDAP URLs' => [
		-default => 0,
		'URI::ldap' => 1.10,
	],
	'Time conversion functions' => [
		-default => 0,
		'Time::Local' => 0,
	],
	'Read/Write DSML files' => [
		-default => 0,
		'MIME::Base64'     => 0,	# core module since Perl 5.7.3
		'XML::SAX::Writer' => 0,
		'XML::SAX::Base'   => 0,
	],
	'LWP support for the LDAP protocol family' => [
		-default => 0,
		'LWP::Protocol'   => 0,
		'LWP::MediaTypes' => 0,
		'HTTP::Negotiate' => 0,
		'HTTP::Response'  => 0,
		'HTTP::Status'    => 0,
		recommends 'JSON',
	];

auto_install_now;

WriteAll	sign => 1;
