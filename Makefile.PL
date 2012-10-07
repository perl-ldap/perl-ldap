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

requires	'Convert::ASN1' => 0.07;

test_requires	'Test::More';

features
	'SASL authentication' => [
		-default => 0,
		'Authen::SASL'  => '2.00',
		recommends 'Digest::MD5',	# for DIGEST-MD5 SASL mech
		recommends 'Digest::HMAC_MD5',	# for CRAM-MD5 SASL mech
		recommends 'GSSAPI',		# for GSSAPI SASL mech
	],
	'LDAP URLs' => [
		-default => 0,
		'URI::ldap' => 1.10,
		recommends 'JSON',
	],
	'LDAPS' => [
		-default => 0,
		'IO::Socket::SSL' => 1.26,
	],
	'Read/Write DSML files' => [
		-default => 0,
		'MIME::Base64'  => 0,
		'XML::SAX::Writer' => 0,
		# dependencies of XML::SAX::Writer:
		#'Text::Iconv' => 0,
		#'XML::Filter::BufferText' => 0,
		#'XML::SAX' => 0,
		#'XML::NamespaceSupport' => 0,
		#'File::Temp' => 0
	],
	'Read/Write LDIF files' => [
		-default => 0,
		'MIME::Base64'  => 0,
	];

auto_install_now;

WriteAll	sign => 1;
