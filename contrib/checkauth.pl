#!/usr/local/bin/perl
#
# Contributed by Mark Wilcox <mewilcox@unt.edu>

use Net::LDAP;
#checkauth.pl
#get id and password from command line
#return if authenticated or not
my $id = shift;
my $password = shift;

print "id is $id\n";
die ("usage checkauth.pl uid password.") unless (($id) && ($password));

my $host = "ldap.acme.com";
my $base = "o=acme.com";
my $ldap = new Net::LDAP($host);

$ldap->bind();

my @attrs = ["uid"];

my $mesg = $ldap->search(
             base => $base,
             filter => "uid=$id",
             attrs => @attrs
             );
   
print "LDAP error is ",$mesg->code(),"\n" if $mesg->code();


#if we don't trap a bad id, authentication will give false positive
#because LDAP server will revert to anonymous authentication
die ("bad id\n") unless $mesg->count(); 

die("more than 1 entry matches uid\n") if $mesg->count > 1;
#get a complete dn from search return
my $entry = $mesg->entry(0); # CAUTION: assumes only one value returned
my $dn = $entry->dn;

#now rebind and then do search again
$mesg = $ldap->bind($dn, password=>$password);


die ("bad id or password \n") if $mesg->code() ;
print "$id OK\n";
$ldap->unbind();

print "done\n";


