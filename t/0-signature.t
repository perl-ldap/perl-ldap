#!/usr/bin/perl
# $File: //member/autrijus/Module-Signature/t/0-signature.t $ $Author: gbarr $
# $Revision: 1.1 $ $Change: 1871 $ $DateTime: 2002/11/03 19:22:02 $

use strict;
use Test::More tests => 1;

SKIP: {
    if (!eval { require Socket; Socket::inet_aton('pgp.mit.edu') }) {
	skip("Cannot connect to the keyserver", 1);
    }
    elsif (!eval { require Module::Signature; 1 }) {
	diag("Next time around, consider install Module::Signature,\n".
	     "so you can verify the integrity of this distribution.\n");
	skip("Module::Signature not installed", 1);
    }
    else {
	ok(Module::Signature::verify()  == Module::Signature::SIGNATURE_OK()
	    => "Valid signature" );
    }
}

__END__
