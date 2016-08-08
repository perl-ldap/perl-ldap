# Porting guidelines

In case you want to help with the porting of the great Perl5 Net::LDAP module to Perl 6, I write my recommendations here:
- Pick a class to port.
- Try to stay as close as possible to the API of the class. The API documentation is a pod file withe the same basename or, if you prefer, on CPAN (https://metacpan.org/release/perl-ldap).
- However, it's a good idea to make use of Perl 6 enhancements (certainly regarding object orientation). E.g., automatic constructors tied to attributes instead of positionals, multi subs/methods, contants, non-flattening of arrays in subs/methods, signatures and varargs, etc. It's OK to change the API in orde to make the code more natural to Perl 6.
- Document the new API by changing the pod documentation.
- Write tests for the class, no matter how trivial it looks. This will help with the integration with other classes. The test of Perl 5 Net::LDAP will be ported once everything is in place.
- We target the lastest stable rakudo release.
 
