class Net::LDAP::Entry {

  # use Net::LDAP::ASN qw(LDAPEntry);
  # use Net::LDAP::Constant qw(LDAP_LOCAL_ERROR LDAP_OTHER);

  ### Attributes ###
  # Public
  has Str $.dn is rw;
  has $.changetype is rw;

  has @.values;


  # Private
  has $!attrs;


  ### Methods ###
  # Public
  method add (Str $attribute, *@values) {
    my $cmd   = $!changetype eq 'modify' ?? [] !! '';
    self!build_attrs();
  }

  # Private
  method !build_attrs() {

  }
  
}
