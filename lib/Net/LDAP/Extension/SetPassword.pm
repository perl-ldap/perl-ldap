
package Net::LDAP::Extension::SetPassword;

require Net::LDAP::Extension;

@ISA = qw(Net::LDAP::Extension);

use Convert::ASN1;
my $passwdModReq = Convert::ASN1->new;
$passwdModReq->prepare(q<SEQUENCE {
                       user         [0] STRING OPTIONAL,
                       oldpasswd    [1] STRING OPTIONAL,
                       newpasswd    [2] STRING OPTIONAL
                       }>);

my $passwdModRes = Convert::ASN1->new;
$passwdModRes->prepare(q<SEQUENCE {
                       genPasswd    [0] STRING OPTIONAL
                       }>);

sub Net::LDAP::set_password {
  my $ldap = shift;
  my %opt = @_;

  my $res = $ldap->extension(
	name => '1.3.6.1.4.1.4203.1.11.1',
	value => $passwdModReq->encode(\%opt)
  );

  bless $res; # Naughty :-)
}

sub gen_password {
  my $self = shift;

  my $out = $passwdModRes->decode($self->response);

  $out->{genPasswd};
}

1;
