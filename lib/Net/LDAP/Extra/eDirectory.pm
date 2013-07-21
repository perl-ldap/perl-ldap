package Net::LDAP::Extra::eDirectory;

use strict;

use Encode;
use Exporter qw(import);
use Convert::ASN1 qw(ASN_NULL);
use Net::LDAP::RootDSE;

require Net::LDAP::Extension;

our @ISA = qw(Net::LDAP::Extension);
our $VERSION = '0.03';

our @EXPORT = qw(is_eDirectory
                 list_replicas
                 get_replica_info
                 _trigger_proccess
                 trigger_backlinker
                 trigger_janitor
                 trigger_limber
                 trigger_skulker
                 trigger_schemasync
                 trigger_partitionpurge
                 refresh_ldap_server);


sub is_eDirectory {
  my $self = shift;
  my $rootdse = $self->root_dse()
    or return undef;

  return ($rootdse->supported_extension(qw(2.16.840.1.113719.1.27.100.9
                                           2.16.840.1.113719.1.27.100.19)))
         ? 1 : 0;
}

my $listReplicasReq = Convert::ASN1->new;
$listReplicasReq->prepare(q<serverDN OCTET STRING>);

my $listReplicasRes = Convert::ASN1->new;
$listReplicasRes->prepare(q<replicaList SEQUENCE OF OCTET STRING>);

sub list_replicas {
  my $ldap = shift;
  my $serverDN = shift;
  my %opt = @_;

  my $res = $ldap->extension(
        name => '2.16.840.1.113719.1.27.100.19',
        value => $listReplicasReq->encode(serverDN => $serverDN),
        ($opt{control} ? (control => $opt{control}) : ())
  );

  bless $res; # Naughty :-)
}

sub replicas {
  my $self = shift;
  my $out;

  if ($self->code == 0 && $self->response_name eq '2.16.840.1.113719.1.27.100.20') {
    $out = $listReplicasRes->decode($self->response);

    return wantarray ? @{$out->{replicaList}} : $out->{replicaList}
      if (ref($out) && exists($out->{replicaList}));
  }

  undef;
}


my $GetReplicaInfoReq = Convert::ASN1->new;
$GetReplicaInfoReq->prepare(q<serverDN     OCTET STRING,
                              partitionDN  OCTET STRING>);

my $GetReplicaInfoRes = Convert::ASN1->new;
$GetReplicaInfoRes->prepare(q<partitionID       INTEGER,
                              replicaState      INTEGER,
                              modificationTime  INTEGER,
                              purgeTime         INTEGER,
                              localPartitionID  INTEGER,
                              partitionDN       OCTET STRING,
                              replicaType       INTEGER,
                              flags             INTEGER>);

sub get_replica_info {
  my $ldap = shift;
  my $serverDN = shift;
  my $partitionDN = shift;
  my %opt = @_;

  my $res = $ldap->extension(
        name => '2.16.840.1.113719.1.27.100.17',
        value => $GetReplicaInfoReq->encode(serverDN    => $serverDN,
                                            partitionDN => $partitionDN),
        ($opt{control} ? (control => $opt{control}) : ())
  );

  bless $res; # Naughty :-)
}

sub replica_info {
  my $self = shift;

  if ($self->code == 0 && $self->response_name eq '2.16.840.1.113719.1.27.100.18') {
     my $out = $GetReplicaInfoRes->decode($self->response);

     return wantarray ? %{$out} : $out;
  }

  undef;
}

use constant {
  EDIR_BK_PROCESS_BKLINKER    => 1,
  EDIR_BK_PROCESS_JANITOR     => 2,
  EDIR_BK_PROCESS_LIMBER      => 3,
  EDIR_BK_PROCESS_SKULKER     => 4,
  EDIR_BK_PROCESS_SCHEMA_SYNC => 5,
  EDIR_BK_PROCESS_PART_PURGE  => 6
};

sub _trigger_proccess()
{
my $ldap = shift;
my $type = shift;
my %opt = @_;
my %typemap = ( 1 => '2.16.840.1.113719.1.27.100.43',
                2 => '2.16.840.1.113719.1.27.100.47',
                3 => '2.16.840.1.113719.1.27.100.49',
                4 => '2.16.840.1.113719.1.27.100.51',
                5 => '2.16.840.1.113719.1.27.100.53',
                6 => '2.16.840.1.113719.1.27.100.55',
		2.16.840.1.113719.1.27.100.9 => '2.16.840.1.113719.1.27.100.9' );

  $type = $typemap{$type}  if ($typemap{$type});

  return undef  if (!grep(/^\Q$type\E$/, values(%typemap)));

  my $res = $ldap->extension(
        name => $type,
        value => ASN_NULL,
        ($opt{control} ? (control => $opt{control}) : ())
  );

  bless $res; # Naughty :-)
}

sub trigger_backlinker {
  my $ldap = shift;
  $ldap->_trigger_proccess(EDIR_BK_PROCESS_BKLINKER, @_);
}

sub trigger_janitor {
  my $ldap = shift;
  $ldap->_trigger_proccess(EDIR_BK_PROCESS_JANITOR, @_);
}

sub trigger_limber {
  my $ldap = shift;
  $ldap->_trigger_proccess(EDIR_BK_PROCESS_LIMBER, @_);
}

sub trigger_skulker {
  my $ldap = shift;
  $ldap->_trigger_proccess(EDIR_BK_PROCESS_SKULKER, @_);
}

sub trigger_schemasync {
  my $ldap = shift;
  $ldap->_trigger_proccess(EDIR_BK_PROCESS_SCHEMA_SYNC, @_);
}

sub trigger_partitionpurge {
  my $ldap = shift;
  $ldap->_trigger_proccess(EDIR_BK_PROCESS_PART_PURGE, @_);
}

sub refresh_ldap_server {
  my $ldap = shift;
  $ldap->_trigger_proccess('2.16.840.1.113719.1.27.100.9', @_);
}

1;

__END__

=head1 NAME

Net::LDAP::Extra::eDirectory -- extensions for Novell eDirectory

=head1 SYNOPSIS

  use Net::LDAP::Extra qw(eDirectory);

  $ldap = Net::LDAP->new( ... );

  ...

  if ($ldap->is_eDirectory)
    my $mesg $ldap->list_replicas($server_dn);

    print "Replicas on $server_dn\n* " . join("\n* ", $mesg->replicas) . "\n"
      if (!$mesg->code);
  }

=head1 DESCRIPTION

Net::LDAP::Extra::eDirectory provides functions / LDAP extensions
specific to Novell eDirectory.

To do so, it provides the following methods:

=head1 METHODS

=over 4

=item is_eDirectory ( )

Tell if the LDAP server queried is Novell eDirectory server.

As the check is done by querying the root DSE of the directory,
it works without being bound to the directory.

In contrast to other Net::LDAP methods this method returns
TRUE / FALSE respectively undef on error.

=item list_replicas ( SERVER_DN, OPTIONS )

Query the replicas on the given server I<SERVER_DN>.

On success, the resulting Net::LDAP::Message object supports the method
C<replicas> that returns the list of replicas on I<SERVER_DN>.

=item get_replica_info ( SERVER_DN, REPLICA_DN, OPTIONS )

Query information of I<REPLICA_DN> on I<SERVER_DN>.

On success, the resulting Net::LDAP::Message object supports the method
C<replica_info> that returns a hash containing information on I<REPLICA_DN>.

=item trigger_backlinker ( OPTIONS )

Trigger the BackLinker process, which resolves external references
to ensure they refer to real entries.

=item trigger_janitor ( OPTIONS )

Trigger the Janitor process, which checks connectivity to all servers in database.

=item trigger_limber ( OPTIONS )

Trigger the Limber process, which verifies the server name,
internal ipx address and tree connectivity of all replicas.

=item trigger_skulker ( OPTIONS )

Trigger the Skulker process, which checks the synchronization status
of every server in the replica ring.

=item trigger_schemasync ( OPTIONS )

Trigger SchemaSync.

=item trigger_partitionpurge ( OPTIONS )

Trigger PartitionPurge.

=item refresh_ldap_server ( OPTIONS )

Trigger refreshing the NLDAP service.

=back

=head1 AUTHOR

Peter Marschall E<lt>peter@adpm.deE<gt>

=head1 COPYRIGHT

Copyright (c) 2013 Peter Marschall. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

