BEGIN {

  # Set this to the path to where you have slapd
  $SLAPD    = $ENV{SLAPD_EXE} || "../../openldap/ldap/servers/slapd/slapd";

  # If your host cannot be contacted as localhost, change this
  $HOST     = 'localhost';

  # Where to but temporary files while testing
  # the Makefile is setup to delete temp/ when make clean is run
  $TEMPDIR  = "./temp";

  # Do NOT change any values below here

  $CONF_IN  = "./data/slapd-conf.in";
  $TESTDB   = "$TEMPDIR/test-db";
  $CONF     = "$TEMPDIR/conf";
  $PASSWD   = 'secret';
  $BASEDN   = "o=University of Michigan, c=US";
  $MANAGERDN= "cn=Manager, o=University of Michigan, c=US";
  $JAJDN    = "cn=James A Jones 1, ou=Alumni Association, ou=People, o=University of Michigan, c=US";
  $BABSDN   = "cn=Barbara Jensen, ou=Information Technology Division, ou=People, o=University of Michigan, c=US";
  $PORT     = 9009;
  @LDAPD    = ($SLAPD, '-f',$CONF,'-p',$PORT,qw(-d 1));

  mkdir($TEMPDIR,0777);
  die "$TEMPDIR is not a directory" unless -d $TEMPDIR;
}

use Net::LDAP;
use Net::LDAP::LDIF;
use File::Path qw(rmtree);
use File::Basename qw(basename);
use vars qw($NO_SERVER);

my $pid;

sub start_server {
  unless (defined($LDAPD[0]) && -x $LDAPD[0]) {
    print "1..0\n";
    exit;
  }

  # Create slapd config file
  open(CONFI,"<$CONF_IN") or die "$!";
  open(CONFO,">$CONF") or die "$!";
  while(<CONFI>) {
    s/\$(\w+)/${$1}/g;
    print CONFO;
  }
  close(CONFI);
  close(CONFO);

  rmtree($TESTDB) if ( -d $TESTDB );
  mkdir($TESTDB,0777);
  die "$TESTDB is not a directory" unless -d $TESTDB;

  my $log = $TEMPDIR . "/" . basename($0,'.t');

  unless ($pid = fork) {
    die "fork: $!" unless defined $pid;

    open(STDERR,">$log");
    open(STDOUT,">&STDERR");
    close(STDIN);

    exec(@LDAPD);
  }

  sleep 2; # wait for server to start
}

sub kill_server {
  if ($pid) {
    kill 9, $pid;
    sleep 2;
    undef $pid;
  }
}

END {
  kill_server();
}

sub client {
  Net::LDAP->new($HOST, port => $PORT) or die "$@"
}

sub server_version {
  my $ldap = shift or return;
  my $dse = $ldap->root_dse or return 2;
  ( sort { $b <=> $a } $dse->get('version'))[0] || 2;
}

sub compare_ldif {
  my($test,$mesg,$test_num,@sort) = @_;

  if ($mesg->code) {
    print $mesg->error,"\n";
    print "not ok ",$test_num++,"\n";
    print "not ok ",$test_num++,"\n";
    print "not ok ",$test_num++,"\n";
    return 3;
  }
  print "ok ",$test_num++,"\n";

  my $ldif = Net::LDAP::LDIF->new("$TEMPDIR/${test}-out.ldif","w");
  unless ($ldif) {
    print "not ok",$test_num++,"\n";
    print "not ok",$test_num++,"\n";
    return 3;
  }
  print "ok ",$test_num++,"\n";

  foreach $entry ($mesg->sorted(@sort)) {
    foreach $attr ($entry->attributes) {
      $entry->delete($attr) if $attr =~ /^(modifiersname|modifytimestamp|creatorsname|createtimestamp)$/;
    }
    $ldif->write($entry);
  }

  $ldif->done; # close the file;

  compare("$TEMPDIR/${test}-out.ldif","data/${test}-cmp.ldif") && print "not ";
  print "ok ",$test_num++,"\n";
  3;
}

require File::Compare;

sub compare($$) {
  local(*FH1,*FH2);
  not( open(FH1,"<".$_[0])
       && open(FH2,"<".$_[1])
       && 0 == File::Compare::compare(*FH1,*FH2, -s FH1)
  );
}

1;
