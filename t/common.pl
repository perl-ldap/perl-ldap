BEGIN {

  foreach (qw(my.cfg test.cfg)) {
    -f and require "$_" and last;
  }

  undef $SERVER_EXE unless $SERVER_EXE and -x $SERVER_EXE;

  # If your host cannot be contacted as localhost, change this
  $HOST     ||= '127.0.0.1';

  # Where to but temporary files while testing
  # the Makefile is setup to delete temp/ when make clean is run
  $TEMPDIR  = "./temp";

  $TESTDB   = "$TEMPDIR/test-db";
  $CONF     = "$TEMPDIR/conf";
  $PASSWD   = 'secret';
  $BASEDN   = "o=University of Michigan, c=US";
  $MANAGERDN= "cn=Manager, o=University of Michigan, c=US";
  $JAJDN    = "cn=James A Jones 1, ou=Alumni Association, ou=People, o=University of Michigan, c=US";
  $BABSDN   = "cn=Barbara Jensen, ou=Information Technology Division, ou=People, o=University of Michigan, c=US";
  $PORT     = 9009;

  my @server_opts;
  ($SERVER_TYPE,@server_opts) = split(/\+/, $SERVER_TYPE || 'none');

  if ($SERVER_TYPE eq 'openldap1') {
    $CONF_IN	  = "./data/slapd-conf.in";
    @LDAPD	  = ($SERVER_EXE, '-f',$CONF,'-p',$PORT,qw(-d 1));
    $LDAP_VERSION = 2;
  }
  elsif ($SERVER_TYPE eq 'openldap2') {
    $SSL_PORT = 9010 if grep { $_ eq 'ssl' } @server_opts;
    $CONF_IN	  = "./data/slapd2-conf.in";
    my $url = "ldap://${HOST}:$PORT/";
    $url .= " ldaps://${HOST}:$SSL_PORT/" if $SSL_PORT;
    @LDAPD	  = ($SERVER_EXE, '-f',$CONF,'-h',$url,qw(-d 1));
    $LDAP_VERSION = 3;
  }

  $LDAP_VERSION ||= 2;
  mkdir($TEMPDIR,0777);
  die "$TEMPDIR is not a directory" unless -d $TEMPDIR;
}

use Net::LDAP;
use Net::LDAP::LDIF;
use File::Path qw(rmtree);
use File::Basename qw(basename);

my $pid;

sub start_server {
  my %arg = (version => 2, @_);

  unless ($LDAP_VERSION >= $arg{version}
	and $LDAPD[0] and -x $LDAPD[0]
	and (!$arg{ssl} or $SSL_PORT))
  {
    print "1..0\n";
    exit;
  }

  if ($CONF_IN and -f $CONF_IN) {
    # Create slapd config file
    open(CONFI,"<$CONF_IN") or die "$!";
    open(CONFO,">$CONF") or die "$!";
    while(<CONFI>) {
      s/\$(\w+)/${$1}/g;
      s/^TLS/#TLS/ unless $SSL_PORT;
      print CONFO;
    }
    close(CONFI);
    close(CONFO);
  }

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
  my %arg = @_;
  my $ldap;
  my $count;
  local $^W = 0;
  if ($arg{ssl}) {
    require Net::LDAPS;
    until($ldap = Net::LDAPS->new($HOST, port => $SSL_PORT, version => 3)) {
      die "ldaps://$HOST:$SSL_PORT/ $@" if ++$count > 10;
      sleep 1;
    }
  }
  else {
    until($ldap = Net::LDAP->new($HOST, port => $PORT)) {
      die "ldap://$HOST:$PORT/ $@" if ++$count > 10;
      sleep 1;
    }
  }
  $ldap;
}

sub compare_ldif {
  my($test,$test_num,$mesg) = splice(@_,0,3);

  if ($mesg->code) {
    print $mesg->error,"\n";
    print "not ok ",$test_num++,"\n";
    print "not ok ",$test_num++,"\n";
    print "not ok ",$test_num++,"\n";
    return 3;
  }
  print "ok ",$test_num++,"\n";

  my $ldif = Net::LDAP::LDIF->new("$TEMPDIR/${test}-out.ldif","w", lowercase => 1);
  unless ($ldif) {
    print "not ok",$test_num++,"\n";
    print "not ok",$test_num++,"\n";
    return 3;
  }
  print "ok ",$test_num++,"\n";

  foreach $entry (@_) {
    foreach $attr ($entry->attributes) {
      $entry->delete($attr) if $attr =~ /^(modifiersname|modifytimestamp|creatorsname|createtimestamp)$/i;
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

sub ldif_populate {
  my ($ldap, $file, $change) = @_;
  my $ok = 1;

  my $ldif = Net::LDAP::LDIF->new($file,"r", changetype => $change || 'add')
	or return;

  while (my $e = $ldif->read_entry) {
    $mesg = $e->update($ldap);
    if ($mesg->code) {
      $ok = 0;
      Net::LDAP::LDIF->new(qw(- w))->write_entry($e);
      print "# ",$mesg->code,": ",$mesg->error,"\n";
    }
  }
  $ok;
}

1;
