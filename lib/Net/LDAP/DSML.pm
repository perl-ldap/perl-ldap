package Net::LDAP::DSML;

# For schema parsing,  add ability to Net::LDAP::Schema to accecpt 
# a Net::LDAP::Entry object. First
# we'll convert XML into Net::LDAP::Entry with schema attributes and 
# then pass to schema object constructor
# 
# move XML::DSML to Net::LDAP::DSML::Parser
# change parser so that it uses callbacks
#
# 12/18/01 Clif Harden
# Changed code to allow and comprehend the passing of an array
# reference instead of a file handle.  This touched all of the
# methods that wrote to a file.
#


use strict;
use Net::LDAP::Entry;
use vars qw($VERSION);

$VERSION = "0.06";

sub new {
  my $pkg = shift;
  my $self = {};

  bless $self, $pkg;
}

sub open {
  my $self = shift;
  my $file = shift ;

  my $fh = $file;  
  my $close = 0;

  $self->finish
    if $self->{net_ldap_fh};

  if (ref($file) or ref(\$file) eq "GLOB" or ref($file) eq "ARRAY") {
    $close = 0;
    $fh = $file;
  }
  else {
    local *FH;
    unless (open(FH,$file)) {
      $self->{error} = "Cannot open file '$file'";
      return 0;
    }
    $close = 1;
    $fh = \*FH;
  }

  $self->{net_ldap_fh} = $fh;
  $self->{net_ldap_close} = $close;

  if ( ref($fh) eq "ARRAY" )
  {
    push(@$fh, $self->start_dsml);
  }
  else
  {
    print $fh $self->start_dsml;
  }
  1;
}

sub finish {
  my $self = shift;
  my $fh = $self->{net_ldap_fh};

  if ($fh) {
    if ( ref($fh) eq "ARRAY" )
    {
      push(@$fh, $self->end_dsml);
    }
    else
    {
      print $fh $self->end_dsml;
      close($fh) if $self->{net_ldap_close};
    }
  }
}

sub start_dsml {
  qq!<?xml version="1.0" encoding="utf-8"?>\n<dsml:dsml xmlns:dsml="http://www.dsml.org/DSML">\n!;
}

sub end_dsml {
  qq!</dsml:dsml>\n!;
}

sub DESTROY { shift->close }

#transform any entity chararcters
#must handle ourselves because I don't know of an XML module that does this
sub _normalize {
  my $normal = shift;

  $normal =~ s/&/&amp;/g;
  $normal =~ s/</&lt;/g;
  $normal =~ s/>/&gt;/g;
  $normal =~ s/\"/&quot;/g;
  $normal =~ s/\'/&apos;/g;
 
  return $normal;
}

sub write {
  my $self = shift;
  my $entry = shift;
  #my @unknown = _print_schema(_print_entries(@_));
  if (ref $entry eq 'Net::LDAP::Entry') {
    $self->_print_entry($entry)
  }
  elsif (ref $entry eq 'Net::LDAP::Schem') {
    _print_schema($entry);
  }
  else {
    return undef;
  }
  1;
}
 
#coming soon! ;)
sub _print_schema {
  my ($self,$entry) = @_;
  
  my $fh = $self->{'net_ldap_fh'} or return;
  return undef unless ($entry->isa('Net::LDAP::Schema')); 

  if ( ref($fh) eq "ARRAY" )
  {
    push(@$fh, "<dsml:directory-entries>\n");
  }
  else
  {
  print  $fh  "<dsml:directory-entries>\n";
  }

  @_;
}
 

sub _print_entry {
  my ($self,$entry) = @_;
  my @unknown;
  my $count;
  
  my $fh = $self->{'net_ldap_fh'} or return;
  return undef unless ($entry->isa('Net::LDAP::Entry')); 

  if ( ref($fh) eq "ARRAY" )
  {
    push(@$fh, "<dsml:directory-entries>\n");
  }
  else
  {
  print  $fh  "<dsml:directory-entries>\n";
  }

  if ( ref($fh) eq "ARRAY" )
  {
    push(@$fh, "<dsml:entry dn=\"");
    push(@$fh, _normalize($entry->dn));
    push(@$fh, "\">\n");
  }
  else
  {
  print $fh "<dsml:entry dn=\"",_normalize($entry->dn),"\">\n";
  }
  
  my @attributes = $entry->attributes();
  
  #at some point integrate with Net::LDAP::Schema to determine if binary or not
  #now look for ;binary tag
  
  for my $attr (@attributes) {
    my $isOC = 0;

    if (lc($attr) eq 'objectclass') {
      $isOC = 1;
    }
    
    if ($isOC) {
     if ( ref($fh) eq "ARRAY" )
     {
       push(@$fh, "<dsml:objectclass>\n");
     }
     else
     {
      print $fh "<dsml:objectclass>\n";
     }
    }
    else { 
      if ( ref($fh) eq "ARRAY" )
      {
       push(@$fh, "<dsml:attr name=\"");
       push(@$fh, _normalize($attr));
       push(@$fh, "\">\n");
      }
      else
      {
      print $fh "<dsml:attr name=\"",_normalize($attr),"\">\n";
      }
    }
    
    my @values = $entry->get_value($attr);
    
    for my $value (@values) {
       if ($isOC) {
         if ( ref($fh) eq "ARRAY" )
         {
          push(@$fh, "<dsml:oc-value>");
          push(@$fh, _normalize($value));
          push(@$fh, "</dsml:oc-value>\n");
         }
         else
         {
         print $fh "<dsml:oc-value>",_normalize($value),"</dsml:oc-value>\n";
         }
       }
       else {
        #at some point we'll use schema object to determine 
        #this but until then we'll borrow this from Net::LDAP::LDIF
        if ($value=~ /(^[ :]|[\x00-\x1f\x7f-\xff])/) {
          require MIME::Base64;
         if ( ref($fh) eq "ARRAY" )
         {
          push(@$fh, qq!<dsml:value  encoding="base64">!);
          push(@$fh, MIME::Base64::encode($value));
          push(@$fh, "</dsml:value>\n");
         }
         else
         {
          print $fh qq!<dsml:value  encoding="base64">!,
       	     MIME::Base64::encode($value),
       	     "</dsml:value>\n";
          }
        }
        else {
         if ( ref($fh) eq "ARRAY" )
         {
          push(@$fh, "<dsml:value>");
          push(@$fh, _normalize($value));
          push(@$fh, "</dsml:value>\n");
         }
         else
         {
          print $fh "<dsml:value>",_normalize($value),"</dsml:value>\n";
         }
        }
      }
    }

    if ($isOC) {
      if ( ref($fh) eq "ARRAY" )
      {
       push(@$fh, "</dsml:objectclass>\n");
      }
      else
      {
       print $fh "</dsml:objectclass>\n";
      }
    }
    else {
      if ( ref($fh) eq "ARRAY" )
      {
       push(@$fh, "</dsml:attr>\n");
      }
      else
      {
       print $fh "</dsml:attr>\n";
      }
    }
  }

  if ( ref($fh) eq "ARRAY" )
  {
   push(@$fh, "</dsml:entry>\n");
   push(@$fh, "</dsml:directory-entries>\n");
  }
  else
  {
   print $fh "</dsml:entry>\n";
   print $fh "</dsml:directory-entries>\n";
  }

  1;
}
 
# only parse DSML entry elements, no schema here
sub read_entries {   
  my ($self, $file) = @_;
  my @entries;

  $self->process($file, entry => sub { push @entries, @_ });

  @entries;
}

sub read_schema {   
  my ($self, $file) = @_;
  my $schema;

  $self->process($file, schema => sub {  $schema = shift } );

  $schema;
}

sub process {
  my $self = shift;
  my $file = shift;
  my %arg  = @_;

  require XML::Parser;
  require Net::LDAP::DSML::Parser;

  my $xml = XML::Parser->new(
    Style => 'Subs',
    Pkg => 'Net::LDAP::DSML::Parser',
    Handlers => {
      ExternEnt => sub { "" },
      Char => \&_Char
    }
  );

  $xml->{net_ldap_entry_handler}  = $arg{entry} if exists $arg{entry};
  $xml->{net_ldap_schema_handler} = $arg{schema} if exists $arg{schema};

  delete $self->{error};
  my $ok = eval { local $SIG{__DIE__}; $xml->parsefile($file); 1 };
  $self->{error} = $@ unless $ok;
  $ok;
}

sub error { shift->{error} }

sub _Char {
  my $self = shift;
  my $tag = $self->current_element;

  if ($tag =~ /^dsml:(oc-)?value$/) {
    $self->{net_ldap_entry}->add(
      ($1 ? 'objectclass' : $self->{net_ldap_attr}),
      $self->{net_ldap_base64}
        ? MIME::Base64::decode(shift)
        : shift
    );
  }
  elsif ($_[0] =~ /\S/) {
    die "Unexpected text '$_[0]', while parsing $tag";
  }
}

1;  

__END__

=head1 NAME

Net::LDAP::DSML -- A DSML Writer and Reader for Net::LDAP

=head1 SYNOPSIS

 use Net::LDAP;
 use Net::LDAP::DSML;
 use IO::File;


 my $server = "localhost";
 my $file = "testdsml.xml";
 my $ldap = Net::LDAP->new($server);
 
 $ldap->bind();

 my $dsml = Net::LDAP::DSML->new();

 my $file = "testdsml.xml";

 my $io = IO::File->new($file,"w") or die ("failed to open $file as filehandle.$!\n");
 $dsml->open($io) or die ("DSML problems opening $file.$!\n"); ;

 #or

 open (IO,">$file") or die("failed to open $file.$!");

 $dsml->open(*IO) or die ("DSML problems opening $file.$!\n");

 #or

 my @data = ();
 $dsml->open(\@data) or die ("DSML problems opening with an array.$!\n");


  my $mesg = $ldap->search(
                           base     => 'o=airius.com',
                           scope    => 'sub',
                           filter   => 'ou=accounting',
                           callback => sub {
					 my ($mesg,$entry) =@_;
					 $dsml->write($entry) if (ref $entry eq 'Net::LDAP::Entry');
				       }
                            );  

 die ("search failed with ",$mesg->code(),"\n") if $mesg->code();

 $dsml->write($schema);
 $dsml->finish();

 print "Finished printing DSML\n";
 print "Starting to process DSML\n";

 $dsml = new Net::LDAP::DSML();
 $dsml->process($file, entry => \&processEntry);

 #future when schema support is available will be
 #$dsml->process($file, entry => \&processEntry, schema => \&processSchema);

 sub processEntry {
   my $entry = shift;
  
   $entry->dump();
 } 

=head1 DESCRIPTION

Directory Service Markup Language (DSML) is the XML standard for
representing directory service information in XML.

At the moment this module only reads and writes DSML entry entities. It
cannot process any schema entities because schema entities are processed
differently than elements.

Eventually this module will be a full level 2 consumer and producer
enabling you to give you full DSML conformance.

The module uses callbacks to improve performance (at least the appearance
of improving performance ;) and to reduce the amount of memory required to
parse large DSML files. Every time a single entry or schema is processed
we pass the Net::LDAP object (either an Entry or Schema object) to the
callback routine.

=head1 CONSTRUCTOR 

new ()
Creates a new Net::LDAP::DSML object.  There are no options
to this method.

B<Example>

  my $dsml = Net::LDAP::DSML->new();

=head1 METHODS

=over 4

=item open ( OUTPUT )

OUTPUT is a referrence to either a file handle that has already
been opened or to an array.

B<Example>

  For a file.

  my $io = IO::File->new($file,"w");
  my $dsml = Net::LDAP::DSML->new();
  $dsml->open($io) or die ("DSML problems opening $file.$!\n");

  For an array.

  my @data = ();
  my $dsml = Net::LDAP::DSML->new();
  $dsml->open(\@data) or die ("DSML opening problems.$!\n"); 

=item write( ENTRY )

Entry is a Net::LDAP::Entry object. The write method will parse
the LDAP data in the Entry object and put it into DSML XML
format.

B<Example>

  my $entry = $mesg->entry();
  $dsml->write($entry);

=item finish ()

This method writes the closing DSML XML statements to the file or
array.  

B<Example>

  $dsml->finish();


=head1 AUTHOR

Mark Wilcox mark@mwjilcox.com

=head1 SEE ALSO

L<Net::LDAP>,
L<XML::Parser>

=head1 COPYRIGHT

Copyright (c) 2000 Graham Barr and Mark Wilcox. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut


