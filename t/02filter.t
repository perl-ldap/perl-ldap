#!perl
# Testcase contributed by  Julian Onions <Julian.Onions@nexor.co.uk>

use Net::LDAP::Filter;
use Net::LDAP::ASN qw(Filter);

my $asn = $Filter;

@tests = 
    (
     [ '(objectclass=foo)', 
       'a312040b6f626a656374636c6173730403666f6f' ],
     [ '(objectclass=)', 
       'a30f040b6f626a656374636c6173730400' ],
     [ 'createTimestamp>=199701011200Z',
       'a520040f63726561746554696d657374616d70040d3139393730313031313230305a' ],
     [ 'createTimestamp<=199801011210Z',
       'a620040f63726561746554696d657374616d70040d3139393830313031313231305a' ],
     [ '(cn=a*)', 'a4090402636e3003800161' ],
     [ '(cn=*a)', 'a4090402636e3003820161' ],
     [ 'cn=*a*', 'a4090402636e3003810161' ],
     [ '(cn=*)', '8702636e'],
     [ '(cn~=foo)', 'a8090402636e0403666f6f'],
# ones taken from RFC2254
     [ '(cn=Babs Jensen)', 
       'a3110402636e040b42616273204a656e73656e' ],
     [ '(!(cn=Tim Howes))',
       'a211a30f0402636e040954696d20486f776573' ],
     [ '!(cn=Tim Howes)',
       'a211a30f0402636e040954696d20486f776573' ],
     [ '(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))',
       'a037a315040b6f626a656374436c6173730406506572736f6ea11ea30c0402736e04064a656e73656ea40e0402636e3008800642616273204a' ],
     [ '(o=univ*of*mich*)', 
       'a41504016f30108004756e697681026f6681046d696368' ],
     [ '(cn:1.2.3.4.5:=Fred Flintstone)',
       'a9238109312e322e332e342e358202636e830f4672656420466c696e7473746f6e65840100'],
     [ '(sn:dn:2.4.6.8.10:=Barney Rubble)',
       'a922810a322e342e362e382e31308202736e830d4261726e657920527562626c658401ff'],
     [ '(o:dn:=Ace Industry)',
       'a91482016f830c41636520496e6475737472798401ff'],
     [ '(:dn:2.4.6.8.10:=Dino)',
       'a917810a322e342e362e382e31308200830444696e6f8401ff'],
# now some other cases.
     [ '(o=univ*of*mich*an)', 
       'a41904016f30148004756e697681026f6681046d6963688202616e' ],
     [ '(&(cn=fred)(!(objectclass=organization)))', 
       'a02ba30a0402636e040466726564a21da31b040b6f626a656374636c617373040c6f7267616e697a6174696f6e' ],
# the following come in pairs. The first is a filter, the second is an
# optimised form of the same filter.
     [ '(| (& (cn=test)) (| (cn=foo)))', 
       'a11ba00ca30a0402636e040474657374a10ba3090402636e0403666f6f' ],
     [ '(| (cn=foo) (cn=test))', 
       'a117a3090402636e0403666f6fa30a0402636e040474657374' ],
     [ '(& (| (cn=test) (cn=foo) (sn=bar)) (| (c=GB) (c=AU)))', 
       'a038a122a30a0402636e040474657374a3090402636e0403666f6fa3090402736e0403626172a112a30704016304024742a30704016304024155' ],
     [ '(| (& (c=GB) (cn=test)) (& (c=AU) (cn=test)) (& (c=GB) (cn=foo)) (& (c=AU) (cn=foo)) (& (c=GB) (sn=bar)) (& (c=AU) (sn=bar)))', 
       'a18186a015a30704016304024742a30a0402636e040474657374a015a30704016304024155a30a0402636e040474657374a014a30704016304024742a3090402636e0403666f6fa014a30704016304024155a3090402636e0403666f6fa014a30704016304024742a3090402736e0403626172a014a30704016304024155a3090402736e0403626172' ],
     [ '(& (| (cn=test) (cn=foo) (sn=bar)) (c=GB))', 
       'a02da122a30a0402636e040474657374a3090402636e0403666f6fa3090402736e0403626172a30704016304024742' ],
     [ '(| (& (sn=bar) (c=GB)) (& (cn=foo) (c=GB)) (& (cn=test) (c=GB)))', 
       'a143a014a3090402736e0403626172a30704016304024742a014a3090402636e0403666f6fa30704016304024742a015a30a0402636e040474657374a30704016304024742' ],
     [ '(& (& (cn=foo) (| (cn=bar) (cn=xyz))) (& (cn=foo2) (| (cn=1) (cn=2))))',
       'a047a023a3090402636e0403666f6fa116a3090402636e0403626172a3090402636e040378797aa020a30a0402636e0404666f6f32a112a3070402636e040131a3070402636e040132' ],
     [ '(& (& (cn=foo) (! (cn=bar))) (| (cn=oof) (cn=foobie)))', 
       'a035a018a3090402636e0403666f6fa20ba3090402636e0403626172a119a3090402636e04036f6f66a30c0402636e0406666f6f626965' ],
     [ '(| (& (cn=foobie) (cn=foo) (! (cn=bar))) (& (cn=oof) (cn=foo) (! (cn=bar))))', 
       'a14da026a30c0402636e0406666f6f626965a3090402636e0403666f6fa20ba3090402636e0403626172a023a3090402636e04036f6f66a3090402636e0403666f6fa20ba3090402636e0403626172' ],
     [ '(| (cn=foo) (cn=bar) (! (& (cn=a) (cn=b) (cn=c))))',
       'a135a3090402636e0403666f6fa3090402636e0403626172a21da01ba3070402636e040161a3070402636e040162a3070402636e040163' ],
     [ '(| (! (cn=a)) (! (cn=b)) (! (cn=c)) (cn=foo) (cn=bar))',
       'a137a209a3070402636e040161a209a3070402636e040162a209a3070402636e040163a3090402636e0403666f6fa3090402636e0403626172' ],
     [ '(& (cn=foo) (cn=bar) (! (& (cn=a) (cn=b) (cn=c))))', 
       'a035a3090402636e0403666f6fa3090402636e0403626172a21da01ba3070402636e040161a3070402636e040162a3070402636e040163' ],
     [ '(| (& (! (cn=a)) (cn=bar) (cn=foo)) (& (! (cn=b)) (cn=bar) (cn=foo)) (& (! (cn=c)) (cn=bar) (cn=foo)))',
       'a169a021a209a3070402636e040161a3090402636e0403626172a3090402636e0403666f6fa021a209a3070402636e040162a3090402636e0403626172a3090402636e0403666f6fa021a209a3070402636e040163a3090402636e0403626172a3090402636e0403666f6f' ],
     [ '(| (cn=foo\(bar\)) (cn=test))', 
       'a11ca30e0402636e0408666f6f2862617229a30a0402636e040474657374' ],
     [ '(cn=foo\\*)',
	'a30a0402636e0404666f6f2a' ],
     [ '(cn=foo\\\\*)',
	'a40c0402636e30068004666f6f5c' ],
     [ '(cn=\\\\*foo)',
	'a40e0402636e300880015c8203666f6f' ],
     [ '(cn=\\\\*foo\\\\*)',
	'a40f0402636e300980015c8104666f6f5c' ],
     );

print "1..", 4*scalar(@tests), "\n";
my $testno = 0;
my $testref;
foreach $testref (@tests) {
    my($filter, $binary) = @$testref;
    $binary = pack("H*", $binary);
    $testno ++;
    print "# ",$filter,"\n";
    $filt = new Net::LDAP::Filter $filter or print "not ";
    print "ok $testno\n";
    $testno ++;
    my $data = $asn->encode($filt) or print "# ",$asn->error,"\nnot ";
    print "ok $testno\n";
    $testno ++;
    unless($data eq $binary) {
	require Data::Dumper;
	print Data::Dumper::Dumper($filt);
	print "got    ", unpack("H*", $data), "\n";
	print "wanted ", unpack("H*", $binary), "\n";

	print "not "
    }
    print "ok $testno\n";
    $testno ++;

    my $str = $filt->as_string;
    $filter = "($filter)" unless $filter =~ /^\(/;
    $filter =~ s/ \(/\(/g;
    print "# ", $str,"\n";
    print "not " unless $str eq $filter;
    print "ok $testno\n";
}
