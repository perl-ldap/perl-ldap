#line 1 "inc/Module/Install/Include.pm - /Users/gbarr/Library/Perl/Module/Install/Include.pm"
# $File: //depot/cpan/Module-Install/lib/Module/Install/Include.pm $ $Author: autrijus $
# $Revision: #8 $ $Change: 1811 $ $DateTime: 2003/12/14 18:52:33 $ vim: expandtab shiftwidth=4

package Module::Install::Include;
use Module::Install::Base; @ISA = qw(Module::Install::Base);

sub include { +shift->admin->include(@_) };
sub include_deps { +shift->admin->include_deps(@_) };
sub auto_include { +shift->admin->auto_include(@_) };

1;
