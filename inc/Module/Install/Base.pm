#line 1 "inc/Module/Install/Base.pm - /Users/gbarr/Library/Perl/Module/Install/Base.pm"
# $File: //depot/cpan/Module-Install/lib/Module/Install/Base.pm $ $Author: autrijus $
# $Revision: #10 $ $Change: 1847 $ $DateTime: 2003/12/31 23:14:54 $ vim: expandtab shiftwidth=4

package Module::Install::Base;

#line 31

sub new {
    my ($class, %args) = @_;

    foreach my $method (qw(call load)) {
        *{"$class\::$method"} = sub {
            +shift->_top->$method(@_);
        } unless defined &{"$class\::$method"};
    }

    bless(\%args, $class);
}

#line 49

sub AUTOLOAD {
    my $self = shift;
    goto &{$self->_top->autoload};
}

#line 60

sub _top { $_[0]->{_top} }

#line 71

sub admin {
    my $self = shift;
    $self->_top->{admin} or Module::Install::Base::FakeAdmin->new;
}

sub is_admin {
    my $self = shift;
    $self->admin->VERSION;
}

sub DESTROY {}

package Module::Install::Base::FakeAdmin;

my $Fake;
sub new { $Fake ||= bless(\@_, $_[0]) }
sub AUTOLOAD {}
sub DESTROY {}

1;

__END__

#line 115
