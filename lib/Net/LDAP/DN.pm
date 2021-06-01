#
# see Net/LDAP/DN.pod for docs
#
package Net::LDAP::DN;

use strict;
use Net::LDAP::Util;
use Carp qw/ /;
use vars qw/ $VERSION /;

$VERSION = "0.01";

use overload
    '""'  => sub { $_[0]->as_string;         },
    'cmp' => sub { $_[0]->compare($_[1]);     },
    'eq'  => sub { $_[0]->equal($_[1]);        },
    'ne'  => sub { not $_[0]->equal($_[1]);     },
    'lt'  => sub { $_[0]->is_subordinate($_[1]); },
    'gt'  => sub { $_[1]->is_subordinate($_[0]);  },
    'le'  => sub { $_[0]->equal($_[1]) or $_[1]->is_subordinate($_[0]) },
    'le'  => sub { $_[0]->equal($_[1]) or $_[0]->is_subordinate($_[1]) },
    '&'   => sub { $_[0]->common_base($_[1]);     },
    '-'   => sub { $_[0]->strip($_[1]);          },
    '+'   => sub { $_[0]->append($_[1]);        },
    ;


sub new {
    my $me   = shift;
    my $dn   = shift;
    my @opts = @_;

    my $type = ref($me) || $me;
    my $self = bless {}, $type;

    @opts = (casefold => 'upper') unless @opts;
    Carp::croak "odd number of option arguments" if @opts % 2;
    $self->options(@opts);

    return $self
        unless defined $dn;

    if (ref $dn eq 'HASH') {
        $self->dn([$dn]);
    } else {
        $self->dn($dn);
    }
    return $self;
}


sub clone {
    my ($self, $dn) = @_;
    my $clone = $self->new();

    $clone->options($self->options);
    $clone->case_insensitive($self->case_insensitive);

    unless (defined $dn) {
        my @dn = ();
        foreach (@{ $self->dn }) {
            my $copy = {};
            while (my ($attr, $val) = each %$_) {
                $copy->{$attr} = $val;
            }
            push @dn, $copy;
        }
        $dn = [@dn];
    }

    $clone->dn($dn);
    return $clone;
}


sub options {
    my $self = shift;
    if (@_ and not @_ % 2) {
        my %opts = @_;
        if (exists $opts{case_insensitive}) {
            $self->case_insensitive(delete $opts{case_insensitive});
        }
        $self->{_options} = [%opts];
    }
    return @{$self->{_options}};
}


sub case_insensitive {
    @_ == 2
        ? $_[0]->{_case_insensitive} = $_[1]
        : $_[0]->{_case_insensitive};
}


sub dn {
    my $self = shift;
    my $dn   = shift;

    if (defined $dn) {
        unless (ref $dn eq 'ARRAY') {
            $dn = Net::LDAP::Util::ldap_explode_dn($dn, $self->options);
        }
        $self->{_dn} = $dn;
    }
    $self->{_dn};
}


sub as_string {
    Net::LDAP::Util::canonical_dn($_[0]->dn, $_[0]->options);
}


sub parent {
    my $self = shift;
    my @dn   = @{ $self->dn }; # use a copy, otherwise $parent eq $self...

    return $self->clone([splice @dn, 1]);
}


sub rdn {
    my $self = shift;
    shift @_
        ? Net::LDAP::Util::canonical_dn([$self->dn->[0]], $self->options)
        : join("+", values %{ $self->dn->[0] });
}

#sub first { $_[0]->clone($_[0]->dn->[0]); }


sub attr {
    join("+", keys %{ $_[0]->dn->[0] });
}


sub attributes {
    map { keys %$_ } @{ $_[0]->dn };
}


sub values {
    map { CORE::values %$_ } @{ $_[0]->dn };
}


sub append {
    my ($self, $other) = @_;

    unless (ref($other) and eval { $other->isa('Net::LDAP::DN') }) {
        $other = $self->clone($other);
    }

    return $self->clone([@{ $self->dn }, @{ $other->dn }]);
}


sub strip {
    my ($self, $other) = @_;

    unless (eval { $other->isa('Net::LDAP::DN') }) {
        $other = $self->clone($other);
    }

    Carp::croak "DN to be stripped is not a parent of self"
        unless $self->is_subordinate($other);

    my @lhs = @{ $self->dn };
    @lhs = splice @lhs, 0, @lhs - @{ $other->dn };

    return $self->clone(\@lhs);
}


sub pretty {
    my $self = shift;
    my $sep  = shift;
    my $func = shift || sub { $_[0]; };

    $sep = defined $sep ? $sep : "/";
    return join($sep, reverse map { $func->($_) } $self->values);
}


sub common_base {
    my ($self, $other) = @_;

    unless (eval { $other->isa('Net::LDAP::DN') }) {
        $other = $self->clone($other);
    }

    my @lhs = reverse @{ $self->dn };
    my @rhs = reverse @{ $other->dn };

    # swap if necessary:
    @rhs = splice @lhs, 0, @lhs, @rhs
        if @lhs < @rhs;

    my @common = ();
    for (my $i = 0; $i < scalar(@rhs); $i++) {
        last unless $self->_rdn_equal($lhs[$i], $rhs[$i]);
        push @common, $lhs[$i];
    }

    return $self->clone([reverse @common])
}


sub equal {
    my ($self, $other) = @_;

    unless (eval { $other->isa('Net::LDAP::DN') }) {
        $other = $self->clone($other);
    }

    return undef
        unless @{ $self->dn } == @{ $other->dn };

    return $self->_compare($self->dn, $other->dn);
}


sub compare {
    return -1 if $_[0]->is_subordinate($_[1]);
    return  1 if $_[1]->is_subordinate($_[0]);
    return  0;
}


sub is_subordinate {
    my ($self, $other) = @_;

    unless (eval { $other->isa('Net::LDAP::DN') }) {
        $other = $self->clone($other);
    }

    my @lhs = reverse @{ $self->dn };
    my @rhs = reverse @{ $other->dn };

    return undef
        unless @lhs > @rhs;
    return $self->_compare(\@rhs, \@lhs);
}

sub _compare {
    my $self = shift;
    # NOTE: scalar(@lhs) must be less or equal scalar(@rhs)
    my @lhs = @{ $_[0] };
    my @rhs = @{ $_[1] };

    for (my $i = 0; $i < scalar(@lhs); $i++) {
        return undef
            unless $self->_rdn_equal($lhs[$i], $rhs[$i]);
    }

    return 1;
}

sub _rdn_equal {
    my $self = shift;
    my ($lhs, $rhs) = @_;

    return undef unless keys %$lhs == keys %$rhs;

    foreach my $key (keys %$lhs) {
        return undef if not exists $rhs->{$key};

        if ($self->case_insensitive) {
            return undef if lc $lhs->{$key} ne lc $rhs->{$key};
        } else {
            return undef if $lhs->{$key} ne $rhs->{$key};
        }
    }

    return 1;
}


sub rename {
    my $self = shift;
    my $rdn  = shift;

    if (ref $rdn ne 'HASH') {
        Carp::croak "'new' is not a hash ref"
            unless @_;
        $rdn = { $rdn => shift };
    }

    $self->dn->[0] = $rdn;
    return $self;
}


sub move {
    my ($self, $other) = @_;

    unless (eval { $other->isa('Net::LDAP::DN') }) {
        $other = $self->clone($other);
    }

    $self->dn( [$self->dn->[0], @{ $other->dn }] );
    return $self;
}

1;
# this is the last line :-)
