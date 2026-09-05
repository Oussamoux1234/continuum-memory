package Time::Piece;

use strict;
use warnings;

my %MONTH = (
    Jan => 1, Feb => 2, Mar => 3, Apr => 4, May => 5, Jun => 6,
    Jul => 7, Aug => 8, Sep => 9, Oct => 10, Nov => 11, Dec => 12,
);

sub import {
    my $caller = caller;
    no strict 'refs';
    *{"${caller}::localtime"} = \&localtime;
}

sub localtime {
    my ($epoch) = @_;
    $epoch = time if !defined($epoch);
    my @parts = CORE::localtime($epoch);
    return bless {
        day => $parts[3],
        month => $parts[4] + 1,
        year => $parts[5] + 1900,
    }, __PACKAGE__;
}

sub strptime {
    my ($class, $value, $format) = @_;
    die "unsupported date format\n" if !defined($format) || $format ne q{%d %b %Y};
    die "invalid release date\n"
        if !defined($value) || $value !~ /\A(\d{2}) ([A-Z][a-z]{2}) (\d{4})\z/;
    my ($day, $month_name, $year) = ($1, $2, $3);
    my $month = $MONTH{$month_name};
    my $leap_year = $year % 4 == 0 && ($year % 100 != 0 || $year % 400 == 0);
    my @month_days = (0, 31, $leap_year ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31);
    die "invalid release date\n"
        if !defined($month)
        || $day < 1
        || $day > $month_days[$month]
        || $year < 1970
        || $year > 9999;
    return bless {day => int($day), month => $month, year => int($year)}, $class;
}

sub strftime {
    my ($self, $format) = @_;
    die "unsupported output format\n" if !defined($format) || $format ne q{%Y-%m-%d};
    return sprintf(q{%04d-%02d-%02d}, $self->{year}, $self->{month}, $self->{day});
}

1;
