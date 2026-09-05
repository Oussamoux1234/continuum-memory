package IPC::Cmd;

use strict;
use warnings;

sub import { }

sub can_run {
    my ($command) = @_;
    return undef if !defined($command) || $command eq q{} || index($command, "\0") >= 0;

    if (index($command, q{/}) >= 0) {
        return (-f $command && -x _) ? $command : undef;
    }

    my $path = $ENV{PATH} // q{};
    for my $directory (split(/:/, $path, -1)) {
        # Empty PATH entries mean the working directory.  The build never
        # needs that behavior, and rejecting it avoids accidental substitution.
        next if $directory eq q{};
        my $candidate = "$directory/$command";
        return $candidate if -f $candidate && -x _;
    }
    return undef;
}

1;
