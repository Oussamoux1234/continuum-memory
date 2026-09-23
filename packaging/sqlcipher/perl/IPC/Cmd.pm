package IPC::Cmd;

# SPDX-License-Identifier: Apache-2.0
# Project-controlled minimal compatibility shim for the pinned OpenSSL build.

use strict;
use warnings;

sub import { }

sub can_run {
    my ($command) = @_;
    return undef if !defined($command) || $command eq q{} || index($command, "\0") >= 0;

    if (index($command, q{/}) >= 0) {
        return undef if substr($command, 0, 1) ne q{/};
        return undef if grep { $_ eq q{} || $_ eq q{.} || $_ eq q{..} } split(q{/}, substr($command, 1), -1);
        return (-f $command && -x _) ? $command : undef;
    }
    return undef if $command !~ /\A[A-Za-z0-9_.+:-]+\z/;

    my $path = $ENV{PATH} // q{};
    for my $directory (split(/:/, $path, -1)) {
        # Empty and relative entries can resolve through the working directory.
        # The build uses an absolute, project-reviewed PATH and never needs them.
        next if $directory eq q{} || substr($directory, 0, 1) ne q{/};
        next if grep { $_ eq q{} || $_ eq q{.} || $_ eq q{..} } split(q{/}, substr($directory, 1), -1);
        my $candidate = "$directory/$command";
        return $candidate if -f $candidate && -x _;
    }
    return undef;
}

1;
