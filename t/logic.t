#!/usr/bin/env perl

# The decision logic, as a truth table.  From the FORMAL SPECIFICATION:
#
#	answer = 1  <=>  setup = ok  AND  baseline = ok  AND  modeSet
#	                 AND  attempt in { EACCES, EPERM }  AND  cleanup = ok
#	answer = 1  <=>  reason = undef
#
# Premises checked for every combination:
#	P1  the answer is 1 exactly when every conjunct holds;
#	P2  the reason is undef exactly when the answer is 1;
#	P3  the reason names the first step that failed (a cleanup failure
#	    is appended to it);
#	P4  whatever the combination, nothing is left in dir.

use strict;
use warnings;

use Errno ();
use File::Temp ();
use Test::Mockingbird ();
use Test::Most;
use Test::Warnings;

use lib 'lib';
use Test::Permissions qw(:all);

my $dir = File::Temp::tempdir(CLEANUP => 1);

sub listing {
	opendir(my $dh, $_[0]) or die;
	return [ sort grep { !/^\.\.?$/ } readdir $dh ];
}

my %ATTEMPT = (
	ok     => [ 1, 0 ],
	EACCES => [ 0, Errno::EACCES() ],
	EPERM  => [ 0, Errno::EPERM() ],
	ENOSPC => [ 0, Errno::ENOSPC() ],
	throws => 'die',
);

my $combinations = 0;
for my $kind (qw(read write create search)) {
	for my $setup (0, 1) {
		for my $baseline (0, 1) {
			for my $mode_set (0, 1) {
				for my $attempt (sort keys %ATTEMPT) {
					for my $cleanup (0, 1) {
						check($kind, $setup, $baseline, $mode_set, $attempt, $cleanup);
						$combinations++;
					}
				}
			}
		}
	}
}
is($combinations, 4 * 2 * 2 * 2 * 5 * 2, 'every combination checked');

sub check {
	my ($kind, $setup, $baseline, $mode_set, $attempt, $cleanup) = @_;
	my $name = "$kind setup=$setup baseline=$baseline modeSet=$mode_set attempt=$attempt cleanup=$cleanup";

	my @guards;
	push @guards, Test::Mockingbird::mock_scoped('Test::Permissions', '_make_probe_dir', sub { die "no setup\n" })
		unless $setup;
	for my $seam (qw(_try_open _try_stat)) {
		my $orig = \&{"Test::Permissions::$seam"};
		my $calls = 0;
		push @guards, Test::Mockingbird::mock_scoped('Test::Permissions', $seam, sub {
			if($calls++ == 0) {
				return $baseline ? $orig->(@_) : (0, Errno::EIO());
			}
			my $how = $ATTEMPT{$attempt};
			die "attempt threw\n" unless ref $how;
			return @{$how};
		});
	}
	unless($mode_set) {
		push @guards, Test::Mockingbird::mock_scoped('Test::Permissions', '_mode_of', sub { 0777 });
	}
	unless($cleanup) {
		my $orig = \&Test::Permissions::_cleanup;
		push @guards, Test::Mockingbird::mock_scoped('Test::Permissions', '_cleanup', sub { $orig->(@_); 'cleanup broke' });
	}

	clear_cache();
	my $answer = can_revoke($kind, $dir);
	my $why = why_not($kind, $dir);
	@guards = ();

	my $expected = ($setup && $baseline && $mode_set && ($attempt eq 'EACCES' || $attempt eq 'EPERM') && $cleanup) ? 1 : 0;
	is($answer, $expected, "P1 answer: $name");
	is(defined $why ? 0 : 1, $answer, "P2 reason iff 0: $name");

	if(!$answer) {
		my $first = !$setup ? qr/^Could not set up/
			: !$baseline ? qr/^\w+ access fails .* even when it is allowed/
			: !$mode_set ? qr/^chmod did not set mode/
			: $attempt eq 'ok' ? qr/^chmod cannot revoke/
			: $attempt eq 'ENOSPC' ? qr/failed for a reason other than permissions/
			: $attempt eq 'throws' ? qr/^Could not set up .*attempt threw/
			: qr/^chmod revoked/;
		like($why, $first, "P3 first failure named: $name");
		like($why, qr/; also could not clean up '.*': cleanup broke\z/, "P3 cleanup appended: $name") unless $cleanup;
	}
	is_deeply(listing($dir), [], "P4 nothing left: $name");
}

clear_cache();
done_testing();
