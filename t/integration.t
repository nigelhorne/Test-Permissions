#!/usr/bin/env perl

# End to end: a separate perl runs a test file that uses Test::Permissions
# the way a downstream distribution does, and its TAP output is checked.
# No mocking: this is also the real-filesystem consistency check.  When an
# answer is 1, the restricted state is set up by hand and the operation
# must really fail; when it is 0, why_not must explain.

use strict;
use warnings;

use Cwd ();
use File::Spec ();
use File::Temp ();
use Test::Most;
use Test::Warnings;

use lib 'lib';
use Test::Permissions qw(:all);

my $lib = Cwd::abs_path('lib');
my $work = File::Temp::tempdir(CLEANUP => 1);

# write_program($name, $code): write a helper program to a file.  (A long
# -e is flattened on Windows.)
sub write_program {
	my ($name, $code) = @_;
	my $path = File::Spec->catfile($work, $name);
	open(my $fh, '>', $path) or die "$path: $!";
	print {$fh} $code;
	close $fh or die "$path: $!";
	return $path;
}

# run(@args): run perl with -I lib, returning (output with CRLF normalised,
# exit status).
sub run {
	my @args = @_;
	open(my $out, '-|', $^X, "-I$lib", @args) or die "Cannot run $^X: $!";
	my $text = do { local $/; <$out> };
	close $out;
	my $status = $? >> 8;
	$text = '' unless defined $text;
	$text =~ s/\r\n/\n/g;
	return ($text, $status);
}

my $downstream = write_program('downstream.t', <<'PROGRAM');
use strict;
use warnings;
use File::Spec;
use File::Temp qw(tempdir);
use Test::More;
use Test::Permissions qw(:revoke);

my $dir = tempdir(CLEANUP => 1);
my %attempt = (
	read   => sub { my ($d) = @_; my $f = "$d/f"; open(my $w, '>', $f) or die; close $w;
			chmod 0, $f; my $ok = open(my $r, '<', $f); chmod 0600, $f; !$ok },
	write  => sub { my ($d) = @_; my $f = "$d/f"; open(my $w, '>', $f) or die; close $w;
			chmod 0400, $f; my $ok = open(my $a, '>>', $f); chmod 0600, $f; !$ok },
	create => sub { my ($d) = @_; mkdir "$d/sub" or die; chmod 0500, "$d/sub";
			my $ok = open(my $w, '>', "$d/sub/new"); chmod 0700, "$d/sub"; !$ok },
	search => sub { my ($d) = @_; mkdir "$d/sub" or die; open(my $w, '>', "$d/sub/f") or die; close $w;
			chmod 0, "$d/sub"; my $ok = stat "$d/sub/f"; chmod 0700, "$d/sub"; !$ok },
);

for my $kind (qw(read write create search)) {
	my $answer = can_revoke($kind, $dir);
	print "# ANSWER $kind $answer\n";
	if(!$answer) {
		my $why = why_not($kind, $dir);
		ok(defined $why && length $why, "$kind: why_not explains a 0");
	}
	SKIP: {
		skip_unless_can_revoke($kind, 2, $dir);
		ok(!defined why_not($kind, $dir), "$kind: why_not is undef for a 1");
		my $scratch = tempdir(DIR => $dir, CLEANUP => 1);
		ok($attempt{$kind}->($scratch), "$kind: the restricted operation really fails");
	}
}
opendir(my $dh, $dir) or die;
my @left = grep { !/^\.\.?$/ && !/^[A-Za-z0-9_]{10}$/ } readdir $dh;
is_deeply(\@left, [], 'no probe directories left');
done_testing();
PROGRAM

subtest 'a downstream test file' => sub {
	my ($output, $status) = run($downstream);
	is($status, 0, 'exits 0') or diag($output);
	my %answer = $output =~ /^# ANSWER (\w+) ([01])$/mg;
	is(scalar keys %answer, 4, 'an answer for every kind');
	for my $kind (sort keys %answer) {
		if($answer{$kind}) {
			like($output, qr/^ok \d+ - $kind: the restricted operation really fails$/m, "$kind: consistent with a real chmod");
		} else {
			my @skips = $output =~ /^ok \d+ # skip (.+)$/mg;
			ok((grep { /\Q$kind\E/ } @skips) == 2, "$kind: exactly 2 tests skipped, with the reason");
		}
	}
	unlike($output, qr/^not ok/m, 'no failures');
	like($output, qr/^1\.\.\d+$/m, 'a plan');
};

subtest 'answers agree with this process' => sub {
	my ($output) = run($downstream);
	my %answer = $output =~ /^# ANSWER (\w+) ([01])$/mg;
	my $dir = File::Temp::tempdir(CLEANUP => 1);
	is(can_revoke($_, $dir), $answer{$_}, "$_: same answer on the same filesystem") for sort keys %answer;
};

subtest 'loaded without importing anything' => sub {
	my $program = write_program('plain.pl', <<'PROGRAM');
use strict;
use warnings;
use Test::Permissions ();
my @subs = sort grep { defined &{"Test::Permissions::$_"} } keys %Test::Permissions::;
print join(',', grep { !/^_/ } @subs), "\n";
print defined &main::can_revoke ? "leaked\n" : "clean\n";
PROGRAM
	my ($output, $status) = run($program);
	is($status, 0, 'runs');
	is((split /\n/, $output)[0],
		'can_revoke,can_revoke_create,can_revoke_read,can_revoke_search,can_revoke_write,clear_cache,set_messages,skip_unless_can_revoke,why_not',
		'the package holds only its own public subs: nothing imported')
		or diag($output);
	like($output, qr/^clean$/m, 'nothing exported by default');
};

subtest 'nothing left behind at exit' => sub {
	my $dir = File::Temp::tempdir(CLEANUP => 1);
	my $program = write_program('exit.pl', <<'PROGRAM');
use strict;
use warnings;
use Test::Permissions ();
Test::Permissions::can_revoke($_, $ARGV[0]) for qw(read write create search);
PROGRAM
	my (undef, $status) = run($program, $dir);
	is($status, 0, 'runs');
	opendir(my $dh, $dir) or die;
	is_deeply([ grep { !/^\.\.?$/ } readdir $dh ], [], 'directory empty afterwards');
};

subtest 'skip helper outside a SKIP block' => sub {
	my $program = write_program('noskip.pl', <<'PROGRAM');
use strict;
use warnings;
use Test::More;
use Test::Permissions ();
open(STDERR, '>&', \*STDOUT) or die;
$| = 1;
no warnings 'redefine';
*Test::Permissions::_try_open = sub { (1, 0) };	# simulate root
Test::Permissions::skip_unless_can_revoke('read', 1);
PROGRAM
	my ($output, $status) = run($program);
	isnt($status, 0, 'dies, as Test::More::skip does');
	like($output, qr/Label not found for "last SKIP"/, "with perl's message");
};

done_testing();
