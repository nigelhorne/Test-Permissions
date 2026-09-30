#!/usr/bin/env perl

# Equivalence partitions and boundary values for every input and output.
#
#	kind    valid: read | write | create | search
#	        invalid: other strings (case, spaces, prefixes), '', undef
#	        (treated as missing), references
#	dir     valid: an existing directory (absolute, relative, with a
#	        trailing separator, a stringifying object); undef/absent ->
#	        tmpdir
#	        invalid: '', a missing path, a file, a reference
#	count   valid: whole numbers >= 1 (boundary 1; large)
#	        invalid: 0, negatives, fractions, non-numbers, absent
#	message keys: the 11 documented keys; anything else is refused
#	message texts: non-empty strings; '', undef and references refused
#	answer  exactly 1 or 0
#	reason  undef (answer 1) or a non-empty single-line string

use strict;
use warnings;

use Errno ();
use File::Spec ();
use File::Temp ();
use Test::Mockingbird ();
use Test::Most;
use Test::Returns;
use Test::Warnings;

use lib 'lib';
use Test::Permissions qw(:all);

my $dir = File::Temp::tempdir(CLEANUP => 1);

subtest 'kind' => sub {
	for my $kind (qw(read write create search)) {
		lives_ok { can_revoke($kind, $dir) } "valid: $kind";
	}
	for my $kind ('Read', 'SEARCH', ' read', 'read ', 're', 'reads', 'exec', 'delete', 'sticky', '0', "read\n") {
		(my $shown = $kind) =~ s/\n/\\n/g;
		throws_ok { can_revoke($kind, $dir) } qr/^Unknown access kind/, "invalid: '$shown'";
	}
	throws_ok { can_revoke('', $dir) } qr/^Unknown access kind ''/, "invalid: ''";
	throws_ok { can_revoke(undef, $dir) } qr/Required parameter 'kind'/, 'undef is missing';
	throws_ok { can_revoke({ dir => $dir }) } qr/Required parameter 'kind'/, 'absent';
	throws_ok { can_revoke(\'read', $dir) } qr/must be a string/, 'scalar reference';
};

subtest 'dir' => sub {
	lives_ok { can_revoke_read($dir) } 'absolute';
	lives_ok { can_revoke_read(File::Spec->catdir($dir, '')) } 'trailing separator';
	lives_ok { can_revoke_read(File::Spec->curdir) } 'relative (.)';
	lives_ok { can_revoke_read() } 'absent: tmpdir';
	lives_ok { can_revoke_read(undef) } 'undef: tmpdir';
	throws_ok { can_revoke_read('') } qr/too short/, "'': refused by the validator";
	throws_ok { can_revoke_read(File::Spec->catdir($dir, 'missing')) } qr/is not a directory/, 'missing';
	my $file = File::Spec->catfile($dir, 'f');
	open(my $fh, '>', $file) or die $!;
	close $fh;
	throws_ok { can_revoke_read($file) } qr/is not a directory/, 'a file';
	unlink $file;
	throws_ok { can_revoke_read([ $dir ]) } qr/must be a string/, 'array reference';
	throws_ok { can_revoke_read({ dir => [ $dir ] }) } qr/must be a string/, 'array reference, named';
	throws_ok { can_revoke_read(dir => '0') } qr/is not a directory/, "'0' is a (missing) path, not false";
};

subtest 'count' => sub {
	my @g;
	for my $seam (qw(_try_open _try_stat)) {
		my $orig = \&{"Test::Permissions::$seam"};
		my $n = 0;
		push @g, Test::Mockingbird::mock_scoped('Test::Permissions', $seam, sub { $n++ ? (0, Errno::EACCES()) : $orig->(@_) });
	}
	clear_cache();
	for my $count (1, 2, 1_000_000, '3') {
		SKIP: {
			lives_ok { skip_unless_can_revoke('read', $count, $dir) } "valid: $count";
		}
	}
	for my $count (0, -1, -1000, 1.5, '1e0x', 'x', '') {
		throws_ok { skip_unless_can_revoke('read', $count, $dir) } qr/'count'/, "invalid: '$count'";
	}
	throws_ok { skip_unless_can_revoke('read') } qr/'count' is missing/, 'absent';
	throws_ok { skip_unless_can_revoke('read', undef, $dir) } qr/'count' is missing/, 'undef';
	clear_cache();
};

subtest 'outputs' => sub {
	Test::Permissions::clear_cache();
	for my $kind (qw(read write create search)) {
		my $answer = can_revoke($kind, $dir);
		ok($answer eq '1' || $answer eq '0', "$kind: answer is exactly 1 or 0");
		returns_ok($answer, { type => 'boolean' }, "$kind: boolean");
		my $why = why_not($kind, $dir);
		returns_ok($why, { type => 'string', optional => 1 }, "$kind: reason schema");
		ok(!defined $why || ($why ne '' && $why !~ /\n/), "$kind: reason undef or one non-empty line");
	}
	my $g = Test::Mockingbird::mock_scoped('Test::Permissions', '_make_probe_dir', sub { die "a\nb\n" });
	clear_cache();
	unlike(why_not('read', $dir), qr/\n/, 'multi-line exception texts are escaped onto one line');
	clear_cache();
};

subtest 'message keys and texts' => sub {
	my @keys = qw(
		error_unknown_kind error_not_a_directory error_unknown_message error_too_many_arguments
		reason_not_enforced reason_chmod_ignored reason_baseline_failed reason_other_error
		reason_setup_failed reason_cleanup_failed reason_probe_succeeded
	);
	# Run last: the texts are left changed.
	for my $key (@keys) {
		lives_ok { set_messages($key => 'x') } "valid key: $key";
		is(Test::Permissions::_msg($key), 'x', '... applied');
	}
	set_messages(error_unknown_message => q{Unknown message key '%s'});
	for my $key ('ERROR_UNKNOWN_KIND', 'error_unknown', 'reason', '', 'x y') {
		throws_ok { set_messages($key => 'x') } qr/^Unknown message key/, "invalid key: '$key'";
	}
	throws_ok { set_messages(reason_other_error => '') } qr/too short/, "text ''";
	throws_ok { set_messages(reason_other_error => undef) } qr/reason_other_error/, 'text undef';
	throws_ok { set_messages(reason_other_error => {}) } qr/must be a string/, 'text reference';
	lives_ok { set_messages(reason_other_error => ' ') } 'text of one space (boundary: length 1)';
};

done_testing();
