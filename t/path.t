#!/usr/bin/env perl

# One case per control-flow path through the module.  %ledger lists every
# path; the last test checks each was taken.  A new branch needs a ledger
# entry.

use strict;
use warnings;

use Carp ();
use Cwd ();
use Errno ();
use File::Spec ();
use File::Temp ();
use Test::Mockingbird ();
use Test::Most;
use Test::Warnings;

use lib 'lib';
use Test::Permissions ();

my %ledger = map { $_ => 0 } qw(
	args.hashref args.named args.positional args.none args.too_many args.get_params_croak
	args.unknown_kind args.validator_error args.not_a_directory args.default_dir args.object
	cache.miss cache.hit
	probe.make_probe_dir_throws probe.setup_throws probe.baseline_fails probe.tidy_throws
	probe.mode_of_undef probe.mode_mismatch probe.attempt_succeeds probe.attempt_eacces
	probe.attempt_eperm probe.attempt_other probe.attempt_throws
	cleanup.ok_answer1 cleanup.fail_answer1 cleanup.fail_answer0 cleanup.restore_false
	cleanup.remove_tree_throws cleanup.remove_tree_errors cleanup.no_probe_dir
	skip.answer1 skip.answer0
	msg.default msg.override msg.sprintf_dies
	printable.chars printable.utf8_bytes printable.other_bytes
	messages.empty messages.unknown_key messages.invalid_value messages.get_params_croak messages.ok
);

sub path { $ledger{$_[0]}++; return }

my $dir = File::Temp::tempdir(CLEANUP => 1);
my $canon = Cwd::abs_path($dir);

# attempt_is(@result): the attempt (second op call) returns @result, or
# dies if @result is ('die').
sub attempt_is {
	my @result = @_;
	my @guards;
	for my $seam (qw(_try_open _try_stat)) {
		my $orig = \&{"Test::Permissions::$seam"};
		my $calls = 0;
		push @guards, Test::Mockingbird::mock_scoped('Test::Permissions', $seam, sub {
			return $orig->(@_) unless $calls++;
			die "attempt died\n" if $result[0] eq 'die';
			return @result;
		});
	}
	return @guards;
}

sub probe { return [ Test::Permissions::_probe($_[0], $canon) ] }

# ---- argument handling ----------------------------------------------------

is(Test::Permissions::can_revoke_read({ dir => $dir }), Test::Permissions::can_revoke_read($dir), 'hashref');
path('args.hashref');
path('args.positional');
lives_ok { Test::Permissions::can_revoke_read(dir => $dir) } 'named';
path('args.named');
my ($p) = Test::Permissions::_check_args('dir', []);
is($p->{dir}, File::Spec->tmpdir, 'no arguments: default dir');
path('args.none');
path('args.default_dir');
throws_ok { Test::Permissions::can_revoke_read(1, 2) } qr/Too many/, 'too many';
path('args.too_many');
throws_ok { Test::Permissions::can_revoke({ kind => 'read' }, 'x', 'y') } qr/Too many/, 'hashref plus extras: positional too many';
{
	my $g = Test::Mockingbird::mock_scoped('Params::Get', 'get_params', sub { Carp::croak('Usage: bad') });
	throws_ok { Test::Permissions::can_revoke_read($dir) } qr/^Usage: bad at /, 'Params::Get croak passed on';
}
path('args.get_params_croak');
throws_ok { Test::Permissions::can_revoke('nope') } qr/Unknown access kind/, 'unknown kind';
path('args.unknown_kind');
throws_ok { Test::Permissions::can_revoke_read('') } qr/too short/, 'validator error';
path('args.validator_error');
throws_ok { Test::Permissions::can_revoke_read("$dir/x") } qr/is not a directory/, 'not a directory';
path('args.not_a_directory');
{
	package Str;
	use overload q{""} => sub { ${ $_[0] } }, fallback => 1;
}
lives_ok { Test::Permissions::can_revoke_read(bless \(my $s = $dir), 'Str') } 'object stringified';
path('args.object');

# ---- cache ----------------------------------------------------------------

Test::Permissions::clear_cache();
{
	my $spy = Test::Mockingbird::spy('Test::Permissions', '_probe');
	Test::Permissions::can_revoke_read($dir);
	is(scalar(my @c = $spy->()), 1, 'miss: probed');
	path('cache.miss');
	Test::Permissions::can_revoke_read($dir);
	is(scalar(@c = $spy->()), 1, 'hit: not probed again');
	path('cache.hit');
	Test::Mockingbird::restore_all();
}

# ---- _probe ---------------------------------------------------------------

{
	my $g = Test::Mockingbird::mock_scoped('Test::Permissions', '_make_probe_dir', sub { die "mk\n" });
	like(probe('read')->[1], qr/^Could not set up the read probe .*: mk$/, '_make_probe_dir throws');
	path('probe.make_probe_dir_throws');
}
{
	my $g = Test::Mockingbird::mock_scoped('Test::Permissions', '_setup_file', sub { die "setup\n" });
	like(probe('read')->[1], qr/: setup$/, 'setup throws after P exists');
	path('probe.setup_throws');
}
{
	my $g = Test::Mockingbird::mock_scoped('Test::Permissions', '_try_stat', sub { (0, Errno::EIO()) });
	like(probe('search')->[1], qr/even when it is allowed/, 'baseline fails');
	path('probe.baseline_fails');
}
{
	# The create probe's tidy step unlinks the file the baseline created;
	# a baseline that reports success without creating it makes tidy throw.
	my $g = Test::Mockingbird::mock_scoped('Test::Permissions', '_try_open', sub { (1, 0) });
	like(probe('create')->[1], qr/^Could not set up the create probe/, 'tidy throws');
	path('probe.tidy_throws');
}
{
	my $g = Test::Mockingbird::mock_scoped('Test::Permissions', '_mode_of', sub { undef });
	like(probe('write')->[1], qr/^Could not set up the write probe/, '_mode_of undef');
	path('probe.mode_of_undef');
}
{
	my $g = Test::Mockingbird::mock_scoped('Test::Permissions', '_mode_of', sub { 0600 });
	like(probe('write')->[1], qr/^chmod did not set mode 0400 .* \(got 0600\)$/, 'mode mismatch');
	path('probe.mode_mismatch');
}
{
	my @g = attempt_is(1, 0);
	like(probe('read')->[1], qr/^chmod cannot revoke read access/, 'attempt succeeds');
	path('probe.attempt_succeeds');
}
{
	my @g = attempt_is(0, Errno::EACCES());
	is_deeply(probe('read'), [ 1, undef ], 'attempt EACCES');
	path('probe.attempt_eacces');
	path('cleanup.ok_answer1');
}
{
	my @g = attempt_is(0, Errno::EPERM());
	is_deeply(probe('write'), [ 1, undef ], 'attempt EPERM');
	path('probe.attempt_eperm');
}
{
	my @g = attempt_is(0, Errno::EROFS());
	like(probe('create')->[1], qr/other than permissions/, 'attempt other errno');
	path('probe.attempt_other');
}
{
	my @g = attempt_is('die');
	like(probe('search')->[1], qr/: attempt died$/, 'attempt throws');
	path('probe.attempt_throws');
}

# ---- _cleanup -------------------------------------------------------------

{
	my @g = attempt_is(0, Errno::EACCES());
	my $orig = \&Test::Permissions::_cleanup;
	push @g, Test::Mockingbird::mock_scoped('Test::Permissions', '_cleanup', sub { $orig->(@_); 'x' });
	like(probe('read')->[1], qr/^chmod revoked read access in .*; also could not clean up .*: x$/, 'cleanup fails, answer was 1');
	path('cleanup.fail_answer1');
}
{
	my @g = attempt_is(1, 0);
	my $orig = \&Test::Permissions::_cleanup;
	push @g, Test::Mockingbird::mock_scoped('Test::Permissions', '_cleanup', sub { $orig->(@_); 'x' });
	like(probe('read')->[1], qr/^chmod cannot revoke read access .*; also could not clean up .*: x$/, 'cleanup fails, answer was 0');
	path('cleanup.fail_answer0');
}
{
	my $target = File::Spec->catfile($dir, 'target');
	like(Test::Permissions::_cleanup(undef, $target, 0600), qr/\Q$target\E/, 'restore throws');
	my $g = Test::Mockingbird::mock_scoped('Test::Permissions', '_set_mode', sub { 0 });
	like(Test::Permissions::_cleanup(undef, $target, 0600), qr/^\Q$target\E: /, 'restore returns false');
	path('cleanup.restore_false');
}
{
	my $g = Test::Mockingbird::mock_scoped('File::Path', 'remove_tree', sub { die "rt\n" });
	is(Test::Permissions::_cleanup('/p', undef, 0700), 'rt', 'remove_tree throws');
	path('cleanup.remove_tree_throws');
}
{
	my $g = Test::Mockingbird::mock_scoped('File::Path', 'remove_tree', sub { ${ $_[1]{error} } = [ { '/p/f' => 'busy' } ] });
	is(Test::Permissions::_cleanup('/p', undef, 0700), '/p/f: busy', 'remove_tree reports errors');
	path('cleanup.remove_tree_errors');
}
is(Test::Permissions::_cleanup(undef, undef, 0700), undef, 'no probe directory: nothing to do');
path('cleanup.no_probe_dir');

# ---- skip_unless_can_revoke --------------------------------------------------

Test::Permissions::clear_cache();
{
	my @g = attempt_is(0, Errno::EACCES());
	SKIP: {
		Test::Permissions::skip_unless_can_revoke('read', 1, $dir);
		pass('answer 1: block runs');
		path('skip.answer1');
	}
}
Test::Permissions::clear_cache();
{
	my @g = attempt_is(1, 0);
	path('skip.answer0');
	SKIP: {
		Test::Permissions::skip_unless_can_revoke('read', 1, $dir);
		fail('answer 0: not reached');
	}
}
Test::Permissions::clear_cache();

# ---- _msg and _printable -------------------------------------------------------

is(Test::Permissions::_msg('error_unknown_message', 'k'), q{Unknown message key 'k'}, 'default text');
path('msg.default');
Test::Permissions::set_messages(error_unknown_message => 'K=%s');
is(Test::Permissions::_msg('error_unknown_message', 'k'), 'K=k', 'override');
path('msg.override');
Test::Permissions::set_messages(error_unknown_message => '%99999999999999999999d');
is(Test::Permissions::_msg('error_unknown_message', 'k'), 'error_unknown_message: k', 'sprintf dies: key and arguments');
path('msg.sprintf_dies');
Test::Permissions::set_messages(error_unknown_message => q{Unknown message key '%s'});

is(Test::Permissions::_printable("\x{263A}\e"), "\x{263A}\\x{1B}", 'character string');
path('printable.chars');
is(Test::Permissions::_printable("\xE2\x98\xBA\e"), "\xE2\x98\xBA\\x{1B}", 'UTF-8 bytes');
path('printable.utf8_bytes');
is(Test::Permissions::_printable("\xFF\e"), "\xFF\\x{1B}", 'other bytes');
path('printable.other_bytes');

# ---- set_messages ----------------------------------------------------------

lives_ok { Test::Permissions::set_messages() } 'no arguments';
path('messages.empty');
throws_ok { Test::Permissions::set_messages(x => 'y') } qr/Unknown message key/, 'unknown key';
path('messages.unknown_key');
throws_ok { Test::Permissions::set_messages(reason_other_error => '') } qr/too short/, 'invalid value';
path('messages.invalid_value');
throws_ok { Test::Permissions::set_messages(1, 2, 3) } qr/Usage/, 'odd list';
path('messages.get_params_croak');
lives_ok { Test::Permissions::set_messages(reason_other_error => q{%s access in '%s' failed for a reason other than permissions: %s}) } 'valid';
path('messages.ok');

subtest 'ledger' => sub {
	ok($ledger{$_}, "path taken: $_") for sort keys %ledger;
};

done_testing();
