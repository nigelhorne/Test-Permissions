#!/usr/bin/env perl

# Black-box tests driven by the POD.  Every documented function, argument
# form, return value and message has an entry in %ledger; the last test
# checks that each entry was exercised.  A new message, argument or
# function needs a ledger entry.

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
use Test::Permissions ();

my %ledger = map { $_ => 0 } (
	# functions
	'fn:can_revoke_read', 'fn:can_revoke_write', 'fn:can_revoke_create', 'fn:can_revoke_search',
	'fn:can_revoke', 'fn:why_not', 'fn:skip_unless_can_revoke', 'fn:clear_cache', 'fn:set_messages',
	# argument forms
	'form:none', 'form:positional', 'form:named', 'form:hashref', 'form:object',
	# exports
	'export:none-by-default', 'export:ok', 'export:all', 'export:revoke',
	# messages
	(map { "msg:$_" } qw(
		error_unknown_kind error_not_a_directory error_unknown_message error_too_many_arguments
		reason_not_enforced reason_chmod_ignored reason_baseline_failed reason_other_error
		reason_setup_failed reason_cleanup_failed reason_probe_succeeded
	)),
);

sub covered { $ledger{$_}++ for @_; return }

my $dir = File::Temp::tempdir(CLEANUP => 1);
my @KINDS = qw(read write create search);

# chmod_works(): make chmod behave as on Unix whatever the platform, so a
# scenario reaches the step it is about.  (On Windows chmod 0 leaves mode
# 0444, and the probe would stop at the mode check.)  _mode_of reports the
# mode last given to _set_mode.  Returns the guards.
sub chmod_works {
	my %mode;
	my $set = \&Test::Permissions::_set_mode;
	my $of = \&Test::Permissions::_mode_of;
	return (
		Test::Mockingbird::mock_scoped('Test::Permissions', '_set_mode',
			sub { my $r = $set->(@_); $mode{$_[0]} = $_[1]; $r }),
		Test::Mockingbird::mock_scoped('Test::Permissions', '_mode_of',
			sub { exists $mode{$_[0]} ? $mode{$_[0]} : $of->(@_) }),
	);
}

sub simulate_attempt {
	my ($ok, $errno) = @_;
	my @guards = chmod_works();
	for my $seam (qw(_try_open _try_stat)) {
		my $orig = \&{"Test::Permissions::$seam"};
		my $calls = 0;
		push @guards, Test::Mockingbird::mock_scoped('Test::Permissions', $seam,
			sub { $calls++ ? ($ok, $errno) : $orig->(@_) });
	}
	return @guards;
}

subtest 'exports' => sub {
	ok(!defined &main::can_revoke_read, 'nothing exported by default');
	covered('export:none-by-default');

	package Ex::Ok { Test::Permissions->import(qw(why_not can_revoke)) }
	ok(defined &Ex::Ok::why_not && defined &Ex::Ok::can_revoke, 'named imports');
	ok(!defined &Ex::Ok::clear_cache, 'only those');
	covered('export:ok');

	package Ex::All { Test::Permissions->import(':all') }
	ok(defined &{"Ex::All::$_"}, ":all has $_") for @Test::Permissions::EXPORT_OK;
	covered('export:all');

	package Ex::Revoke { Test::Permissions->import(':revoke') }
	ok(defined &{"Ex::Revoke::$_"}, ":revoke has $_")
		for qw(can_revoke_read can_revoke_write can_revoke_create can_revoke_search can_revoke why_not skip_unless_can_revoke);
	ok(!defined &Ex::Revoke::clear_cache && !defined &Ex::Revoke::set_messages, ':revoke excludes the general functions');
	covered('export:revoke');

	throws_ok { Test::Permissions->import('no_such_function') } qr/not exported/, 'unknown import refused';
};

subtest 'can_revoke_<kind>: returns 1 or 0, never undef' => sub {
	for my $kind (@KINDS) {
		my $fn = \&{"Test::Permissions::can_revoke_$kind"};
		my $answer = $fn->($dir);
		returns_ok($answer, { type => 'boolean' }, "can_revoke_$kind matches its output schema");
		ok(defined $answer && ($answer eq '1' || $answer eq '0'), "can_revoke_$kind is 1 or 0");
		is($answer, Test::Permissions::can_revoke($kind, $dir), "same as can_revoke('$kind')");
		covered("fn:can_revoke_$kind");
	}
	covered('fn:can_revoke');
};

subtest 'argument forms' => sub {
	my $expected = Test::Permissions::can_revoke_read($dir);
	is(Test::Permissions::can_revoke_read(dir => $dir), $expected, 'f(dir => $dir)');
	covered('form:named');
	is(Test::Permissions::can_revoke_read({ dir => $dir }), $expected, 'f({ dir => $dir })');
	covered('form:hashref');
	is(Test::Permissions::can_revoke_read($dir), $expected, 'f($dir)');
	covered('form:positional');
	returns_ok(Test::Permissions::can_revoke_read(), { type => 'boolean' }, 'f() probes File::Spec->tmpdir');
	covered('form:none');

	is(Test::Permissions::can_revoke('read', $dir), $expected, "can_revoke('read', \$dir)");
	is(Test::Permissions::can_revoke(kind => 'read', dir => $dir), $expected, 'can_revoke(kind =>, dir =>)');
	is(Test::Permissions::can_revoke({ kind => 'read', dir => $dir }), $expected, 'can_revoke({ ... })');
	returns_ok(Test::Permissions::can_revoke('read'), { type => 'boolean' }, "can_revoke('read')");

	{
		package Stringifies;
		use overload q{""} => sub { ${ $_[0] } }, fallback => 1;
	}
	my $object = bless \(my $path = $dir), 'Stringifies';
	is(Test::Permissions::can_revoke_read($object), $expected, 'an object that stringifies');
	covered('form:object');
};

subtest 'why_not' => sub {
	for my $kind (@KINDS) {
		my $why = Test::Permissions::why_not($kind, $dir);
		returns_ok($why, { type => 'string', optional => 1 }, "$kind: matches its output schema");
		if(Test::Permissions::can_revoke($kind, $dir)) {
			ok(!defined $why, "$kind: undef when the answer is 1");
		} else {
			ok(defined $why && length $why, "$kind: a non-empty reason when the answer is 0");
		}
	}
	covered('fn:why_not');
};

subtest 'skip_unless_can_revoke' => sub {
	Test::Permissions::clear_cache();
	my $ran = 0;
	{
		my @guards = simulate_attempt(0, Errno::EACCES());
		SKIP: {
			my @r = Test::Permissions::skip_unless_can_revoke('read', 1, $dir);
			is(scalar @r, 0, 'returns nothing when the answer is 1');
			$ran = 1;
		}
	}
	ok($ran, 'block runs when the answer is 1');

	Test::Permissions::clear_cache();
	$ran = 0;
	{
		my @guards = simulate_attempt(1, 0);
		SKIP: {
			Test::Permissions::skip_unless_can_revoke('read', 2, $dir);
			$ran = 1;
			fail('not reached');
			fail('not reached');
		}
	}
	ok(!$ran, 'block skipped when the answer is 0');
	covered('fn:skip_unless_can_revoke');
	Test::Permissions::clear_cache();
};

subtest 'clear_cache' => sub {
	my @r = Test::Permissions::clear_cache();
	is(scalar @r, 0, 'returns nothing');
	my $spy = Test::Mockingbird::spy('Test::Permissions', '_make_probe_dir');
	Test::Permissions::can_revoke_read($dir);
	Test::Permissions::can_revoke_read($dir);
	is(scalar(my @c = $spy->()), 1, 'cached: one probe');
	Test::Permissions::clear_cache();
	Test::Permissions::can_revoke_read($dir);
	is(scalar(@c = $spy->()), 2, 'after clear_cache: probed again');
	Test::Mockingbird::restore_all();
	covered('fn:clear_cache');
};

# Every reason, triggered through the public API, with its documented text.
subtest 'reasons' => sub {
	my %cases = (
		reason_not_enforced => [ sub { simulate_attempt(1, 0) },
			qr/\Achmod cannot revoke read access in '.+' \(running as root, or the filesystem ignores permissions\)\z/ ],
		reason_other_error => [ sub { simulate_attempt(0, Errno::ENOSPC()) },
			qr/\Aread access in '.+' failed for a reason other than permissions: .+\z/ ],
		reason_chmod_ignored => [ sub { Test::Mockingbird::mock_scoped('Test::Permissions', '_mode_of', sub { 0444 }) },
			qr/\Achmod did not set mode 0000 in '.+' \(got 0444\)\z/ ],
		reason_baseline_failed => [ sub { Test::Mockingbird::mock_scoped('Test::Permissions', '_try_open', sub { (0, Errno::EIO()) }) },
			qr/\Aread access fails in '.+' even when it is allowed: .+\z/ ],
		reason_setup_failed => [ sub { Test::Mockingbird::mock_scoped('Test::Permissions', '_make_probe_dir', sub { die "no\n" }) },
			qr/\ACould not set up the read probe in '.+': no\z/ ],
		reason_cleanup_failed => [ sub {
				simulate_attempt(0, Errno::EACCES()),
				Test::Mockingbird::mock_scoped('Test::Permissions', '_cleanup', sub { 'gone wrong' });
			},
			qr/\Achmod revoked read access in '.+'; also could not clean up '.+': gone wrong\z/ ],
	);
	for my $key (sort keys %cases) {
		my ($setup, $re) = @{ $cases{$key} };
		Test::Permissions::clear_cache();
		my @guards = $setup->();
		is(Test::Permissions::can_revoke_read($dir), 0, "$key: answer 0");
		like(Test::Permissions::why_not('read', $dir), $re, "$key: text");
		covered("msg:$key");
	}
	covered('msg:reason_probe_succeeded');
	Test::Permissions::clear_cache();
};

subtest 'errors' => sub {
	throws_ok { Test::Permissions::can_revoke('bogus') } qr/^Unknown access kind 'bogus'; expected one of: read, write, create, search at /,
		'error_unknown_kind';
	covered('msg:error_unknown_kind');
	throws_ok { Test::Permissions::why_not('read', File::Spec->catdir($dir, 'nope')) } qr/^'.*nope' is not a directory at /,
		'error_not_a_directory';
	covered('msg:error_not_a_directory');
	throws_ok { Test::Permissions::set_messages(bogus => 'x') } qr/^Unknown message key 'bogus' at /,
		'error_unknown_message';
	covered('msg:error_unknown_message');
	throws_ok { Test::Permissions::can_revoke('read', $dir, 'x') } qr/^Too many arguments: expected at most 2, got 3 at /,
		'error_too_many_arguments';
	covered('msg:error_too_many_arguments');
};

subtest 'set_messages' => sub {
	my @r = Test::Permissions::set_messages();
	is(scalar @r, 0, 'returns nothing');
	Test::Permissions::set_messages({ error_unknown_kind => 'Type inconnu %s (%s)' });
	throws_ok { Test::Permissions::can_revoke('x') } qr/^Type inconnu x \(read, write, create, search\)/, 'hashref form, used at once';
	Test::Permissions::set_messages(error_unknown_kind => q{Unknown access kind '%s'; expected one of: %s});
	throws_ok { Test::Permissions::set_messages(error_unknown_kind => 'new', bogus => 'x') } qr/bogus/, 'one bad key';
	throws_ok { Test::Permissions::can_revoke('x') } qr/^Unknown access kind/, '... and nothing was changed';
	covered('fn:set_messages');
};

subtest 'POD documents every message key' => sub {
	my $pm = $INC{'Test/Permissions.pm'};
	open(my $fh, '<', $pm) or die "$pm: $!";
	my $source = do { local $/; <$fh> };
	close $fh;
	for my $key (grep { s/^msg:// } my @k = keys %ledger) {
		like($source, qr/\($key\)/, "$key has a MESSAGES entry");
	}
	my ($messages) = $source =~ /Readonly::Hash my %MESSAGES => \((.*?)\n\);/s;
	my @in_code = $messages =~ /^\t(\w+)\s+=>/mg;
	is_deeply([ sort @in_code ], [ sort grep { s/^msg:// } my @l = keys %ledger ], 'ledger lists every key in %MESSAGES');
};

subtest 'ledger' => sub {
	for my $entry (sort keys %ledger) {
		ok($ledger{$entry}, "exercised: $entry");
	}
};

done_testing();
