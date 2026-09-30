package Test::Permissions;

use strict;
use warnings;
use autodie qw(:all);

# Nothing is imported: every external function is called by its full name,
# so the only subroutines in this package are its own.
use Carp ();
use Cwd ();
use Errno ();
use File::Path ();
use File::Spec ();
use File::Temp ();
use Params::Get ();
use Params::Validate::Strict ();
use Readonly ();
use Return::Set ();
use overload ();

# Exporter is inherited rather than imported, for the same reason.  (Not
# 'use parent': that is only core from perl 5.10.1.)
require Exporter;
our @ISA = ('Exporter');	## no critic (ClassHierarchies::ProhibitExplicitISA)

=head1 NAME

Test::Permissions - Find out whether chmod can really take access away, so tests know when to skip

=head1 VERSION

0.001.0

=cut

our $VERSION = '0.001.0';

# One tag per family of functions.  A new family (for example can_* or a
# new skip_unless_* helper) gets its own tag and is added to :all.
our @EXPORT_OK = qw(
	can_revoke_read can_revoke_write can_revoke_create can_revoke_search
	can_revoke why_not skip_unless_can_revoke
	clear_cache set_messages
);
our %EXPORT_TAGS = (
	all    => [ @EXPORT_OK ],
	revoke => [ qw(
		can_revoke_read can_revoke_write can_revoke_create can_revoke_search
		can_revoke why_not skip_unless_can_revoke
	) ],
);

# -----------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------

# Modes given to the scratch objects.  Every object gets an explicit mode
# after it is created, so the result never depends on the caller's umask.
Readonly::Scalar my $MODE_NONE    => 0;
Readonly::Scalar my $MODE_FILE_RW => oct '0600';
Readonly::Scalar my $MODE_FILE_RO => oct '0400';
Readonly::Scalar my $MODE_DIR_RWX => oct '0700';
Readonly::Scalar my $MODE_DIR_RX  => oct '0500';

# The permission bits of st_mode, and the owner's share of them.  The
# probe runs as the owner of its scratch objects, so only the owner bits
# decide whether access is allowed.  Comparing just those bits also copes
# with Windows, where perl reports a read-only file as 0444: chmod 0 there
# still gives owner bits 0400 (caught), and chmod 0400 gives owner bits
# 0400 (correct).
Readonly::Scalar my $MODE_BITS  => oct '07777';
Readonly::Scalar my $OWNER_BITS => oct '0700';

# Index of the mode in the list returned by stat.
Readonly::Scalar my $STAT_MODE => 2;

# Names inside the probe directory P.
Readonly::Scalar my $PROBE_TEMPLATE => 'test-permissions-XXXXXXXX';
Readonly::Scalar my $PROBE_FILE     => 'f';
Readonly::Scalar my $PROBE_SUBDIR   => 'd';
Readonly::Scalar my $PROBE_NEW      => 'new';
Readonly::Scalar my $PROBE_CONTENT  => 'x';	# the one byte of a read probe

# open() modes used by the probes.
Readonly::Scalar my $OPEN_READ     => '<';
Readonly::Scalar my $OPEN_APPEND   => '>>';
Readonly::Scalar my $OPEN_TRUNCATE => '>';

# The errnos that mean "permission denied".  Any other failure of the
# attempt says nothing about permissions.
Readonly::Hash my %DENIED_ERRNO => map { $_ => 1 } (Errno::EACCES(), Errno::EPERM());

# Separates the parts of a cache key; cannot appear in a path.
Readonly::Scalar my $KEY_SEP => "\0";

# Control characters and Unicode bidirectional controls ("Trojan Source",
# CVE-2021-42574).  They are escaped in every path and error text placed
# in a message, so a hostile directory name cannot send escape sequences
# to the terminal or make a message display differently from its content.
Readonly::Scalar my $UNSAFE_CHARS_RE =>
	qr/[\x00-\x1F\x7F-\x9F\x{061C}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/;

# Characters that are unsafe in a byte string that is not valid UTF-8
# (C0 and C1 controls in Latin-1).
Readonly::Scalar my $UNSAFE_BYTES_RE => qr/[\x00-\x1F\x7F-\x9F]/;

# How each kind of access is probed.  Every kind follows the same steps
# (see _probe); this table holds what differs:
#   setup      - creates the scratch objects in P with explicit modes and
#                returns { target => path to chmod, object => path to use }
#   op         - the operation; returns (ok, errno) and never throws
#   tidy       - optional; undoes a successful baseline so the attempt
#                starts from the same state (runs under autodie)
#   permissive - the mode of the target while the operation is allowed
#   restricted - the mode that should forbid it
# The ops call the seams by name, so that tests can mock them.
Readonly::Hash my %PROBE => (
	read => {
		setup      => sub { _setup_file($_[0]) },
		op         => sub { _try_open($_[0]{object}, $OPEN_READ) },
		permissive => $MODE_FILE_RW,
		restricted => $MODE_NONE,
	},
	write => {
		setup      => sub { _setup_file($_[0]) },
		op         => sub { _try_open($_[0]{object}, $OPEN_APPEND) },
		permissive => $MODE_FILE_RW,
		restricted => $MODE_FILE_RO,
	},
	create => {
		setup      => sub { _setup_subdir($_[0], 0) },
		op         => sub { _try_open($_[0]{object}, $OPEN_TRUNCATE) },
		tidy       => sub { unlink $_[0]{object} },
		permissive => $MODE_DIR_RWX,
		restricted => $MODE_DIR_RX,
	},
	search => {
		setup      => sub { _setup_subdir($_[0], 1) },
		op         => sub { _try_stat($_[0]{object}) },
		permissive => $MODE_DIR_RWX,
		restricted => $MODE_NONE,
	},
);

# The kinds, in the order they are listed in messages.
Readonly::Array my @KINDS => qw(read write create search);

# Input schemas (Params::Validate::Strict), as documented in the POD.
# 'position' gives the order of positional arguments.
Readonly::Hash my %INPUT_SCHEMA => (
	dir => {
		dir => {
			type     => 'string',
			optional => 1,
			min      => 1,
			position => 0,
		},
	},
	kind_dir => {
		kind => {
			type     => 'string',
			memberof => [ @KINDS ],
			position => 0,
		},
		dir => {
			type     => 'string',
			optional => 1,
			min      => 1,
			position => 1,
		},
	},
	kind_count_dir => {
		kind => {
			type     => 'string',
			memberof => [ @KINDS ],
			position => 0,
		},
		count => {
			type     => 'integer',
			min      => 1,
			position => 1,
		},
		dir => {
			type     => 'string',
			optional => 1,
			min      => 1,
			position => 2,
		},
	},
);

# Output schemas (Return::Set).
Readonly::Hash my %OUTPUT_SCHEMA => (
	answer => { type => 'boolean' },
	reason => { type => 'string', optional => 1 },
);

# Every user-facing text, as sprintf formats.  set_messages() overrides
# them by key; see MESSAGES in the POD.
Readonly::Hash my %MESSAGES => (
	error_unknown_kind       => q{Unknown access kind '%s'; expected one of: %s},
	error_not_a_directory    => q{'%s' is not a directory},
	error_unknown_message    => q{Unknown message key '%s'},
	error_too_many_arguments => q{Too many arguments: expected at most %d, got %d},
	reason_not_enforced      => q{chmod cannot revoke %s access in '%s' (running as root, or the filesystem ignores permissions)},
	reason_chmod_ignored     => q{chmod did not set mode %04o in '%s' (got %04o)},
	reason_baseline_failed   => q{%s access fails in '%s' even when it is allowed: %s},
	reason_other_error       => q{%s access in '%s' failed for a reason other than permissions: %s},
	reason_setup_failed      => q{Could not set up the %s probe in '%s': %s},
	reason_cleanup_failed    => q{%s; also could not clean up '%s': %s},
	reason_probe_succeeded   => q{chmod revoked %s access in '%s'},
);

# -----------------------------------------------------------------------
# Package state
# -----------------------------------------------------------------------

# Answers already found: "kind\0canonical dir" => [ answer, reason ].
my %cache;

# Message texts set by set_messages(), by key.
my %message_override;

=head1 SYNOPSIS

	use Test::More;
	use File::Temp qw(tempdir);
	use Test::Permissions qw(:revoke);

	my $dir = tempdir(CLEANUP => 1);	# where the fixtures live

	SKIP: {
		skip why_not('read', $dir), 1 unless can_revoke_read($dir);

		chmod 0, "$dir/fixture";
		ok(!open(my $fh, '<', "$dir/fixture"), 'unreadable file is refused');
		chmod 0600, "$dir/fixture";
	}

	SKIP: {
		skip_unless_can_revoke('search', 1, $dir);
		...
	}

	done_testing();

=head1 DESCRIPTION

Test suites often need to know whether C<chmod> really takes access away,
so they can skip tests that rely on an unreadable file or an unsearchable
directory.  The usual guess, C<skip ... if $E<gt> == 0>, is wrong on:

=over 4

=item * Windows, where C<chmod> only sets the read-only attribute;

=item * C<fakeroot>, and containers where a non-root user holds
C<CAP_DAC_OVERRIDE>;

=item * filesystems that ignore mode bits (FAT, some SMB/NFS/FUSE mounts,
Cygwin C<noacl> mounts);

=item * root in a user namespace, where root may I<not> be able to bypass
modes.

=back

Test::Permissions does not guess.  It tries the operation on a scratch
file in the directory you care about, and reports what actually happened.
Results are cached per process.

Four kinds of access can be probed:

	Kind     Question                                          Restricted mode
	read     can a file be made unreadable?                    file 0
	write    can a file be made unwritable?                    file 0400
	create   can a directory be made to refuse new files?      directory 0500
	search   can a directory be made unsearchable (stat of a   directory 0
	         file inside it fails)?

What to expect (your tests must not rely on these; that is the point):

	Environment                        read  write  create  search
	Linux/BSD/macOS, normal user        1     1      1       1
	Unix root, or CAP_DAC_OVERRIDE      0     0      0       0
	Windows (NTFS)                      0     1      0       0
	FAT or a mount that ignores modes   0     0      0       0

=head2 Which directory to probe

The answer depends on the filesystem, so pass the directory your fixtures
live in (usually your own C<tempdir>).  If you pass nothing, the probe
runs in C<< File::Spec->tmpdir >>, which may be on a different filesystem
from your fixtures (a C<tmpfs>, for example) and give a different answer.

=head2 How a probe works

Each probe creates a fresh directory C<P> inside the target directory and
then:

=over 4

=item 1. B<Setup>: creates the scratch objects with explicit modes, so the
answer does not depend on your C<umask>.

=item 2. B<Baseline>: does the operation while it is allowed.  If that
fails, the filesystem cannot tell us anything, and the answer is 0.

=item 3. B<Restrict>: C<chmod>s to the restricted mode and checks, with
C<stat>, that the owner's permission bits really changed.  If not (this is
what happens on Windows), the answer is 0.

=item 4. B<Attempt>: does the operation again.  It must fail with
C<EACCES> or C<EPERM> for the answer to be 1.

=item 5. B<Restore and clean up>: always, even if an earlier step failed.
Nothing is left in the target directory.

=back

A probe never dies and never warns: anything that goes wrong becomes an
answer of 0, and L</why_not(kind, dir)> tells you why.  Only mistakes in
the call itself (an unknown kind, a directory that does not exist) croak.

=head1 SUBROUTINES/METHODS

Nothing is exported by default.  Import what you need by name, or use a
tag: C<:revoke> gives the C<can_revoke> family (every function except
C<clear_cache> and C<set_messages>), and C<:all> gives everything.

Every function that takes C<dir> accepts it in any of these forms:

	f()                  # dir is File::Spec->tmpdir
	f($dir)
	f(dir => $dir)
	f({ dir => $dir })

An object that stringifies (such as a L<Path::Tiny> object) is accepted
wherever a directory name is.

=head2 can_revoke_read(dir)

=head3 PURPOSE

Find out whether a file with mode 0 refuses C<< open '<' >>: that is,
whether C<chmod> can make a file unreadable in C<dir>.  The same as
C<can_revoke('read', $dir)>.

=head3 ARGUMENTS

=over 4

=item * C<dir> - optional.  The directory to probe in.  It must exist
and be a directory.  Default: C<< File::Spec->tmpdir >>.

=back

=head3 RETURNS

1 if C<chmod> can take that access away in C<dir>, otherwise 0.  Never
undef.

=head3 SIDE EFFECTS

=over 4

=item * The first call for a kind and directory creates and removes a
probe directory inside C<dir>.  Later calls use the cache and do not touch
the filesystem.

=item * Never dies or warns because of what it finds; see
L</FAILURE POLICY>.

=item * Does not change the caller's C<$@>, C<$!> or C<umask>.

=back

=head3 USAGE EXAMPLE

	SKIP: {
		skip 'chmod cannot make a file unreadable here', 1
			unless Test::Permissions::can_revoke_read($dir);
		...
	}

=head3 API SPECIFICATION

=head4 Input

	{
		dir => {
			type     => 'string',
			optional => 1,
			min      => 1,
			position => 0,
		},
	}

=head4 Output

	{ type => 'boolean' }

=head3 MESSAGES

Errors (the call dies):

	'$dir' is not a directory                     (error_not_a_directory)
	    dir does not exist, or is not a directory.
	    What to do: pass the directory your fixtures live in.

	Too many arguments: expected at most 1, got N (error_too_many_arguments)
	    More than one positional argument was given.
	    What to do: pass only the directory.

	(an error from Params::Validate::Strict or Params::Get)
	    dir is not a string (for example an array reference), is empty,
	    or the named form has an unknown key.

The reason for a 0 answer is available from L</why_not(kind, dir)>, which
lists every C<reason_*> message.

=cut

sub can_revoke_read { return _revoke_wrapper('read', \@_) }

=head2 can_revoke_write(dir)

=head3 PURPOSE

Find out whether a file with mode 0400 refuses C<<< open '>>' >>>: that
is, whether C<chmod> can make a file unwritable in C<dir>.  The same as
C<can_revoke('write', $dir)>.

=head3 ARGUMENTS

=over 4

=item * C<dir> - optional.  As for L</can_revoke_read(dir)>.

=back

=head3 RETURNS

1 or 0, never undef.

=head3 SIDE EFFECTS

As for L</can_revoke_read(dir)>.

=head3 USAGE EXAMPLE

	SKIP: {
		skip 'chmod cannot make a file read-only here', 1
			unless Test::Permissions::can_revoke_write($dir);
		chmod 0400, $file;
		ok(!open(my $fh, '>>', $file), 'read-only file is refused');
		chmod 0600, $file;
	}

=head3 API SPECIFICATION

=head4 Input

	{
		dir => {
			type     => 'string',
			optional => 1,
			min      => 1,
			position => 0,
		},
	}

=head4 Output

	{ type => 'boolean' }

=head3 MESSAGES

The same as L</can_revoke_read(dir)>.

=cut

sub can_revoke_write { return _revoke_wrapper('write', \@_) }

=head2 can_revoke_create(dir)

=head3 PURPOSE

Find out whether a directory with mode 0500 refuses C<< open '>' >> of a
new file in it: that is, whether C<chmod> can stop files being created
in a directory in C<dir>.  The same as C<can_revoke('create', $dir)>.

Note: in App-makefilepl2cpanfile's private copy of this module, this
question was called C<can_revoke_write>.  L</can_revoke_write(dir)> now
asks about a file's own write bit.

=head3 ARGUMENTS

=over 4

=item * C<dir> - optional.  As for L</can_revoke_read(dir)>.

=back

=head3 RETURNS

1 or 0, never undef.

=head3 SIDE EFFECTS

As for L</can_revoke_read(dir)>.

=head3 USAGE EXAMPLE

	SKIP: {
		skip Test::Permissions::why_not('create', $dir), 1
			unless Test::Permissions::can_revoke_create($dir);
		chmod 0500, $outdir;
		ok(!eval { write_report($outdir) }, 'cannot write the report');
		chmod 0700, $outdir;
	}

=head3 API SPECIFICATION

=head4 Input

	{
		dir => {
			type     => 'string',
			optional => 1,
			min      => 1,
			position => 0,
		},
	}

=head4 Output

	{ type => 'boolean' }

=head3 MESSAGES

The same as L</can_revoke_read(dir)>.

=cut

sub can_revoke_create { return _revoke_wrapper('create', \@_) }

=head2 can_revoke_search(dir)

=head3 PURPOSE

Find out whether a directory with mode 0 makes C<stat> of a file inside
it fail: that is, whether C<chmod> can make a directory in C<dir>
unsearchable.  The same as C<can_revoke('search', $dir)>.

=head3 ARGUMENTS

=over 4

=item * C<dir> - optional.  As for L</can_revoke_read(dir)>.

=back

=head3 RETURNS

1 or 0, never undef.

=head3 SIDE EFFECTS

As for L</can_revoke_read(dir)>.

=head3 USAGE EXAMPLE

	SKIP: {
		skip 'chmod cannot hide a directory here', 1
			unless Test::Permissions::can_revoke_search($dir);
		chmod 0, $subdir;
		ok(!-e "$subdir/file", 'file inside is hidden');
		chmod 0700, $subdir;
	}

=head3 API SPECIFICATION

=head4 Input

	{
		dir => {
			type     => 'string',
			optional => 1,
			min      => 1,
			position => 0,
		},
	}

=head4 Output

	{ type => 'boolean' }

=head3 MESSAGES

The same as L</can_revoke_read(dir)>.

=cut

sub can_revoke_search { return _revoke_wrapper('search', \@_) }

# _revoke_wrapper
#
# Purpose:  The shared body of the can_revoke_<kind> functions.
# Entry:    $kind - a kind from @KINDS; $args - arrayref of the caller's @_.
# Exit:     1 or 0.  Croaks (from the caller's line) on bad arguments.
sub _revoke_wrapper {
	my ($kind, $args) = @_;

	my ($params, $error) = _check_args('dir', $args);
	Carp::croak($error) if defined $error;

	return _set_return(_answer($kind, $params->{dir})->[0], 'answer');
}

=head2 can_revoke(kind, dir)

=head3 PURPOSE

The general form of the C<can_revoke_*> functions: answer the question
for the kind of access named by C<kind>.

=head3 ARGUMENTS

=over 4

=item * C<kind> - required.  One of C<read>, C<write>, C<create> or
C<search>.

=item * C<dir> - optional.  As for L</can_revoke_read(dir)>.

=back

Positional (C<can_revoke('read', $dir)>), named
(C<< can_revoke(kind => 'read', dir => $dir) >>) and hash reference
(C<< can_revoke({ kind => 'read' }) >>) forms are all accepted.

=head3 RETURNS

1 or 0, never undef.

=head3 SIDE EFFECTS

As for L</can_revoke_read(dir)>.

=head3 USAGE EXAMPLE

	for my $kind (qw(read search)) {
		SKIP: {
			skip "cannot revoke $kind access", 1
				unless Test::Permissions::can_revoke($kind, $dir);
			...
		}
	}

=head3 API SPECIFICATION

=head4 Input

	{
		kind => {
			type     => 'string',
			memberof => [ 'read', 'write', 'create', 'search' ],
			position => 0,
		},
		dir => {
			type     => 'string',
			optional => 1,
			min      => 1,
			position => 1,
		},
	}

=head4 Output

	{ type => 'boolean' }

=head3 MESSAGES

Errors (the call dies):

	Unknown access kind '$kind'; expected one of: read, write, create, search
	                                              (error_unknown_kind)
	    What to do: use one of the listed kinds.

	'$dir' is not a directory                     (error_not_a_directory)
	    What to do: pass an existing directory.

	Too many arguments: expected at most 2, got N (error_too_many_arguments)

	(an error from Params::Validate::Strict or Params::Get)
	    kind is missing or not a string, dir is not a string or is empty,
	    or the named form has an unknown key.

=cut

sub can_revoke {
	my ($params, $error) = _check_args('kind_dir', \@_);
	Carp::croak($error) if defined $error;

	return _set_return(_answer($params->{kind}, $params->{dir})->[0], 'answer');
}

=head2 why_not(kind, dir)

=head3 PURPOSE

Say why the answer for C<kind> in C<dir> is 0, in words suitable for a
skip message.

=head3 ARGUMENTS

The same as L</can_revoke(kind, dir)>.

=head3 RETURNS

undef when the answer is 1.  Otherwise a non-empty string: one of the
C<reason_*> messages below.

=head3 SIDE EFFECTS

Runs the probe if it has not run yet for this kind and directory, exactly
as L</can_revoke(kind, dir)> would, and caches the result.

=head3 USAGE EXAMPLE

	SKIP: {
		my $why = Test::Permissions::why_not('search', $dir);
		skip $why, 2 if defined $why;
		...
	}

=head3 API SPECIFICATION

=head4 Input

	{
		kind => {
			type     => 'string',
			memberof => [ 'read', 'write', 'create', 'search' ],
			position => 0,
		},
		dir => {
			type     => 'string',
			optional => 1,
			min      => 1,
			position => 1,
		},
	}

=head4 Output

	{ type => 'string', optional => 1 }

=head3 MESSAGES

Errors: the same as L</can_revoke(kind, dir)>.

Reasons (returned, never thrown or warned).  C<$dir> is the canonical
path of the directory; C<$error> is the system's error text.

	chmod cannot revoke $kind access in '$dir' (running as root, or the
	filesystem ignores permissions)               (reason_not_enforced)
	    The operation still worked after chmod.  You are root, hold
	    CAP_DAC_OVERRIDE, run under fakeroot, or the filesystem ignores
	    modes.
	    What to do: nothing; skip the test.  To run it, run the suite as
	    an ordinary user on a filesystem that honours modes.

	chmod did not set mode $wanted in '$dir' (got $got)
	                                              (reason_chmod_ignored)
	    chmod "worked" but the owner's permission bits did not change.
	    This is Windows, or a FAT or noacl mount.
	    What to do: nothing; skip the test.

	$kind access fails in '$dir' even when it is allowed: $error
	                                              (reason_baseline_failed)
	    The operation failed before any permission was removed, so the
	    probe learnt nothing.  The filesystem may be read-only or broken.
	    What to do: check the directory and the filesystem.

	$kind access in '$dir' failed for a reason other than permissions: $error
	                                              (reason_other_error)
	    After chmod the operation failed, but not with EACCES or EPERM
	    (for example ENOSPC).
	    What to do: check the error; the directory may be full or odd.

	Could not set up the $kind probe in '$dir': $error
	                                              (reason_setup_failed)
	    The probe could not create its scratch files, usually because you
	    cannot write to dir.
	    What to do: pass a directory you can write to.

	$reason; also could not clean up '$probe_dir': $error
	                                              (reason_cleanup_failed)
	    Restoring the modes or removing the probe directory failed, so
	    the answer is 0 whatever the probe found.  $reason is one of the
	    reasons above, or, if the probe itself succeeded, the text of
	    reason_probe_succeeded:

	chmod revoked $kind access in '$dir'          (reason_probe_succeeded)
	    Only ever seen as the first part of reason_cleanup_failed.
	    What to do: remove $probe_dir by hand; it is also removed when
	    the process exits.

Paths and error texts in reasons have control characters and Unicode
direction-override characters replaced by C<\x{..}> escapes.

=cut

sub why_not {
	my ($params, $error) = _check_args('kind_dir', \@_);
	Carp::croak($error) if defined $error;

	my $entry = _answer($params->{kind}, $params->{dir});
	return _set_return($entry->[0] ? undef : $entry->[1], 'reason');
}

=head2 skip_unless_can_revoke(kind, count, dir)

=head3 PURPOSE

Skip the rest of the enclosing C<SKIP:> block, with the reason from
L</why_not(kind, dir)>, when C<chmod> cannot revoke C<kind> access.

=head3 ARGUMENTS

=over 4

=item * C<kind> - required.  As for L</can_revoke(kind, dir)>.

=item * C<count> - required.  The number of tests in the block, as for
C<Test::More::skip>.  A whole number, 1 or more.

=item * C<dir> - optional.  As for L</can_revoke_read(dir)>.

=back

=head3 RETURNS

Nothing, when the answer is 1.  When the answer is 0 it does not return:
it calls C<Test::More::skip>, which leaves the enclosing C<SKIP:> block
exactly as a direct C<skip> call would.

=head3 SIDE EFFECTS

=over 4

=item * Runs the probe, as L</can_revoke(kind, dir)> does.

=item * When the answer is 0, records C<count> skipped tests.

=item * Must be called inside a C<SKIP:> block, like C<Test::More::skip>.
Outside one, perl dies with C<Label not found for "last SKIP">.

=back

=head3 USAGE EXAMPLE

	SKIP: {
		Test::Permissions::skip_unless_can_revoke('search', 2, $dir);
		chmod 0, $subdir;
		ok(!-e "$subdir/file", 'file hidden');
		ok(!opendir(my $dh, $subdir), 'directory unreadable');
		chmod 0700, $subdir;
	}

=head3 API SPECIFICATION

=head4 Input

	{
		kind => {
			type     => 'string',
			memberof => [ 'read', 'write', 'create', 'search' ],
			position => 0,
		},
		count => {
			type     => 'integer',
			min      => 1,
			position => 1,
		},
		dir => {
			type     => 'string',
			optional => 1,
			min      => 1,
			position => 2,
		},
	}

=head4 Output

	{ type => 'undef' }

Returns nothing (an empty list) when the answer is 1.

=head3 MESSAGES

Errors: the same as L</can_revoke(kind, dir)>, plus an error from
Params::Validate::Strict when C<count> is missing, not a whole number, or
less than 1.

The skip message is one of the reasons listed under
L</why_not(kind, dir)>.

=cut

sub skip_unless_can_revoke {
	my ($params, $error) = _check_args('kind_count_dir', \@_);
	Carp::croak($error) if defined $error;

	my $entry = _answer($params->{kind}, $params->{dir});
	return if $entry->[0];

	# Loaded here, not at compile time, so that code which never skips does
	# not load Test::Builder.  skip() leaves the SKIP block with 'last SKIP',
	# which unwinds through this sub.
	require Test::More;
	Test::More::skip($entry->[1], $params->{count});
	return;	# not reached inside a SKIP block
}

=head2 clear_cache()

=head3 PURPOSE

Forget every answer, so the next call probes again.  This is mainly for
the module's own tests, and for a directory whose permissions or mount
have changed since it was probed.

=head3 ARGUMENTS

None.

=head3 RETURNS

Nothing.

=head3 SIDE EFFECTS

Empties the cache.

=head3 USAGE EXAMPLE

	Test::Permissions::clear_cache();

=head3 API SPECIFICATION

=head4 Input

	{}

=head4 Output

	{ type => 'undef' }

=head3 MESSAGES

None.

=cut

sub clear_cache {
	%cache = ();
	return;
}

=head2 set_messages(%overrides)

=head3 PURPOSE

Replace message texts by key, for example to translate them.

=head3 ARGUMENTS

Pairs of message key and text, as a list or a hash reference.  The keys
are those listed under MESSAGES for each function (C<error_*> and
C<reason_*>).  Each text is a C<sprintf> format taking the same
arguments, in the same order, as the default text.

=head3 RETURNS

Nothing.

=head3 SIDE EFFECTS

=over 4

=item * Changes the texts for the rest of the process.

=item * Reasons are worded when a probe runs, so answers already in the
cache keep their old wording until L</clear_cache()>.

=item * All pairs are checked before any is applied: if one is invalid,
nothing changes.

=back

=head3 USAGE EXAMPLE

	Test::Permissions::set_messages(
		reason_not_enforced => q{chmod ne peut pas retirer l'acces %s dans '%s'},
	);

=head3 API SPECIFICATION

=head4 Input

	{
		error_unknown_kind       => { type => 'string', min => 1, optional => 1 },
		error_not_a_directory    => { type => 'string', min => 1, optional => 1 },
		error_unknown_message    => { type => 'string', min => 1, optional => 1 },
		error_too_many_arguments => { type => 'string', min => 1, optional => 1 },
		reason_not_enforced      => { type => 'string', min => 1, optional => 1 },
		reason_chmod_ignored     => { type => 'string', min => 1, optional => 1 },
		reason_baseline_failed   => { type => 'string', min => 1, optional => 1 },
		reason_other_error       => { type => 'string', min => 1, optional => 1 },
		reason_setup_failed      => { type => 'string', min => 1, optional => 1 },
		reason_cleanup_failed    => { type => 'string', min => 1, optional => 1 },
		reason_probe_succeeded   => { type => 'string', min => 1, optional => 1 },
	}

=head4 Output

	{ type => 'undef' }

=head3 MESSAGES

Errors (the call dies, and no text is changed):

	Unknown message key '$key'                    (error_unknown_message)
	    What to do: use a key listed under MESSAGES.

	(an error from Params::Validate::Strict or Params::Get)
	    A text is empty or not a string, or the arguments are not pairs.

=cut

sub set_messages {
	my ($texts, $error) = _check_messages(\@_);
	Carp::croak($error) if defined $error;

	@message_override{keys %{$texts}} = values %{$texts};
	return;
}

# -----------------------------------------------------------------------
# Argument handling
# -----------------------------------------------------------------------

# _check_args
#
# Purpose:  Turn a public function's @_ into a validated hashref.
#           Errors are returned rather than thrown, so the caller can
#           croak outside the local($@, $!) scope here (on perl < 5.14 a
#           die inside a 'local $@' scope loses the message).
# Entry:    $schema_name - a key of %INPUT_SCHEMA; $args - arrayref of @_.
# Exit:     ($params, undef) on success, with dir set (default tmpdir);
#           (undef, $message) on a caller error.
sub _check_args {
	my ($schema_name, $args) = @_;
	local ($@, $!);

	my $schema = $INPUT_SCHEMA{$schema_name};
	my @names = sort { $schema->{$a}{position} <=> $schema->{$b}{position} } keys %{$schema};

	my $params;
	my $ok = eval {
		$params = _normalise_args(\@names, $args);
		1;
	};
	return (undef, _exception_text($@)) unless $ok;
	return (undef, $params) if !ref $params;	# an error message

	# Our own message for an unknown kind, before the generic validator.
	my $kind = $params->{kind};
	if(defined $kind && !ref $kind && !grep { $_ eq $kind } @KINDS) {
		return (undef, _msg('error_unknown_kind', _printable($kind), join(', ', @KINDS)));
	}

	# The documented schemas carry 'position'; the validator's positional
	# mode mis-reports missing arguments, so validate the hash form.
	my %hash_schema = map { $_ => _hash_rule($schema->{$_}) } @names;
	$ok = eval {
		$params = Params::Validate::Strict::validate_strict(schema => \%hash_schema, input => $params);
		1;
	};
	return (undef, _exception_text($@)) unless $ok;

	if(exists $schema->{dir}) {
		$params->{dir} = File::Spec->tmpdir() unless defined $params->{dir};
		return (undef, _msg('error_not_a_directory', _printable($params->{dir})))
			unless -d $params->{dir};
	}
	return ($params, undef);
}

# _hash_rule
#
# Purpose:  A plain (not Readonly) copy of one schema rule, without
#           'position', for validating the hash form of the arguments.
# Entry:    $rule - a hashref from %INPUT_SCHEMA.
# Exit:     A new hashref.
sub _hash_rule {
	my $rule = $_[0];
	my %copy = %{$rule};
	delete $copy{position};
	$copy{memberof} = [ @{ $copy{memberof} } ] if $copy{memberof};
	return \%copy;
}

# _normalise_args
#
# Purpose:  Accept every calling form: f(), f(@positional),
#           f(name => value, ...), f({ name => value }).
#           Params::Get's positional mode does not recognise named pairs,
#           so the named form is detected here: an even number of
#           arguments, the first of which is an argument name.  (No valid
#           positional call looks like that: a kind is never 'kind', 'count'
#           or 'dir', and a lone directory is a single argument.)  Unknown
#           names in the rest are then reported by the validator.
# Entry:    $names - argument names in positional order; $args - arrayref.
# Exit:     A new hashref (the caller's hash is never modified), with
#           undefined values removed and stringifiable objects turned into
#           strings; or a plain string, the error message for too many
#           positional arguments.  Params::Get may croak on malformed
#           input.
sub _normalise_args {
	my ($names, $args) = @_;

	my %known = map { $_ => 1 } @{$names};
	my $params;
	if(@{$args} == 1 && ref $args->[0] eq 'HASH') {
		$params = { %{ Params::Get::get_params(undef, $args->[0]) } };
	} elsif(@{$args} >= 2 && @{$args} % 2 == 0 && defined $args->[0] && !ref $args->[0] && $known{$args->[0]}) {
		$params = { %{ Params::Get::get_params(undef, @{$args}) } };
	} else {
		return _msg('error_too_many_arguments', scalar @{$names}, scalar @{$args})
			if @{$args} > @{$names};
		$params = @{$args} ? { %{ Params::Get::get_params([ @{$names} ], @{$args}) } } : {};
	}

	for my $name (keys %{$params}) {
		my $value = $params->{$name};
		if(!defined $value) {
			delete $params->{$name};
		} elsif(ref $value && overload::Method($value, q{""})) {
			$params->{$name} = "$value";
		}
	}
	return $params;
}

# _check_messages
#
# Purpose:  Validate set_messages() arguments, all before any is applied.
# Entry:    $args - arrayref of @_.
# Exit:     ($hashref, undef) or (undef, $message).
sub _check_messages {
	my $args = $_[0];
	local ($@, $!);

	return ({}, undef) unless @{$args};

	my $texts;
	my $ok = eval {
		$texts = { %{ Params::Get::get_params(undef, @{$args}) } };
		1;
	};
	return (undef, _exception_text($@)) unless $ok;

	for my $key (sort keys %{$texts}) {
		return (undef, _msg('error_unknown_message', _printable($key))) unless exists $MESSAGES{$key};
	}

	# Every key given is required, so an undef text is refused too.
	my %schema = map { $_ => { type => 'string', min => 1 } } keys %{$texts};
	$ok = eval {
		Params::Validate::Strict::validate_strict(schema => \%schema, input => $texts);
		1;
	};
	return (undef, _exception_text($@)) unless $ok;
	return ($texts, undef);
}

# _set_return
#
# Purpose:  Return a value checked against an output schema (Return::Set),
#           without letting Return::Set's eval change the caller's $@.
# Entry:    $value; $schema_name - a key of %OUTPUT_SCHEMA.
# Exit:     $value.
sub _set_return {
	my ($value, $schema_name) = @_;
	local ($@, $!);
	return Return::Set::set_return($value, { %{ $OUTPUT_SCHEMA{$schema_name} } });
}

# -----------------------------------------------------------------------
# Messages
# -----------------------------------------------------------------------

# _msg
#
# Purpose:  Format a user-facing text from the message dictionary.
# Entry:    $key - a key of %MESSAGES; @args - sprintf arguments, already
#           passed through _printable where they come from outside.
# Exit:     The text.  Never warns or dies: a translated text with the
#           wrong number of arguments must not fail the caller's tests.
sub _msg {
	my ($key, @args) = @_;

	my $format = defined $message_override{$key} ? $message_override{$key} : $MESSAGES{$key};
	my $text = eval {
		no warnings;	## no critic (TestingAndDebugging::ProhibitNoWarnings)
		sprintf $format, @args;
	};
	return defined $text ? $text : join ': ', $key, @args;
}

# _printable
#
# Purpose:  Make a path or error text safe to put in a message.  Control
#           characters and bidirectional-override characters become \x{..}
#           escapes; everything else is kept.
#           A byte string that is valid UTF-8 (the usual form of a
#           non-ASCII path on Unix) is checked as characters and returned
#           as bytes again, so its letters are not escaped; other byte
#           strings are checked for C0 and C1 controls.
# Entry:    $_[0] - any value (stringified; undef is '').
# Exit:     The escaped string.
sub _printable {
	my $text = defined $_[0] ? "$_[0]" : q{};
	my $escape = sub { sprintf '\\x{%X}', ord $_[0] };

	if(!utf8::is_utf8($text)) {
		my $chars = $text;
		if(utf8::decode($chars)) {
			$chars =~ s/($UNSAFE_CHARS_RE)/$escape->($1)/ge;
			utf8::encode($chars);
			return $chars;
		}
		$text =~ s/($UNSAFE_BYTES_RE)/$escape->($1)/ge;
		return $text;
	}
	$text =~ s/($UNSAFE_CHARS_RE)/$escape->($1)/ge;
	return $text;
}

# _exception_text
#
# Purpose:  Turn an exception (a string, or an autodie::exception object)
#           into one printable line.
# Entry:    $_[0] - the exception.
# Exit:     The text, without trailing newlines or a trailing
#           "at FILE line N.", via _printable.
sub _exception_text {
	my $text = defined $_[0] ? "$_[0]" : q{};
	$text = substr($text, 0, -1) while length $text && substr($text, -1) eq "\n";
	# A croak from inside this module (the validator, Params::Get) names a
	# line here; croak adds the caller's line instead.
	$text =~ s/ at \S+ line [0-9]+\.\z//;
	return _printable($text);
}

# _errno_text
#
# Purpose:  The system's text for an errno, in the current locale.
# Entry:    $errno - a number.
# Exit:     The printable text.
sub _errno_text {
	my ($errno) = @_;
	local $! = $errno;
	return _printable("$!");
}

# -----------------------------------------------------------------------
# Probing
# -----------------------------------------------------------------------

# _answer
#
# Purpose:  Look up, or probe and cache, the answer for a kind and dir.
# Entry:    $kind - a kind from @KINDS; $dir - an existing directory.
# Exit:     Arrayref [ answer (1 or 0), reason (undef when 1) ].
# Effects:  May create and remove a probe directory in $dir.  $@ and $!
#           are restored.
sub _answer {
	my ($kind, $dir) = @_;
	local ($@, $!);

	my $canonical = _canonical($dir);
	my $key = join $KEY_SEP, $kind, $canonical;
	$cache{$key} = [ _probe($kind, $canonical) ] unless $cache{$key};
	return $cache{$key};
}

# _canonical
#
# Purpose:  The canonical absolute path of a directory: the cache key.
#           Not the device number: ACLs and bind mounts can differ within
#           one device, and inode numbers are 0 on Windows.
# Entry:    $dir - an existing directory.
# Exit:     Cwd::abs_path($dir), or the absolute form of $dir if that fails.
sub _canonical {
	my ($dir) = @_;
	my $abs = eval { Cwd::abs_path($dir) };
	return defined $abs && length $abs ? $abs : File::Spec->rel2abs($dir);
}

# _probe
#
# Purpose:  Find out whether chmod can revoke $kind access in $dir, by
#           trying it (see "How a probe works" in the POD).
#           Strategy: steps 1-4 run inside one eval, so an exception from
#           any of them (autodie during setup, a mocked seam dying) becomes
#           reason_setup_failed.  Step 5 (restore and clean up) runs after
#           the eval, whatever happened, and any failure there overrides
#           the answer with 0 and reason_cleanup_failed.
# Entry:    $kind - a kind from @KINDS; $dir - canonical directory path.
# Exit:     (answer, reason): (1, undef) or (0, text).  Never dies or warns.
# Effects:  Creates and removes a probe directory in $dir.
sub _probe {
	my ($kind, $dir) = @_;
	my $probe = $PROBE{$kind};
	my $shown = _printable($dir);

	# Internal exceptions are expected; the caller's die hook (for example
	# a stack-trace printer) must not see them.
	local $SIG{__DIE__};

	my ($probe_dir, $paths, $restore_target);
	my ($answer, $reason) = (0, undef);

	my $ok = eval {
		# 1. Setup.
		$probe_dir = _make_probe_dir($dir);
		$paths = $probe->{setup}->($probe_dir);

		# 2. Baseline: the operation must work while it is allowed.
		my ($baseline_ok, $baseline_errno) = $probe->{op}->($paths);
		if(!$baseline_ok) {
			$reason = _msg('reason_baseline_failed', $kind, $shown, _errno_text($baseline_errno));
			return 1;
		}
		$probe->{tidy}->($paths) if $probe->{tidy};

		# 3. Restrict, and check that chmod really changed the owner bits.
		$restore_target = $paths->{target};
		_set_mode($paths->{target}, $probe->{restricted});
		my $got = _mode_of($paths->{target});
		if(!defined $got) {
			$reason = _msg('reason_setup_failed', $kind, $shown, _printable("$!"));
			return 1;
		}
		if(($got & $OWNER_BITS) != ($probe->{restricted} & $OWNER_BITS)) {
			$reason = _msg('reason_chmod_ignored', $probe->{restricted}, $shown, $got & $MODE_BITS);
			return 1;
		}

		# 4. Attempt: only EACCES or EPERM means chmod took access away.
		my ($attempt_ok, $attempt_errno) = $probe->{op}->($paths);
		if($attempt_ok) {
			$reason = _msg('reason_not_enforced', $kind, $shown);
		} elsif($DENIED_ERRNO{$attempt_errno}) {
			$answer = 1;
		} else {
			$reason = _msg('reason_other_error', $kind, $shown, _errno_text($attempt_errno));
		}
		1;
	};
	if(!$ok) {
		($answer, $reason) = (0, _msg('reason_setup_failed', $kind, $shown, _exception_text($@)));
	}

	# 5. Restore and clean up, always.
	my $problem = _cleanup($probe_dir, $restore_target, $probe->{permissive});
	if(defined $problem) {
		$reason = _msg('reason_probe_succeeded', $kind, $shown) if $answer;
		($answer, $reason) = (0, _msg('reason_cleanup_failed', $reason,
			_printable(defined $probe_dir ? $probe_dir : $dir), $problem));
	}

	return ($answer, $answer ? undef : $reason);
}

# _cleanup
#
# Purpose:  Step 5 of a probe: restore the permissive mode, then remove the
#           probe directory.  Both are attempted even if the first fails.
# Entry:    $probe_dir - P, or undef if it was never created;
#           $target - the path that was chmod-ed, or undef;
#           $mode - the permissive mode to restore.
# Exit:     undef on success, or the printable text of what went wrong.
sub _cleanup {
	my ($probe_dir, $target, $mode) = @_;

	my @problems;
	if(defined $target) {
		my $restored = eval { _set_mode($target, $mode) };
		push @problems, _exception_text($@ || "$target: $!") unless $restored;
	}
	if(defined $probe_dir) {
		my $errors;
		my $ok = eval {
			File::Path::remove_tree($probe_dir, { error => \$errors });
			1;
		};
		push @problems, _exception_text($@) unless $ok;
		for my $error (@{ $errors || [] }) {
			my ($path, $text) = %{$error};
			push @problems, _printable(length $path ? "$path: $text" : $text);
		}
	}
	return @problems ? join('; ', @problems) : undef;
}

# _setup_file
#
# Purpose:  Setup for the read and write kinds: file P/f holding one byte,
#           mode 0600.
# Entry:    $probe_dir - P.
# Exit:     { target => P/f, object => P/f }.  Throws (autodie) on failure.
sub _setup_file {
	my ($probe_dir) = @_;
	my $file = File::Spec->catfile($probe_dir, $PROBE_FILE);
	_make_file($file, $PROBE_CONTENT);
	_set_mode($file, $MODE_FILE_RW);
	return { target => $file, object => $file };
}

# _setup_subdir
#
# Purpose:  Setup for the create and search kinds: directory P/d, mode
#           0700, optionally holding file P/d/f (mode 0600).
# Entry:    $probe_dir - P; $with_file - true to create P/d/f.
# Exit:     { target => P/d, object => P/d/f or P/d/new }.  Throws on
#           failure.
sub _setup_subdir {
	my ($probe_dir, $with_file) = @_;
	my $subdir = File::Spec->catdir($probe_dir, $PROBE_SUBDIR);
	mkdir $subdir;
	_set_mode($subdir, $MODE_DIR_RWX);
	if($with_file) {
		my $file = File::Spec->catfile($subdir, $PROBE_FILE);
		_make_file($file, q{});
		_set_mode($file, $MODE_FILE_RW);
		return { target => $subdir, object => $file };
	}
	return { target => $subdir, object => File::Spec->catfile($subdir, $PROBE_NEW) };
}

# _make_file
#
# Purpose:  Create a file with the given content.  Setup step: autodie.
# Entry:    $path; $content.
# Exit:     Nothing useful.  Throws on failure (close reports write errors).
sub _make_file {
	my ($path, $content) = @_;
	open(my $fh, $OPEN_TRUNCATE, $path);
	print {$fh} $content if length $content;
	close $fh;
	return;
}

# -----------------------------------------------------------------------
# Seams: every probe step goes through one of these, so that tests can
# simulate any environment by mocking them.
# -----------------------------------------------------------------------

# _make_probe_dir
#
# Purpose:  Create the probe directory P inside $dir, mode 0700.
#           CLEANUP is only a fallback; _cleanup removes P explicitly.
# Entry:    $dir - the target directory.
# Exit:     The path of P.  Throws on failure.
sub _make_probe_dir {
	my ($dir) = @_;
	my $probe_dir = File::Temp::tempdir($PROBE_TEMPLATE, DIR => $dir, CLEANUP => 1);
	_set_mode($probe_dir, $MODE_DIR_RWX);
	return $probe_dir;
}

# _try_open
#
# Purpose:  The attempt for read, write and create: open a file.
# Entry:    $path; $mode - an open() mode.
# Exit:     (1, 0) if it opened (the handle is closed again), else
#           (0, errno).  Never throws.
sub _try_open {
	my ($path, $mode) = @_;
	no autodie;
	if(open my $fh, $mode, $path) {
		close $fh;
		return (1, 0);
	}
	return (0, 0 + $!);
}

# _try_stat
#
# Purpose:  The attempt for search: stat a file.
# Entry:    $path.
# Exit:     (1, 0) or (0, errno).  Never throws.
sub _try_stat {
	my ($path) = @_;
	no autodie;
	my @stat = stat $path;
	return @stat ? (1, 0) : (0, 0 + $!);
}

# _set_mode
#
# Purpose:  chmod one path.
# Entry:    $path; $mode.
# Exit:     1.  Throws (autodie) on failure.
sub _set_mode {
	my ($path, $mode) = @_;
	chmod $mode, $path;
	return 1;
}

# _mode_of
#
# Purpose:  The permission bits of a path.
# Entry:    $path.
# Exit:     mode & 07777, or undef if stat fails ($! says why).
sub _mode_of {
	my ($path) = @_;
	my @stat = stat $path;
	return @stat ? $stat[$STAT_MODE] & $MODE_BITS : undef;
}

=head1 FAILURE POLICY

=over 4

=item * B<Caller errors croak>: an unknown kind, a C<dir> that is not an
existing directory, bad arguments (reported by Params::Validate::Strict or
Params::Get), or an unknown message key.

=item * B<Probe errors never escape.>  Anything that goes wrong inside a
probe becomes a 0 answer with a reason.  A helper whose job is to decide
whether to skip must never be the thing that fails your test file.

=item * B<No warnings.>  Many suites run under L<Test::Warnings> or C<-W>,
so a warning would itself fail them.  Use L</why_not(kind, dir)> for
diagnostics.

=item * A failed restore or cleanup makes the answer 0, and is added to
the reason (C<reason_cleanup_failed>).

=back

=head1 LIMITATIONS

=over 4

=item * Results are per directory and per process.  Different
directories are probed separately, even on the same filesystem.

=item * A directory whose permissions or mount change after the first
call keeps its cached answer until L</clear_cache()>.

=item * Probing needs write access to C<dir>: the probe creates a scratch
directory there.  Without it the answer is 0 (C<reason_setup_failed>).

=item * Only mode bits are probed.  A file that an ACL denies, even though
its mode allows access, is not detected.

=item * The mode check after C<chmod> compares the owner's permission
bits, because the probe runs as the owner of its scratch files, and
because perl on Windows reports a read-only file as 0444.

=item * The execute bit on files, deleting from a read-only directory and
sticky-bit semantics are not probed yet.

=item * The runtime code needs perl 5.10.  The test suite needs perl 5.16
(Test::Mockingbird).

=back

=head1 SEE ALSO

L<Test::More>, L<Test::Warnings>, L<File::Temp>.

=head1 SUPPORT

This module is provided as-is without any warranty.

Please report bugs and feature requests at
L<https://github.com/nigelhorne/Test-Permissions/issues>.

=head1 AUTHOR

Nigel Horne E<lt>njh@nigelhorne.comE<gt>

=head1 STATE DIAGRAM

The cache, for one (kind, canonical directory) key.  C<can_revoke>,
C<can_revoke_*>, C<why_not> and C<skip_unless_can_revoke> are all
"queries".  A call that croaks does not change the state.

	                   query: probe, answer 1
	    +---------+ ---------------------------> +------------+
	    |  EMPTY  |                              | CACHED_YES | --+ query: no probe
	    +---------+ ---------------------------> +------------+ <-+
	      ^  ^  ^      query: probe, answer 0          |
	      |  |  |                                      |
	      |  |  +------------- clear_cache ------------+
	      |  |                                      +-----------+
	      |  +-------------- clear_cache ---------- | CACHED_NO | --+ query: no probe
	      |                                         +-----------+ <-+
	      +-- clear_cache (from EMPTY: no change)

There is no edge between CACHED_YES and CACHED_NO: a cached answer stays
until C<clear_cache>, even if the environment changes.  C<set_messages>
changes no state; a cached reason keeps the wording it was given when the
probe ran.

=encoding utf-8

=head1 FORMAL SPECIFICATION

The specification below uses Z notation.  The English sections above are
the normative description for everyday use.

	[PATH, ERRNO, CHAR]
	Kind   ::= read | write | create | search
	Answer == { 0, 1 }
	DENIED == { EACCES, EPERM }
	Reason == seq₁ CHAR

	-- Outcome of one probe step.
	Outcome ::= ok | failed⟨⟨ERRNO⟩⟩ | threw

	restricted : Kind → ℕ
	restricted = { read ↦ 0, write ↦ 0400, create ↦ 0500, search ↦ 0 }

	Probe
	  kind? : Kind
	  dir?  : PATH
	  setup, baseline, attempt, cleanup : Outcome
	  gotMode : ℕ
	  modeSet : 𝔹
	  answer! : Answer
	  reason! : Reason ∪ {⊥}
	  ---------------------------------------------
	  modeSet ⇔ gotMode ∧ 0700 = restricted(kind?) ∧ 0700
	  answer! = 1 ⇔ setup = ok ∧ baseline = ok ∧ modeSet
	                ∧ (∃ e : DENIED • attempt = failed(e))
	                ∧ cleanup = ok
	  answer! = 1 ⇔ reason! = ⊥

	Cache == Kind × PATH ⇸ Answer × (Reason ∪ {⊥})

	CanRevoke
	  ΔCache ; Probe
	  canon : PATH → PATH
	  ---------------------------------------------
	  (kind?, canon(dir?)) ∈ dom cache  ⇒ cache' = cache
	                                       ∧ answer! = first(cache (kind?, canon(dir?)))
	  (kind?, canon(dir?)) ∉ dom cache  ⇒ cache' = cache ∪ { (kind?, canon(dir?)) ↦ (answer!, reason!) }

	WhyNot
	  ΞCache after CanRevoke
	  why! : Reason ∪ {⊥}
	  ---------------------------------------------
	  why! = second(cache (kind?, canon(dir?)))

	ClearCache
	  ΔCache
	  ---------------------------------------------
	  cache' = ∅

	-- Invariant: the probe leaves the target directory as it found it.
	entries'(dir?) = entries(dir?)

=head1 LICENSE AND COPYRIGHT

Copyright 2026 Nigel Horne.

Usage is subject to the GPL2 licence terms.
If you use it,
please let me know.

=cut

# TODO: exec - a mode-0600 script cannot be executed (can_revoke_exec).
# TODO: delete - a file cannot be unlinked from a 0500 directory
#	(can_revoke_delete).
# TODO: sticky - another user's file cannot be removed from a 01777
#	directory.  This needs two uids, so it is probably only possible as
#	root.
# TODO: an optional check for whether an ACL denies access even though the
#	mode bits allow it.

1;
