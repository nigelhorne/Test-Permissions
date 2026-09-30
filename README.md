## Name

Test::Permissions - Find out whether chmod can really take access away, so tests know when to skip

## Version

This document describes Test::Permissions version 0.01.

## Synopsis

```perl
    use Test::More;
    use File::Temp qw(tempdir);
    use Test::Permissions qw(:revoke);

    my $dir = tempdir(CLEANUP => 1);        # where the fixtures live

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
```

## Description

Test suites often need to know whether `chmod` really takes access away,
so they can skip tests that rely on an unreadable file or an unsearchable
directory.  The usual guess, `skip ... if $> == 0`, is wrong on:

- Windows, where `chmod` only sets the read-only attribute;
- `fakeroot`, and containers where a non-root user holds
`CAP_DAC_OVERRIDE`;
- filesystems that ignore mode bits (FAT, some SMB/NFS/FUSE mounts,
Cygwin `noacl` mounts);
- root in a user namespace, where root may _not_ be able to bypass
modes.

Test::Permissions does not guess.  It tries the operation on a scratch
file in the directory you care about, and reports what actually happened.
Results are cached per process.

Four kinds of access can be probed:

```
    Kind     Question                                          Restricted mode
    read     can a file be made unreadable?                    file 0
    write    can a file be made unwritable?                    file 0400
    create   can a directory be made to refuse new files?      directory 0500
    search   can a directory be made unsearchable (stat of a   directory 0
             file inside it fails)?
```

What to expect (your tests must not rely on these; that is the point):

```
    Environment                        read  write  create  search
    Linux/BSD/macOS, normal user        1     1      1       1
    Unix root, or CAP_DAC_OVERRIDE      0     0      0       0
    Windows (NTFS)                      0     1      0       0
    FAT or a mount that ignores modes   0     0      0       0
```

### Which Directory to Probe

The answer depends on the filesystem, so pass the directory your fixtures
live in (usually your own `tempdir`).  If you pass nothing, the probe
runs in `File::Spec->tmpdir`, which may be on a different filesystem
from your fixtures (a `tmpfs`, for example) and give a different answer.

### How a Probe Works

Each probe creates a fresh directory `P` inside the target directory and
then:

- 1. **Setup**: creates the scratch objects with explicit modes, so the
answer does not depend on your `umask`.
- 2. **Baseline**: does the operation while it is allowed.  If that
fails, the filesystem cannot tell us anything, and the answer is 0.
- 3. **Restrict**: `chmod`s to the restricted mode and checks, with
`stat`, that the owner's permission bits really changed.  If not (this is
what happens on Windows), the answer is 0.
- 4. **Attempt**: does the operation again.  It must fail with
`EACCES` or `EPERM` for the answer to be 1.
- 5. **Restore and clean up**: always, even if an earlier step failed.
Nothing is left in the target directory.

A probe never dies and never warns: anything that goes wrong becomes an
answer of 0, and ["why\_not(kind, dir)"](#why_not-kind-dir) tells you why.  Only mistakes in
the call itself (an unknown kind, a directory that does not exist) croak.

## Subroutines/Methods

Nothing is exported by default.  Import what you need by name, or use a
tag: `:revoke` gives the `can_revoke` family (every function except
`clear_cache` and `set_messages`), and `:all` gives everything.

Every function that takes `dir` accepts it in any of these forms:

```perl
    f()                  # dir is File::Spec->tmpdir
    f($dir)
    f(dir => $dir)
    f({ dir => $dir })
```

An object that stringifies (such as a [Path::Tiny](https://metacpan.org/pod/Path%3A%3ATiny) object) is accepted
wherever a directory name is.

### Can\_Revoke\_Read(dir)

#### Purpose

Find out whether a file with mode 0 refuses `open '<'`: that is,
whether `chmod` can make a file unreadable in `dir`.  The same as
`can_revoke('read', $dir)`.

#### Arguments

- `dir` - optional.  The directory to probe in.  It must exist
and be a directory.  Default: `File::Spec->tmpdir`.

#### Returns

1 if `chmod` can take that access away in `dir`, otherwise 0.  Never
undef.

#### Side Effects

- The first call for a kind and directory creates and removes a
probe directory inside `dir`.  Later calls use the cache and do not touch
the filesystem.
- Never dies or warns because of what it finds; see
["FAILURE POLICY"](#failure-policy).
- Does not change the caller's `$@`, `$!` or `umask`.

#### Usage Example

```
    SKIP: {
            skip 'chmod cannot make a file unreadable here', 1
                    unless Test::Permissions::can_revoke_read($dir);
            ...
    }
```

#### Api Specification

##### Input

```perl
    {
            dir => {
                    type     => 'string',
                    optional => 1,
                    min      => 1,
                    position => 0,
            },
    }
```

##### Output

```perl
    { type => 'boolean' }
```

#### Messages

Errors (the call dies):

```
    '$dir' is not a directory                     (error_not_a_directory)
        dir does not exist, or is not a directory.
        What to do: pass the directory your fixtures live in.

    Too many arguments: expected at most 1, got N (error_too_many_arguments)
        More than one positional argument was given.
        What to do: pass only the directory.

    (an error from Params::Validate::Strict or Params::Get)
        dir is not a string (for example an array reference), is empty,
        or the named form has an unknown key.
```

The reason for a 0 answer is available from ["why\_not(kind, dir)"](#why_not-kind-dir), which
lists every `reason_*` message.

### Can\_Revoke\_Write(dir)

#### Purpose

Find out whether a file with mode 0400 refuses `open '>>'`: that
is, whether `chmod` can make a file unwritable in `dir`.  The same as
`can_revoke('write', $dir)`.

#### Arguments

- `dir` - optional.  As for ["can\_revoke\_read(dir)"](#can_revoke_read-dir).

#### Returns

1 or 0, never undef.

#### Side Effects

As for ["can\_revoke\_read(dir)"](#can_revoke_read-dir).

#### Usage Example

```perl
    SKIP: {
            skip 'chmod cannot make a file read-only here', 1
                    unless Test::Permissions::can_revoke_write($dir);
            chmod 0400, $file;
            ok(!open(my $fh, '>>', $file), 'read-only file is refused');
            chmod 0600, $file;
    }
```

#### Api Specification

##### Input

```perl
    {
            dir => {
                    type     => 'string',
                    optional => 1,
                    min      => 1,
                    position => 0,
            },
    }
```

##### Output

```perl
    { type => 'boolean' }
```

#### Messages

The same as ["can\_revoke\_read(dir)"](#can_revoke_read-dir).

### Can\_Revoke\_Create(dir)

#### Purpose

Find out whether a directory with mode 0500 refuses `open '>'` of a
new file in it: that is, whether `chmod` can stop files being created
in a directory in `dir`.  The same as `can_revoke('create', $dir)`.

Note: in App-makefilepl2cpanfile's private copy of this module, this
question was called `can_revoke_write`.  ["can\_revoke\_write(dir)"](#can_revoke_write-dir) now
asks about a file's own write bit.

#### Arguments

- `dir` - optional.  As for ["can\_revoke\_read(dir)"](#can_revoke_read-dir).

#### Returns

1 or 0, never undef.

#### Side Effects

As for ["can\_revoke\_read(dir)"](#can_revoke_read-dir).

#### Usage Example

```
    SKIP: {
            skip Test::Permissions::why_not('create', $dir), 1
                    unless Test::Permissions::can_revoke_create($dir);
            chmod 0500, $outdir;
            ok(!eval { write_report($outdir) }, 'cannot write the report');
            chmod 0700, $outdir;
    }
```

#### Api Specification

##### Input

```perl
    {
            dir => {
                    type     => 'string',
                    optional => 1,
                    min      => 1,
                    position => 0,
            },
    }
```

##### Output

```perl
    { type => 'boolean' }
```

#### Messages

The same as ["can\_revoke\_read(dir)"](#can_revoke_read-dir).

### Can\_Revoke\_Search(dir)

#### Purpose

Find out whether a directory with mode 0 makes `stat` of a file inside
it fail: that is, whether `chmod` can make a directory in `dir`
unsearchable.  The same as `can_revoke('search', $dir)`.

#### Arguments

- `dir` - optional.  As for ["can\_revoke\_read(dir)"](#can_revoke_read-dir).

#### Returns

1 or 0, never undef.

#### Side Effects

As for ["can\_revoke\_read(dir)"](#can_revoke_read-dir).

#### Usage Example

```
    SKIP: {
            skip 'chmod cannot hide a directory here', 1
                    unless Test::Permissions::can_revoke_search($dir);
            chmod 0, $subdir;
            ok(!-e "$subdir/file", 'file inside is hidden');
            chmod 0700, $subdir;
    }
```

#### Api Specification

##### Input

```perl
    {
            dir => {
                    type     => 'string',
                    optional => 1,
                    min      => 1,
                    position => 0,
            },
    }
```

##### Output

```perl
    { type => 'boolean' }
```

#### Messages

The same as ["can\_revoke\_read(dir)"](#can_revoke_read-dir).

### Can\_Revoke(kind, Dir)

#### Purpose

The general form of the `can_revoke_*` functions: answer the question
for the kind of access named by `kind`.

#### Arguments

- `kind` - required.  One of `read`, `write`, `create` or
`search`.
- `dir` - optional.  As for ["can\_revoke\_read(dir)"](#can_revoke_read-dir).

Positional (`can_revoke('read', $dir)`), named
(`can_revoke(kind => 'read', dir => $dir)`) and hash reference
(`can_revoke({ kind => 'read' })`) forms are all accepted.

#### Returns

1 or 0, never undef.

#### Side Effects

As for ["can\_revoke\_read(dir)"](#can_revoke_read-dir).

#### Usage Example

```perl
    for my $kind (qw(read search)) {
            SKIP: {
                    skip "cannot revoke $kind access", 1
                            unless Test::Permissions::can_revoke($kind, $dir);
                    ...
            }
    }
```

#### Api Specification

##### Input

```perl
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
```

##### Output

```perl
    { type => 'boolean' }
```

#### Messages

Errors (the call dies):

```perl
    Unknown access kind '$kind'; expected one of: read, write, create, search
                                                  (error_unknown_kind)
        What to do: use one of the listed kinds.

    '$dir' is not a directory                     (error_not_a_directory)
        What to do: pass an existing directory.

    Too many arguments: expected at most 2, got N (error_too_many_arguments)

    (an error from Params::Validate::Strict or Params::Get)
        kind is missing or not a string, dir is not a string or is empty,
        or the named form has an unknown key.
```

### Why\_Not(kind, Dir)

#### Purpose

Say why the answer for `kind` in `dir` is 0, in words suitable for a
skip message.

#### Arguments

The same as ["can\_revoke(kind, dir)"](#can_revoke-kind-dir).

#### Returns

undef when the answer is 1.  Otherwise a non-empty string: one of the
`reason_*` messages below.

#### Side Effects

Runs the probe if it has not run yet for this kind and directory, exactly
as ["can\_revoke(kind, dir)"](#can_revoke-kind-dir) would, and caches the result.

#### Usage Example

```perl
    SKIP: {
            my $why = Test::Permissions::why_not('search', $dir);
            skip $why, 2 if defined $why;
            ...
    }
```

#### Api Specification

##### Input

```perl
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
```

##### Output

```perl
    { type => 'string', optional => 1 }
```

#### Messages

Errors: the same as ["can\_revoke(kind, dir)"](#can_revoke-kind-dir).

Reasons (returned, never thrown or warned).  `$dir` is the canonical
path of the directory; `$error` is the system's error text.

```
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
```

Paths and error texts in reasons have control characters and Unicode
direction-override characters replaced by `\x{..}` escapes.

### Skip\_Unless\_Can\_Revoke(kind, Count, Dir)

#### Purpose

Skip the rest of the enclosing `SKIP:` block, with the reason from
["why\_not(kind, dir)"](#why_not-kind-dir), when `chmod` cannot revoke `kind` access.

#### Arguments

- `kind` - required.  As for ["can\_revoke(kind, dir)"](#can_revoke-kind-dir).
- `count` - required.  The number of tests in the block, as for
`Test::More::skip`.  A whole number, 1 or more.
- `dir` - optional.  As for ["can\_revoke\_read(dir)"](#can_revoke_read-dir).

#### Returns

Nothing, when the answer is 1.  When the answer is 0 it does not return:
it calls `Test::More::skip`, which leaves the enclosing `SKIP:` block
exactly as a direct `skip` call would.

#### Side Effects

- Runs the probe, as ["can\_revoke(kind, dir)"](#can_revoke-kind-dir) does.
- When the answer is 0, records `count` skipped tests.
- Must be called inside a `SKIP:` block, like `Test::More::skip`.
Outside one, perl dies with `Label not found for "last SKIP"`.

#### Usage Example

```perl
    SKIP: {
            Test::Permissions::skip_unless_can_revoke('search', 2, $dir);
            chmod 0, $subdir;
            ok(!-e "$subdir/file", 'file hidden');
            ok(!opendir(my $dh, $subdir), 'directory unreadable');
            chmod 0700, $subdir;
    }
```

#### Api Specification

##### Input

```perl
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
```

##### Output

```perl
    { type => 'undef' }
```

Returns nothing (an empty list) when the answer is 1.

#### Messages

Errors: the same as ["can\_revoke(kind, dir)"](#can_revoke-kind-dir), plus an error from
Params::Validate::Strict when `count` is missing, not a whole number, or
less than 1.

The skip message is one of the reasons listed under
["why\_not(kind, dir)"](#why_not-kind-dir).

### Clear\_Cache()

#### Purpose

Forget every answer, so the next call probes again.  This is mainly for
the module's own tests, and for a directory whose permissions or mount
have changed since it was probed.

#### Arguments

None.

#### Returns

Nothing.

#### Side Effects

Empties the cache.

#### Usage Example

```
    Test::Permissions::clear_cache();
```

#### Api Specification

##### Input

```
    {}
```

##### Output

```perl
    { type => 'undef' }
```

#### Messages

None.

### Set\_Messages(%Overrides)

#### Purpose

Replace message texts by key, for example to translate them.

#### Arguments

Pairs of message key and text, as a list or a hash reference.  The keys
are those listed under MESSAGES for each function (`error_*` and
`reason_*`).  Each text is a `sprintf` format taking the same
arguments, in the same order, as the default text.

#### Returns

Nothing.

#### Side Effects

- Changes the texts for the rest of the process.
- Reasons are worded when a probe runs, so answers already in the
cache keep their old wording until ["clear\_cache()"](#clear_cache).
- All pairs are checked before any is applied: if one is invalid,
nothing changes.

#### Usage Example

```perl
    Test::Permissions::set_messages(
            reason_not_enforced => q{chmod ne peut pas retirer l'acces %s dans '%s'},
    );
```

#### Api Specification

##### Input

```perl
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
```

##### Output

```perl
    { type => 'undef' }
```

#### Messages

Errors (the call dies, and no text is changed):

```perl
    Unknown message key '$key'                    (error_unknown_message)
        What to do: use a key listed under MESSAGES.

    (an error from Params::Validate::Strict or Params::Get)
        A text is empty or not a string, or the arguments are not pairs.
```

## Failure Policy

- **Caller errors croak**: an unknown kind, a `dir` that is not an
existing directory, bad arguments (reported by Params::Validate::Strict or
Params::Get), or an unknown message key.
- **Probe errors never escape.**  Anything that goes wrong inside a
probe becomes a 0 answer with a reason.  A helper whose job is to decide
whether to skip must never be the thing that fails your test file.
- **No warnings.**  Many suites run under [Test::Warnings](https://metacpan.org/pod/Test%3A%3AWarnings) or `-W`,
so a warning would itself fail them.  Use ["why\_not(kind, dir)"](#why_not-kind-dir) for
diagnostics.
- A failed restore or cleanup makes the answer 0, and is added to
the reason (`reason_cleanup_failed`).

## Limitations

- Results are per directory and per process.  Different
directories are probed separately, even on the same filesystem.
- A directory whose permissions or mount change after the first
call keeps its cached answer until ["clear\_cache()"](#clear_cache).
- Probing needs write access to `dir`: the probe creates a scratch
directory there.  Without it the answer is 0 (`reason_setup_failed`).
- Only mode bits are probed.  A file that an ACL denies, even though
its mode allows access, is not detected.
- The mode check after `chmod` compares the owner's permission
bits, because the probe runs as the owner of its scratch files, and
because perl on Windows reports a read-only file as 0444.
- The execute bit on files, deleting from a read-only directory and
sticky-bit semantics are not probed yet.
- The runtime code needs perl 5.10.  The test suite needs perl 5.16
(Test::Mockingbird).

## See Also

[Test::More](https://metacpan.org/pod/Test%3A%3AMore), [Test::Warnings](https://metacpan.org/pod/Test%3A%3AWarnings), [File::Temp](https://metacpan.org/pod/File%3A%3ATemp).

## Support

This module is provided as-is without any warranty.

Please report bugs and feature requests at
[https://github.com/nigelhorne/Test-Permissions/issues](https://github.com/nigelhorne/Test-Permissions/issues).

## Author

Nigel Horne <njh@nigelhorne.com>

## State Diagram

The cache, for one (kind, canonical directory) key.  `can_revoke`,
`can_revoke_*`, `why_not` and `skip_unless_can_revoke` are all
"queries".  A call that croaks does not change the state.

```
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
```

There is no edge between CACHED\_YES and CACHED\_NO: a cached answer stays
until `clear_cache`, even if the environment changes.  `set_messages`
changes no state; a cached reason keeps the wording it was given when the
probe ran.

## Formal Specification

The specification below uses Z notation.  The English sections above are
the normative description for everyday use.

```
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
```

## License and Copyright

Copyright 2026 Nigel Horne.

Usage is subject to the GPL2 licence terms.
If you use it,
please let me know.
