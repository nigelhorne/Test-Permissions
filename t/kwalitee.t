#!/usr/bin/env perl

use strict;
use warnings;

# Test::DescribeMe is a develop prerequisite, so an ordinary install may not
# have it: skip before loading it.
BEGIN {
	unless($ENV{AUTHOR_TESTING} || $ENV{RELEASE_TESTING}) {
		require Test::More;
		Test::More::plan(skip_all => 'Author test: set AUTHOR_TESTING=1 to run');
	}
}

use Test::DescribeMe qw(author);
use Test::Most;

eval 'use Test::Kwalitee tests => [ qw( -has_meta_yml ) ]';

if($@) {
	plan(skip_all => 'Test::Kwalitee not installed; skipping') if $@;
} else {
	unlink('Debian_CPANTS.txt') if -e 'Debian_CPANTS.txt';
}
