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
use Test::Needs 'Test::EOF';

Test::EOF->import();
all_perl_files_ok({ minimum_newlines => 1, maximum_newlines => 4 });
done_testing();
