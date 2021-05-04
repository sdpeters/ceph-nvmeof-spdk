#!/usr/bin/env bash

rootdir=$(readlink -f $(dirname $0))

# In autotest_common.sh all tests are disabled by default.
# If the configuration of tests is not provided, no tests will be carried out.
if [[ -z $1 ]]; then
	echo "SPDK test configuration not specified"
	exit 1
fi

source $1
source "$rootdir/test/common/autotest_common.sh"
source "$rootdir/test/nvmf/common.sh"

set -xe

if [ $EUID -ne 0 ]; then
	echo "$0 must be run as root"
	exit 1
fi

if [ $(uname -s) = Linux ]; then
	# set core_pattern to a known value to avoid ABRT, systemd-coredump, etc.
	echo "core" > /proc/sys/kernel/core_pattern

	# make sure nbd (network block device) driver is loaded if it is available
	# this ensures that when tests need to use nbd, it will be fully initialized
	modprobe nbd || true
fi

trap "process_core; autotest_cleanup; exit 1" SIGINT SIGTERM EXIT

src=$(readlink -f $(dirname $0))
out=$PWD
cd $src

./scripts/setup.sh status

freebsd_update_contigmem_mod

if hash lcov; then
	# setup output dir for unittest.sh
	export UT_COVERAGE=$out/ut_coverage
	export LCOV_OPTS="
		--rc lcov_branch_coverage=1
		--rc lcov_function_coverage=1
		--rc genhtml_branch_coverage=1
		--rc genhtml_function_coverage=1
		--rc genhtml_legend=1
		--rc geninfo_all_blocks=1
		"
	export LCOV="lcov $LCOV_OPTS --no-external"
	# Print lcov version to log
	$LCOV -v
	# zero out coverage data
	$LCOV -q -c -i -t "Baseline" -d $src -o cov_base.info
fi

# Make sure the disks are clean (no leftover partition tables)
timing_enter cleanup
# Remove old domain socket pathname just in case
rm -f /var/tmp/spdk*.sock

# Load the kernel driver
./scripts/setup.sh reset

# Let the kernel discover any filesystems or partitions
sleep 10

if [ $(uname -s) = Linux ]; then
	# Load RAM disk driver if available
	modprobe brd || true
fi
timing_exit cleanup

timing_enter lib

run_test suite ./test/json_config/json_config.sh

run_test suite test/bdev/bdev_redirector.sh

#if [ $SPDK_TEST_JSON -eq 1 ]; then
#run_test suite test/config_converter/test_converter.sh
#fi

timing_enter cleanup
autotest_cleanup
timing_exit cleanup

timing_exit autotest
chmod a+r $output_dir/timing.txt

trap - SIGINT SIGTERM EXIT

# catch any stray core files
process_core

if hash lcov; then
	# generate coverage data and combine with baseline
	# $LCOV -q -c -d $src -t "$(hostname)" -o cov_test.info
	# $LCOV -q -a cov_base.info -a cov_test.info -o $out/cov_total.info
	# $LCOV -q -r $out/cov_total.info '*/dpdk/*' -o $out/cov_total.info
	# $LCOV -q -r $out/cov_total.info '/usr/*' -o $out/cov_total.info
	# git clean -f "*.gcda"
	rm -f cov_base.info cov_test.info OLD_STDOUT OLD_STDERR
fi
