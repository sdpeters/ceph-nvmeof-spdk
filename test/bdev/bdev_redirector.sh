#!/usr/bin/env bash

set -e

if [ -n "$PAUSE_FOR_DEBUGGER" ]; then
	rpc_timeout_arg="-t 3600"
fi

testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../..)
rpc_py_base="$rootdir/scripts/rpc.py ${rpc_timeout_arg}"
rpc_server=/var/tmp/spdk-rd.sock0
rpc_py="${rpc_py_base} -s ${rpc_server}"
rpc_server1=/var/tmp/spdk-rd.sock1
rpc_py1="${rpc_py_base} -s ${rpc_server1}"
histogram_py="$rootdir/scripts/histogram.py"
tmp_file=/tmp/redirectorrandtest
extent_1_file=/tmp/extent_1
extent_2_file=/tmp/extent_2

source $rootdir/test/common/autotest_common.sh
source $testdir/nbd_common.sh

#redirector_fio(nbd_dev, seconds, jobs, iodepth, blocksize, json_file)
function redirector_fio() {
	local nbd=$1
	local blksize=$(lsblk -o  LOG-SEC $nbd | grep -v LOG-SEC | cut -d ' ' -f 5)
	local seconds=5
	local jobs=1
	local bs=512
	local iodepth=64
	local bsrange=512-16384

	if [ -n "$2" ]; then
		seconds=$2
	fi

	if [ -n "$3" ]; then
		jobs=$3
	fi

	if [ -n "$4" ]; then
		iodepth=$4
	fi

	if [ -n "$5" ]; then
		bs=$5
	fi

    json_file=$6

    json_out_args=""
    if [ ! -z $json_file ]; then
        json_out_args="--output-format=json --output=${json_file}"
    fi


	fio --name=rd_nbd --rw=randrw --bs=${bs} --direct=1 --iodepth=${iodepth} --numjobs=${jobs} --group_reporting --time_based --runtime=${seconds} --filename=$nbd ${json_out_args}
	#fio --name=rd_nbd --rw=randrw --bsrange=${bsrange} --direct=1 --iodepth=64 --numjobs=${jobs} --group_reporting --time_based --runtime=${seconds} --filename=$nbd
	return 0
}

function redirector_unmap_data_verify() {
	local nbd=$1
	local rpc_server=$2
	local blksize=$(lsblk -o  LOG-SEC $nbd | grep -v LOG-SEC | cut -d ' ' -f 5)
	local rw_blk_num=4096
	local rw_len=$((blksize * rw_blk_num))

	if hash blkdiscard; then
		local unmap_blk_offs=(0	  1028 321)
		local unmap_blk_nums=(128 2035 456)
		local unmap_off
		local unmap_len

		# data write
		dd if=/dev/urandom of=$tmp_file bs=$blksize count=$rw_blk_num
		dd if=$tmp_file of=$nbd bs=$blksize count=$rw_blk_num oflag=direct
		blockdev --flushbufs $nbd

		# confirm random data is written correctly in rd0 device
		cmp -b -n $rw_len $tmp_file $nbd

		for (( i=0; i<${#unmap_blk_offs[@]}; i++ )); do
			unmap_off=$((blksize * ${unmap_blk_offs[$i]}))
			unmap_len=$((blksize * ${unmap_blk_nums[$i]}))

			# data unmap on tmp_file
			dd if=/dev/zero of=$tmp_file bs=$blksize seek=${unmap_blk_offs[$i]} count=${unmap_blk_nums[$i]} conv=notrunc

			# data unmap on redirector bdev
			blkdiscard -o $unmap_off -l $unmap_len $nbd
			blockdev --flushbufs $nbd

			# data verify after unmap
			cmp -b -n $rw_len $tmp_file $nbd
		done
	fi

	redirector_fio $nbd
	return 0
}

function on_error_exit() {
	$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_errorexit_rd0 &
	bdevs_pid=$!
	$rpc_py1 bdev_get_bdevs > /tmp/bdev_get_bdevs_errorexit &
	bdevs_pid1=$!

	wait $bdevs_pid
	wait $bdevs_pid1

	if [ ! -z $redirector_pid ]; then
		killprocess $redirector_pid
	fi
	if [ ! -z $redirector1_pid ]; then
		killprocess $redirector1_pid
	fi

	rm -f $tmp_file
	print_backtrace
	exit 1
}

function get_histograms() {
	rm -rf $testdir/rpcs.txt

	echo bdev_get_histogram rd0 > $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt | $histogram_py | tee /tmp/rd_hist.json

	rm -rf $testdir/rpcs.txt
}

function get_iostats() {
	rm -rf $testdir/rpcs.txt

    # thread_get_stats not supported in this SPDK version
	echo thread_get_stats | $rpc_py | tee /tmp/rd_th_stats.json
	if [ -e $rpc_server1 ]; then
		 echo thread_get_stats | $rpc_py1 | tee /tmp/rd1_th_stats.json
	fi
	echo bdev_get_iostat >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt | tee /tmp/rd_stats.json
	if [ -e $rpc_server1 ]; then
		$rpc_py1 < $testdir/rpcs.txt | tee /tmp/rd1_stats.json
	fi

	rm -rf $testdir/rpcs.txt
}

function configure_redirector_bdev() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	echo log_set_flag bdev >> $testdir/rpcs.txt
	#echo log_set_flag bdev_null >> $testdir/rpcs.txt
	#echo log_set_flag vbdev_split >> $testdir/rpcs.txt
	#echo log_set_flag bdev_malloc >> $testdir/rpcs.txt
	#echo log_set_flag vbdev_passthru >> $testdir/rpcs.txt

	echo construct_redirector_bdev -d \"null_default\" -n rd0 >> $testdir/rpcs.txt
	#echo redirector_add_hint --redirector rd0 --target null_default_2 --start_lba 0 --blocks $rd_block_count --persist >> $testdir/rpcs.txt
	echo redirector_add_hint --redirector rd0 --target bare_0_0 --start_lba 0 --blocks $malloc_block_count --authoritative --persist >> $testdir/rpcs.txt
	echo redirector_add_hint --redirector rd0 --target bare_0_1 --start_lba $malloc_block_count --blocks $malloc_block_count --target_start_lba 0 --authoritative --persist >> $testdir/rpcs.txt
	echo redirector_add_target --redirector rd0 --target null_default_2 --is_redirector --persist >> $testdir/rpcs.txt
	echo redirector_add_target --redirector rd0 --target bare_0_0 --required --persist >> $testdir/rpcs.txt
	echo redirector_add_target --redirector rd0 --target bare_0_1 --required --persist >> $testdir/rpcs.txt
	echo bdev_null_create null_default $rd_size_mb $rd_block_size >> $testdir/rpcs.txt
	echo bdev_null_create null_default_2 $rd_size_mb $rd_block_size >> $testdir/rpcs.txt
	echo bdev_malloc_create $malloc_size_mb $rd_block_size --name bare_0_0 >> $testdir/rpcs.txt
	echo bdev_malloc_create $malloc_size_mb $rd_block_size --name bare_0_1 >> $testdir/rpcs.txt
	echo bdev_enable_histogram -e rd0 >> $testdir/rpcs.txt
	echo bdev_enable_histogram -e bare_0_0 >> $testdir/rpcs.txt
	echo bdev_enable_histogram -e bare_0_1 >> $testdir/rpcs.txt
	echo bdev_null_create null_default_3 $rd_size_mb $rd_block_size >> $testdir/rpcs.txt
	echo redirector_add_target --redirector rd0 --target null_default_3 --is_redirector --persist >> $testdir/rpcs.txt
	echo redirector_add_target --redirector rd0 --target null_default_4 --is_redirector --persist >> $testdir/rpcs.txt
	#echo redirector_add_hint --redirector rd0 --target null_default_3 --start_lba 0 --blocks $rd_block_count --persist >> $testdir/rpcs.txt
	echo redirector_remove_target --redirector rd0 --target null_default_2 >> $testdir/rpcs.txt
	echo bdev_null_delete null_default_2 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function reconfigure_redirector_bdev() {
	local rd_size_mb=$1
	local rd_block_size=$2

	# hot-remove a target
	rm -rf $testdir/rpcs.txt
	echo bdev_null_delete null_default_3 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	# recreated target should register with rd0 and come back up
	rm -rf $testdir/rpcs.txt
	echo bdev_null_create null_default_3 $rd_size_mb $rd_block_size >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	# remove an unrelated target to wait for channel state update to complete
	rm -rf $testdir/rpcs.txt
	echo redirector_remove_target --redirector rd0 --target null_default_4 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	# Now remove the hotplugged and restored target, which should have been re-registered and pushed to the channels by now
	rm -rf $testdir/rpcs.txt
	echo redirector_remove_target --redirector rd0 --target null_default_3 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function redirector_function_test() {
	if [ $(uname -s) = Linux ] && modprobe -n nbd; then
		local nbd=/dev/nbd0
		local redirector_bdev
		local rd_size_mb=64
		local rd_block_size=512

		echo "############# function_test begins #############"

		modprobe nbd
		#$rootdir/test/app/bdev_svc/bdev_svc -r $rpc_server -i 0 -L vbdev_redirector &
		$rootdir/test/app/bdev_svc/bdev_svc -r $rpc_server -i 0 &
		redirector_pid=$!
		echo "Process redirector pid: $redirector_pid"
		waitforlisten $redirector_pid $rpc_server

		if [ -n "$PAUSE_FOR_DEBUGGER" ]; then
			echo "===== attach gdb to PID $redirector_pid now ..."
			read
		fi

		configure_redirector_bdev $rd_size_mb $rd_block_size

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs
		redirector_bdev=$($rpc_py bdev_get_bdevs | jq -r 'first(.[] | select(.product_name == "redirector") | .name)')
		if [ -z $redirector_bdev ]; then
			echo "No rd0 device in SPDK app"
			return 1
		fi

		nbd_start_disks $rpc_server ${redirector_bdev} $nbd
		count=$(nbd_get_count $rpc_server)
		if [ $count -ne 1 ]; then
			return -1
		fi

		redirector_unmap_data_verify $nbd $rpc_server
		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_2

		reconfigure_redirector_bdev $rd_size_mb $rd_block_size
		get_histograms > /dev/null
		get_iostats > /dev/null
		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_3

		nbd_stop_disks $rpc_server $nbd
		count=$(nbd_get_count $rpc_server)
		if [ $count -ne 0 ]; then
			return -1
		fi

		killprocess $redirector_pid

		echo "############# function_test ends #############"
    else
		echo "skipping bdev redirector tests."
	fi

	return 0
}

################################################################################################################

function configure_multi_redirector_bdev() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	echo log_set_flag bdev >> $testdir/rpcs.txt
	#echo log_set_flag bdev_null >> $testdir/rpcs.txt
	#echo log_set_flag vbdev_split >> $testdir/rpcs.txt
	echo log_set_flag bdev_aio >> $testdir/rpcs.txt
	#echo log_set_flag bdev_malloc >> $testdir/rpcs.txt
	echo log_set_flag vbdev_passthru >> $testdir/rpcs.txt

	# Here we'll send IO through a few redirectors configured like a simple
	# DVM or pairwise HA use case.
	#
	# We'll put rd0 on top. It will have rd1p1 & rd2p1 as targets. We're still
	# constructing a logical namespace out of two malloc bdevs. Now one of these
	# will be on rd1, and the other will be on rd2. Rd1 & 2 will have the corresponding
	# authoritative hints from the previous simple case. They'll each also have
	# each other (port 0) as default targets.
	#
	# Because we're not testing hint passing here, rd0 will also have (non-auth) hints for the
	# two physical extents pointing directly at rd1 & 2. We'll test removing the rd1 & 2
	# targets from rd0 alternately, and see if we can still do IO to the whole volume.

	# Use an aio bdev for the first extent, so IO to it actuallyhas a delay,
	# and the test can verify that channel draining had to wait for in-flight IO
	rm -rf ${extent_1_file}
	dd if=/dev/zero of=${extent_1_file} bs=${rd_block_size} count=${malloc_block_count}
	echo bdev_aio_create ${extent_1_file} bare_0_0 $rd_block_size >> $testdir/rpcs.txt

	echo bdev_malloc_create $malloc_size_mb $rd_block_size --name bare_1_0 >> $testdir/rpcs.txt

	echo construct_redirector_bdev -d \"PTrd1p1 PTrd2p1\" -n rd0 >> $testdir/rpcs.txt

	echo bdev_passthru_create -b rd1p1 -p PTrd1p1 >> $testdir/rpcs.txt
	echo bdev_passthru_create -b rd2p1 -p PTrd2p1 >> $testdir/rpcs.txt

	echo construct_redirector_bdev -d \"rd2p0\" -n rd1 --blockcnt $rd_block_count --blocklen $rd_block_size --optimal_io_boundary $rd_io_boundary >> $testdir/rpcs.txt
	echo bdev_split_create rd1 2 -r >> $testdir/rpcs.txt

	echo construct_redirector_bdev -d \"rd1p0\" -n rd2 --blockcnt $rd_block_count --blocklen $rd_block_size --optimal_io_boundary $rd_io_boundary >> $testdir/rpcs.txt
	echo bdev_split_create rd2 2 -r >> $testdir/rpcs.txt

	# hints pointing to the first extent
	echo redirector_add_hint --redirector rd1 --target bare_0_0 --start_lba 0 --blocks $malloc_block_count --authoritative --persist >> $testdir/rpcs.txt
	echo redirector_add_hint --redirector rd2 --target rd1p0 --start_lba 0 --blocks $malloc_block_count --authoritative	 --persist >> $testdir/rpcs.txt
	echo redirector_add_hint --redirector rd0 --target PTrd1p1 --start_lba 0 --blocks $malloc_block_count --persist >> $testdir/rpcs.txt

	# hints pointing to the second extent
	echo redirector_add_hint --redirector rd2 --target bare_1_0 --start_lba $malloc_block_count --blocks $malloc_block_count --target_start_lba 0 --authoritative --persist >> $testdir/rpcs.txt
	echo redirector_add_hint --redirector rd1 --target rd2p0 --start_lba $malloc_block_count --blocks $malloc_block_count --persist >> $testdir/rpcs.txt
	echo redirector_add_hint --redirector rd0 --target PTrd2p1 --start_lba $malloc_block_count --blocks $malloc_block_count --persist >> $testdir/rpcs.txt

	# targets of egress redirectors
	echo redirector_add_target --redirector rd1 --target bare_0_0 --required --persist >> $testdir/rpcs.txt
	echo redirector_add_target --redirector rd2 --target bare_1_0 --required --persist >> $testdir/rpcs.txt

	echo bdev_enable_histogram -e rd0 >> $testdir/rpcs.txt

	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function reconfigure_multi_redirector_bdev_1() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	rm -rf $testdir/rpcs.txt
	# Disconnect rd0 from rd1 and see that IO still works
	echo bdev_passthru_delete PTrd1p1 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function reconfigure_multi_redirector_bdev_2() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	rm -rf $testdir/rpcs.txt
	# reconnect rd0 to rd1, then disconnect rd2 from rd0
	echo bdev_passthru_create -b rd1p1 -p PTrd1p1 >> $testdir/rpcs.txt
	echo bdev_passthru_delete PTrd2p1 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function reconfigure_multi_redirector_bdev_2_reverse() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	rm -rf $testdir/rpcs.txt
	# disconnect rd2 from rd0, then reconnect rd0 to rd1
	echo bdev_passthru_delete PTrd2p1 >> $testdir/rpcs.txt
	echo bdev_passthru_create -b rd1p1 -p PTrd1p1 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function restore_multi_redirector_bdev() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	rm -rf $testdir/rpcs.txt
	# reconnect rd0 to rd2
	echo bdev_passthru_create -b rd2p1 -p PTrd2p1 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function multi_redirector_function_test() {
	if [ $(uname -s) = Linux ] && modprobe -n nbd; then
		local nbd=/dev/nbd0
		local redirector_bdev
		local rd_size_mb=64
		local rd_block_size=512
		local bg_io_seconds=30
		local bg_io_jobs=64
		local reconfig_delay_seconds=2
		local num_cycles=5

		echo "############# multi_redirector_function_test begins #############"
		modprobe nbd
		#$rootdir/test/app/bdev_svc/bdev_svc -r $rpc_server -i 0 -L vbdev_redirector &
		$rootdir/test/app/bdev_svc/bdev_svc -r $rpc_server -i 0 &
		redirector_pid=$!
		echo "Process redirector pid: $redirector_pid"
		waitforlisten $redirector_pid $rpc_server

		if [ -n "$PAUSE_FOR_DEBUGGER" ]; then
			echo "===== attach gdb to PID $redirector_pid now ..."
			read
		fi

		configure_multi_redirector_bdev $rd_size_mb $rd_block_size

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs
		redirector_bdev=$($rpc_py bdev_get_bdevs | jq -r 'first(.[] | select(.product_name == "redirector" and .claimed == false) | .name)')
		if [ -z $redirector_bdev ]; then
			echo "No rd0 device in SPDK app"
			return 1
		fi

		nbd_start_disks $rpc_server ${redirector_bdev} $nbd
		count=$(nbd_get_count $rpc_server)
		if [ $count -ne 1 ]; then
			return -1
		fi

		redirector_unmap_data_verify $nbd $rpc_server
		get_iostats > /dev/null

		reconfigure_multi_redirector_bdev_1 $rd_size_mb $rd_block_size
		redirector_unmap_data_verify $nbd $rpc_server
		get_iostats > /dev/null

		reconfigure_multi_redirector_bdev_2 $rd_size_mb $rd_block_size
		redirector_unmap_data_verify $nbd $rpc_server
		get_iostats > /dev/null

		# redirector changes with IO in flight
		redirector_fio $nbd $bg_io_seconds $bg_io_jobs &
		fio_pid=$!

		for (( i=0; i<${num_cycles}; i++ )); do
			sleep ${reconfig_delay_seconds}
			get_iostats > /dev/null
			restore_multi_redirector_bdev $rd_size_mb $rd_block_size
			$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs1
			reconfigure_multi_redirector_bdev_1 $rd_size_mb $rd_block_size
			get_iostats > /dev/null
			sleep ${reconfig_delay_seconds}
			get_iostats > /dev/null
			if [ $((i%2)) -eq 0 ];
			then
				reconfigure_multi_redirector_bdev_2 $rd_size_mb $rd_block_size
			else
				reconfigure_multi_redirector_bdev_2_reverse $rd_size_mb $rd_block_size
			fi
			get_iostats > /dev/null
		done
		sleep ${reconfig_delay_seconds}
		restore_multi_redirector_bdev $rd_size_mb $rd_block_size

		wait $fio_pid
		get_histograms > /dev/null
		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs2
		channel_ios_drained=$($rpc_py bdev_get_bdevs | jq -r ".[] | select(.product_name == \"redirector\" and .name == \"${redirector_bdev}\") | .driver_specific.redirector.channel_ios_drained")
		if [ -z $channel_ios_drained ]; then
			channel_ios_drained=0
		fi
		if [ $channel_ios_drained -eq 0 ]; then
			echo "No channel IOs drained"
			return -1
		fi
		get_iostats > /dev/null

		nbd_stop_disks $rpc_server $nbd
		count=$(nbd_get_count $rpc_server)
		if [ $count -ne 0 ]; then
			return -1
		fi

		killprocess $redirector_pid
		echo "############# multi_redirector_function_test ends #############"
	else
		echo "skipping bdev redirector tests."
	fi

	return 0
}

################################################################################################################

function configure_nvmf_redirector_bdev() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )
	local target_nqn=nqn.2018-09.io.spdk
	local target_ip=127.0.0.1
	local subsys_1_name=subsys_1
	local subsys_1_port=4420
	local subsys_1_nqn=${target_nqn}:${subsys_1_name}
	local subsys_2_name=subsys_2
	local subsys_2_port=4421
	local subsys_2_nqn=${target_nqn}:${subsys_2_name}
    # UUID format, lower case
    local ln_uuid=94cc7162-2267-47b8-b099-9f6a469939d2
    # NGUID is 16 hex bytes, upper case
    local ln_nguid=94CC7162226747B8B0999F6A469939D2
    # EUI64 is 8 hex bytes, upper case
    local ln_eui64=B0999F6A469939D2

	echo log_set_flag bdev >> $testdir/rpcs.txt
	echo log_set_flag nvmf >> $testdir/rpcs.txt
	#echo log_set_flag rdma >> $testdir/rpcs.txt
	echo log_set_flag nvmf_tcp >> $testdir/rpcs.txt
	echo log_set_flag bdev_nvme >> $testdir/rpcs.txt
	echo log_set_flag nvme >> $testdir/rpcs.txt
	#echo log_set_flag vbdev_split >> $testdir/rpcs.txt
	#echo log_set_flag bdev_aio >> $testdir/rpcs.txt
	echo log_set_flag notify_rpc >> $testdir/rpcs.txt
	echo log_set_flag app_config >> $testdir/rpcs.txt
	#echo log_set_flag reactor >> $testdir/rpcs.txt
	echo log_set_flag net >> $testdir/rpcs.txt
	#echo log_set_flag bdev_malloc >> $testdir/rpcs.txt
	echo log_set_flag vbdev_passthru >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt
	$rpc_py1 < $testdir/rpcs.txt
	rm -rf $testdir/rpcs.txt

	echo nvmf_create_transport -t TCP >> $testdir/rpcs.txt
	echo nvmf_create_subsystem ${subsys_1_nqn} -a -m 8 -s SPDK001 >> $testdir/rpcs.txt
	echo nvmf_subsystem_add_listener ${subsys_1_nqn} -t TCP -f ipv4 -s ${subsys_1_port} -a ${target_ip} >> $testdir/rpcs.txt
	echo nvmf_create_subsystem ${subsys_2_nqn} -a -m 8 -s SPDK002 >> $testdir/rpcs.txt
	echo nvmf_subsystem_add_listener ${subsys_2_nqn} -t TCP -f ipv4 -s ${subsys_2_port} -a ${target_ip} >> $testdir/rpcs.txt
	$rpc_py1 < $testdir/rpcs.txt
	rm -rf $testdir/rpcs.txt
	$rpc_py1 save_config > /tmp/save_config_conf1
	$rpc_py1 bdev_get_bdevs > /tmp/bdev_get_bdevs_conf1

	# Here we repeat the multi_redirector pattern, but connect rd0 to the other
	# redirectors via NVMe-TCP.
	#
	# RD2 & 3 will be constructed on the redirector1 process, and rd0 will run
	# on the redirector (redirector0) process
	#
	# We'll put rd0 on top. It will have rd1p1 & rd2p1 as targets. We're still
	# constructing a logical namespace out of two malloc bdevs. Now one of these
	# will be on rd1, and the other will be on rd2. Rd1 & 2 will have the corresponding
	# authoritative hints from the previous simple case. They'll each also have
	# each other (port 0) as default targets.
	#
	# Because we're not testing hint passing here, rd0 will also have (non-auth) hints for the
	# two physical extents pointing directly at rd1 & 2. We'll test removing the rd1 & 2
	# targets from rd0 alternately, and see if we can still do IO to the whole volume.

	# Use an aio bdev for the first extent, so IO to it actuallyhas a delay,
	# and the test can verify that channel draining had to wait for in-flight IO
	rm -rf ${extent_1_file}
	dd if=/dev/zero of=${extent_1_file} bs=${rd_block_size} count=${malloc_block_count}
	echo bdev_aio_create ${extent_1_file} bare_0_0 $rd_block_size >> $testdir/rpcs.txt

	echo bdev_malloc_create $malloc_size_mb $rd_block_size --name bare_1_0 >> $testdir/rpcs.txt

	echo construct_redirector_bdev -d \"rd2p0\" -n rd1 --uuid ${ln_uuid} --nqn ${subsys_1_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size --optimal_io_boundary $rd_io_boundary >> $testdir/rpcs.txt
	echo bdev_split_create rd1 2 -r >> $testdir/rpcs.txt

	echo construct_redirector_bdev -d \"rd1p0\" -n rd2 --nqn ${subsys_2_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size --optimal_io_boundary $rd_io_boundary >> $testdir/rpcs.txt
	echo bdev_split_create rd2 2 -r >> $testdir/rpcs.txt

	$rpc_py1 < $testdir/rpcs.txt
	rm -rf $testdir/rpcs.txt
	$rpc_py1 bdev_get_bdevs > /tmp/bdev_get_bdevs_conf1.1
	$rpc_py1 save_config > /tmp/save_config_conf1.1

	# hints pointing to the first extent
	echo redirector_add_hint --redirector rd1 --target bare_0_0 --start_lba 0 --blocks $malloc_block_count --authoritative --persist >> $testdir/rpcs.txt
	echo redirector_add_hint --redirector rd2 --target rd1p0 --start_lba 0 --blocks $malloc_block_count --authoritative	--persist >> $testdir/rpcs.txt
    # NQN hint below causes rd2 to not start for nvmf tgt. Stuck awaiting IDENTIFY?
	#echo redirector_add_hint --redirector rd2 --target ${subsys_1_nqn} --start_lba 0 --blocks $malloc_block_count --authoritative --persist >> $testdir/rpcs.txt

	# hints pointing to the second extent
	echo redirector_add_hint --redirector rd2 --target bare_1_0 --start_lba $malloc_block_count --blocks $malloc_block_count --target_start_lba 0 --authoritative --persist >> $testdir/rpcs.txt
	#echo redirector_add_hint --redirector rd1 --target rd2p0 --start_lba $malloc_block_count --blocks $malloc_block_count --persist >> $testdir/rpcs.txt
	echo redirector_add_hint --redirector rd1 --target ${subsys_2_nqn} --start_lba $malloc_block_count --blocks $malloc_block_count --persist >> $testdir/rpcs.txt

	$rpc_py1 < $testdir/rpcs.txt
	rm -rf $testdir/rpcs.txt
    sleep 5
	$rpc_py1 bdev_get_bdevs > /tmp/bdev_get_bdevs_conf1.2
	$rpc_py1 save_config > /tmp/save_config_conf1.2

	# targets of egress redirectors
	echo redirector_add_target --redirector rd1 --target bare_0_0 --required --persist >> $testdir/rpcs.txt
	echo redirector_add_target --redirector rd2 --target bare_1_0 --required --persist >> $testdir/rpcs.txt
	$rpc_py1 < $testdir/rpcs.txt
	rm -rf $testdir/rpcs.txt
    sleep 5
	$rpc_py1 bdev_get_bdevs > /tmp/bdev_get_bdevs_conf2
	$rpc_py1 save_config > /tmp/save_config_conf2

	# NVMf namespaces for redirectors (which must have started by now). Both have the NGUID of the Nemo LN
	#echo nvmf_subsystem_add_ns --uuid ${ln_uuid} --nguid ${ln_nguid} --eui64 ${ln_eui64} ${subsys_1_nqn} rd1p1 >> $testdir/rpcs.txt
    # NVMf target NS should inherit UUID from the redirector bdev, so we won't set it here
	echo nvmf_subsystem_add_ns ${subsys_1_nqn} rd1p1 >> $testdir/rpcs.txt

	$rpc_py1 < $testdir/rpcs.txt
	rm -rf $testdir/rpcs.txt
	$rpc_py1 bdev_get_bdevs > /tmp/bdev_get_bdevs_conf2.1
	$rpc_py1 save_config > /tmp/save_config_conf2.1

	#echo nvmf_subsystem_add_ns --uuid ${ln_uuid} --nguid ${ln_nguid} --eui64 ${ln_eui64} ${subsys_2_nqn} rd2p1 >> $testdir/rpcs.txt
	echo nvmf_subsystem_add_ns ${subsys_2_nqn} rd2p1 >> $testdir/rpcs.txt
	$rpc_py1 < $testdir/rpcs.txt
	rm -rf $testdir/rpcs.txt
	$rpc_py1 save_config > /tmp/save_config_conf3
	$rpc_py1 bdev_get_bdevs > /tmp/bdev_get_bdevs_conf3
	$rpc_py1 save_config > /tmp/save_config_conf3

	###################################################################################################
	# Construct rd0 on the "main" process
	echo construct_redirector_bdev -d \"PTrd1p1 PTrd2p1\" -n rd0 >> $testdir/rpcs.txt

	echo bdev_passthru_create -b rd1p1n1 -p PTrd1p1 >> $testdir/rpcs.txt
	echo bdev_passthru_create -b rd2p1n1 -p PTrd2p1 >> $testdir/rpcs.txt
	#echo redirector_add_hint --redirector rd0 --target PTrd1p1 --start_lba 0 --blocks $malloc_block_count --persist >> $testdir/rpcs.txt
	echo redirector_add_hint --redirector rd0 --target ${subsys_1_nqn} --start_lba 0 --blocks $malloc_block_count --persist >> $testdir/rpcs.txt
	#echo redirector_add_hint --redirector rd0 --target PTrd2p1 --start_lba $malloc_block_count --blocks $malloc_block_count --persist >> $testdir/rpcs.txt
	echo redirector_add_hint --redirector rd0 --target ${subsys_2_nqn} --start_lba $malloc_block_count --blocks $malloc_block_count --persist >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt
	rm -rf $testdir/rpcs.txt

	# NVMe (-oF) bdevs for rd1 & 2 targeting the above namespace
	echo bdev_nvme_attach_controller -t TCP -b rd1p1 -a ${target_ip} -f ipv4 -s ${subsys_1_port} -n ${subsys_1_nqn} >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt
	rm -rf $testdir/rpcs.txt

	echo bdev_nvme_attach_controller -t TCP -b rd2p1 -a ${target_ip} -f ipv4 -s ${subsys_2_port} -n ${subsys_2_nqn} >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt
	rm -rf $testdir/rpcs.txt

	$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_conf_rd0
	$rpc_py save_config > /tmp/save_config_conf_rd0
}

function reconfigure_nvmf_redirector_bdev_1() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	rm -rf $testdir/rpcs.txt
	# Disconnect rd0 from rd1 and see that IO still works
	echo bdev_passthru_delete PTrd1p1 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function reconfigure_nvmf_redirector_bdev_2() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	rm -rf $testdir/rpcs.txt
	# reconnect rd0 to rd1, then disconnect rd2 from rd0
	echo bdev_passthru_create -b rd1p1n1 -p PTrd1p1 >> $testdir/rpcs.txt
	echo bdev_passthru_delete PTrd2p1 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function reconfigure_nvmf_redirector_bdev_2_reverse() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	rm -rf $testdir/rpcs.txt
	# disconnect rd2 from rd0, then reconnect rd0 to rd1
	echo bdev_passthru_delete PTrd2p1 >> $testdir/rpcs.txt
	echo bdev_passthru_create -b rd1p1n1 -p PTrd1p1 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function restore_nvmf_redirector_bdev() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	rm -rf $testdir/rpcs.txt
	# reconnect rd0 to rd2
	echo bdev_passthru_create -b rd2p1n1 -p PTrd2p1 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function nvmf_redirector_function_test() {
	if [ $(uname -s) = Linux ] && modprobe -n nbd; then
		local nbd=/dev/nbd0
		local redirector_bdev
		local rd_size_mb=64
		local rd_block_size=512
		local bg_io_seconds=30
		local bg_io_jobs=64
		local reconfig_delay_seconds=1
		local num_cycles=5

		echo "############# nvmf_redirector_function_test begins #############"
		modprobe nbd
		$rootdir/test/app/bdev_svc/bdev_svc -r $rpc_server --shm-id 0 --cpumask 0xd -L vbdev_redirector &
		#$rootdir/test/app/bdev_svc/bdev_svc -r $rpc_server --shm-id 0 --cpumask 0xd &
		redirector_pid=$!
		echo "Process redirector pid: $redirector_pid"
		waitforlisten $redirector_pid $rpc_server

		# Second bdev_svc process for redirector we access over TCP
		$rootdir/test/app/bdev_svc/bdev_svc -r $rpc_server1 --shm-id 1 --cpumask 0xd0 -L vbdev_redirector &
		#$rootdir/test/app/bdev_svc/bdev_svc -r $rpc_server1 --shm-id 1 --cpumask 0xd0 &
		redirector1_pid=$!
		echo "Process redirector1 pid: $redirector1_pid"
		waitforlisten $redirector1_pid $rpc_server1

		if [ -n "$PAUSE_FOR_DEBUGGER" ]; then
			echo "===== attach gdb to PID $redirector_pid (rd0) or $redirector1_pid (rd1, rd2, and base bdevs) now ..."
			read
		fi

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_conf0_rd0
		$rpc_py save_config > /tmp/save_config_conf0_rd0
		$rpc_py1 bdev_get_bdevs > /tmp/bdev_get_bdevs_conf0
		$rpc_py1 save_config > /tmp/save_config_conf0

		configure_nvmf_redirector_bdev $rd_size_mb $rd_block_size

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_rd0
		$rpc_py1 bdev_get_bdevs > /tmp/bdev_get_bdevs
		redirector_bdev=$($rpc_py bdev_get_bdevs | jq -r 'first(.[] | select(.product_name == "redirector" and .claimed == false) | .name)')
		if [ -z $redirector_bdev ]; then
			echo "No rd0 device in SPDK app"
			return 1
		fi

        # TODO: See that the UUID of all the redirectors is the same.
        # TODO: See that uuid_generated is false for all redirectors, and uuid_inherited is true for rd2 and rd0
		echo bdev_enable_histogram -e rd0 >> $testdir/rpcs.txt
		$rpc_py < $testdir/rpcs.txt
		rm -rf $testdir/rpcs.txt

		nbd_start_disks $rpc_server ${redirector_bdev} $nbd
		count=$(nbd_get_count $rpc_server)
		if [ $count -ne 1 ]; then
			return -1
		fi

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_started_rd0
		$rpc_py save_config > /tmp/save_config_started_rd0
		$rpc_py1 bdev_get_bdevs > /tmp/bdev_get_bdevs_started
		$rpc_py1 save_config > /tmp/save_config_started

		redirector_unmap_data_verify $nbd $rpc_server
		get_iostats > /dev/null

		reconfigure_nvmf_redirector_bdev_1 $rd_size_mb $rd_block_size
		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs0_rd0
		$rpc_py1 bdev_get_bdevs > /tmp/bdev_get_bdevs0
		redirector_unmap_data_verify $nbd $rpc_server
		get_iostats > /dev/null

		reconfigure_nvmf_redirector_bdev_2 $rd_size_mb $rd_block_size
		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs0_rd0
		$rpc_py1 bdev_get_bdevs > /tmp/bdev_get_bdevs0
		redirector_unmap_data_verify $nbd $rpc_server
		get_iostats > /dev/null

		# redirector changes with IO in flight
		redirector_fio $nbd $bg_io_seconds $bg_io_jobs &
		fio_pid=$!

		for (( i=0; i<${num_cycles}; i++ )); do
			sleep ${reconfig_delay_seconds}
			get_iostats > /dev/null
			restore_nvmf_redirector_bdev $rd_size_mb $rd_block_size
			$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs1_rd0
			$rpc_py1 bdev_get_bdevs > /tmp/bdev_get_bdevs1
			reconfigure_nvmf_redirector_bdev_1 $rd_size_mb $rd_block_size
			get_iostats > /dev/null
			sleep ${reconfig_delay_seconds}
			get_iostats > /dev/null
			if [ $((i%2)) -eq 0 ];
			then
				reconfigure_nvmf_redirector_bdev_2 $rd_size_mb $rd_block_size
			else
				reconfigure_nvmf_redirector_bdev_2_reverse $rd_size_mb $rd_block_size
			fi
			get_iostats > /dev/null
		done
		sleep ${reconfig_delay_seconds}
		restore_nvmf_redirector_bdev $rd_size_mb $rd_block_size

		wait $fio_pid
		get_histograms > /dev/null
		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs2_rd0
		$rpc_py1 bdev_get_bdevs > /tmp/bdev_get_bdevs2
		channel_ios_drained=$($rpc_py bdev_get_bdevs | jq -r ".[] | select(.product_name == \"redirector\" and .name == \"${redirector_bdev}\") | .driver_specific.redirector.channel_ios_drained")
		if [ -z $channel_ios_drained ]; then
			channel_ios_drained=0
		fi
		if [ $channel_ios_drained -eq 0 ]; then
			echo "No channel IOs drained"
			return -1
		fi
		get_iostats > /dev/null

		nbd_stop_disks $rpc_server $nbd
		count=$(nbd_get_count $rpc_server)
		if [ $count -ne 0 ]; then
			return -1
		fi

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs3_rd0
		$rpc_py1 bdev_get_bdevs > /tmp/bdev_get_bdevs3
        echo "Stop rd0"
		killprocess $redirector_pid
        echo "Stop rd1 & rd2"
		killprocess $redirector1_pid
        unset redirector1_pid
		echo "############# nvmf_redirector_function_test ends #############"
	else
		echo "skipping bdev redirector tests."
	fi

	return 0
}

################################################################################################################

function configure_hash_bdev() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local rd1_nqn=nqn.2019-11-14.com.intel.nemo:node1
	local rd2_nqn=nqn.2019-11-14.com.intel.nemo:node2
	local rd3_nqn=nqn.2019-11-14.com.intel.nemo:node3
	local rd4_nqn=nqn.2019-11-14.com.intel.nemo:node4
    local ln_uuid=c119038a-54ab-463a-aa86-f0fc3db84b49

    rm -f $testdir/rpcs.txt
	echo log_set_flag bdev >> $testdir/rpcs.txt
	#echo log_set_flag bdev_null >> $testdir/rpcs.txt
	echo log_set_flag vbdev_split >> $testdir/rpcs.txt
	echo log_set_flag bdev_aio >> $testdir/rpcs.txt
	#echo log_set_flag bdev_malloc >> $testdir/rpcs.txt
	echo log_set_flag vbdev_passthru >> $testdir/rpcs.txt

	# Here we set up a "host" redirector connected to some "egress" redirectors using a hash
    # hint. We'll configure the hash hint in the host redirector, and leave the egress
    # redirectors with just one default target. We'll simplify the bottom of the stack by
    # creating just one base (malloc or aio) bdev with a split on top of it. We'll stack
    # passthrus on top of the split ports as in the cases above, so we can disconnect
    # each target from rd0.
    #
    # We'll submit IO to the host redirector, and repeatedly disconnect one of the first two egress
    # redirectors (by deleting the PT bdev between the host and egress redirectir) and reconnect the
    # other. We'll see that IO continues while this goes on, and that none is still in progress (stuck
    # on a target) when fio completes.
    #
    # Without learning, the only point of the egress redirectors in this test is to provide
    # targets with different NQNs that the host redirector can identify.
    #
    # The host redirector is rd0. The others are rd1..rdn
    #
    # We'll use a hand-generated hash hint params file, specifying the null hash fn ID, and with
    # a small hash table. This makes extent locations very predictable.
	rm -rf ${extent_1_file}
	dd if=/dev/zero of=${extent_1_file} bs=${rd_block_size} count=${rd_block_count}
	echo bdev_aio_create ${extent_1_file} bare $rd_block_size >> $testdir/rpcs.txt
	echo bdev_split_create bare 4 -r >> $testdir/rpcs.txt

	echo construct_redirector_bdev -d \"PTrd1 PTrd2 PTrd3 PTrd4\" -n rd0 >> $testdir/rpcs.txt

	$rpc_py < $testdir/rpcs.txt
	rm -rf $testdir/rpcs.txt

	$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hash_init_0

	echo redirector_add_hash_hint --redirector rd0 --hash_hint_file $rootdir/test/json_config/test_null_hash_hint.json >> $testdir/rpcs.txt

	echo bdev_passthru_create -b rd1 -p PTrd1 >> $testdir/rpcs.txt
	echo bdev_passthru_create -b rd2 -p PTrd2 >> $testdir/rpcs.txt
	echo bdev_passthru_create -b rd3 -p PTrd3 >> $testdir/rpcs.txt
	echo bdev_passthru_create -b rd4 -p PTrd4 >> $testdir/rpcs.txt

	$rpc_py < $testdir/rpcs.txt
	rm -rf $testdir/rpcs.txt

	$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hash_init_1

	echo construct_redirector_bdev -d barep0 -n rd1 --uuid ${ln_uuid} --nqn ${rd1_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt

	echo construct_redirector_bdev -d barep1 -n rd2 --uuid ${ln_uuid} --nqn ${rd2_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt

	echo construct_redirector_bdev -d barep2 -n rd3 --uuid ${ln_uuid} --nqn ${rd3_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt

	echo construct_redirector_bdev -d barep3 -n rd4 --uuid ${ln_uuid} --nqn ${rd4_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt

	echo bdev_enable_histogram -e rd0 >> $testdir/rpcs.txt

	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function reconfigure_hash_bdev_1() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	rm -rf $testdir/rpcs.txt
	# Disconnect rd0 from rd1 and see that IO still works
	echo bdev_passthru_delete PTrd1 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function reconfigure_hash_bdev_2() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	rm -rf $testdir/rpcs.txt
	# reconnect rd0 to rd1, then disconnect rd2 from rd0
	echo bdev_passthru_create -b rd1 -p PTrd1 >> $testdir/rpcs.txt
	echo bdev_passthru_delete PTrd2 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function reconfigure_hash_bdev_2_reverse() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	rm -rf $testdir/rpcs.txt
	# disconnect rd2 from rd0, then reconnect rd0 to rd1
	echo bdev_passthru_delete PTrd2 >> $testdir/rpcs.txt
	echo bdev_passthru_create -b rd1 -p PTrd1 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function restore_hash_bdev() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	rm -rf $testdir/rpcs.txt
	# reconnect rd0 to rd2
	echo bdev_passthru_create -b rd2 -p PTrd2 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function hash_function_test() {
	if [ $(uname -s) = Linux ] && modprobe -n nbd; then
		local nbd=/dev/nbd0
		local redirector_bdev
		local rd_size_mb=64
		local rd_block_size=512
		local bg_io_seconds=30
		local bg_io_jobs=64
		local reconfig_delay_seconds=2
		local num_cycles=5

		echo "############# hash_function_test begins #############"
		modprobe nbd
		$rootdir/test/app/bdev_svc/bdev_svc -r $rpc_server -i 0 &
		redirector_pid=$!
		echo "Process redirector pid: $redirector_pid"
		waitforlisten $redirector_pid $rpc_server

		if [ -n "$PAUSE_FOR_DEBUGGER" ]; then
			echo "===== attach gdb to PID $redirector_pid now ..."
			read
		fi

		configure_hash_bdev $rd_size_mb $rd_block_size

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hash
		redirector_bdev=$($rpc_py bdev_get_bdevs | jq -r 'first(.[] | select(.product_name == "redirector" and .claimed == false) | .name)')
		if [ -z $redirector_bdev ]; then
			echo "No rd0 device in SPDK app"
			return 1
		fi

		nbd_start_disks $rpc_server ${redirector_bdev} $nbd
		count=$(nbd_get_count $rpc_server)
		if [ $count -ne 1 ]; then
			return -1
		fi

		lsblk ${nbd}

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hash_before

		redirector_unmap_data_verify $nbd $rpc_server
		get_iostats > /dev/null

		reconfigure_hash_bdev_1 $rd_size_mb $rd_block_size
		redirector_unmap_data_verify $nbd $rpc_server
		get_iostats > /dev/null

		reconfigure_hash_bdev_2 $rd_size_mb $rd_block_size
		redirector_unmap_data_verify $nbd $rpc_server
		get_iostats > /dev/null

		# redirector changes with IO in flight
		redirector_fio $nbd $bg_io_seconds $bg_io_jobs &
		fio_pid=$!

		for (( i=0; i<${num_cycles}; i++ )); do
			sleep ${reconfig_delay_seconds}
			get_iostats > /dev/null
			restore_hash_bdev $rd_size_mb $rd_block_size
			$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hash_restore
			reconfigure_hash_bdev_1 $rd_size_mb $rd_block_size
			get_iostats > /dev/null
			$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hash_reconfig_1
			sleep ${reconfig_delay_seconds}
			get_iostats > /dev/null
			if [ $((i%2)) -eq 0 ];
			then
				reconfigure_hash_bdev_2 $rd_size_mb $rd_block_size
			    $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hash_reconfig_2
			else
				reconfigure_hash_bdev_2_reverse $rd_size_mb $rd_block_size
			    $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hash_reconfig_2_rev
			fi
			get_iostats > /dev/null
		done
		sleep ${reconfig_delay_seconds}
		restore_hash_bdev $rd_size_mb $rd_block_size

		wait $fio_pid

		get_histograms > /dev/null
		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hash_2
		channel_ios_drained=$($rpc_py bdev_get_bdevs | jq -r ".[] | select(.product_name == \"redirector\" and .name == \"${redirector_bdev}\") | .driver_specific.redirector.channel_ios_drained")
		if [ -z $channel_ios_drained ]; then
			channel_ios_drained=0
		fi
		if [ $channel_ios_drained -eq 0 ]; then
			echo "No channel IOs drained"
			return -1
		fi
		get_iostats > /dev/null

		nbd_stop_disks $rpc_server $nbd
		count=$(nbd_get_count $rpc_server)
		if [ $count -ne 0 ]; then
			return -1
		fi

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hash_end

		killprocess $redirector_pid
		echo "############# hash_function_test ends #############"
	else
		echo "skipping bdev redirector tests."
	fi

	return 0
}

################################################################################################################

function hint_learning_test() {
	local rd_size_mb=64
	local rd_block_size=512
    local rd1_nqn=nqn.2019-11-14.com.intel.nemo:node1
    local rd2_nqn=nqn.2019-11-14.com.intel.nemo:node2
    local rd3_nqn=nqn.2019-11-14.com.intel.nemo:node3
    local rd4_nqn=nqn.2019-11-14.com.intel.nemo:node4
    local ln_uuid=c119038a-54ab-463a-aa86-f0fc3db84b49
	local one_mb=$( expr 1024 \* 1024 )
	local two_mb=$( expr 2 \* $one_mb )
	local three_mb=$( expr 3 \* $one_mb )
	local one_mb_block=$( expr $one_mb / $rd_block_size )
	local two_mb_block=$( expr $two_mb / $rd_block_size )
	local three_mb_block=$( expr $three_mb / $rd_block_size )

    function configure_hint_learning_bdev() {
	    rm -rf $testdir/rpcs.txt
	    local rd_size_mb=$1
	    local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	    local rd_block_size=$2
	    local rd_io_boundary=$( expr 64 \* 1024 )
	    local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )

        rm -f $testdir/rpcs.txt
	    echo log_set_flag bdev >> $testdir/rpcs.txt
	    #echo log_set_flag bdev_null >> $testdir/rpcs.txt
	    echo log_set_flag vbdev_split >> $testdir/rpcs.txt
	    echo log_set_flag bdev_aio >> $testdir/rpcs.txt
	    #echo log_set_flag bdev_malloc >> $testdir/rpcs.txt
	    echo log_set_flag vbdev_passthru >> $testdir/rpcs.txt

	    # Here we set up a "host" redirector connected to some "egress" redirectors which will pass
        # it location hints it should apply.
        #
        # The egress redirectors will have just one default target. We'll simplify the bottom of the
        # stack by creating just one base (malloc or aio) bdev with a split on top of it. We'll stack
        # passthrus on top of the split ports as in the cases above, so we can disconnect each target
        # from rd0.
        #
        # We won't configure any location hints in rd0, only in the egress redirectors.
        #
        # We're not testing the ability to handle a stream of IO as targets disconnect and reconnect here,
        # so any disconnects we do will be to show the effect on learned hints.
        #
        # We'll configure hints in the egress redirectors, ensure that the host redirector has read the
        # hints from all its targets, then retrieve the rule table from the host redirector and ensure
        # it learned incorporated the hints it learned from the egress redirectors.
        #
        # Initially no hints are configured in any redirector, so the host redirector rule table should send
        # everything to the default target (here that will be rd1).
        #
        # The host redirector is rd0. The others are rd1..rdn
	    rm -rf ${extent_1_file}
	    dd if=/dev/zero of=${extent_1_file} bs=${rd_block_size} count=${rd_block_count}
	    echo bdev_aio_create ${extent_1_file} bare $rd_block_size >> $testdir/rpcs.txt
	    echo bdev_split_create bare 4 -r >> $testdir/rpcs.txt

	    echo construct_redirector_bdev -d \"PTrd1 PTrd2 PTrd3 PTrd4\" -n rd0 >> $testdir/rpcs.txt

	    $rpc_py < $testdir/rpcs.txt
	    rm -rf $testdir/rpcs.txt

	    $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hint_learning_init_0

	    echo construct_redirector_bdev -d barep0 -n rd1 --uuid ${ln_uuid} --nqn ${rd1_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt
	    echo construct_redirector_bdev -d barep1 -n rd2 --uuid ${ln_uuid} --nqn ${rd2_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt
	    echo construct_redirector_bdev -d barep2 -n rd3 --uuid ${ln_uuid} --nqn ${rd3_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt
	    echo construct_redirector_bdev -d barep3 -n rd4 --uuid ${ln_uuid} --nqn ${rd4_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt

	    $rpc_py < $testdir/rpcs.txt
	    rm -rf $testdir/rpcs.txt

        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hint_learning_init_1

        # Auth hints in each egress redirector should get passed to rd0
        #
        # Because the egress redirectors are using a split/share of a single aio device, we don't want
        # the egress redirectors to do any LBA translation when they submit IO to the egress targets.
        # We omit the --target_start_lba argument an egress redirector would normally have.
	    echo redirector_add_hint --redirector rd1 --target barep0 --start_lba 0 --blocks ${one_mb_block} --authoritative >> $testdir/rpcs.txt
	    echo redirector_add_hint --redirector rd2 --target barep1 --start_lba ${one_mb_block} --blocks ${one_mb_block} --authoritative >> $testdir/rpcs.txt
	    echo redirector_add_hint --redirector rd3 --target barep2 --start_lba ${two_mb_block} --blocks ${one_mb_block} --authoritative >> $testdir/rpcs.txt
	    echo redirector_add_hint --redirector rd4 --target barep3 --start_lba ${three_mb_block} --blocks ${one_mb_block} --authoritative >> $testdir/rpcs.txt
	    $rpc_py < $testdir/rpcs.txt
	    rm -rf $testdir/rpcs.txt

        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hint_learning_init_2

        # Stats collection side effect is to ensure prior commands have completed
		get_iostats > /dev/null

        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hint_learning_init_3

        # expose egress redirectors to rd0 (deferred to ensure the egress redirectors are all ready to
        # pass location hints when rd0 interrogates them)
	    echo bdev_passthru_create -b rd1 -p PTrd1 >> $testdir/rpcs.txt
	    echo bdev_passthru_create -b rd2 -p PTrd2 >> $testdir/rpcs.txt
	    echo bdev_passthru_create -b rd3 -p PTrd3 >> $testdir/rpcs.txt
	    echo bdev_passthru_create -b rd4 -p PTrd4 >> $testdir/rpcs.txt

	    $rpc_py < $testdir/rpcs.txt
	    rm -rf $testdir/rpcs.txt

		get_iostats > /dev/null

        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hint_learning_init_4

	    echo bdev_enable_histogram -e rd0 >> $testdir/rpcs.txt

	    $rpc_py < $testdir/rpcs.txt
	    rm -rf $testdir/rpcs.txt
    }

    # main
	if [ $(uname -s) = Linux ] && modprobe -n nbd; then
		local nbd=/dev/nbd0
		local redirector_bdev
		local bg_io_seconds=30
		local bg_io_jobs=64
		local reconfig_delay_seconds=2
		local num_cycles=5

		echo "############# hint_learning_test begins #############"
		modprobe nbd
		$rootdir/test/app/bdev_svc/bdev_svc -r $rpc_server -i 0 -L vbdev_redirector &
		#$rootdir/test/app/bdev_svc/bdev_svc -r $rpc_server -i 0 -L &
		redirector_pid=$!
		echo "Process redirector pid: $redirector_pid"
		waitforlisten $redirector_pid $rpc_server

		if [ -n "$PAUSE_FOR_DEBUGGER" ]; then
			echo "===== attach gdb to PID $redirector_pid now ..."
			read
		fi

		configure_hint_learning_bdev $rd_size_mb $rd_block_size

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hash
		redirector_bdev=$($rpc_py bdev_get_bdevs | jq -r 'first(.[] | select(.product_name == "redirector" and .claimed == false) | .name)')
		if [ -z $redirector_bdev ]; then
			echo "No rd0 device in SPDK app"
			return 1
		fi

		nbd_start_disks $rpc_server ${redirector_bdev} $nbd
		count=$(nbd_get_count $rpc_server)
		if [ $count -ne 1 ]; then
			return -1
		fi

		lsblk ${nbd}

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hint_learning_before

		redirector_unmap_data_verify $nbd $rpc_server
		get_iostats > /dev/null

        # Here rd0 should have learned one auth hint from each of rd1-rd4 to the first 4 1MB regoins of the LN
        expected_hints_from_rd4=1
        hints_from_rd4=$(jq -r "[ (.[] | select(.product_name == \"redirector\" and .name == \"rd0\") | .driver_specific.redirector.locations[] | select(.hint_source == \"${rd4_nqn}\") ) ] | length" /tmp/bdev_get_bdevs_hint_learning_before)
        if [ -z $hints_from_rd4 ]; then
          hints_from_rd4=0
        fi
        if [ $hints_from_rd4 -ne $expected_hints_from_rd4 ]; then
          echo "(at $LINENO) Expected ${expected_hints_from_rd4} hints learned from ${rd4_nqn}, got ${hints_from_rd4}"
          return -1
        fi

        # Add auth hints to rd4 for the 1MB regions on rd1-rd3 using their NQN
	    rm -rf $testdir/rpcs.txt
	    echo redirector_add_hint --redirector rd4 --target ${rd1_nqn} --start_lba 0 --blocks ${one_mb_block} --authoritative >> $testdir/rpcs.txt
	    echo redirector_add_hint --redirector rd4 --target ${rd2_nqn} --start_lba ${one_mb_block} --blocks ${one_mb_block} --authoritative >> $testdir/rpcs.txt
	    echo redirector_add_hint --redirector rd4 --target ${rd3_nqn} --start_lba ${two_mb_block} --blocks ${one_mb_block} --authoritative >> $testdir/rpcs.txt
	    #echo redirector_add_hint --redirector rd4 --target ${rd4_nqn} --start_lba ${three_mb_block} --blocks ${one_mb_block} --authoritative >> $testdir/rpcs.txt
	    $rpc_py < $testdir/rpcs.txt
	    rm -rf $testdir/rpcs.txt
		get_iostats > /dev/null

        # IO should still work
        redirector_unmap_data_verify $nbd $rpc_server

        # Remove & re-add rd4 to cause rd0 to replace the hints learned from rd4
        # (on disconnect from a still configured target we retain the hints learned from it)
	    #echo bdev_passthru_delete PTrd4 >> $testdir/rpcs.txt
	    echo redirector_remove_target --redirector rd0 --target PTrd4 >> $testdir/rpcs.txt
	    $rpc_py < $testdir/rpcs.txt
	    rm -rf $testdir/rpcs.txt
		get_iostats > /dev/null

        # Here rd0 should have removed all hints from rd4
        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hint_learning_0

        expected_hints_from_rd4=0
        hints_from_rd4=$(jq -r "[ (.[] | select(.product_name == \"redirector\" and .name == \"rd0\") | .driver_specific.redirector.locations[] | select(.hint_source == \"${rd4_nqn}\") ) ] | length" /tmp/bdev_get_bdevs_hint_learning_0)
        if [ -z $hints_from_rd4 ]; then
          hints_from_rd4=0
        fi
        if [ $hints_from_rd4 -ne $expected_hints_from_rd4 ]; then
          echo "(at $LINENO) Expected ${expected_hints_from_rd4} hints learned from ${rd4_nqn}, got ${hints_from_rd4}"
          return -1
        fi

	    #echo bdev_passthru_create -b rd4 -p PTrd4 >> $testdir/rpcs.txt
	    echo redirector_add_target --redirector rd0 --target PTrd4 --persist --required >> $testdir/rpcs.txt
	    $rpc_py < $testdir/rpcs.txt
	    rm -rf $testdir/rpcs.txt
		get_iostats > /dev/null

        # IO should still work
        redirector_unmap_data_verify $nbd $rpc_server

        # Here rd0 should have learned the 3 auth hints from rd4
        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hint_learning_1

        expected_hints_from_rd4=4
        hints_from_rd4=$(jq -r "[ (.[] | select(.product_name == \"redirector\" and .name == \"rd0\") | .driver_specific.redirector.locations[] | select(.hint_source == \"${rd4_nqn}\") ) ] | length" /tmp/bdev_get_bdevs_hint_learning_1)
        if [ -z $hints_from_rd4 ]; then
          hints_from_rd4=0
        fi
        if [ $hints_from_rd4 -ne $expected_hints_from_rd4 ]; then
          echo "(at $LINENO) Expected ${expected_hints_from_rd4} hints learned from ${rd4_nqn}, got ${hints_from_rd4}"
          return -1
        fi

        # Remove 3 hints in rd4, wait for polling, and confirm rd0 learned them (replacing the others)
		echo "------------------ hint_learning_test: remove hints from egress rd"
	    echo redirector_remove_hint --redirector rd4 --target ${rd1_nqn} --start_lba 0 --blocks ${one_mb_block} >> $testdir/rpcs.txt
	    echo redirector_remove_hint --redirector rd4 --target ${rd2_nqn} --start_lba ${one_mb_block} --blocks ${one_mb_block} >> $testdir/rpcs.txt
	    echo redirector_remove_hint --redirector rd4 --target ${rd3_nqn} --start_lba ${two_mb_block} --blocks ${one_mb_block} >> $testdir/rpcs.txt
	    $rpc_py < $testdir/rpcs.txt
	    rm -rf $testdir/rpcs.txt
		get_iostats > /dev/null

        # Here rd0 may not have removed all hints from rd4
        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hint_learning_2

        # Wait for hint polling to complete and discover change
		echo "------------------ hint_learning_test: wait for hint poll on rd0"
        sleep 10

        # Here rd0 should have removed all hints from rd4
		echo "------------------ hint_learning_test: verify rd0 learned removed hints"
        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hint_learning_3

        expected_hints_from_rd4=1
        hints_from_rd4=$(jq -r "[ (.[] | select(.product_name == \"redirector\" and .name == \"rd0\") | .driver_specific.redirector.locations[] | select(.hint_source == \"${rd4_nqn}\") ) ] | length" /tmp/bdev_get_bdevs_hint_learning_3)
        if [ -z $hints_from_rd4 ]; then
          hints_from_rd4=0
        fi
        if [ $hints_from_rd4 -ne $expected_hints_from_rd4 ]; then
          echo "(at $LINENO) Expected ${expected_hints_from_rd4} hints learned from ${rd4_nqn}, got ${hints_from_rd4}"
          return -1
        fi

        # Disconnect rd4 and see that hints learned from it are retained
        # TODO

        # IO should still work
        redirector_unmap_data_verify $nbd $rpc_server

		get_histograms > /dev/null
		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hint_learning_4
		channel_ios_drained=$($rpc_py bdev_get_bdevs | jq -r ".[] | select(.product_name == \"redirector\" and .name == \"${redirector_bdev}\") | .driver_specific.redirector.channel_ios_drained")
		if [ -z $channel_ios_drained ]; then
			channel_ios_drained=0
		fi
		if [ $channel_ios_drained -eq 0 ]; then
			echo "No channel IOs drained"
			#return -1
		fi
		get_iostats > /dev/null

		nbd_stop_disks $rpc_server $nbd
		count=$(nbd_get_count $rpc_server)
		if [ $count -ne 0 ]; then
			return -1
		fi

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hint_learning_end

		killprocess $redirector_pid
		echo "############# hint_learning_test ends #############"
	else
		echo "skipping bdev redirector tests."
	fi

	return 0
}

################################################################################################################

function configure_ceph_hash_bdev() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local rd1_nqn=nqn.2019-11-14.com.intel.nemo:node1-rdma
	local rd2_nqn=nqn.2019-11-14.com.intel.nemo:node2-rdma
	local rd3_nqn=nqn.2019-11-14.com.intel.nemo:node3-rdma
	local ln_uuid=c119038a-54ab-463a-aa86-f0fc3db84b49

	rm -f $testdir/rpcs.txt
	echo log_set_flag bdev >> $testdir/rpcs.txt
	#echo log_set_flag bdev_null >> $testdir/rpcs.txt
	echo log_set_flag vbdev_split >> $testdir/rpcs.txt
	echo log_set_flag bdev_aio >> $testdir/rpcs.txt
	#echo log_set_flag bdev_malloc >> $testdir/rpcs.txt
	echo log_set_flag vbdev_passthru >> $testdir/rpcs.txt

	# Here we set up a "host" redirector connected to some "egress" redirectors using a hash
	# hint as above. Above we used a hint parameters file that specified the null hash function
	# and a small hash table. Here we'll use a hint parameters file closer to what we'd get
	# from a real ceph cluster. The test_hash_hint.json file was actully collected from a real
	# Ceph cluster in a lab, and then adjusted to have generic hostnames for the OSD nodes.
	#
	# The extent locations here will be less predictable. We'd expect them to be evenly distributed
	# across the target.
	#
	# TODO Since this small volume has only about 16 objects so that may not be the case. Create a
	# tweaked version of the int params with a smaller obect size if necessary to get an even distri
	#
	# Without learning, the only point of the egress redirectors in this test is to provide
	# tartgets with different NQNs that the host redirector can identify.
	#
	# The host redirector is rd0. The others are rd1..rdn
	rm -rf ${extent_1_file}
	dd if=/dev/zero of=${extent_1_file} bs=${rd_block_size} count=${rd_block_count}
	echo bdev_aio_create ${extent_1_file} bare $rd_block_size >> $testdir/rpcs.txt
	echo bdev_split_create bare 3 -r >> $testdir/rpcs.txt

	echo construct_redirector_bdev -d \"PTrd1 PTrd2 PTrd3\" -n rd0 >> $testdir/rpcs.txt

	$rpc_py < $testdir/rpcs.txt
	rm -rf $testdir/rpcs.txt

	$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_init_0

	echo redirector_add_hash_hint --redirector rd0 --hash_hint_file $rootdir/test/json_config/test_hash_hint.json >> $testdir/rpcs.txt

	echo bdev_passthru_create -b rd1 -p PTrd1 >> $testdir/rpcs.txt
	echo bdev_passthru_create -b rd2 -p PTrd2 >> $testdir/rpcs.txt
	echo bdev_passthru_create -b rd3 -p PTrd3 >> $testdir/rpcs.txt

	$rpc_py < $testdir/rpcs.txt
	rm -rf $testdir/rpcs.txt

	$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_init_1
	$rpc_py save_config > /tmp/save_config_ceph_hash_init_1

	echo construct_redirector_bdev -d barep0 -n rd1 --uuid ${ln_uuid} --nqn ${rd1_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt

	echo construct_redirector_bdev -d barep1 -n rd2 --uuid ${ln_uuid} --nqn ${rd2_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt

	$rpc_py < $testdir/rpcs.txt
	rm -rf $testdir/rpcs.txt

	$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_init_2
	$rpc_py save_config > /tmp/save_config_ceph_hash_init_2

	echo construct_redirector_bdev -d barep2 -n rd3 --uuid ${ln_uuid} --nqn ${rd3_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt

	echo bdev_enable_histogram -e rd0 >> $testdir/rpcs.txt

	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function reconfigure_ceph_hash_bdev_1() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	rm -rf $testdir/rpcs.txt
	# Disconnect rd0 from rd1 and see that IO still works
	echo bdev_passthru_delete PTrd1 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function reconfigure_ceph_hash_bdev_2() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	rm -rf $testdir/rpcs.txt
	# reconnect rd0 to rd1, then disconnect rd2 from rd0
	echo bdev_passthru_create -b rd1 -p PTrd1 >> $testdir/rpcs.txt
	echo bdev_passthru_delete PTrd2 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function reconfigure_ceph_hash_bdev_2_reverse() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	rm -rf $testdir/rpcs.txt
	# disconnect rd2 from rd0, then reconnect rd0 to rd1
	echo bdev_passthru_delete PTrd2 >> $testdir/rpcs.txt
	echo bdev_passthru_create -b rd1 -p PTrd1 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function restore_ceph_hash_bdev() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local malloc_size_mb=$( expr $rd_size_mb / 2 )
	local malloc_size_bytes=$( expr $malloc_size_mb \* 1024 \* 1024 )
	local malloc_block_count=$( expr $malloc_size_bytes / $rd_block_size )

	rm -rf $testdir/rpcs.txt
	# reconnect rd0 to rd2
	echo bdev_passthru_create -b rd2 -p PTrd2 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function ceph_hash_function_test() {
	if [ $(uname -s) = Linux ] && modprobe -n nbd; then
		local nbd=/dev/nbd0
		local redirector_bdev
		local rd_size_mb=64
		local rd_block_size=512
		local bg_io_seconds=30
		local bg_io_jobs=64
		local reconfig_delay_seconds=2
		local num_cycles=5

		echo "############# hash_function_test begins #############"
		modprobe nbd
		$rootdir/test/app/bdev_svc/bdev_svc -r $rpc_server -i 0 &
		redirector_pid=$!
		echo "Process redirector pid: $redirector_pid"
		waitforlisten $redirector_pid $rpc_server

		if [ -n "$PAUSE_FOR_DEBUGGER" ]; then
			echo "===== attach gdb to PID $redirector_pid now ..."
			read
		fi

		configure_ceph_hash_bdev $rd_size_mb $rd_block_size

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash
		redirector_bdev=$($rpc_py bdev_get_bdevs | jq -r 'first(.[] | select(.product_name == "redirector" and .claimed == false) | .name)')
		if [ -z $redirector_bdev ]; then
			echo "No rd0 device in SPDK app"
			return 1
		fi

		nbd_start_disks $rpc_server ${redirector_bdev} $nbd
		count=$(nbd_get_count $rpc_server)
		if [ $count -ne 1 ]; then
			return -1
		fi

		lsblk ${nbd}

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_before

		#redirector_unmap_data_verify $nbd $rpc_server
		#get_iostats > /dev/null

		reconfigure_ceph_hash_bdev_1 $rd_size_mb $rd_block_size
		#redirector_unmap_data_verify $nbd $rpc_server
		#get_iostats > /dev/null

		reconfigure_ceph_hash_bdev_2 $rd_size_mb $rd_block_size
		#redirector_unmap_data_verify $nbd $rpc_server
		get_iostats > /dev/null

		# redirector changes with IO in flight
		redirector_fio $nbd $bg_io_seconds $bg_io_jobs &
		fio_pid=$!

		for (( i=0; i<${num_cycles}; i++ )); do
			sleep ${reconfig_delay_seconds}
			get_iostats > /dev/null
			restore_ceph_hash_bdev $rd_size_mb $rd_block_size
			$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_restore
			reconfigure_ceph_hash_bdev_1 $rd_size_mb $rd_block_size
			get_iostats > /dev/null
			$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_reconfig_1
			sleep ${reconfig_delay_seconds}
			get_iostats > /dev/null
			if [ $((i%2)) -eq 0 ];
			then
				reconfigure_ceph_hash_bdev_2 $rd_size_mb $rd_block_size
			    $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_reconfig_2
			else
				reconfigure_ceph_hash_bdev_2_reverse $rd_size_mb $rd_block_size
			    $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_reconfig_2_rev
			fi
			get_iostats > /dev/null
		done
		sleep ${reconfig_delay_seconds}
		restore_ceph_hash_bdev $rd_size_mb $rd_block_size

		wait $fio_pid

		get_histograms > /dev/null
		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_2
		channel_ios_drained=$($rpc_py bdev_get_bdevs | jq -r ".[] | select(.product_name == \"redirector\" and .name == \"${redirector_bdev}\") | .driver_specific.redirector.channel_ios_drained")
		if [ -z $channel_ios_drained ]; then
			channel_ios_drained=0
		fi
		if [ $channel_ios_drained -eq 0 ]; then
			echo "No channel IOs drained"
			return -1
		fi
		get_iostats > /dev/null

		nbd_stop_disks $rpc_server $nbd
		count=$(nbd_get_count $rpc_server)
		if [ $count -ne 0 ]; then
			return -1
		fi

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_end

		killprocess $redirector_pid
		echo "############# hash_function_test ends #############"
	else
		echo "skipping bdev redirector tests."
	fi

	return 0
}

################################################################################################################

function ceph_hash_learning_test() {
	local rd_size_mb=64
	local rd_block_size=512
	local rd1_nqn=nqn.2019-11-14.com.intel.nemo:node1-rdma
	local rd2_nqn=nqn.2019-11-14.com.intel.nemo:node2-rdma
	local rd3_nqn=nqn.2019-11-14.com.intel.nemo:node3-rdma
	local rd4_nqn=nqn.2019-11-14.com.intel.nemo:node4-rdma
	local ln_uuid=c119038a-54ab-463a-aa86-f0fc3db84b49
    local one_mb=$( expr 1024 \* 1024 )
	local two_mb=$( expr 2 \* $one_mb )
	local three_mb=$( expr 3 \* $one_mb )
	local one_mb_block=$( expr $one_mb / $rd_block_size )
	local two_mb_block=$( expr $two_mb / $rd_block_size )
	local three_mb_block=$( expr $three_mb / $rd_block_size )

    function configure_ceph_hash_learning_bdev() {
	    rm -rf $testdir/rpcs.txt
	    local rd_size_mb=$1
	    local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	    local rd_block_size=$2
	    local rd_io_boundary=$( expr 64 \* 1024 )
	    local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )

        rm -f $testdir/rpcs.txt
	    echo log_set_flag bdev >> $testdir/rpcs.txt
	    #echo log_set_flag bdev_null >> $testdir/rpcs.txt
	    echo log_set_flag vbdev_split >> $testdir/rpcs.txt
	    echo log_set_flag bdev_aio >> $testdir/rpcs.txt
	    #echo log_set_flag bdev_malloc >> $testdir/rpcs.txt
	    echo log_set_flag vbdev_passthru >> $testdir/rpcs.txt

	    # Here we set up a "host" redirector connected to some "egress" redirectors which will pass
        # it location hints it should apply.
        #
        # The egress redirectors will have just one default target. We'll simplify the bottom of the
        # stack by creating just one base (malloc or aio) bdev with a split on top of it. We'll stack
        # passthrus on top of the split ports as in the cases above, so we can disconnect each target
        # from rd0.
        #
        # We won't configure any location hints in rd0, only in the egress redirectors.
        #
        # We're not testing the ability to handle a stream of IO as targets disconnect and reconnect here,
        # so any disconnects we do will be to show the effect on learned hints.
        #
        # We'll configure hints in the egress redirectors, ensure that the host redirector has read the
        # hints from all its targets, then retrieve the rule table from the host redirector and ensure
        # it learned incorporated the hints it learned from the egress redirectors.
        #
        # The first hash hint loaded will be the same used in other tests here which specifies only 3 targets.
        # We'll configure 4, and make "node4" appear first in rd0's default target list. That will make
        # node4 rd0's default. All IO should go to node4 if no hints are learned.
        #
        # We'll configure the hash hint in node 4 here, and see that rd0 learns it when it comes up
        #
        # The host redirector is rd0. The others are rd1..rdn
	    rm -rf ${extent_1_file}
	    dd if=/dev/zero of=${extent_1_file} bs=${rd_block_size} count=${rd_block_count}
	    echo bdev_aio_create ${extent_1_file} bare $rd_block_size >> $testdir/rpcs.txt
	    echo bdev_split_create bare 4 -r >> $testdir/rpcs.txt

	    echo construct_redirector_bdev -d \"PTrd4 PTrd1 PTrd2 PTrd3\" -n rd0 >> $testdir/rpcs.txt

	    $rpc_py < $testdir/rpcs.txt
	    rm -rf $testdir/rpcs.txt

	    $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_learning_init_0

	    echo construct_redirector_bdev -d barep0 -n rd1 --uuid ${ln_uuid} --nqn ${rd1_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt
	    echo construct_redirector_bdev -d barep1 -n rd2 --uuid ${ln_uuid} --nqn ${rd2_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt
	    echo construct_redirector_bdev -d barep2 -n rd3 --uuid ${ln_uuid} --nqn ${rd3_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt
	    echo construct_redirector_bdev -d barep3 -n rd4 --uuid ${ln_uuid} --nqn ${rd4_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt

	    $rpc_py < $testdir/rpcs.txt
	    rm -rf $testdir/rpcs.txt

        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_learning_init_1

        # Add hash hint to rd4
        echo redirector_add_hash_hint --redirector rd4 --hash_hint_file $rootdir/test/json_config/test_hash_hint.json --authoritative >> $testdir/rpcs.txt
	    $rpc_py < $testdir/rpcs.txt
	    rm -rf $testdir/rpcs.txt

        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_learning_init_2

        # Stats collection side effect is to ensure prior commands have completed
		get_iostats > /dev/null

        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_learning_init_3

        # expose egress redirectors to rd0 (deferred to ensure the egress redirectors are all ready to
        # pass location hints when rd0 interrogates them)
	    echo bdev_passthru_create -b rd1 -p PTrd1 >> $testdir/rpcs.txt
	    echo bdev_passthru_create -b rd2 -p PTrd2 >> $testdir/rpcs.txt
	    echo bdev_passthru_create -b rd3 -p PTrd3 >> $testdir/rpcs.txt
	    echo bdev_passthru_create -b rd4 -p PTrd4 >> $testdir/rpcs.txt

	    $rpc_py < $testdir/rpcs.txt
	    rm -rf $testdir/rpcs.txt

		get_iostats > /dev/null

        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_learning_init_4

	    echo bdev_enable_histogram -e rd0 >> $testdir/rpcs.txt

	    $rpc_py < $testdir/rpcs.txt
	    rm -rf $testdir/rpcs.txt
    }

    # main
	if [ $(uname -s) = Linux ] && modprobe -n nbd; then
		local nbd=/dev/nbd0
		local redirector_bdev
		local bg_io_seconds=30
		local bg_io_jobs=64
		local reconfig_delay_seconds=2
		local num_cycles=5

		echo "############# ceph_hash_learning_test begins #############"
		modprobe nbd
		$rootdir/test/app/bdev_svc/bdev_svc -r $rpc_server -i 0 -L vbdev_redirector &
		#$rootdir/test/app/bdev_svc/bdev_svc -r $rpc_server -i 0 -L &
		redirector_pid=$!
		echo "Process redirector pid: $redirector_pid"
		waitforlisten $redirector_pid $rpc_server

		if [ -n "$PAUSE_FOR_DEBUGGER" ]; then
			echo "===== attach gdb to PID $redirector_pid now ..."
			read
		fi

		configure_ceph_hash_learning_bdev $rd_size_mb $rd_block_size

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_hash
		redirector_bdev=$($rpc_py bdev_get_bdevs | jq -r 'first(.[] | select(.product_name == "redirector" and .claimed == false) | .name)')
		if [ -z $redirector_bdev ]; then
			echo "No rd0 device in SPDK app"
			return 1
		fi

		nbd_start_disks $rpc_server ${redirector_bdev} $nbd
		count=$(nbd_get_count $rpc_server)
		if [ $count -ne 1 ]; then
			return -1
		fi

		lsblk ${nbd}

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_learning_before

		redirector_unmap_data_verify $nbd $rpc_server
		get_iostats > /dev/null

        # Here rd0 should have learned one hash hint from rd4
        expected_hints_from_rd4=1
        hints_from_rd4=$(jq -r "[ (.[] | select(.product_name == \"redirector\" and .name == \"rd0\") | .driver_specific.redirector.locations[] | select(.hint_source == \"${rd4_nqn}\") ) ] | length" /tmp/bdev_get_bdevs_ceph_hash_learning_before)
        if [ -z $hints_from_rd4 ]; then
          hints_from_rd4=0
        fi
        if [ $hints_from_rd4 -ne $expected_hints_from_rd4 ]; then
          echo "(at $LINENO) Expected ${expected_hints_from_rd4} hints learned from ${rd4_nqn}, got ${hints_from_rd4}"
          return -1
        fi

        # Remove/replace rd4 to cause rd0 to replace the hints learned from rd4
	    echo redirector_remove_target --redirector rd0 --target PTrd4 >> $testdir/rpcs.txt
        $rpc_py < $testdir/rpcs.txt
	    rm -rf $testdir/rpcs.txt
		get_iostats > /dev/null

        # Here rd0 should have removed all hints from rd4
        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_learning_0

        expected_hints_from_rd4=0
        hints_from_rd4=$(jq -r "[ (.[] | select(.product_name == \"redirector\" and .name == \"rd0\") | .driver_specific.redirector.locations[] | select(.hint_source == \"${rd4_nqn}\") ) ] | length" /tmp/bdev_get_bdevs_ceph_hash_learning_0)
        if [ -z $hints_from_rd4 ]; then
          hints_from_rd4=0
        fi
        if [ $hints_from_rd4 -ne $expected_hints_from_rd4 ]; then
          echo "(at $LINENO) Expected ${expected_hints_from_rd4} hints learned from ${rd4_nqn}, got ${hints_from_rd4}"
          return -1
        fi

	    echo redirector_add_target --redirector rd0 --target PTrd4 --persist --required >> $testdir/rpcs.txt
	    $rpc_py < $testdir/rpcs.txt
	    rm -rf $testdir/rpcs.txt
		get_iostats > /dev/null

        # IO should still work
        redirector_unmap_data_verify $nbd $rpc_server

        # Here rd0 should have learned the 3 auth hints from rd4
        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_learning_1

        expected_hints_from_rd4=1
        hints_from_rd4=$(jq -r "[ (.[] | select(.product_name == \"redirector\" and .name == \"rd0\") | .driver_specific.redirector.locations[] | select(.hint_source == \"${rd4_nqn}\") ) ] | length" /tmp/bdev_get_bdevs_ceph_hash_learning_1)
        if [ -z $hints_from_rd4 ]; then
          hints_from_rd4=0
        fi
        if [ $hints_from_rd4 -ne $expected_hints_from_rd4 ]; then
          echo "(at $LINENO) Expected ${expected_hints_from_rd4} hints learned from ${rd4_nqn}, got ${hints_from_rd4}"
          return -1
        fi

        # TODO: Get rd0 hint table generation
        # TODO: get rd0 hash table digest
        # TODO: get rd0 nqn list digest
        # Replace hash hint in rd4 with the same hint JSON. hints shouldn't change
		echo "------------------ ceph_hash_learning_test: update but don't change hash hint"
        echo redirector_add_hash_hint --redirector rd4 --hash_hint_file $rootdir/test/json_config/test_hash_hint.json --authoritative >> $testdir/rpcs.txt
	    $rpc_py < $testdir/rpcs.txt
	    rm -rf $testdir/rpcs.txt
		get_iostats > /dev/null

        # Here rd0 may not have updated all hints from rd4
        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_learning_2

        # Wait for hint polling to complete and discover change
		echo "------------------ ceph_hash_learning_test: wait for hint poll on rd0"
        sleep 10

        # Here rd0 should have updated all hints from rd4
		echo "------------------ ceph_hash_learning_test: verify rd0 hints didn't change"
        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_learning_3

        expected_hints_from_rd4=1
        hints_from_rd4=$(jq -r "[ (.[] | select(.product_name == \"redirector\" and .name == \"rd0\") | .driver_specific.redirector.locations[] | select(.hint_source == \"${rd4_nqn}\") ) ] | length" /tmp/bdev_get_bdevs_ceph_hash_learning_3)
        if [ -z $hints_from_rd4 ]; then
          hints_from_rd4=0
        fi
        if [ $hints_from_rd4 -ne $expected_hints_from_rd4 ]; then
          echo "(at $LINENO) Expected ${expected_hints_from_rd4} hints learned from ${rd4_nqn}, got ${hints_from_rd4}"
          return -1
        fi

        # TODO: Verify rd0 hint table generation number unchanged
        # TODO: Verify rd0 hash table digest unchanged
        # TODO: Verify rd0 nqn list digest unchanged

        # IO should still work
        redirector_unmap_data_verify $nbd $rpc_server

        # TODO: replace hint config on rd4 with a different nqn and hash table (adding rd4 as a target), verify rd0
        # generation number and table digests change

		get_histograms > /dev/null
		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_learning_4
		channel_ios_drained=$($rpc_py bdev_get_bdevs | jq -r ".[] | select(.product_name == \"redirector\" and .name == \"${redirector_bdev}\") | .driver_specific.redirector.channel_ios_drained")
		if [ -z $channel_ios_drained ]; then
			channel_ios_drained=0
		fi
		if [ $channel_ios_drained -eq 0 ]; then
			echo "No channel IOs drained"
			#return -1
		fi
		get_iostats > /dev/null

		nbd_stop_disks $rpc_server $nbd
		count=$(nbd_get_count $rpc_server)
		if [ $count -ne 0 ]; then
			return -1
		fi

		$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_learning_end

		killprocess $redirector_pid
		echo "############# ceph_hash_learning_test ends #############"
	else
		echo "skipping bdev redirector tests."
	fi

	return 0
}

################################################################################################################

function configure_ceph_hash_perf_bdev() {
	rm -rf $testdir/rpcs.txt
	local rd_size_mb=$1
	local rd_size_bytes=$( expr $rd_size_mb \* 1024 \* 1024 )
	local rd_block_size=$2
	local rd_io_boundary=$( expr 64 \* 1024 )
	local rd_block_count=$( expr $rd_size_bytes / $rd_block_size )
	local rd1_nqn=nqn.2019-11-14.com.intel.nemo:node1-rdma
	local rd2_nqn=nqn.2019-11-14.com.intel.nemo:node2-rdma
	local rd3_nqn=nqn.2019-11-14.com.intel.nemo:node3-rdma
	local ln_uuid=c119038a-54ab-463a-aa86-f0fc3db84b49

	rm -f $testdir/rpcs.txt
	echo log_set_flag bdev >> $testdir/rpcs.txt
	#echo log_set_flag bdev_null >> $testdir/rpcs.txt
	echo log_set_flag vbdev_split >> $testdir/rpcs.txt
	echo log_set_flag bdev_aio >> $testdir/rpcs.txt
	#echo log_set_flag bdev_malloc >> $testdir/rpcs.txt
	echo log_set_flag vbdev_passthru >> $testdir/rpcs.txt

	# Here we set up a "host" redirector connected to some "egress" redirectors using a hash
	# hint as above. Above we used a hint parameters file that specified the null hash function
	# and a small hash table. Here we'll use a hint parameters file closer to what we'd get
	# from a real ceph cluster. The test_hash_hint.json file was actully collected from a real
	# Ceph cluster in a lab, and then adjusted to have generic hostnames for the OSD nodes.
	#
	# The extent locations here will be less predictable. We'd expect them to be evenly distributed
	# across the target.
	#
	# TODO Since this small volume has only about 16 objects so that may not be the case. Create a
	# tweaked version of the hint params with a smaller obect size if necessary to get an even
	# distribution
	#
	# Without learning, the only point of the egress redirectors in this test is to provide
	# tartgets with different NQNs that the host redirector can identify.
	#
	# The host redirector is rd0. The others are rd1..rdn
	rm -rf ${extent_1_file}
	#dd if=/dev/zero of=${extent_1_file} bs=${rd_block_size} count=${rd_block_count}
	#echo bdev_aio_create ${extent_1_file} bare $rd_block_size >> $testdir/rpcs.txt
	echo bdev_malloc_create $rd_size_mb $rd_block_size --name bare >> $testdir/rpcs.txt
	#echo bdev_null_create bare $rd_size_mb $rd_block_size >> $testdir/rpcs.txt
	echo bdev_split_create bare 3 -r >> $testdir/rpcs.txt

	echo construct_redirector_bdev -d \"PTrd1 PTrd2 PTrd3\" -n rd0 >> $testdir/rpcs.txt
	$rpc_py < $testdir/rpcs.txt
	rm -rf $testdir/rpcs.txt

	$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_init_0

	# Hash hint added later
	#echo redirector_add_hash_hint --redirector rd0 --hash_hint_file $rootdir/test/json_config/test_hash_hint.json >> $testdir/rpcs.txt

	echo bdev_passthru_create -b rd1 -p PTrd1 >> $testdir/rpcs.txt
	echo bdev_passthru_create -b rd2 -p PTrd2 >> $testdir/rpcs.txt
	echo bdev_passthru_create -b rd3 -p PTrd3 >> $testdir/rpcs.txt

	$rpc_py < $testdir/rpcs.txt
	rm -rf $testdir/rpcs.txt

	$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_init_1
	$rpc_py save_config > /tmp/save_config_ceph_hash_init_1

	echo construct_redirector_bdev -d barep0 -n rd1 --uuid ${ln_uuid} --nqn ${rd1_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt

	echo construct_redirector_bdev -d barep1 -n rd2 --uuid ${ln_uuid} --nqn ${rd2_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt

	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt

	$rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_init_2
	$rpc_py save_config > /tmp/save_config_ceph_hash_init_2

	echo construct_redirector_bdev -d barep2 -n rd3 --uuid ${ln_uuid} --nqn ${rd3_nqn} --blockcnt $rd_block_count --blocklen $rd_block_size >> $testdir/rpcs.txt

	echo bdev_enable_histogram -e rd0 >> $testdir/rpcs.txt

	$rpc_py < $testdir/rpcs.txt

	rm -rf $testdir/rpcs.txt
}

function ceph_hash_perf_test() {
    if [ $(uname -s) = Linux ] && modprobe -n nbd; then
        local nbd=/dev/nbd0
        local redirector_bdev
        local rd_size_mb=64
        local rd_block_size=4096
        local bg_io_seconds=60
        local bg_io_jobs=1
        local bg_io_depth=1

        echo "############# hash_perf_test begins #############"
        modprobe nbd
        $rootdir/test/app/bdev_svc/bdev_svc -r $rpc_server -i 0 --cpumask 0x2 &
        redirector_pid=$!
        echo "Process redirector pid: $redirector_pid"
        waitforlisten $redirector_pid $rpc_server

        if [ -n "$PAUSE_FOR_DEBUGGER" ]; then
            echo "===== attach gdb to PID $redirector_pid now ..."
            read
        fi

        configure_ceph_hash_perf_bdev $rd_size_mb $rd_block_size

        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_perf
        redirector_bdev=$($rpc_py bdev_get_bdevs | jq -r 'first(.[] | select(.product_name == "redirector" and .claimed == false) | .name)')
        if [ -z $redirector_bdev ]; then
            echo "No rd0 device in SPDK app"
            return 1
        fi

        nbd_start_disks $rpc_server ${redirector_bdev} $nbd
        count=$(nbd_get_count $rpc_server)
        if [ $count -ne 1 ]; then
            return -1
        fi

        lsblk ${nbd}

        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_perf_before

        #redirector_unmap_data_verify $nbd $rpc_server
        #get_iostats > /dev/null

        get_iostats > /dev/null
        cp /tmp/rd_th_stats.json /tmp/rd_th_stats_before_nohash.json
        cp /tmp/rd_stats.json /tmp/rd_stats_before_nohash.json
        cp /tmp/rd_hist.json /tmp/rd_hist_before_nohash.json

        # typical tick rate: 2300000000
        tick_rate=$(jq -r ".tick_rate" /tmp/rd_stats.json)
        # (ns/S) / (ticks/S) = ns/tick
        ns_per_tick=$(echo "scale=6; 1000000000/${tick_rate}" | bc)
        echo "------------------------ SPDK tick rate = ${tick_rate} ticks/S (${ns_per_tick} nS/tick) "

        # stats before fio
        read_ops_t1=$(jq -r ".bdevs[] | select(.name == \"rd0\") | .num_read_ops" /tmp/rd_stats.json)
        read_ticks_t1=$(jq -r ".bdevs[] | select(.name == \"rd0\") | .read_latency_ticks" /tmp/rd_stats.json)
        write_ops_t1=$(jq -r ".bdevs[] | select(.name == \"rd0\") | .num_write_ops" /tmp/rd_stats.json)
        write_ticks_t1=$(jq -r ".bdevs[] | select(.name == \"rd0\") | .write_latency_ticks" /tmp/rd_stats.json)
        barep0_read_ops_t1=$(jq -r ".bdevs[] | select(.name == \"barep0\") | .num_read_ops" /tmp/rd_stats.json)
        barep1_read_ops_t1=$(jq -r ".bdevs[] | select(.name == \"barep1\") | .num_read_ops" /tmp/rd_stats.json)
        barep2_read_ops_t1=$(jq -r ".bdevs[] | select(.name == \"barep2\") | .num_read_ops" /tmp/rd_stats.json)

        # Fio on bdev stack without hash hint in place (uses default target)
        echo "############# hash_perf_test without hash hint #############"
        #redirector_fio $nbd $bg_io_seconds $bg_io_jobs
        rd_fio_stats_nohash=/tmp/rd_fio_stats_nohash.json
        redirector_fio $nbd $bg_io_seconds ${bg_io_jobs} ${bg_io_depth} ${rd_block_size} ${rd_fio_stats_nohash}

        get_iostats > /dev/null
        cp /tmp/rd_th_stats.json /tmp/rd_th_stats_after_nohash.json
        cp /tmp/rd_stats.json /tmp/rd_stats_after_nohash.json
        cp /tmp/rd_hist.json /tmp/rd_hist_after_nohash.json

        fio_read_iops_nohash=$(jq -r 'first(.jobs[]) | .read.iops' ${rd_fio_stats_nohash})
        fio_read_lat_ns_nohash=$(jq -r 'first(.jobs[]) | .read.lat_ns.mean' ${rd_fio_stats_nohash})
        fio_write_iops_nohash=$(jq -r 'first(.jobs[]) | .write.iops' ${rd_fio_stats_nohash})
        fio_write_lat_ns_nohash=$(jq -r 'first(.jobs[]) | .write.lat_ns.mean' ${rd_fio_stats_nohash})
        fio_disk_util_nohash=$(jq -r 'first(.disk_util[] | .util)' ${rd_fio_stats_nohash})
        echo "------- fio stats without hash hint: r/w latency(ns) = ${fio_read_lat_ns_nohash}/${fio_write_lat_ns_nohash}, r/w iops = ${fio_read_iops_nohash}/${fio_write_iops_nohash}"

        # stats after fio
        read_ops_t2=$(jq -r ".bdevs[] | select(.name == \"rd0\") | .num_read_ops" /tmp/rd_stats.json)
        read_ticks_t2=$(jq -r ".bdevs[] | select(.name == \"rd0\") | .read_latency_ticks" /tmp/rd_stats.json)
        write_ops_t2=$(jq -r ".bdevs[] | select(.name == \"rd0\") | .num_write_ops" /tmp/rd_stats.json)
        write_ticks_t2=$(jq -r ".bdevs[] | select(.name == \"rd0\") | .write_latency_ticks" /tmp/rd_stats.json)
        barep0_read_ops_t2=$(jq -r ".bdevs[] | select(.name == \"barep0\") | .num_read_ops" /tmp/rd_stats.json)
        barep1_read_ops_t2=$(jq -r ".bdevs[] | select(.name == \"barep1\") | .num_read_ops" /tmp/rd_stats.json)
        barep2_read_ops_t2=$(jq -r ".bdevs[] | select(.name == \"barep2\") | .num_read_ops" /tmp/rd_stats.json)

        # Ticks / op for fio without hash hint
        reads_1=`echo "(${read_ops_t2} - ${read_ops_t1})" | bc`
        barep0_reads_1=`echo "(${barep0_read_ops_t2} - ${barep0_read_ops_t1})" | bc`
        barep1_reads_1=`echo "(${barep1_read_ops_t2} - ${barep1_read_ops_t1})" | bc`
        barep2_reads_1=`echo "(${barep2_read_ops_t2} - ${barep2_read_ops_t1})" | bc`
        read_ticks_1=`echo "(${read_ticks_t2} - ${read_ticks_t1})" | bc`
        writes_1=`echo "(${write_ops_t2} - ${write_ops_t1})" | bc`
        write_ticks_1=`echo "(${write_ticks_t2} - ${write_ticks_t1})" | bc`
        ops_1=`echo "${reads_1} + ${writes_1}" | bc`
        ticks_1=`echo "${read_ticks_1} + ${write_ticks_1}" | bc`
        #ticks_per_op_1=`echo "((${read_ops_t2} - ${read_ops_t1}) + (${write_ops_t2} - ${write_ops_t1})) / ((${read_ticks_t2} - ${read_ticks_t1}) + (${write_ticks_t2} - ${write_ticks_t1}))" | bc`
        ticks_per_op_1=`echo "scale=6; ${ticks_1} / ${ops_1}" | bc`
        ns_per_op_1=`echo "scale=6; ${ticks_per_op_1} * ${ns_per_tick}" | bc`

        echo "----- barep0_reads=${barep0_reads_1}, barep1_reads=${barep1_reads_1}, barep2_reads=${barep2_reads_1} (one target should get most of the reads)"
        echo "------------------------ Ticks/op without hash hint = ${ticks_per_op_1} (${ns_per_op_1} nS/op) "

        get_histograms > /dev/null
        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_perf_after_nohash
        # channel_ios_drained=$($rpc_py bdev_get_bdevs | jq -r ".[] | select(.product_name == \"redirector\" and .name == \"${redirector_bdev}\") | .driver_specific.redirector.channel_ios_drained")
        # if [ -z $channel_ios_drained ]; then
        #   channel_ios_drained=0
        # fi
        # if [ $channel_ios_drained -eq 0 ]; then
        #   echo "No channel IOs drained"
        #   return -1
        # fi

        echo "############# hash_perf_test with hash hint #############"
        # We now add the hash hint to rd0 and repeat the test to measure the CPU overhead of hashing
        rm -rf $testdir/rpcs.txt
        echo redirector_add_hash_hint --redirector rd0 --hash_hint_file $rootdir/test/json_config/test_hash_hint.json >> $testdir/rpcs.txt
        $rpc_py < $testdir/rpcs.txt

        get_iostats > /dev/null
        cp /tmp/rd_th_stats.json /tmp/rd_th_stats_before_withhash.json
        cp /tmp/rd_stats.json /tmp/rd_stats_before_withhash.json
        cp /tmp/rd_hist.json /tmp/rd_hist_before_withhash.json

        # stats before second fio
        read_ops_t3=$(jq -r ".bdevs[] | select(.name == \"rd0\") | .num_read_ops" /tmp/rd_stats.json)
        read_ticks_t3=$(jq -r ".bdevs[] | select(.name == \"rd0\") | .read_latency_ticks" /tmp/rd_stats.json)
        write_ops_t3=$(jq -r ".bdevs[] | select(.name == \"rd0\") | .num_write_ops" /tmp/rd_stats.json)
        write_ticks_t3=$(jq -r ".bdevs[] | select(.name == \"rd0\") | .write_latency_ticks" /tmp/rd_stats.json)
        barep0_read_ops_t3=$(jq -r ".bdevs[] | select(.name == \"barep0\") | .num_read_ops" /tmp/rd_stats.json)
        barep1_read_ops_t3=$(jq -r ".bdevs[] | select(.name == \"barep1\") | .num_read_ops" /tmp/rd_stats.json)
        barep2_read_ops_t3=$(jq -r ".bdevs[] | select(.name == \"barep2\") | .num_read_ops" /tmp/rd_stats.json)

        #redirector_fio $nbd $bg_io_seconds $bg_io_jobs
        rd_fio_stats_withhash=/tmp/rd_fio_stats_withash.json
        redirector_fio $nbd $bg_io_seconds ${bg_io_jobs} ${bg_io_depth} ${rd_block_size} ${rd_fio_stats_withhash}

        get_iostats > /dev/null
        cp /tmp/rd_th_stats.json /tmp/rd_th_stats_after_withhash.json
        cp /tmp/rd_stats.json /tmp/rd_stats_after_withhash.json
        cp /tmp/rd_hist.json /tmp/rd_hist_after_withhash.json

        fio_read_iops_withhash=$(jq -r 'first(.jobs[]) | .read.iops' ${rd_fio_stats_withhash})
        fio_read_lat_ns_withhash=$(jq -r 'first(.jobs[]) | .read.lat_ns.mean' ${rd_fio_stats_withhash})
        fio_write_iops_withhash=$(jq -r 'first(.jobs[]) | .write.iops' ${rd_fio_stats_withhash})
        fio_write_lat_ns_withhash=$(jq -r 'first(.jobs[]) | .write.lat_ns.mean' ${rd_fio_stats_withhash})
        fio_disk_util_withhash=$(jq -r 'first(.disk_util[] | .util)' ${rd_fio_stats_withhash})
        echo "------- fio stats with hash hint: r/w latency(ns) = ${fio_read_lat_ns_withhash}/${fio_write_lat_ns_withhash}, r/w iops = ${fio_read_iops_withhash}/${fio_write_iops_withhash}"

        # stats after second fio
        read_ops_t4=$(jq -r ".bdevs[] | select(.name == \"rd0\") | .num_read_ops" /tmp/rd_stats.json)
        read_ticks_t4=$(jq -r ".bdevs[] | select(.name == \"rd0\") | .read_latency_ticks" /tmp/rd_stats.json)
        write_ops_t4=$(jq -r ".bdevs[] | select(.name == \"rd0\") | .num_write_ops" /tmp/rd_stats.json)
        write_ticks_t4=$(jq -r ".bdevs[] | select(.name == \"rd0\") | .write_latency_ticks" /tmp/rd_stats.json)
        barep0_read_ops_t4=$(jq -r ".bdevs[] | select(.name == \"barep0\") | .num_read_ops" /tmp/rd_stats.json)
        barep1_read_ops_t4=$(jq -r ".bdevs[] | select(.name == \"barep1\") | .num_read_ops" /tmp/rd_stats.json)
        barep2_read_ops_t4=$(jq -r ".bdevs[] | select(.name == \"barep2\") | .num_read_ops" /tmp/rd_stats.json)

        # Ticks / op for fio with hash hint
        reads_2=`echo "(${read_ops_t4} - ${read_ops_t3})" | bc`
        barep0_reads_2=`echo "(${barep0_read_ops_t4} - ${barep0_read_ops_t3})" | bc`
        barep1_reads_2=`echo "(${barep1_read_ops_t4} - ${barep1_read_ops_t3})" | bc`
        barep2_reads_2=`echo "(${barep2_read_ops_t4} - ${barep2_read_ops_t3})" | bc`
        read_ticks_2=`echo "(${read_ticks_t4} - ${read_ticks_t3})" | bc`
        writes_2=`echo "(${write_ops_t4} - ${write_ops_t3})" | bc`
        write_ticks_2=`echo "(${write_ticks_t4} - ${write_ticks_t3})" | bc`
        ops_2=`echo "${reads_2} + ${writes_2}" | bc`
        ticks_2=`echo "${read_ticks_2} + ${write_ticks_2}" | bc`
        ticks_per_op_2=`echo "scale=6; ${ticks_2} / ${ops_2}" | bc`
        ns_per_op_2=`echo "scale=6; ${ticks_per_op_2} * ${ns_per_tick}" | bc`
        delta_ticks_per_op=`echo "scale=6; ${ticks_per_op_2} - ${ticks_per_op_1}" | bc`
        delta_ns_per_op=`echo "scale=6; ${ns_per_op_2} - ${ns_per_op_1}" | bc`

        echo "----- barep0_reads=${barep0_reads_2}, barep1_reads=${barep1_reads_2}, barep2_reads=${barep2_reads_2} (should be about the same)"
        echo "------------------------ Ticks/op with hash hint = ${ticks_per_op_2} (${ns_per_op_2} nS/op) "
        echo "------------------------ Ticks/op increase with hash hint = ${delta_ticks_per_op} (${delta_ns_per_op} nS/op additional) "

        fio_read_iops_delta=`echo "scale=6; ${fio_read_iops_withhash} - ${fio_read_iops_nohash}" | bc`
        fio_read_lat_ns_delta=`echo "scale=6; ${fio_read_lat_ns_withhash} - ${fio_read_lat_ns_nohash}" | bc`
        fio_write_iops_delta=`echo "scale=6; ${fio_write_iops_withhash} - ${fio_write_iops_nohash}" | bc`
        fio_write_lat_ns_delta=`echo "scale=6; ${fio_write_lat_ns_withhash} - ${fio_write_lat_ns_nohash}" | bc`
        fio_disk_util_delta=`echo "scale=6; ${fio_disk_util_withhash} - ${fio_disk_util_nohash}" | bc`
        echo "------- Change in fio stats (with - without hash hint): r/w latency(ns) = ${fio_read_lat_ns_delta}/${fio_write_lat_ns_delta}, r/w iops = ${fio_read_iops_delta}/${fio_write_iops_delta}"

        get_histograms > /dev/null
        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_perf_after_hash
        # channel_ios_drained=$($rpc_py bdev_get_bdevs | jq -r ".[] | select(.product_name == \"redirector\" and .name == \"${redirector_bdev}\") | .driver_specific.redirector.channel_ios_drained")
        # if [ -z $channel_ios_drained ]; then
        #   channel_ios_drained=0
        # fi
        # if [ $channel_ios_drained -eq 0 ]; then
        #   echo "No channel IOs drained"
        #   return -1
        # fi

        nbd_stop_disks $rpc_server $nbd
        count=$(nbd_get_count $rpc_server)
        if [ $count -ne 0 ]; then
            return -1
        fi

        $rpc_py bdev_get_bdevs > /tmp/bdev_get_bdevs_ceph_hash_perf_end

        killprocess $redirector_pid
        echo "############# hash_perf_test ends #############"
    else
        echo "skipping bdev redirector tests."
    fi

    return 0
}

timing_enter vbdev_redirector
trap 'on_error_exit;' ERR

redirector_function_test
multi_redirector_function_test
#nvmf_redirector_function_test
hash_function_test
hint_learning_test
ceph_hash_function_test
ceph_hash_learning_test
ceph_hash_perf_test

rm -f $tmp_file
timing_exit vbdev_redirector
