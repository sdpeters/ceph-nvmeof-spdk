#!/bin/bash
# Get the ADNN hash table (up_primary of each PG) for a given pool
#
# Scott Peterson <scott.d.peterson@intel.com>
#
# Note:
# - need ceph cluster running
# - need jq tool to parse json
#
# usage:
# 	get-pg-table.sh <pool>
#

# Set this to "-c <your ceph.conf>" to override default
: ${CEPH_CONF:=""}

: ${POOL:=rbd}

if [ ! -z $1 ]; then
    POOL=$1
fi

ceph ${CEPH_CONF} pg ls-by-pool ${POOL} -f json-pretty | jq "{ pool: \"${POOL}\", num_pgs: (.pg_stats | length), pgs: [(.pg_stats[].up_primary)] }"
