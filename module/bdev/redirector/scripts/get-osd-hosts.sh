#!/bin/bash
# Get the hostname corresponding to every OSD in the cluster
#
# Scott Peterson <scott.d.peterson@intel.com>
#
# Note:
# - need ceph cluster running
# - need jq tool to parse json
#
# usage:
# 	get-osd-hosts.sh <pool>
#

# Set this to "-c <your ceph.conf>" to override default
: ${CEPH_CONF:=""}

tempfile=$(mktemp)
osdlist=$(mktemp)
trap 'rm -f $tempfile $osdlist' EXIT

ceph ${CEPH_CONF} osd ls --format json-pretty > $osdlist

#set -x
NUM_OSDS=`jq -r ". | length" < ${osdlist}`

echo "{" > $tempfile
for ((i =0; i < ${NUM_OSDS}; i++))
do
    if [ "$i" -ne "0" ]; then
		echo "," >> $tempfile
	fi

    OSDNUM=`jq -r ".[${i}]" < ${osdlist}`
    OSDHOST=`ceph ${CEPH_CONF} osd find ${OSDNUM} --format json-pretty | jq -r ".host"`

    echo "\"osd${OSDNUM}\": \"${OSDHOST}\"" >> $tempfile
done
echo "}" >> $tempfile

jq . < $tempfile
rm $tempfile $odslist
