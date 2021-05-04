#!/bin/bash
#
# Transform an rbd-properties file (the output of rbd-roperties-json.sh) into an ADNN hash hint
#
# Scott Peterson <scott.d.peterson@intel.com>
#
# usage:
# 	rbd-hash-hint.sh <rbd-properties file> <nqn format string>
#
# The hash hint JSON file is intended to be consumed by a redirector, so will have a simplified
# structure.
#
# The <nqn format string> looks like 'nqn.2019-11-14.com.intel.nemo:%s-rdma', where %s is replaced by the
# OSD host name (lower case).
#
# The properties file refers to OSDs with their OSD number in the Ceph cluster they were recorded
# from. Those aren't necessarily contiguous for a nunmber of reasons (some OSDs may have been removed,
# or the RBD image may just be in an OSD pool that's a subset of all the cluster's OSDs).
#
# The hash hint contains a hash table. The buckets in that hash table correspond 1:1 with PG map entries.
# Each bucket will refer to the NQN of of the ADNN/Ceph egress redirector (NVMe-oF target) on the same
# node as the up primary OSD of the PG referred to by its corresponding PG map entry.
#
# We'll produce a table of these NQNs, and the hash table buckets will each contain an index into that
# NQN table. These indexes will start at zero.
#
# The hash hint file contains:
#
# {
#   label: {
#     name: <RBD image name>,
#     cluster: <Name of Ceph cluster>
#     cluster_fsid: <Unique ID of Ceph cluster>
#     osdmap_epoch: <epoch # of OSD map when this was captured>
#     pool: <RBD pool name>,
#     namespace: <RADOS namespace, if any>,
#     id: <RBD image ID>,
#     update: {
#       host_nqn_format: <nqn format string>,
#       host_table: [ <array of hostnames in NQN table order> ]
#     }
#   },
#   ln_nguid: <LN NGUID>,
#   ns_bytes: <NS size in bytes>,
#   object_bytes: <object size in bytes>,
#   object_name_format: <object name format string>,
#   hash_fn: "ceph_rjenkins",
#   nqn_table : [ <array of NQN strings> ],
#   hash_table : [ <array of integers> ],
# }
#
# The redirector will ignore everything in "label". That's for humans, or the script that updates
# the hint.
#
# TODO: accept an arg for a JSON file with an arbitrary mapping of hostnames to NQNs
#
# TODO: Extend OSD to NQN mapping mechanism for servers with OSDs and NICs in multiple NUMA nodes (map
# each OSD to the NIC / NQN in the same NUMA node).
#

IMAGE_PROPERTIES_FILE=$1
HOST_NQN_FORMAT=$2
if [ -z $IMAGE_PROPERTIES_FILE ]; then
	echo "Need RBD image properties file"
	exit -1
fi
if [ -z $HOST_NQN_FORMAT ]; then
	echo "Need OSD host NQN format string"
	exit -1
fi

#set -x
TEST_NQN=`printf ${HOST_NQN_FORMAT} test_hostname`
if [ $? != 0 ]; then
    echo "Bad host NQN format string"
    exit -1
fi

NQN_PARTS_STR=`printf ${HOST_NQN_FORMAT} " "`
if [ $? != 0 ]; then
    echo "Bad host NQN format string"
    exit -1
fi
NQN_PARTS=($NQN_PARTS_STR)

#KEYS="name pool id size object_size block_name_prefix bogus"
KEYS="name pool id size object_size block_name_prefix cluster cluster_fsid osdmap_epoch ln_nguid"
declare -A RBDIMG
for key in ${KEYS}
do
	RBDIMG[${key}]=`jq -r ". | select(.${key} != null) | .${key}" < ${IMAGE_PROPERTIES_FILE}`

	#echo "\"${key}\":\"${RBDIMG[${key}]}\""
    if [ -z ${RBDIMG[${key}]} ]; then
        echo "Bad properties file"
        exit -1
    fi
done

OPTIONAL_KEYS="namespace"
for key in ${OPTIONAL_KEYS}
do
	RBDIMG[${key}]=`jq -r ". | select(.${key} != null) | .${key}" < ${IMAGE_PROPERTIES_FILE}`
done

OBJ_FORMAT_STRING="${RBDIMG[block_name_prefix]}.%016x"
if [ ! -z ${RBDIMG[namespace]} ]; then
    OBJ_FORMAT_STRING_END=${OBJ_FORMAT_STRING}
    # Avoid putting OBJ_FORMAT_STRING in bash printf format string
    OBJ_FORMAT_STRING=$(printf "${RBDIMG[namespace]}\037%s" "${OBJ_FORMAT_STRING_END}")
fi

tempout=$(mktemp)
tempin=$(mktemp)
osd_to_host="$(mktemp)_osd_to_host"
osd_to_host_index="$(mktemp)_osd_to_host_index"
host_nqns="$(mktemp)_host_nqns"
host_table="$(mktemp)_host_table"
nqn_table="$(mktemp)_nqn_table"
hash_table="$(mktemp)_hash_table"
trap 'rm -f $tempout $tempin $osd_to_host $osd_to_host_index $host_nqns $host_table $nqn_table $hash_table' EXIT

# Extract osd to host map, and make hostnames uniformly lower case. If we used >1 target per
# OSD node, the values here would identify the target within the host (or use hostnames with suffixes,
# e.g. "<numanode>.<hostname>.<domain>")
jq '(.osd_hosts |.[] |= ascii_downcase)' < ${IMAGE_PROPERTIES_FILE} > $osd_to_host
#cat $osd_to_host

# Generate unique host (/ADNN target) table. If there were multiple targets per OSD node, they'd all
# be listed here.
jq 'to_entries | map( {(.value) : null } ) | add | [ (keys[] as $k | ($k)) ]' < $osd_to_host > $host_table
#cat $host_table

# Generate OSD number to host index table
jq --argjson host_table "$(<$host_table)" 'def hostindex($hostname): ($host_table | index($hostname)); to_entries | map_values(.value = hostindex(.value)) | from_entries' < $osd_to_host > $osd_to_host_index
#cat $osd_to_host_index

# Translate PG table entries from up primary OSD # to host table index. This is the hash table for the hint.
jq --argjson osd_to_host_index "$(<$osd_to_host_index)" 'def hostindex($osd): ($osd_to_host_index | to_entries | .[] | select(.key==("osd" + $osd)) | .value); .pg_table.pgs |  [ .[] | hostindex(tostring) ]' < ${IMAGE_PROPERTIES_FILE} > $hash_table
#head -10 $hash_table
#tail -10 $hash_table

# Generate map of unique OSD hostnames to their corresponding NQNs
jq --arg nqn_prefix "${NQN_PARTS[0]}" --arg nqn_suffix "${NQN_PARTS[1]}" 'to_entries | map( {(.value) : ($nqn_prefix + .value + $nqn_suffix) } ) | add' < $osd_to_host > $host_nqns
#cat $host_nqns

# Generate NQN table
jq --arg nqn_prefix "${NQN_PARTS[0]}" --arg nqn_suffix "${NQN_PARTS[1]}" '[ (.[] | ($nqn_prefix + . + $nqn_suffix) ) ]' < $host_table > $nqn_table
#cat $nqn_table

#set -x
jq -n \
   --arg cluster ${RBDIMG[cluster]} \
   --arg cluster_fsid ${RBDIMG[cluster_fsid]} \
   --argjson osdmap_epoch ${RBDIMG[osdmap_epoch]} \
   --arg name ${RBDIMG[name]} \
   --arg id ${RBDIMG[id]} \
   --arg pool ${RBDIMG[pool]} \
   --arg host_nqn_format ${HOST_NQN_FORMAT} \
   --arg ln_nguid ${RBDIMG[ln_nguid]} \
   --argjson ns_bytes ${RBDIMG[size]} \
   --argjson object_bytes ${RBDIMG[object_size]} \
   --arg object_name_format ${OBJ_FORMAT_STRING} \
   "{\
        \"label\": { \
                   \"name\": \$name , \
                   \"cluster\": \$cluster , \
                   \"cluster_fsid\": \$cluster_fsid , \
                   \"osdmap_epoch\": \$osdmap_epoch , \
                   \"id\": \$id , \
                   \"pool\": \$pool, \
                   \"update\": { \
                               \"host_nqn_format\": \$host_nqn_format, \
                   } \
        }, \
        \"ln_nguid\": \$ln_nguid, \
        \"ns_bytes\": \$ns_bytes, \
        \"object_bytes\": \$object_bytes, \
        \"object_name_format\": \$object_name_format, \
        \"hash_fn\": \"ceph_rjenkins\", \
   }" > $tempout
#cat $tempout
mv $tempout $tempin

if [ ! -z ${RBDIMG[namespace]} ]; then
    jq --arg namespace ${RBDIMG[namespace]} '. | .label=(.label + { namespace: $namespace } )' < $tempin > $tempout
    mv $tempout $tempin
fi

# Insert host table (in .label.update), nqn table, and hash tablle from files
jq \
   '. | .label.update=(.label.update + { host_table: (input) } ) | . + { nqn_table: (input) } | . + { hash_table: (input) }' $tempin $host_table $nqn_table $hash_table > $tempout

# Emit result
cat $tempout
