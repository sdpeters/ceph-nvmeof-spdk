#!/bin/bash
# Extract the properties of an RBD image for rbd-hash-hint.sh
#
# Yi Zou <yi.zou@intel.com>
#
# Note:
# - need ceph cluster running
# - need jq tool to parse json
#
# Emits JSON containing the image properties, the name of each object in the image,
# and the OSD containing that object as indicated by the ceph osd map command (the
# up primary OSD).
#
# The output also contains the pg table for the pool containing the image (the
# output of get_pg_table.sh) in the field called pg_table.
#
# usage:
# 	rbd-properties-json.sh [<pool>/[<namespace>/]]<image> <output-file>
#

#set -x
# Set this to "-c <your ceph.conf>" to override default
: ${CEPH_CONF:=""}

# -- input is a give RBD image name
IMAGESPEC=$1
OUT=$2
if [ -z $IMAGESPEC ]; then
	echo "Need a rbd image spec"
	exit -1
fi
if [ -z $OUT ]; then
	echo "Need output file"
	exit -1
fi

#IMAGE_SPEC_PARTS=(${IMAGESPEC//\//})
IFS='/'
IMAGE_SPEC_PARTS=($IMAGESPEC)
unset IFS
#echo "IMAGESPEC=${IMAGESPEC}; 0: ${IMAGE_SPEC_PARTS[0]} 1: ${IMAGE_SPEC_PARTS[1]} 2: ${IMAGE_SPEC_PARTS[2]}"

if [ ! -z ${IMAGE_SPEC_PARTS[2]} ]; then
    #echo "spec includes pool/ns"
    POOL=${IMAGE_SPEC_PARTS[0]}
    NS=${IMAGE_SPEC_PARTS[1]}
    IMG=${IMAGE_SPEC_PARTS[2]}
    NSIMG=${NS}/${IMG}
elif [ ! -z ${IMAGE_SPEC_PARTS[1]} ]; then
    #echo "spec includes pool"
    POOL=${IMAGE_SPEC_PARTS[0]}
    IMG=${IMAGE_SPEC_PARTS[1]}
    NSIMG=$IMG
else
    #echo "spec does not specify pool"
    POOL=rbd
    IMG=${IMAGE_SPEC_PARTS[0]}
    NSIMG=$IMG
fi

# -- we use these commands from ceph
CMDRBD="rbd ${CEPH_CONF}"
CMDMAP="ceph ${CEPH_CONF} osd map ${POOL}"
CMDSTATUS="ceph ${CEPH_CONF} status"

tempfile=$(mktemp)
tempfile2=$(mktemp)
pgfile=$(mktemp)
osdfile=$(mktemp)
trap 'rm -f $tempfile2 $pgfile osdfile' EXIT

echo "{" > $tempfile
echo "\"pool\":\"${POOL}\"," >> $tempfile

# Fail if image doesn't exist
${CMDRBD} info ${IMAGESPEC} > /dev/null
if [ $? != 0 ]; then
    exit -1
fi

CLUSTER_NAME=`ceph-conf ${CEPH_CONF} -D | grep "^cluster =" | awk '{print $3}'`
echo "\"cluster\":\"${CLUSTER_NAME}\"," >> $tempfile

CLUSTER_FSID=`${CMDSTATUS} --format json | jq -r ".fsid"`
echo "\"cluster_fsid\":\"${CLUSTER_FSID}\"," >> $tempfile

OSDMAP_EPOCH=`${CMDSTATUS} --format json | jq -r ".osdmap.osdmap.epoch"`
echo "\"osdmap_epoch\":\"${OSDMAP_EPOCH}\"," >> $tempfile

./set-image-nguid.sh ${IMAGESPEC}
LN_NGUID=`./get-image-nguid.sh ${IMAGESPEC}`
echo "\"ln_nguid\":\"${LN_NGUID}\"," >> $tempfile

# -- use rbd and jq to get important fields
KEYS="name id size objects object_size block_name_prefix"
declare -A RBDIMG
for key in ${KEYS}
do
	RBDIMG[${key}]=`${CMDRBD} info ${IMAGESPEC} --format json | sed -n '/^{/,$p' | jq -r ".${key}"`
	echo "\"${key}\":\"${RBDIMG[${key}]}\"," >> $tempfile
done

# get max lbas
let "maxlbas=${RBDIMG[size]}/512"
let "extlbas=${RBDIMG[size]}%512"
let "maxlbas=${maxlbas}+${extlbas}"
RBDIMG[maxlbas]=${maxlbas}
echo "\"maxlbas\":\"${RBDIMG[maxlbas]}\"," >> $tempfile
echo "Input=${IMGSPEC} OUT=${OUT} Total size=${RBDIMG[size]} Total LBAs=${RBDIMG[maxlbas]}"

# -- list all data objects
echo "\"objects\": [" >> $tempfile

echo "]" >> $tempfile

echo "}" >> $tempfile

./get-pg-table.sh $POOL > $pgfile

./get-osd-hosts.sh > $osdfile

# Prettify and remove useless stuff from all the "osd map ..." JSON objects
jq < $tempfile 'del(.objects[].epoch) | del (.objects[].raw_pgid) | del (.objects[].pgid) | del(.objects[].pool) | del(.objects[].pool_id) | del(.objects[].acting_primary) | del(.objects[].acting) | del(.objects[].up)' | jq --argjson pg_table "$(<$pgfile)" '. + { pg_table: ($pg_table) }' > $tempfile2
mv $tempfile2 $tempfile

cat $tempfile | jq --argjson osd_hosts "$(<$osdfile)" '. + { osd_hosts: ($osd_hosts) }' > $tempfile2

# Drop (empty) objects array (if any), and add num_objects
jq --argjson num_objects ${RBDIMG[objects]} < $tempfile2 '.  + { num_objects: ($num_objects) } | del(.objects)' > ${OUT}

rm -f $tempfile $tempfile2 $pgfile $osdfile
