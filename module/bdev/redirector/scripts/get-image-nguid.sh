#!/bin/bash
# Returns the image NGUID, or fails i there isn't one
#
# Scott Peterson <scott.d.peterson@intel.com>
#
# usage:
# 	get-image-nguid.sh <imagespec>
#

LN_NGUID_KEY="nemo_ln_nguid"
IMAGESPEC=$1

if [ -z $1 ]; then
    echo "Need image spec"
    exit -1
fi

tempfile=$(mktemp)
tempfile2=$(mktemp)
trap 'rm -f $tempfile $tempfile2' EXIT

rbd image-meta list ${IMAGESPEC} --format json > $tempfile
if [ $? != 0 ]; then
    exit -1
fi

sed -n '/^{/,$p' < $tempfile > $tempfile2

EXISTING_NGUID=`jq -r ". | select(.${LN_NGUID_KEY} != null) | .${LN_NGUID_KEY}" < ${tempfile2}`

if [ -z $EXISTING_NGUID ]; then
    exit -1
fi

echo $EXISTING_NGUID
