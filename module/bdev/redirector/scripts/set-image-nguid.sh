#!/bin/bash
# Assigns a ADNN LN NGUID to an RBD image if it doesn't already have one
#
# Scott Peterson <scott.d.peterson@intel.com>
#
# usage:
# 	set-image-nguid.sh <imagespec> [<nguid>]
#

LN_NGUID_KEY="nemo_ln_nguid"
IMAGESPEC=$1
NGUID=`uuidgen`

if [ -z $1 ]; then
    echo "Need image spec"
    exit -1
fi

if [ ! -z $2 ]; then
    NGUID=$2
fi

EXISTING_NGUID=`./get-image-nguid.sh ${IMAGESPEC}`

if [ -z $EXISTING_NGUID ]; then
    rbd image-meta set ${IMAGESPEC} ${LN_NGUID_KEY} ${NGUID}
fi
