#!/bin/bash

export ORACLE_HOME=/orahome/app/oracle/product/11.2.0/dbhome_1
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${ORACLE_HOME}/lib

COAM_DIR=/usr/local/etc/coas

/usr/local/bin/coas -p ${COAM_DIR}/coas.pid -c ${COAM_DIR}/coas.conf -f
