#!/bin/bash

IP=$1
TYPE=$2

BASE="/
/time
/description.xml
/cloud
/connectivity
/connectivity/events
/device-info
/device-settings
/dashboard
/mode
/firmware
/logging 
/wifi 
/wifi/scan"

DOSE="/head/1/settings
/head/2/settings
/head/3/settings
/head/4/settings
/daily-log
/dosing-queue
/supplement
/head/1/supplement-volume
/head/2/supplement-volume
/head/3/supplement-volume
/head/4/supplement-volume
/export-log"

#MAT
MAT="/configuration
"
#LED
LED="/manual
/acclimation
/moonphase
/current
/timer
/auto/1
/auto/2
/auto/3
/auto/4
/auto/5
/auto/6
/auto/7
/preset_name
/preset_name/1
/preset_name/2
/preset_name/3
/preset_name/4
/preset_name/5
/preset_name/6
/preset_name/7
/clouds/1
/clouds/2
/clouds/3
/clouds/4
/clouds/5
/clouds/6
/clouds/7"

#RUN
RUN="/pump/settings"

#WAV
WAVE="/controlling-mode
/feeding/schedulle"

ping -W 2 -c 1 ${IP} &> /dev/null


case ${TYPE} in
    "DOSE")
	TYPE_EXT=${DOSE}
	;;
    "MAT")
	TYPE_EXT=${MAT}
	;;
    "LED")
	TYPE_EXT=${LED}
	;;
    "RUN")
	TYPE_EXT=${RUN}
	;;
    "WAVE")
	TYPE_EXT=${WAVE}
	;;
    *)
	exit 1
	;;
esac

URLS="${BASE}
${TYPE_EXT}"

[ $? -ne 0 ] && echo "${IP} not alived" && exit 1

for url in ${URLS}
do
    echo ${url}
    dest=${url}
    if [ ${dest} != "/" ]
    then
	dest=`echo ${dest} |cut -c 2-`
	mkdir -p ${dest}
    else
	dest="."
    fi
    wget --quiet -O ${dest}/data http://${IP}${url}
    # Prepare for IP replacement
    sed -i s/"${IP}"/"__REEFBEAT_DEVICE_IP__"/g ${dest}/data
    echo '{"rights":["GET"]}' > ${dest}/access.json
    # Generate a new UUID and friendlyname
    if [ ${dest} == "description.xml" ]
    then
     	sed -i s/'uuid:[0-9a-z\-]*'/'uuid:'`uuidgen`/ ${dest}/data
    fi
done

hw_id=`cat device-info/data |grep -o '"hwid":"[0-9a-f]*"' |cut -d ':' -f 2 |sed s/'"'/''/g`
random=`shuf -i 1-281474976710655 -n 1`
new_hw_id=`echo "obase=16; ${random}" |bc|tr '[:upper:]' '[:lower:]'`
name=`cat device-info/data |grep -o '"name":"[0-9A-Z\-]*"' |cut -d ':' -f 2 |sed s/'"'/''/g`
random=`shuf -i 1-9999999999 -n 1`
#RSLED160-2081858396
new_name="SIMU-"`echo ${name} |sed  s/"\-[0-9]*"/\-${random}/`

echo "Changing name from ${name} to ${new_name}"
echo "Changing serial from ${hw_id} to ${new_hw_id}"
for url in ${URLS}
do
    dest=${url}
    if [ ${dest} != "/" ]
    then
	dest=`echo ${dest} |cut -c 2-`
    else
	dest="."
    fi
    sed -i s/"${hw_id}"/"${new_hw_id}"/g ${dest}/data
    sed -i s/"${name}"/"${new_name}"/g ${dest}/data
done
