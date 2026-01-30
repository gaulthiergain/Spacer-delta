#!/bin/bash

#USED AS ITERATIVE V0, then V1 then V2 ... ON DIFFERENT CORES
TEST=${1:-1}
ASLR=${2:-0}
CORE=31

source "utils.sh"

RESULTDIR="${WORKSPACE_VERSION}/results/perf_others"

len=$(file "${UNIKRAFT_APPS}"@v*|wc -l)

perform_test(){
    local file="$1"
    local method="$2"
    local is_aslr="$3"
    local release="_release"
    local firecracker_bin="firecracker_madvise${release}"
    local uk_config="uk_config"
    
    init_ksm_base
    if [ "$method" == "dce" ]; then
		uk_config="uk_config_dce"
	elif [ "$method" == "default" ]; then
		uk_config="uk_config"
    elif [ "$method" == "spacer" ]; then
        uk_config="uk_config_spacer"
	elif [ "$method" == "delta" ]; then
        uk_config="uk_config_delta"
    elif [ "$method" == "spacer-slt" ]; then
        firecracker_bin="firecracker${release}"
        uk_config="uk_config_spacer"
		${WORKSPACE_VERSION}/scripts/utils/copy_shm.sh $is_aslr spacer $TEST
		disable_ksm
	elif [ "$method" == "delta-slt" ]; then
        firecracker_bin="firecracker${release}"
        uk_config="uk_config_delta"
		${WORKSPACE_VERSION}/scripts/utils/copy_shm.sh $is_aslr delta $TEST
		disable_ksm
    fi

    if [ "$is_aslr" == "1" ]; then
        uk_config="${uk_config}_aslr"
        file="${file}_aslr"
    fi

    echo "Running benchmark for $method [$len instances]"

    for i in $(seq 1 $len); do
        cp "${UNIKRAFT_APPS}@v${i}/${uk_config}.json" "${UNIKRAFT_APPS}@v${i}/${uk_config}_loop.json"
        sed -i "s/-- perf/-- /g" "${UNIKRAFT_APPS}@v${i}/${uk_config}_loop.json"
    done

    i_m1=0
    for i in $(seq 1 $len); do
        truncate -s 0 /tmp/logger "${file}_${i}.txt" "${file}_logger_${i}.txt"
        for _ in $(seq 1 30); do

            # RUN previous instance 10-14
            for j in $(seq 1 $i_m1); do
                ${firecracker_bin} --no-api --config-file "${UNIKRAFT_APPS}@v${j}/${uk_config}_loop.json" &> /dev/null &
                sleep 0.1
            done

            sleep 1
            ps -aux | grep ${firecracker_bin}|wc -l
            taskset -c "$CORE" perf stat -d -e "$STATS" ${firecracker_bin} --boot-timer --level "debug" --log-path "/tmp/logger" --no-api --config-file "${UNIKRAFT_APPS}@v${i}/${uk_config}.json" &>> "${file}_${i}.txt"
            echo "${firecracker_bin} --config-file ${UNIKRAFT_APPS}@v${i}/${uk_config}.json" >> "${file}_logger_${i}.txt"
            cat /tmp/logger >> "${file}_logger_${i}.txt"

            killall ${firecracker_bin} &> /dev/null
        done

        i_m1=$i
    done

}


do_benchmark(){
    init_ksm_base
    array_method=("dce" "default" "spacer" "spacer-slt" "delta" "delta-slt")
    for method in "${array_method[@]}"; do
        clear_cache
        mkdir -p "${RESULTDIR}/perf_$1/"
        perform_test "${RESULTDIR}/perf_$1/${method}" "$method" "$ASLR"
    done
}

do_benchmark "$TEST" "$ASLR"
