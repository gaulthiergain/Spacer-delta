#!/bin/bash

TEST=${1:-1}
SLEEP=30

source "utils.sh"

RESULTDIR="${WORKSPACE_VERSION}/results/memory/"

len=$(file "${UNIKRAFT_APPS}"@v*|wc -l)

compute_memory(){
    local csvfile="$1"
    local method="$2"
    local release="_release"
    local firecracker_bin="firecracker_madvise"
    local uk_config="uk_config"
    
    if [ "$method" == "dce" ]; then
        firecracker_bin="firecracker_madvise${release}"
		uk_config="uk_config_dce"
	elif [ "$method" == "default" ]; then
		firecracker_bin="firecracker_madvise${release}"
		uk_config="uk_config"
    elif [ "$method" == "spacer" ]; then
        firecracker_bin="firecracker_madvise${release}"
        uk_config="uk_config_spacer"
	elif [ "$method" == "delta" ]; then
        firecracker_bin="firecracker_madvise${release}"
        uk_config="uk_config_delta"
    elif [ "$method" == "spacer-slt" ]; then
        firecracker_bin="firecracker${release}"
        uk_config="uk_config_spacer"
		./copy_shm.sh 1 spacer $TEST
	elif [ "$method" == "delta-slt" ]; then
        firecracker_bin="firecracker${release}"
        uk_config="uk_config_delta"
		./copy_shm.sh 1 delta $TEST
    fi

    echo "Running benchmark for $method [$len instances]"
    echo "date,memory_kb" > "$csvfile"
    watch -n 1 smap_rollup_parser -d "$csvfile" -n "${firecracker_bin}" &> /dev/null &

	rm /tmp/instance* &> /dev/null
    for i in $(seq 1 $len)
    do
        ${firecracker_bin} --no-api --config-file "${UNIKRAFT_APPS}@v${i}/${uk_config}_aslr.json" &> "/tmp/instance${i}.log" &
        sleep 10
    done

    sleep "${SLEEP}"
	cat /tmp/instance*
    killall watch smap_rollup_parser &> /dev/null
    killall ${firecracker_bin}
}

do_benchmark(){
    init_ksm_base
    array_method=("dce" "default" "spacer" "spacer-slt" "delta" "delta-slt")
    for method in "${array_method[@]}"; do
        mkdir -p "${RESULTDIR}/memory_$1/"
        compute_memory "${RESULTDIR}/memory_$1/${method}_aslr.csv" "$method"
    done
}

do_benchmark "$TEST"