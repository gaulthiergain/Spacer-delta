#!/bin/bash


TEST=${1:-1}

source "utils.sh"

RESULTDIR="${WORKSPACE_VERSION}/results/filesize/"
POOL="${WORKSPACE_VERSION}/dev/firecracker/pool"

len=$(file "${UNIKRAFT_APPS}"@v*|wc -l)
echo "Number of instances: $len"

compute_filesize(){
    local csvfile="$1"
    local method="$2"
    local suffix="$3"
    local uk_name=""
    local total=0

	if [ "$method" == "default" ]; then
		uk_name="app-lambda_kvmfc-x86_64"
    elif [ "$method" == "dce" ]; then
        uk_name="app-lambda_kvmfc-x86_64_dce"
    elif [ "$method" == "spacer" ]; then
        uk_name="unikernel_kvmfc-x86_64_spacer"
	elif [ "$method" == "delta" ]; then
		uk_name="unikernel_kvmfc-x86_64_local_align"
    fi

    for i in $(seq 1 $len)
    do
        size=$(du -s "${UNIKRAFT_APPS}@v${i}/build/${uk_name}${suffix}" | awk '{print $1}')
        total=$((total+size))
    done
    echo "$total,$len" >> "$csvfile"
}

compute_filesize_delta_slt(){
    local csvfile="$1"
    local suffix="$2"
    local total=0
    local total_size_bin=0
	local total_size_sec=0
    for i in $(seq 1 $len)
    do
        if [ "$suffix" == "_aslr" ]; then
            size=$(du -s "${UNIKRAFT_APPS}@v${i}/build/unikernel_kvmfc-x86_64_local_align${suffix}_update" | awk '{print $1}')
        else
            size=$(du -s "${UNIKRAFT_APPS}@v${i}/build/unikernel_kvmfc-x86_64_local_align${suffix}.data" | awk '{print $1}')
            for j in $(seq 1 $len); do
                if [ -f "${UNIKRAFT_APPS}@v${i}/build/unikernel_kvmfc-x86_64_local_align${suffix}.ind.lib-lambda-v${j}" ]; then
                    value=$(du -s "${UNIKRAFT_APPS}@v${i}/build/unikernel_kvmfc-x86_64_local_align${suffix}.ind.lib-lambda-v${j}" | awk '{print $1}')
                    size=$(( size + value ))
                fi                
            done
        fi
        size_sec=$(du -s "${UNIKRAFT_APPS}@v${i}/build/unikernel_kvmfc-x86_64_local_align${suffix}.sec" | awk '{print $1}')
		total_size_bin=$((total_size_bin+size))
		total_size_sec=$((total_size_sec+size_sec))
    done
	if [ "$method" == "spacer-slt" ]; then
		pool=$(du -s "${POOL}_spacer${suffix}" | awk '{print $1}')
	else
		pool=$(du -s "${POOL}${suffix}" | awk '{print $1}')
	fi
    all=$((total_size_bin+total_size_sec+pool))
    echo "$total_size_bin,$total_size_sec,$pool,$all,$len" >> "$csvfile"
}

compute_filesize_spacer_slt(){
    local csvfile="$1"
    local suffix="$2"
    local total=0
    local total_size_bin=0
	local total_size_sec=0
    for i in $(seq 1 $len)
    do
        if [ "$suffix" == "_aslr" ]; then
            size=$(du -s "${UNIKRAFT_APPS}@v${i}/build/unikernel_kvmfc-x86_64_spacer${suffix}_update" | awk '{print $1}')
        else
            size=$(du -s "${UNIKRAFT_APPS}@v${i}/build/unikernel_kvmfc-x86_64_spacer${suffix}.data" | awk '{print $1}')
        fi
        size_sec=$(du -s "${UNIKRAFT_APPS}@v${i}/build/unikernel_kvmfc-x86_64_spacer${suffix}.sec" | awk '{print $1}')
		total_size_bin=$((total_size_bin+size))
		total_size_sec=$((total_size_sec+size_sec))
    done
	if [ "$method" == "spacer-slt" ]; then
		pool=$(du -s "${POOL}_spacer${suffix}" | awk '{print $1}')
	else
		pool=$(du -s "${POOL}${suffix}" | awk '{print $1}')
	fi
    all=$((total_size_bin+total_size_sec+pool))
    echo "$total_size_bin,$total_size_sec,$pool,$all,$len" >> "$csvfile"
}

do_benchmark(){
    local test="$1"
    local use_aslr="$2"
    suffix=""
    if [ $use_aslr -eq 1 ]; then
        suffix="_aslr"
    fi
    array_method=("dce" "default" "spacer" "spacer-slt" "delta" "delta-slt")
    for method in "${array_method[@]}"; do
        mkdir -p "${RESULTDIR}/filesize_$1/"
        if [ "$method" == "delta-slt" ]; then
            echo "binary_size,sec,pool,size,instances" > "${RESULTDIR}/filesize_${test}/${method}${suffix}.csv"
            compute_filesize_delta_slt "${RESULTDIR}/filesize_${test}/${method}${suffix}.csv" "$suffix"
        elif [ "$method" == "spacer-slt" ]; then
			echo "binary_size,sec,pool,size,instances" > "${RESULTDIR}/filesize_${test}/${method}${suffix}.csv"
			compute_filesize_spacer_slt "${RESULTDIR}/filesize_${test}/${method}${suffix}.csv" "$suffix"
		else
            echo "size,instances" > "${RESULTDIR}/filesize_${test}/${method}${suffix}.csv"
            compute_filesize "${RESULTDIR}/filesize_${test}/${method}${suffix}.csv" "$method" "$suffix"
        fi
    done
}

do_benchmark "$TEST" 0
do_benchmark "$TEST" 1