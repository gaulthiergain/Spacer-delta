#!/bin/bash

WORKSPACE_VERSION="$HOME/versioning"
UNIKRAFT_APPS="${WORKSPACE_VERSION}/apps/applambda"
POOL="${WORKSPACE_VERSION}/dev/firecracker/pool"

CLEAR='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'

STATS="faults,major-faults,minor-faults,cycles,instructions,branches,branch-misses,cache-references,cache-misses"
ID=0

libs=()

PASSWORD="TO_DEFINE"

run_sudo_cmd(){
    echo "$PASSWORD" | sudo -S date > "/dev/null"
}

function init_ksm_base(){
    run_sudo_cmd && echo 1 | sudo tee /sys/kernel/mm/ksm/run
    run_sudo_cmd && echo 100 | sudo tee /sys/kernel/mm/ksm/pages_to_scan
    run_sudo_cmd && echo 20 | sudo tee /sys/kernel/mm/ksm/sleep_millisecs
    run_sudo_cmd && echo 256 | sudo tee /sys/kernel/mm/ksm/max_page_sharing
    run_sudo_cmd && echo 0 | sudo tee /sys/kernel/mm/ksm/use_zero_pages
    run_sudo_cmd && echo "never"|sudo tee /sys/kernel/mm/transparent_hugepage/enabled
}

function clear_cache(){
    run_sudo_cmd && sync
    run_sudo_cmd && echo 3 | sudo tee /proc/sys/vm/drop_caches
}

function disable_ksm(){
    run_sudo_cmd && echo 2 | sudo tee /sys/kernel/mm/ksm/run
    run_sudo_cmd && echo 0 | sudo tee /sys/kernel/mm/ksm/run
}

function get_libs(){
    local t="$1"
    libs=()
    folder_path="${WORKSPACE_VERSION}/tests/test$t/"
    subfolders=($(ls -v1 "$folder_path"))
    for f in "${subfolders[@]}"; do
        if [ -d "$folder_path/$f" ]; then
            libs+=("$(basename "$f")")
        fi
    done
    len=${#libs[@]}
}

function die() {
    echo "$@" >&2
    cp "${UNIKRAFT_APPS}/Makefile.BAK" "${UNIKRAFT_APPS}/Makefile"
    exit 1
}