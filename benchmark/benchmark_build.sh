#!/bin/bash
TEST=${1:-1}
ASLR=${2:-0}
PERF=${3:-0}
RESET=1

source "utils.sh"
cd "${WORKSPACE_VERSION}/scripts/script_version" || die "cd 'script_version' failed"

if [ $RESET -eq 1 ]; then
	rm -f /dev/shm/* &> /dev/null
	rm -rf "${WORKSPACE_VERSION}"/apps/applambda@v* &> /dev/null

	./build.sh --build ${TEST} --perf ${PERF} || die "build.sh build failed"
	./build.sh --merge-only ${TEST} || die "build.sh merge failed"
fi
./build.sh --align ${TEST} || die "build.sh align failed"
if [ $ASLR -eq 1 ]; then
	rm -f /dev/shm/* &> /dev/null
	./build_aslr.sh --build ${TEST} || die "build_aslr.sh failed"
	./build_aslr.sh --align ${TEST} || die "build_aslr.sh align failed"
	exit 0
fi