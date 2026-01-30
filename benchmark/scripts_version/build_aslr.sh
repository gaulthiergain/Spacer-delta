#!/bin/bash
libs=()
source "../utils.sh"

MERGED="${WORKSPACE_VERSION}/merged"

PERF_TEST=0

build(){
	echo "***** (2) Building with ASLR *****"
    TEST="$1"
    rm -rf "${WORKSPACE_VERSION}"/libs/lib-lambda-v* &> /dev/null
	rm -f "/dev/shm/aslr"*
	rm -f "/dev/shm/lib"*
    current=$PWD

    get_libs "$TEST"

    cp -r "${WORKSPACE_VERSION}/tests/test${TEST}"/. "${WORKSPACE_VERSION}/libs/"|| die "cp failed"
	rm "${POOL}_aslr" &> /dev/null
	mkdir -p "${POOL}_aslr" || die "mkdir pool_aslr failed"
	
	#Build Default (prepare, not final)
	for lib in "${libs[@]}"
    do
		local version=$(echo "$lib" | cut -d'-' -f3)
		cd "${UNIKRAFT_APPS}@${version}" || die "cd failed"
		mv build/app-lambda_kvmfc-x86_64 build/app-lambda_kvmfc-x86_64_default || die "mv default failed"
		sed -i "s/lib-lambda-v1/$lib/g" Makefile
		rm build/applambda.o build/liblambda.o build/liblambda.ld.o build/lib-lambda-v* build/liblambda-v* &> /dev/null
		make -j$(nproc) &> /dev/null
		mv build/applambda.o "build/applambda-${version}.o" || die "mv applambda.o failed"
		mv build/liblambda.o "build/liblambda-${version}.o" || die "mv liblambda.o failed"
	done
	cd "${WORKSPACE_VERSION}/aligner_old" || die "cd 'aligner_old' failed"
	if [ "$TEST" -eq 24 ] || [ "$TEST" -eq 27 ]; then
		echo "Running randomize with initrd for test 24 or 27"
		./runner.sh --use_aslr  --nb_unikernels "$len" --randomize --use_initrd || die "runner.sh randomize dce failed"
	else
		echo "Running randomize without initrd for other tests"
		./runner.sh --use_aslr  --nb_unikernels "$len" --randomize &> /dev/null || die "runner.sh randomize dce failed"
	fi
	
	#Build DCE
    for lib in "${libs[@]}"
    do
		local version=$(echo "$lib" | cut -d'-' -f3)
		cd "${UNIKRAFT_APPS}@${version}" || die "cd failed"

		echo "Making $lib"
		rm build/liblambda.o build/liblambda.ld.o build/lib-lambda-v* build/liblambda-v* &> /dev/null

		sed -i "s/lib-lambda-v1/$lib/g" Makefile

        sed -i 's/# CONFIG_OPTIMIZE_DEADELIM is not set/CONFIG_OPTIMIZE_DEADELIM=y/g' .config || die "sed failed"
        make clean &> /tmp/error.txt || (cat /tmp/error.txt && die "make clean failed")
		make -j$(nproc) &>> /tmp/error.txt || (cat /tmp/error.txt && die "make 2 failed")
		if [ -f "${WORKSPACE_VERSION}/libs/$lib/script.sh" ]; then
			sh ${WORKSPACE_VERSION}/libs/$lib/script.sh
			make &> /tmp/error.txt || (cat /tmp/error.txt && die "make 3 failed")
		fi
		mv build/liblambda.o "build/liblambda-${version}.o" || die "mv liblambda.o failed"
		mv build/applambda.o "build/applambda-${version}.o" || die "mv applambda.o failed"
		
	done

	cd "${WORKSPACE_VERSION}/aligner_old" || die "cd 'aligner_old' failed"
	len=$(file "${UNIKRAFT_APPS}"@v*|wc -l)
	if [ "$TEST" -eq 24 ] || [ "$TEST" -eq 27 ]; then
		echo "Running randomize with initrd for test 24 or 27"
		./runner.sh --use_aslr  --nb_unikernels "$len" --randomize  --use_dce --use_initrd || die "runner.sh randomize dce failed"
	else
		echo "Running randomize without initrd for other tests"
		./runner.sh --use_aslr  --nb_unikernels "$len" --randomize  --use_dce || die "runner.sh randomize dce failed"
	fi	
	
	#Build Default and create ASLR configs
	for lib in "${libs[@]}"
    do

		local version=$(echo "$lib" | cut -d'-' -f3)
		cd "${UNIKRAFT_APPS}@${version}" || die "cd failed"

        sed -i 's/CONFIG_OPTIMIZE_DEADELIM=y/# CONFIG_OPTIMIZE_DEADELIM is not set/g' .config || die "sed failed"
        make clean &> /tmp/error.txt || (cat /tmp/error.txt && die "make clean failed")
		make -j$(nproc) &> /tmp/error.txt || (cat /tmp/error.txt && die "make 4 failed")
		if [ -f "${WORKSPACE_VERSION}/libs/$lib/script.sh" ]; then
			sh ${WORKSPACE_VERSION}/libs/$lib/script.sh
			make &> /tmp/error.txt || (cat /tmp/error.txt && die "make 5 failed")
		fi

		mv build/applambda.o "build/applambda-${version}.o" || die "mv applambda.o failed"
		mv build/app-lambda_kvmfc-x86_64_default build/app-lambda_kvmfc-x86_64 || die "mv def failed"
		mv build/liblambda.o "build/liblambda-${version}.o" || die "mv liblambda.o failed"

		echo "Creating ASLR configs for $lib"

		cat "${UNIKRAFT_APPS}@${version}/uk_config.json" > /tmp/uk_config_tmp.json

		# Spacer (base)
		cp "${UNIKRAFT_APPS}@${version}/uk_config.json" "${UNIKRAFT_APPS}@${version}/uk_config_spacer_aslr.json"
		sed -i "s:app-lambda_kvmfc-x86_64:unikernel_kvmfc-x86_64_spacer_aslr:g" "${UNIKRAFT_APPS}@${version}/uk_config_spacer_aslr.json"

		# Spacer (Delta)
		cp "${UNIKRAFT_APPS}@${version}/uk_config.json" "${UNIKRAFT_APPS}@${version}/uk_config_delta_aslr.json"
		sed -i "s:app-lambda_kvmfc-x86_64:unikernel_kvmfc-x86_64_local_align_aslr:g" "${UNIKRAFT_APPS}@${version}/uk_config_delta_aslr.json"

		# DCE
		cp "${UNIKRAFT_APPS}@${version}/uk_config.json" "${UNIKRAFT_APPS}@${version}/uk_config_dce_aslr.json"
    	sed -i "s:app-lambda_kvmfc-x86_64:app-lambda_kvmfc-x86_64_dce_aslr:g" "${UNIKRAFT_APPS}@${version}/uk_config_dce_aslr.json"

		# Default 
		sed -i "s/lib-lambda-v1/lib-lambda-${version}/g" "${UNIKRAFT_APPS}@${version}/Makefile"
		cp "${UNIKRAFT_APPS}@${version}/uk_config.json" "${UNIKRAFT_APPS}@${version}/uk_config_aslr.json"
    	sed -i "s:app-lambda_kvmfc-x86_64:app-lambda_kvmfc-x86_64_aslr:g" "${UNIKRAFT_APPS}@${version}/uk_config_aslr.json"
		
        sed -i "s/$lib/lib-lambda-v1/g" Makefile
    done

	len=$(file "${UNIKRAFT_APPS}"@v*|wc -l)
	cd "${WORKSPACE_VERSION}/aligner_old" || die "cd 'aligner_old' failed"
	
	#Spacer ASLR
	if [ "$TEST" -eq 24 ] || [ "$TEST" -eq 27 ]; then
		echo "Aligning with Spacer (vanilla) - with initrd"
		./runner.sh --use_aslr --nb_unikernels "$len" --aligner --use_initrd  || die "runner.sh aligner failed"
	else
		echo "Aligning with Spacer (vanilla) - no initrd"
    	./runner.sh --use_aslr --nb_unikernels "$len" --aligner || die "runner.sh aligner failed"
	fi
	./runner.sh --use_aslr --nb_unikernels "$len" --checker || die "runner.sh checker failed"
	./runner.sh --use_aslr --nb_unikernels "$len" --dump_json --minifier --extractor &> /dev/null || die "runner.sh slt failed"

	#last step for Spacer delta
	for lib in "${libs[@]}"
    do
		local version=$(echo "$lib" | cut -d'-' -f3)
		rm "${UNIKRAFT_APPS}@${version}/build/liblambda-${version}.o" || die "rm liblambda-${version}.o failed"
		mv "${UNIKRAFT_APPS}@${version}/build/unikernel_kvmfc-x86_64_local_align_aslr" "${UNIKRAFT_APPS}@${version}/build/unikernel_kvmfc-x86_64_spacer_aslr"
		mv "${UNIKRAFT_APPS}@${version}/build/unikernel_kvmfc-x86_64_local_align_aslr.dbg" "${UNIKRAFT_APPS}@${version}/build/unikernel_kvmfc-x86_64_spacer_aslr.dbg"
		mv "${UNIKRAFT_APPS}@${version}/build/unikernel_kvmfc-x86_64_local_align_aslr_update" "${UNIKRAFT_APPS}@${version}/build/unikernel_kvmfc-x86_64_spacer_aslr_update"
		mv "${UNIKRAFT_APPS}@${version}/build/unikernel_kvmfc-x86_64_local_align_aslr.sec" "${UNIKRAFT_APPS}@${version}/build/unikernel_kvmfc-x86_64_spacer_aslr.sec"

		if [[ "$TEST" -eq 24 ]] || [[ "$TEST" -eq 27 ]]; then
			echo "Running rm liblambda_extensions for test 24 or 27"
			rm "${UNIKRAFT_APPS}@${version}/build/liblambda_extensions"* &> /dev/null
		fi
		cd "${UNIKRAFT_APPS}@${version}/" || die "cd failed"
		rm build/*.o build/*.ld.o &> /dev/null
		cp "/tmp/versioning/${version}/build/"*.o "${UNIKRAFT_APPS}@${version}/build/" || die "cp failed"
	done

	rm -rf "${POOL}_spacer_aslr" &> /dev/null
	mv "${POOL}_aslr" "${POOL}_spacer_aslr" &> /dev/null

	if [ $PERF_TEST -eq 1 ]; then
		echo "TODO"
	fi

    cd $current || die "cd failed"
}

apply_versioning(){
	index=1
	len=$(file "${UNIKRAFT_APPS}"@v*|wc -l)
	for _ in $(seq 1 $len);
	do
		for i in $(seq 1 $index); do
			echo "Copying ${MERGED}/diff-v${i}.o to ${UNIKRAFT_APPS}@v${index}/build/lib-lambda-v${i}.o"
			cp "${MERGED}/diff-v${i}.o" "${UNIKRAFT_APPS}@v${index}/build/lib-lambda-v${i}.o"
		done
		
		index=$((index+1))
    done
}

while [[ "$#" > 0 ]]; do case $1 in
-a|--align) ALIGN_TEST="$2"; shift;shift;;
-b|--build) BUILD_TEST="$2"; shift;shift;;
-p|--perf) PERF_TEST="$2"; shift;shift;;
*) usage "Unknown parameter passed: $1"; shift; shift;;
esac; done

if [ ! -z $BUILD_TEST ]; then
	build "$BUILD_TEST"
	#apply_versioning
	exit 0
fi

if [ ! -z $ALIGN_TEST ]; then

    len=$(file "${UNIKRAFT_APPS}"@v*|wc -l)
    cd "${WORKSPACE_VERSION}/aligner" || die "cd 'aligner' failed"
	if [[ "$ALIGN_TEST" -eq 24 ]] || [[ "$ALIGN_TEST" -eq 27 ]]; then
		echo "Running aligner with initrd for test 24 or 27"
		./runner.sh --use_aslr --nb_unikernels "$len" --omit_copy_objs --aligner --use_initrd || die "runner.sh aligner (new) failed"
	else
		echo "Running aligner without initrd for other tests"
    	./runner.sh --use_aslr --nb_unikernels "$len" --omit_copy_objs --aligner  || die "runner.sh aligner (new) failed"
	fi

	if [[ "$ALIGN_TEST" -eq 24 ]] || [[ "$ALIGN_TEST" -eq 27 ]]; then
		echo "Running objcopy script for test 24 or 27"
		"${WORKSPACE_VERSION}"/tests/test"${ALIGN_TEST}"/script_objcopy_aslr.sh
		for i in $(seq 1 $len); do
			version=$i
			sed -i 's/128/2048/' "${UNIKRAFT_APPS}@v${version}/uk_config_aslr.json"
			sed -i 's/128/2048/' "${UNIKRAFT_APPS}@v${version}/uk_config_dce_aslr.json"
			sed -i 's/128/2048/' "${UNIKRAFT_APPS}@v${version}/uk_config_spacer_aslr.json"
			sed -i 's/128/2048/' "${UNIKRAFT_APPS}@v${version}/uk_config_delta_aslr.json"
		done
	fi

	./runner.sh --use_aslr --nb_unikernels "$len" --checker || die "runner.sh checker (new) failed"
	./runner.sh --use_aslr --nb_unikernels "$len" --dump_json --minifier --extractor &> /dev/null  || die "runner.sh slt failed"

	len=$(file "${UNIKRAFT_APPS}"@v*|wc -l)
	for i in $(seq 1 $len); do
		version=$i
		echo "Running unikernel version $version"
		timeout --foreground 2 firecracker_madvise --no-api --config-file "${UNIKRAFT_APPS}@v${version}/uk_config_delta_aslr.json" &> /tmp/1.txt
		timeout --foreground 2 firecracker_madvise --no-api --config-file "${UNIKRAFT_APPS}@v${version}/uk_config_dce_aslr.json" &> /tmp/2.txt
		icdiff /tmp/1.txt /tmp/2.txt
	done
	exit 0
fi

