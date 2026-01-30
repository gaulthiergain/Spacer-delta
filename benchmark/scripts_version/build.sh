#!/bin/bash
libs=()
source "../utils.sh"

MERGED="${WORKSPACE_VERSION}/merged"
PERF_TEST=0

build(){
	echo "***** (1) Building without ASLR *****"
    TEST="$1"
    rm -rf "${WORKSPACE_VERSION}"/libs/lib-lambda-v* &> /dev/null
	rm -rf "$MERGED" &> /dev/null
	mkdir -p "$MERGED" || die "mkdir failed"
    current=$PWD

    get_libs "$TEST"

    cp -r "${WORKSPACE_VERSION}/tests/test${TEST}"/. "${WORKSPACE_VERSION}/libs/"|| die "cp failed"

	cd "${UNIKRAFT_APPS}" && make clean &> /dev/null || die "global make clean failed"
	rm "$POOL" &> /dev/null 
	mkdir -p "$POOL" || die "mkdir pool failed"

    for lib in "${libs[@]}"
    do
		local version=$(echo "$lib" | cut -d'-' -f3)
		cp -r "${UNIKRAFT_APPS}" "${UNIKRAFT_APPS}@${version}" || die "cp failed"
		cd "${UNIKRAFT_APPS}@${version}" || die "cd failed"

		echo "Making $lib"
        if [ -f "${WORKSPACE_VERSION}/libs/$lib/Makefile" ]; then
            cp "${WORKSPACE_VERSION}/libs/$lib/Makefile" Makefile || die "cp Makefile failed"  
        else
            cp Makefile.BAK Makefile || die "cp Makefile failed"
        fi
        sed -i "s/lib-lambda-v1/$lib/g" Makefile

		rm build/liblambda.o build/liblambda.ld.o &> /dev/null

		cp "${WORKSPACE_VERSION}/libs/$lib/main_lambda.c" main_lambda.c || die "cp main_lambda.c failed"
		
		if [ -f "${WORKSPACE_VERSION}/libs/$lib/.config" ]; then
			echo "Using custom config for $lib"
			cp "${WORKSPACE_VERSION}/libs/$lib/Config.uk" Config.uk || die "cp Config.uk failed"
        	cp "${WORKSPACE_VERSION}/libs/$lib/.config" .config || die "cp config failed"
			cp "${WORKSPACE_VERSION}/libs/$lib/.config" .config.old || die "cp config failed"
        	
    	else
        	cp .config.BAK .config || die "cp config failed"
			echo "" > Config.uk || die "echo Config failed"
    	fi

        sed -i 's/# CONFIG_OPTIMIZE_DEADELIM is not set/CONFIG_OPTIMIZE_DEADELIM=y/g' .config || die "sed failed"
        make clean &> /tmp/error.txt || (cat /tmp/error.txt && die "make clean failed")
		timeout 30 make &> /dev/null
		make -j$(nproc) &>> /tmp/error.txt || (cat /tmp/error.txt && die "make 2 failed")
		if [ -f "${WORKSPACE_VERSION}/libs/$lib/script.sh" ]; then
			sh ${WORKSPACE_VERSION}/libs/$lib/script.sh
			make &> /tmp/error.txt || (cat /tmp/error.txt && die "make 3 failed")
		fi

        cp build/app-lambda_kvmfc-x86_64.dbg build/app-lambda_kvmfc-x86_64_dce.dbg || die "cp failed"
		cp build/app-lambda_kvmfc-x86_64 build/app-lambda_kvmfc-x86_64_dce || die "cp failed"
		strip build/app-lambda_kvmfc-x86_64_dce

        sed -i 's/CONFIG_OPTIMIZE_DEADELIM=y/# CONFIG_OPTIMIZE_DEADELIM is not set/g' .config || die "sed failed"
        make clean &> /tmp/error.txt || (cat /tmp/error.txt && die "make clean failed")
		make -j$(nproc) &> /tmp/error.txt || (cat /tmp/error.txt && die "make 4 failed")
		if [ -f "${WORKSPACE_VERSION}/libs/$lib/script.sh" ]; then
			sh ${WORKSPACE_VERSION}/libs/$lib/script.sh
			make &> /tmp/error.txt || (cat /tmp/error.txt && die "make 5 failed")
		fi
		
		cp build/liblambda.o "$MERGED/lib-lambda-${version}.o"
		mv build/liblambda.o "build/liblambda-${version}.o"
		mv build/applambda.o "build/applambda-${version}.o"

		if [ "$TEST" -eq 25 ]; then
			mv build/libnginx.o "build/libnginx-${version}.o"
			mv build/libnewlibc.o "build/libnewlibc-${version}.o"
		fi

		cp /tmp/link64.lds build/libkvmfcplat/link64.lds || die "cp link64.lds failed"

        strip build/app-lambda_kvmfc-x86_64

		# Spacer (base)
		cp "${UNIKRAFT_APPS}@${version}/uk_config.json" "${UNIKRAFT_APPS}@${version}/uk_config_spacer.json"
		sed -i "s:applambda/build/app-lambda_kvmfc-x86_64:applambda@${version}/build/unikernel_kvmfc-x86_64_spacer:g" "${UNIKRAFT_APPS}@${version}/uk_config_spacer.json"

		# Spacer (Delta)
		cp "${UNIKRAFT_APPS}@${version}/uk_config.json" "${UNIKRAFT_APPS}@${version}/uk_config_delta.json"
		sed -i "s:applambda/build/app-lambda_kvmfc-x86_64:applambda@${version}/build/unikernel_kvmfc-x86_64_local_align:g" "${UNIKRAFT_APPS}@${version}/uk_config_delta.json"

		# DCE
		cp "${UNIKRAFT_APPS}@${version}/uk_config.json" "${UNIKRAFT_APPS}@${version}/uk_config_dce.json"
    	sed -i "s:applambda/build/app-lambda_kvmfc-x86_64:applambda@${version}/build/app-lambda_kvmfc-x86_64_dce:g" "${UNIKRAFT_APPS}@${version}/uk_config_dce.json"

		# Default 
		sed -i "s/lib-lambda-v1/lib-lambda-${version}/g" "${UNIKRAFT_APPS}@${version}/Makefile"
    	sed -i "s:applambda:applambda@${version}:g" "${UNIKRAFT_APPS}@${version}/uk_config.json"
		
        sed -i "s/$lib/lib-lambda-v1/g" Makefile
    done

	echo "Aligning with Spacer (vanilla)"
	len=$(file "${UNIKRAFT_APPS}"@v*|wc -l)
    cd "${WORKSPACE_VERSION}/aligner_old" || die "cd 'aligner_old' failed"
	if [ "$TEST" -eq 24 ] || [ "$TEST" -eq 27 ]; then
		./runner.sh --nb_unikernels "$len" --aligner --use_initrd || die "runner.sh aligner failed"
	else
    	./runner.sh --nb_unikernels "$len" --aligner || die "runner.sh aligner failed"
	fi
	./runner.sh --nb_unikernels "$len" --checker || die "runner.sh checker failed"
	./runner.sh --use_ind --nb_unikernels "$len" --dump_json --minifier --extractor &> /dev/null || die "runner.sh slt failed"

	rm -rf /tmp/versioning/* &> /dev/null
	for lib in "${libs[@]}"
    do
		local version=$(echo "$lib" | cut -d'-' -f3)
		rm "${UNIKRAFT_APPS}@${version}/build/liblambda-${version}.o" || die "rm liblambda-${version}.o failed"
		mv "${UNIKRAFT_APPS}@${version}/build/applambda-${version}.o" "${UNIKRAFT_APPS}@${version}/build/applambda.o" || die "mv  applambda.o failed"
		mv "${UNIKRAFT_APPS}@${version}/build/unikernel_kvmfc-x86_64_local_align" "${UNIKRAFT_APPS}@${version}/build/unikernel_kvmfc-x86_64_spacer"
		mv "${UNIKRAFT_APPS}@${version}/build/unikernel_kvmfc-x86_64_local_align.dbg" "${UNIKRAFT_APPS}@${version}/build/unikernel_kvmfc-x86_64_spacer.dbg"
		mv "${UNIKRAFT_APPS}@${version}/build/unikernel_kvmfc-x86_64_local_align.data" "${UNIKRAFT_APPS}@${version}/build/unikernel_kvmfc-x86_64_spacer.data"
		mv "${UNIKRAFT_APPS}@${version}/build/unikernel_kvmfc-x86_64_local_align.sec" "${UNIKRAFT_APPS}@${version}/build/unikernel_kvmfc-x86_64_spacer.sec"

		mkdir -p "/tmp/versioning/${version}/build/" || die "mkdir failed"
		if [ "$TEST" -eq 25 ]; then
			mv "${UNIKRAFT_APPS}@${version}/build/libnginx-${version}.o" "${UNIKRAFT_APPS}@${version}/build/libnginx.o"
			mv "${UNIKRAFT_APPS}@${version}/build/libnewlibc-${version}.o" "${UNIKRAFT_APPS}@${version}/build/libnewlibc.o"
		fi
		cp "${UNIKRAFT_APPS}@${version}/build/"*.o "/tmp/versioning/${version}/build/" || die "cp failed"
	done

	rm -rf "${POOL}_spacer" &> /dev/null
	mv "$POOL" "${POOL}_spacer" &> /dev/null
	mkdir -p "$POOL" || die "mkdir pool failed"

	if [ $PERF_TEST -eq 1 ]; then
		echo "TODO"
	fi

    cd $current || die "cd failed"
}

apply_versioning(){
	index=1
	for file in "$MERGED"/*; do
		/usr/bin/versionner --log critical --workspace "${MERGED}/" --uk_version "$index" &> /tmp/versionner.log || (cat /tmp/versionner.log && die "versionner failed")
		
		for i in $(seq 1 $index); do
			echo "Copying ${MERGED}/diff-v${i}.o to ${UNIKRAFT_APPS}@v${index}/build/lib-lambda-v${i}.o"
			cp "${MERGED}/diff-v${i}.o" "${UNIKRAFT_APPS}@v${index}/build/lib-lambda-v${i}.o"
			cp "${UNIKRAFT_APPS}@v${index}/build/lib-lambda-v${i}.o" "/tmp/versioning/v${index}/build/" || die "cp failed"
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
	apply_versioning
	exit 0
fi

if [ ! -z $ALIGN_TEST ]; then

    len=$(file "${UNIKRAFT_APPS}"@v*|wc -l)
    cd "${WORKSPACE_VERSION}/aligner" || die "cd 'aligner' failed"
	if [[ "$ALIGN_TEST" -eq 24 ]] || [[ "$ALIGN_TEST" -eq 27 ]]; then
		./runner.sh --use_ind --nb_unikernels "$len" --omit_copy_objs --aligner --use_initrd || die "runner.sh aligner failed"
	else
    	./runner.sh --use_ind --nb_unikernels "$len" --omit_copy_objs --aligner || die "runner.sh aligner failed"
	fi
	./runner.sh --nb_unikernels "$len" --checker || die "runner.sh checker failed"
	./runner.sh --use_ind --nb_unikernels "$len" --dump_json --minifier --extractor  &> /dev/null || die "runner.sh slt failed"

	if [[ "$ALIGN_TEST" -eq 24 ]] || [[ "$ALIGN_TEST" -eq 27 ]]; then
		echo "Running objcopy script for test 24 or 27"
		"${WORKSPACE_VERSION}"/tests/test"${ALIGN_TEST}"/script_objcopy.sh
		for i in $(seq 1 $len); do
			version=$i
			sed -i 's/128/2048/' "${UNIKRAFT_APPS}@v${version}/uk_config.json"
			sed -i 's/128/2048/' "${UNIKRAFT_APPS}@v${version}/uk_config_dce.json"
			sed -i 's/128/2048/' "${UNIKRAFT_APPS}@v${version}/uk_config_spacer.json"
			sed -i 's/128/2048/' "${UNIKRAFT_APPS}@v${version}/uk_config_delta.json"
		done
	fi

	# for range 1 to len, run the aligned unikernel
	len=$(file "${UNIKRAFT_APPS}"@v*|wc -l)
	for i in $(seq 1 $len); do
		version=$i
		echo "Running unikernel version $version"
		timeout --foreground 2 firecracker_madvise --no-api --config-file "${UNIKRAFT_APPS}@v${version}/uk_config_delta.json" &> /tmp/1.txt
		timeout --foreground 2 firecracker_madvise --no-api --config-file "${UNIKRAFT_APPS}@v${version}/uk_config_dce.json" &> /tmp/2.txt
		icdiff /tmp/1.txt /tmp/2.txt
	done
	exit 0
fi

