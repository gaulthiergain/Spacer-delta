#!/bin/bash
use_aslr=${1:-0}
uk_type=${2:-"delta"}
TEST=${3:-1}
shm_dir="/dev/shm"

workdir="$HOME/versioning"

copy_shm() {

	rm -f "/dev/shm/aslr_"* &> /dev/null
	rm -f "/dev/shm/lib"* &> /dev/null

	use_aslr="$1"
	uk_type="$2"

	suffix=""

	if [[ $uk_type == "delta" ]]; then
		pool_dir="${workdir}/dev/firecracker/pool"
		uk="${workdir}/apps/applambda@v1/build/unikernel_kvmfc-x86_64_local_align"
	else
		pool_dir="${workdir}/dev/firecracker/pool_spacer"
		uk="${workdir}/apps/applambda@v1/build/unikernel_kvmfc-x86_64_spacer"
	fi

    if [[ $use_aslr == 1 ]]; then
		pool_dir="${pool_dir}_aslr"
		cd "${pool_dir}" || exit
        for f in .*; do cp -- "$f" "${shm_dir}/aslr_lib$f" 2> "/dev/null"; done
        cp "${pool_dir}/uk_lib_arg__lib_param" "${shm_dir}/aslr_libuk_lib_arg__lib_param"
        if [[ ! -f "${shm_dir}/aslr_libuk_lib_arg__lib_param" ]]; then
            cp "${pool_dir}/uk_lib_arg__lib_param" "${shm_dir}/aslr_libuk_lib_arg__lib_param"
        fi
		suffix="aslr_"
		uk="${uk}_aslr"
    else
		cd "${pool_dir}" || exit
        for f in .*; do cp -- "$f" "${shm_dir}/lib$f" 2> "/dev/null"; done
    fi
    cd "$current"|| exit 1

    objcopy -O binary --only-section=.uk_thread_inittab  "${uk}" /tmp/lib.uk_thread_inittab
    objcopy -O binary --only-section=netdev__param_arg  "${uk}" /tmp/lib.netdev__param_arg
    objcopy -O binary --only-section=vfs__param_arg "${uk}" /tmp/lib.vfs__param_arg
    objcopy -O binary --only-section=.uk_lib_arg__lib_param "${uk}" /tmp/lib.uk_lib_arg__lib_param
    cat "/tmp/lib.uk_thread_inittab" "/tmp/lib.netdev__param_arg" "/tmp/lib.vfs__param_arg" "/tmp/lib.uk_lib_arg__lib_param" > "/tmp/lib.uk_all1"
    
    objcopy -O binary --only-section=.uk_ctortab  "${uk}" /tmp/lib.uk_ctortab
    objcopy -O binary --only-section=.uk_inittab  "${uk}" /tmp/lib.uk_inittab
    objcopy -O binary --only-section=.uk_eventtab "${uk}" /tmp/lib.uk_eventtab
    objcopy -O binary --only-section=.uk_fs_list  "${uk}" /tmp/lib.uk_fs_list
    cat "/tmp/lib.uk_ctortab" "/tmp/lib.uk_inittab" "/tmp/lib.uk_eventtab" "/tmp/lib.uk_fs_list" > "/tmp/lib.uk_all2"
    
    mv "/tmp/lib.uk_all1" "${shm_dir}/${suffix}lib.uk_thread_inittab"
    mv "/tmp/lib.uk_all2" "${shm_dir}/${suffix}lib.uk_ctortab"
    rm "/tmp/lib"*

	if [[ "$TEST" -eq 24 ]] || [[ "$TEST" -eq 27 ]]; then
		rm "${shm_dir}/initrd" &> /dev/null
		cp $HOME/versioning/tmp.cpio "${shm_dir}/${suffix}libinitrd"
	fi
}

copy_shm "$use_aslr" "$uk_type" "$TEST"