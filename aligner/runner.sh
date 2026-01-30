#!/bin/bash
nb_unikernels=0
use_initrd=0
copy_objs=1
use_ind=0
current=$PWD
unikernels=()
 
unikernels_path=()
unikraft="/home/unikraft/versioning"
pool_dir="/home/unikraft/versioning/dev/firecracker/pool"
use_aslr=0
shm_dir="/dev/shm"

copy_shm() {
    
    cd "${pool_dir}${1}" || exit
	suffix=""
    if [[ $use_aslr == 1 ]]; then
        for f in .*; do cp -- "$f" "${shm_dir}/aslr_lib$f" 2> "/dev/null"; done
        cp "${pool_dir}/.uk_lib_arg__lib_param" "${shm_dir}/aslr_libuk_lib_arg__lib_param"
        if [[ ! -f "${shm_dir}/aslr_libuk_lib_arg__lib_param" ]]; then
            cp "${pool_dir}/uk_lib_arg__lib_param" "${shm_dir}/aslr_libuk_lib_arg__lib_param"
        fi
		suffix="aslr_"
    else
        for f in .*; do cp -- "$f" "${shm_dir}/lib$f" 2> "/dev/null"; done
    fi
    cd "$current"|| exit 1

    objcopy -O binary --only-section=.uk_thread_inittab  "${2}" /tmp/lib.uk_thread_inittab
    objcopy -O binary --only-section=netdev__param_arg  "${2}" /tmp/lib.netdev__param_arg
    objcopy -O binary --only-section=vfs__param_arg "${2}" /tmp/lib.vfs__param_arg
    objcopy -O binary --only-section=.uk_lib_arg__lib_param "${2}" /tmp/lib.uk_lib_arg__lib_param
    cat "/tmp/lib.uk_thread_inittab" "/tmp/lib.netdev__param_arg" "/tmp/lib.vfs__param_arg" "/tmp/lib.uk_lib_arg__lib_param" > "/tmp/lib.uk_all1"
    
    objcopy -O binary --only-section=.uk_ctortab  "${2}" /tmp/lib.uk_ctortab
    objcopy -O binary --only-section=.uk_inittab  "${2}" /tmp/lib.uk_inittab
    objcopy -O binary --only-section=.uk_eventtab "${2}" /tmp/lib.uk_eventtab
    objcopy -O binary --only-section=.uk_fs_list  "${2}" /tmp/lib.uk_fs_list
    cat "/tmp/lib.uk_ctortab" "/tmp/lib.uk_inittab" "/tmp/lib.uk_eventtab" "/tmp/lib.uk_fs_list" > "/tmp/lib.uk_all2"
    
    mv "/tmp/lib.uk_all1" "${shm_dir}/${suffix}lib.uk_thread_inittab"
    mv "/tmp/lib.uk_all2" "${shm_dir}/${suffix}lib.uk_ctortab"
    rm "/tmp/lib"*
}

runner() {

    aslr=""
    if [[ $use_aslr == 1 ]]; then
        aslr="_aslr"
        use_aslr=1
    fi
    
    if [[ $clean ]]; then
        for f in "${unikernels[@]}"
        do
            echo "clean $unikraft/apps/$f/"
            cd "$unikraft/apps/$f/"|| exit 1
            make clean &> /dev/null
            make -j 32 &> /dev/null
            if [[ $! -ne 0 ]]; then
                echo "make failed"
                exit 1
            fi
            cd "$current"|| exit 1
        done
    fi

    if [[ $randomize ]]; then
        cd "helpers"|| exit 1
        python3 perform_aslr.py --uks "${unikernels[@]}" --app_folder "apps"
        exit 0
    fi

    for uk in "${unikernels[@]}"
    do
        p="$unikraft/apps/$uk/build"
        if [[ -f "${p}/libkvmfcplat.o" ]]; then
            unikernels_path+=("$p/unikernel_kvmfc-x86_64_local_align${aslr}")
        else
            unikernels_path+=("$p/unikernel_kvmfc-x86_64_local_align${aslr}")
        fi
    done

    if [[ $update_map_aslr ]]; then
        cd "helpers"|| exit 1
        python3 lib_alsr_changes.py --uks "${unikernels[@]}"
        exit 0
    fi

	if [[ $rewriter ]]; then
		echo "Running rewriter ... $rewriter - $aslr"
		cd "aslr"|| exit 1
		python3 binary_rewriter_new.py --uks "${unikernels[@]}" --workspace "$unikraft/apps"
		for uk in "${unikernels_path[@]}"
        do
            cp "$uk.dbg" "$uk"
			strip "$uk"
        done
		exit 0
	fi

    if [[ $aligner ]]; then
        if [[ $use_aslr == 1 ]]; then
            rm /dev/shm/aslr*
        else
            rm /dev/shm/lib*
        fi
        if [[ $use_initrd == 1 ]]; then
			python3 aligner.py --use_ind "$use_ind" --uks "${unikernels[@]}" --aslr "$use_aslr" --copy_objs "$copy_objs" --use_initrd 1
		else
        	python3 aligner.py --use_ind "$use_ind" --uks "${unikernels[@]}" --aslr "$use_aslr" --copy_objs "$copy_objs" #--relink-only
        fi
		if [[ $use_aslr == 1 ]]; then
            cd "aslr"|| exit 1
            python3 binary_rewriter_new.py --uks "${unikernels[@]}" --workspace "$unikraft/apps"
            cd ..|| exit 1
        fi
        
        for uk in "${unikernels_path[@]}"
        do
            cp "$uk.dbg" "$uk"
			strip "$uk"
        done
    fi

    if [[ $checker ]]; then
        cd "helpers"|| exit 1
        python3 check_alignment.py --uks "${unikernels[@]}" --aslr "${use_aslr}"
        cd ..|| exit 1
    fi

    if [[ $dump_json ]]; then
        cd "helpers"|| exit 1
        for uk in "${unikernels_path[@]}"
        do
            python3 dump_sections.py --uk "$uk"
        done
        cd ..|| exit 1
    fi

    if [[ $extractor ]]; then

        rm -rf "${pool_dir}${aslr}" ; mkdir "${pool_dir}${aslr}"
        cd "helpers"|| exit 1
        for uk in "${unikernels_path[@]}"
        do
            python3 lib_extractor.py --uk "$uk" --dir "$pool_dir"
        done
        cd ..|| exit 1

        copy_shm "$aslr" "${unikernels_path[0]}"
    fi

    if [[ $minifier ]]; then

        cd "helpers"|| exit 1
        for uk in "${unikernels_path[@]}"
        do
            python3 elf_minimizer.py --uk "$uk"
        done
        cd ..|| exit 1
    fi


    if [[ $parser_uk ]]; then

        cd "helpers"|| exit 1
        for uk in "${unikernels_path[@]}"
        do
            "$current/helpers/parser_uk/target/debug/parser_uk" "${uk}_update_minimal"
        done
        cd ..|| exit 1
    fi

    if [[ $elf_compare ]]; then

        cd "helpers"|| exit 1
        python3 uk_elf_sharing.py --uks "${unikernels[@]}" --aslr "${use_aslr}"
        cd ..|| exit 1
    fi

    if [[ $save_read_elf ]]; then
        mkdir -p "readelf_output"
        for uk in "${unikernels_path[@]}"
        do
            ukname=$(echo "$uk" |cut -d/ -f 6)
            readelf --wide --sections "$uk" > "readelf_output/${ukname}.txt"
        done
    fi

    if [[ $create_snapshot ]]; then
        rm /tmp/firecracker.socket 2> "/dev/null"
        cd "${unikraft}/scripts/scripts_snapshot" || exit 1
        unikernel_types=("spacer" "default" "size")
        firecracker_bin="firecracker_madvise"
        for uk_type in "${unikernel_types[@]}"; do
            for uk in "${unikernels[@]}"; do
                echo "running $uk (${uk_type}) ..." 
                if [ "$uk_type" != "spacer" ]; then
                    firecracker_bin="firecracker_madvise"
                fi
                ./script_snapshot_manager.sh "create" "${uk#*-}" "${firecracker_bin}" "${uk_type}"
                sleep 3
            done
        done
        cd "$current"|| exit 1
    fi
}

while [[ "$#" -gt 0 ]]; do
        case $1 in
            -t|--target) target="$2"; shift ;;
            --clean) clean=1 ;;
            --create_snapshot) create_snapshot=1 ;;
            --randomize) randomize=1 ;;
            --aligner) aligner=1 ;;
            --checker) checker=1 ;;
            --dump_json) dump_json=1 ;;
			--rewriter) rewriter=1 ;;
            --extractor) extractor=1 ;;
            --minifier) minifier=1 ;;
            --parser_uk) parser_uk=1 ;;
            --elf_compare) elf_compare=1 ;;
            --update_map_aslr) update_map_aslr=1 ;;
            --use_aslr) use_aslr=1 ;;
            --use_ind) use_ind=1 ;;
            --readelf) save_read_elf=1 ;;
			--use_initrd) use_initrd=1 ;;
            --all) do_all=1 ;;
            --nb_unikernels) nb_unikernels=$2; shift ;;
            --omit_copy_objs) copy_objs=0 ;;
            *) echo "Unknown parameter passed: $1"; exit 1 ;;
        esac
        shift
done

for i in $(seq 1 $nb_unikernels); do
    unikernels+=("applambda@v$i")
done

if [[ $do_all ]]; then
    aligner=1 && checker=1 && dump_json=1 && extractor=1 && minifier=1
fi

runner 
