#pragma once

#include <iostream>
#include <vector>
#include <unordered_map>
#include <string>
#include <regex>
#include <set>
#include <filesystem>
#include "UkObjectFile.hpp"
#include "UkModifier.hpp"

#include <spdlog/spdlog.h>
#include <elfio/elfio.hpp>

namespace fs = std::filesystem;

class UkObjectManager {
public:
    UkObjectManager(const std::string& workspace, const std::string& uk_name, const std::string& uksection, const std::string& link_file, const std::string& sec_to_patch, const std::string& sec_to_globalize, const int uk_version) :
        workspace(workspace),
        uk_name(uk_name),
        uksection(uksection),
        link_file(link_file),
        sec_to_patch(sec_to_patch),
        sec_to_globalize(sec_to_globalize),
        uk_version(uk_version),
        diff_obj(nullptr),
        diff_path(workspace + "diff-v" + std::to_string(uk_version) + ".o")
    {
        current_obj = diff_obj = nullptr;
    }

    ~UkObjectManager(){
        if (diff_obj != nullptr){
            delete diff_obj;
        }
        if (current_obj != nullptr){
            delete current_obj;
        }
        for (UkObjectFile* obj : all_diff_objs){
            delete obj;
        }
    }

    void adjust_symtab(){
        diff_obj->adjust_symtab();
    }

    bool save_merged() {
        return diff_obj->save();
    }

    void process_folder(){
        for (auto &entry : fs::directory_iterator(workspace)){
            if (entry.path().extension() == ".o") {
                const std::string obj_str = entry.path().string();
                
                std::regex versionRegex("v([0-9]+)\\.o");
                std::smatch match;

                std::regex_search(obj_str, match, versionRegex);
                if (match.size() != 2){
                    spdlog::warn("Skip object file: {}", obj_str);
                    continue;
                }
                int version = std::stoi(match[1]);
                
                if (version == uk_version && obj_str.find(uk_name) != std::string::npos){
                    
                    spdlog::info("Chosen Object file: {}", obj_str);
                    create_object();
                    diff_obj = new UkObjectFile(diff_path, &ukcommon);

                    // Current obj to versionize with the previous one
                    current_obj = new UkObjectFile(obj_str, &ukcommon);
                    map_path_objs[current_obj->get_path()] = current_obj;

                }else if (version < uk_version && obj_str.find("diff") != std::string::npos){
                    spdlog::info("Processing diff object file: {}", obj_str);
                    all_diff_objs.push_back(new UkObjectFile(obj_str, &ukcommon));
                }else{
                    spdlog::warn("Skip object file: {}", obj_str);
                }
            }
        }

        if (current_obj == nullptr || diff_obj == nullptr){
            std::cerr << "No object file found for the chosen unikernel" << std::endl;
            throw std::runtime_error("No object file found for the chosen unikernel");
        }

        if (all_diff_objs.size() == 0){
            std::cerr << "No diff object files found in the workspace" << std::endl;
            throw std::runtime_error("No diff object files found in the workspace");
        }
    }

    void process_symbols(){
        for (UkSymbol* symbol : current_obj->get_local_symbols_external()){
            if (diff_obj->is_in_symbol(symbol->get_name())){
                spdlog::debug("Symbol: {} is in the diff_obj object", symbol->get_name());
            }else{
                ELFIO::Elf_Half l_ndx = 0;
                spdlog::warn("Symbol: {} is not in the diff_obj object", symbol->get_name());
                if (symbol->get_type() == ELFIO::STT_OBJECT){

                    auto it = std::find_if(all_diff_objs.begin(), all_diff_objs.end(), [&symbol](const auto &obj) {
                        return obj->is_in_symbol(symbol->get_name());
                    });

                    if (it != all_diff_objs.end()) {
                        spdlog::debug("Symbol: {} is already in object: {}", symbol->get_name(), (*it)->get_path());
                        //TOD check if the object is the same (same size and same value)
                    } else {
                        std::string l_sect = current_obj->get_section_by_ndx(symbol->get_ndx())->get_name();

                        // Consider only the .bss section
                        if (l_sect.find(BSS) != std::string::npos){
                            // Update size of the section (more specifically the .bss section)
                            size_object_bss_sect += symbol->get_size();
                        }else if (l_sect.find(RODATA) != std::string::npos){

                            // Add data to RODATA section
                            spdlog::critical("Add data to RODATA section (size:{}) via symbol {}", symbol->get_size() , symbol->get_name());

                            int max_size = 0;
                            const char* raw_data = current_obj->extract_data_from_section(l_sect, &max_size);

                            const char* sliced =  UkCommon::slice_array(raw_data, max_size, symbol->get_value(), symbol->get_size());
                            if (sliced == nullptr){
                                spdlog::critical("Failed to slice array");
                                exit(EXIT_FAILURE);
                            }

                            symbol->set_value(diff_obj->add_data_to_section(sliced, symbol->get_size(), l_sect));

                            delete[] sliced;
                        }

                        l_ndx = diff_obj->update_symbol_ndx(l_sect);
                        if (diff_obj->add_symbol(symbol, l_ndx) == false) {
                            spdlog::error("Failed to add symbol: {}", symbol->get_name());
                        }
                    }
                }else{
                    // Other types of symbols
                    if (diff_obj->add_symbol(symbol, l_ndx) == false){
                        spdlog::error("Failed to add symbol: {}", symbol->get_name());
                    }
                }
            }
        }
    }

    void process_section(){
        // get all the sections from ukcommon
        const std::unordered_map<std::string, std::list<std::string>>& all_sections_name = ukcommon.get_all_sections_name();
        const std::unordered_map<std::string, std::list<std::string>>& all_sections_hash = ukcommon.get_all_sections_hash();

        for (auto &section : all_sections_name){
            // Check if section has the same hash for all objects in all_sections_hash
            auto lst = all_sections_hash.at(section.first);
            if (std::adjacent_find( lst.begin(), lst.end(), std::not_equal_to<>() ) == lst.end()){
                add_new_section(section);
            }else{
                // Objects have modified functions/sections with the same name but different content
                UkSection* uk_sect = handle_modified_section(section);
                if (uk_sect != nullptr){
                    bool found = false;
                    std::string modified_name = uk_sect->get_name() + uk_sect->get_version_name();
                    for (auto &obj : all_diff_objs){
                        if (obj->is_in_section(modified_name)){
                            spdlog::debug("Section: {} is already in object: {}", modified_name, obj->get_path());
                            found=true;
                            break;
                        }
                    }
                    if (!found){
                        // Add in diff object only if it is not already in the merged object
                        diff_obj->add_section(uk_sect, true);
                        patched_sections.push_back(std::make_pair(section.first, uk_sect->get_version_name()));
                    }
                }else{
                    add_new_section(section);
                }
            }
        }
    }

    void update_size_section(){
        spdlog::warn("Update size of section: {} with size: {}", BSS, size_object_bss_sect);
        diff_obj->update_size_section(BSS, size_object_bss_sect);
    }


    void get_updated_symbols(){
        diff_obj->get_updated_symbols();
    }

    void add_custom_relocations(){

        auto sec = current_obj->get_section(".data");
        if (sec != nullptr && sec->get_size() > 0){
            spdlog::warn("Copy .data section to diff object with a size of {}", sec->get_size());
            diff_obj->copy_section(sec->get_raw_data(), sec->get_size(), sec->get_name());
        }
        if (current_obj->get_rela_sections().size() == 0){
            spdlog::warn("No rela (.data/.rodata) relocations found in the current object");
            return;
        }

        for (const UkSection* ukSection : current_obj->get_rela_sections()){
            spdlog::warn("Add custom relocations for section: {}", ukSection->get_name());
            // Check if the section is rodata
            if (ukSection->get_name().find(RODATA) != std::string::npos){
                diff_obj->add_custom_section(ukSection, uk_version, true);
            }else if (ukSection->get_name().find(DATA) != std::string::npos){
                diff_obj->add_custom_section(ukSection, uk_version, false);
            }else{
                spdlog::warn("Skip section: {}", ukSection->get_name());
                return;
            }
        }

        diff_obj->add_inner_relocations(map_path_objs);
    }

    void update_relocations(){
        diff_obj->add_relocations();
    }

    bool have_global_sections() const{
        return ukcommon.get_global_sections().size() > 0;
    }

    bool have_modified_sections() const{
        return diff_obj->have_modified_sections();
    }

    void write_global_sections(){
        fs::path directory = std::filesystem::path(link_file).parent_path();
        std::ofstream outfile(directory / sec_to_globalize);
        for (auto const &section : ukcommon.get_global_sections()){
            outfile << section.first << "\t" << section.second << std::endl;
        }
        spdlog::info("Writing to file: {}", sec_to_globalize);
        outfile.close();
    }

    void write_modified_sections(){
        fs::path directory = std::filesystem::path(link_file).parent_path();
        std::ofstream outfile(directory / sec_to_patch);
        for (auto const &section : patched_sections){
            outfile << section.first << "\t" << section.second << std::endl;
        }
        spdlog::info("Writing to file: {}", sec_to_patch);
        outfile.close();
    }

    bool modify_symbol_binding() {
        
        for (UkObjectFile* obj : all_diff_objs){
            UkModifier ukModifier(obj->get_path());
            bool success = ukModifier.modify_symbol_binding(ukcommon.get_weak_symbols());
            if (success) {
                ukModifier.write_elf_file();
            }
        }
        return true;
    }

private:
    std::vector<UkObjectFile*> all_diff_objs;
    std::vector<std::pair<std::string, std::string>> patched_sections;
    std::unordered_map<std::string, UkObjectFile*> map_path_objs;

    const std::string workspace;
    const std::string uk_name;
    const std::string uksection;
    const std::string link_file;
    const std::string sec_to_patch;
    const std::string sec_to_globalize;
    const int uk_version;

    UkCommon ukcommon;
    UkObjectFile* diff_obj;
    UkObjectFile* current_obj;

    size_t size_object_bss_sect = 0;

    const std::string diff_path;

    void add_new_section(const std::pair<const std::string, std::list<std::string>> &section){
        for (UkObjectFile* obj : all_diff_objs){
            if (obj->is_in_section(section.first)){
                spdlog::debug("Section: {} is in object: {}", section.first, obj->get_path());
                return;
            }
        }

        spdlog::warn("Section: {} is not in the merged object", section.first);
        UkSection* uk_sect = map_path_objs[section.second.front()]->get_section(section.first);
        if (uk_sect != nullptr){
            diff_obj->add_section(uk_sect);
        }else{
            spdlog::critical("Failed to add section: {}", section.first);
            throw std::runtime_error("Failed to add section");
        }
    }

    UkSection* handle_modified_section(const std::pair<const std::string, std::list<std::string>> &section){
        
        UkSection* uk_sect = current_obj->get_section(section.first);
        if (uk_sect == nullptr){
            spdlog::critical("Section: {} is not in object: {}", section.first, current_obj->get_path());
            return nullptr;
        }

        for (UkObjectFile* obj : all_diff_objs){
            
            ELFIO::Elf_Xword size = 0;
            const UkSection* uks = obj->get_section(section.first);
            if (uks != nullptr){
                // Get the size of the section of the merged object
                size = uks->get_size();
            }

            // Only consider sections which have different size
            if (uk_sect->get_size() != size){
                return uk_sect;
            }
        }
        return nullptr;
    }

    inline void create_object() const{
        try{
            fs::copy_file("/var/tmp/obj_base.o", diff_path, fs::copy_options::overwrite_existing);
        }catch(const fs::filesystem_error& e){
            spdlog::critical("Failed to copy file: {}", e.what());
            exit(EXIT_FAILURE);
        }
    }
};