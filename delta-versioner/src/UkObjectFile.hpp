#pragma once
#include <set>
#include <string>
#include <iostream>
#include <unordered_map>

#include <spdlog/spdlog.h>
#include <elfio/elfio.hpp>
#include <elfio/elfio_dump.hpp>

#define LIMIT_SIZE_SECTION 1

#include "UkCommon.hpp"
#include "UkSection.hpp"
#include "UkReloSection.hpp"

const static std::string EMPTY = "";
const static std::string TEXT = ".text";
const static std::string RODATA = ".rodata";
const static std::string DATA = ".data";
const static std::string BSS = ".bss";
const static std::string RELA = ".rela";

const static int N_SIZE = 8;

class UkObjectFile {
public:
    UkObjectFile(const std::string& filepath, UkCommon* ukcommon)
        : path(filepath), ukcommon(ukcommon)
    {
        if (!reader.load(path)) {
            throw std::runtime_error("Cannot load " + path);
        }

        parse_section();
        parse_symbols();
        for (size_t i = 0; i < vec_index_relo_section.size(); i++) {
            parse_relocations(reader.sections[vec_index_relo_section[i]]);
        }
    }

    ~UkObjectFile(){
        for (UkSection* section : vec_local_sections){
            delete section;
        }
        for (UkSymbol* symbol : vec_local_symbols){
            delete symbol;
        }
    }

    UkSection* get_section(const std::string& section_name){
        if (map_local_sections_name.find(section_name) != map_local_sections_name.end()){
            return map_local_sections_name[section_name];
        }else{
            return nullptr;
        }
    }

    // get sections by ndx 
    UkSection* get_section_by_ndx(const size_t ndx){
        if (ndx < vec_local_sections.size()){
            return vec_local_sections[ndx];
        }else{
            return nullptr;
        }
    }

    void update_size_section(const std::string& section_name, size_t size_bss){
        ELFIO::section* sec = reader.sections[section_name];
        if (sec != nullptr){
            sec->set_size(size_bss);
        }else{
            spdlog::critical("Section {} not found", section_name);
        }
    }

    void copy_section(const char* data, const ELFIO::Elf_Xword size, const std::string& section_name){
        ELFIO::section* sec = reader.sections[section_name];
        if (sec != nullptr){
            sec->set_data(data, size);
        }else{
            spdlog::critical("Section {} not found while copying", section_name);
        }
    }

    ELFIO::Elf64_Addr add_data_to_section(const char* data, const ELFIO::Elf_Xword size, const std::string& section_name){
        ELFIO::section* sec = reader.sections[section_name];
        if (sec != nullptr){

            const ELFIO::Elf64_Addr s = sec->get_size();
            sec->append_data(data, size);
            return s;

        }else{
            spdlog::critical("Section {} not found while adding data", section_name);
            return 0;
        }
    }

    const char* extract_data_from_section(const std::string& section_name, int *max_size){
        ELFIO::section* sec = reader.sections[section_name];
        if (sec != nullptr){
            *max_size = sec->get_size();
            return sec->get_data();
        }else{
            spdlog::critical("Section {} not found while extracting data", section_name);
            return nullptr;
        }
    }

    void get_updated_symbols(){
        ELFIO::symbol_section_accessor symbols(reader, reader.sections[".symtab"]);

        // reset the map and the vector
        for (UkSymbol* symbol : vec_local_symbols){
            delete symbol;
        }
        map_local_symbols.clear();
        vec_local_symbols.clear();

        for (ELFIO::Elf_Xword i = 0; i < symbols.get_symbols_num(); i++) {
            std::string name;
            ELFIO::Elf64_Addr value = 0;
            ELFIO::Elf_Xword size = 0;
            unsigned char bind = 0;
            unsigned char type = 0;
            ELFIO::Elf_Half ndx = 0;
            unsigned char other = 0;

            symbols.get_symbol(i, name, value, size, bind, type, ndx, other);
            if (name.length() == 0){
                // For SECTION type, the symbol name is empty (override it with the section name)
                name = reader.sections[ndx]->get_name();
            }

            UkSymbol* uk = new UkSymbol(name, value, size, bind, type, ndx, other, i);
            map_name_symbol[name] = uk;
            map_local_symbols[name] = i;
            vec_local_symbols.push_back(uk);

            /*ELFIO::section* sec = reader.sections[ndx];
            if (type == ELFIO::STT_OBJECT && sec->get_name().rfind(DATA, 0) == 0){
                spdlog::info("{} -> {} - size: {} - offset: 0x{:x}", sec->get_name(), name, size, value);
            }else if (type == ELFIO::STT_OBJECT && sec->get_name().rfind(RODATA, 0) == 0){
                spdlog::critical("{} -> {} - size: {} - offset: 0x{:x}", sec->get_name(), name, size, value);
            }*/
        }
    }

    const std::string get_path() const {
        return path;
    }

    bool is_in_symbol(const std::string& symbol_name){
        if (map_local_symbols.find(symbol_name) != map_local_symbols.end()){
            return true;
        }else{
            return false;
        }
    }

    bool is_in_section(const std::string& section_name){
        if (map_local_sections_name.find(section_name) != map_local_sections_name.end()){
            return true;
        }else{
            return false;
        }
    }

    ELFIO::Elf_Half update_symbol_ndx(const std::string& section_name){
        if (map_local_sections_name.find(section_name) != map_local_sections_name.end()){
            return map_local_sections_name[section_name]->get_ndx();
        }
        return 0;
    }

    bool add_symbol(const UkSymbol* ukSymbol, ELFIO::Elf_Half l_ndx = 0){

        ELFIO::string_section_accessor stra( reader.sections[".strtab"] );
        ELFIO::section* symtab_sec = reader.sections[".symtab"];
        ELFIO::symbol_section_accessor symtab( reader, symtab_sec );

        map_local_symbols[ukSymbol->get_name()] = symtab.get_symbols_num();

        UkSymbol* uk_copy = new UkSymbol(ukSymbol->get_name(), ukSymbol->get_value(), ukSymbol->get_size(), ukSymbol->get_bind(), ukSymbol->get_type(), ukSymbol->get_ndx(), ukSymbol->get_other());
        uk_copy->set_related_section(ukSymbol->get_related_section());
        vec_local_symbols.push_back(uk_copy);

        ELFIO::Elf_Half ndx  = ukSymbol->get_ndx();
        if (l_ndx > 0){
            ndx = l_ndx;
        }
        bool success = symtab.add_symbol(stra.add_string( ukSymbol->get_name()), ukSymbol->get_value(), ukSymbol->get_size(), ukSymbol->get_bind(), ukSymbol->get_type(), ukSymbol->get_other() , ndx);

        symtab_sec->set_info(symtab.get_symbols_num());

        return success;
    }

    ELFIO::section* get_section_in_map(const std::string &sec_name){
        for (const std::string& prefix : {EMPTY, TEXT + ".", RODATA + ".", DATA + ".", BSS + "."}) {
            ELFIO::section* sec = reader.sections[prefix + sec_name];
            if (sec != nullptr){
               return sec;
            }
        }

        // Get the index of the symbol in the symtab and then get the associated section from the symbol
        size_t index_symtab = map_local_symbols[sec_name];
        ELFIO::section* sec = reader.sections[vec_local_symbols[index_symtab]->get_related_section()];
        if (sec != nullptr){
            spdlog::info("Section: {} found", sec->get_name());
            return sec;
        }

        spdlog::critical("Section: {} not found", sec_name);

        return nullptr;
    }

    void adjust_symtab(){
        ELFIO::section* symtab_sec = reader.sections[".symtab"];
        ELFIO::symbol_section_accessor symtab( reader, symtab_sec );
        // Arrange symbols in the symtab (Local symbols first, then global symbols, then weak symbols, then undefined symbols)
        symtab.arrange_local_symbols( [&]( ELFIO::Elf_Xword first, ELFIO::Elf_Xword second ) {
            spdlog::debug("Swapping symbols: {} and {}", first, second);
        } );
    }

    bool is_in_map_symbol(std::string& symbol_name, const size_t &version){

        if(map_name_symbol.find(symbol_name) != map_name_symbol.end()){
            // Get symbol name from the map
            if (map_name_symbol[symbol_name]->get_type() == ELFIO::STT_NOTYPE){
                return false;
            }
            return true;
        }

        std::string new_symbol_name = symbol_name + "__v"  + std::to_string(version) + "__";
        if(map_name_symbol.find(new_symbol_name) != map_name_symbol.end()){
            // override the symbol name
            symbol_name = new_symbol_name;
            return true;
        }

        return false;
    }

    bool add_custom_section(const UkSection* ukSection, const size_t &version, const bool is_rodata){

        // Section name is either .rela.rodata or .rela.data or rela.init_array
        std::string section_name = RELA + ukSection->get_name();

        ELFIO::section* new_sec = reader.sections.add( section_name );
        new_sec->set_addr_align( 0x8 );
        new_sec->set_type( ELFIO::SHT_RELA );
        new_sec->set_flags( ELFIO::SHF_INFO_LINK );

        new_sec->set_type( ELFIO::SHT_RELA );

        // Ref_sect is either .rodata or .data or .init_array
        ELFIO::section* ref_sect = reader.sections[ukSection->get_name()];

        new_sec->set_info( ref_sect->get_index() );
        new_sec->set_addr_align( 0x8 );
        new_sec->set_entry_size( 0x18 );
        new_sec->set_flags( ELFIO::SHF_INFO_LINK );

        ELFIO::section* symtab_sec = reader.sections[".symtab"];
        new_sec->set_link( symtab_sec->get_index() );

        ELFIO::symbol_section_accessor symbols(reader, reader.sections[".symtab"]);

        for (const UkRelocation* ukRelocation : ukSection->get_relocations()){

            std::string name_offset = ukRelocation->get_name() + "@" + std::to_string(ukRelocation->get_offset());

            // if name_offset is in map_inner_relocation, remove it 
            if (map_inner_relocation.find(name_offset) != map_inner_relocation.end()){
                spdlog::critical("Relocation: {} found in map_inner_relocation. Remove it.", name_offset);
                continue;
            }

            std::string relo_name = ukRelocation->get_name();
            ELFIO::Elf_Sxword addend = ukRelocation->get_addend();
            ELFIO::Elf64_Addr offset = ukRelocation->get_offset();

            //spdlog::warn("<-1-> Relocation: {} - (from {})", relo_name, ukRelocation->get_uk_symbol()->get_name());
            //continue;

            if (is_rodata && !is_in_map_symbol(relo_name, version)){
                spdlog::debug("Relocation: {} not found in map_name_symbol. Skip it.", relo_name);
                continue;
            }

            if (ukSection->get_name().rfind(RODATA, 0) == 0){

                offset = ref_sect->get_size();
                char *data = new char[N_SIZE];
                std::memset(data, 0, N_SIZE);
                ref_sect->append_data(data, N_SIZE);
                delete[] data;

                map_old_new_offset[relo_name + "@" + std::to_string(ukRelocation->get_offset())] = offset;
                //std::cout << relo_name + "@" + std::to_string(ukRelocation->get_offset()) << " = 0x" << std::hex << offset << std::endl;

            }else if (relo_name.rfind(RODATA, 0) == 0||relo_name.rfind(DATA, 0) == 0||relo_name.rfind(BSS, 0) == 0){

                // For .rodata, .data and .bss
                ELFIO::section* sect = reader.sections[ukRelocation->get_name()];
                addend = sect->get_size();
                //sect->append_data( ukRelocation->get_data(), ukRelocation->get_data_size() );

                if (map_relo_hash_addend[relo_name].find(ukRelocation->get_hash()) != map_relo_hash_addend[relo_name].end()){
                    // Retrieve old addend to avoid duplicated data
                    //TODO save ukRelocation->get_data() into a file for tracking purpose
                    spdlog::debug("Relocation: {} found in map_relo_hash_addend (size={})", relo_name, ukRelocation->get_data_size());
                    addend = map_relo_hash_addend[relo_name][ukRelocation->get_hash()];
                }else{
                    spdlog::debug("Relocation: {} not found in map_relo_hash_addend [{}] = [{}]", relo_name, ukRelocation->get_hash(), ukRelocation->get_data());
                    // Update the addend to have the correct offset in the new section
#if LIMIT_SIZE_SECTION
                    if (relo_name.rfind(RODATA, 0) == 0){
                        map_relo_hash_addend[relo_name][ukRelocation->get_hash()] = addend;
                        sect->append_data( ukRelocation->get_data(), ukRelocation->get_data_size() );
                    }
#endif
                }
            }

            ELFIO::relocation_section_accessor relo( reader, new_sec );

            // Check if the symbol is in the map_name_symbol
            if (map_name_symbol.find(relo_name) == map_name_symbol.end()){
                spdlog::debug("Symbol {} not found in map_name_symbol", relo_name);
                continue;
            }
            relo.add_entry(offset, map_name_symbol[relo_name]->get_index_entry(), ukRelocation->get_type(), addend);
        }

        return true;
    }

    bool add_inner_relocations(std::unordered_map<std::string, UkObjectFile*>& map_path_objs){
        // iterate through map_inner_relocation
        for (const auto& [key, value] : map_inner_relocation){

            // split the key to @
            std::string section_name = key.substr(0, key.find("@"));
            ELFIO::Elf64_Addr offset = std::stoi(key.substr(key.find("@")+1));
            ELFIO::Elf_Sxword addend = value->get_addend();

            // check if in map_old_new_offset
            std::string key_offset = section_name + "@" + std::to_string(value->get_addend());
            if (map_old_new_offset.find(key_offset) != map_old_new_offset.end()){
                std::cout << "Found in map_old_new_offset: " << std::hex << value->get_addend() << " New value:" << map_old_new_offset[key_offset] << std::endl;
                addend = map_old_new_offset[key_offset];
            }else{
                // add 8 bytes read from other object file
                std::cout << "Not found in map_old_new_offset: " << std::hex << value->get_addend() << std::endl;
                //const char* bytes_sect = map_path_objs[value->get_obj_name()]->get_data_from_addend(value->get_name(), value->get_addend(), N_SIZE);

                int max_size = 0;
                const char* raw_data = map_path_objs[value->get_obj_name()]->extract_data_from_section(value->get_name(), &max_size);

                const char* sliced = UkCommon::slice_array(raw_data, max_size, value->get_addend(), N_SIZE);
                if (sliced == nullptr){
                    spdlog::critical("Failed to slice array");
                    exit(EXIT_FAILURE);
                }

                ELFIO::section* sec = reader.sections[value->get_name()];
                addend = sec->get_size();

                // Add the sliced data to the section value->get_name()
                sec->append_data(sliced, N_SIZE);

                delete[] sliced;
            }

            // add the relocation to the section
            ELFIO::section* sec = reader.sections[RELA + section_name];
            if (sec != nullptr){
                ELFIO::relocation_section_accessor relo( reader, sec );
                relo.add_entry(offset, map_name_symbol[value->get_uk_symbol()->get_name()]->get_index_entry(), value->get_type(), addend);
            }else{
                spdlog::critical("Section {} not found while adding inner relocations", section_name);
            }

            //std::cout << section_name << std::hex << " =  0x" << offset << " => " << value->get_uk_symbol()->get_name() << '\n';
        }
        return true;
    }

    bool add_section(UkSection* ukSection, const bool is_modified = false){

        std::string section_name = ukSection->get_name();
        std::string symbol_name = ukSection->get_symbol()->get_name();

        if (is_modified){
            // Add hash for modified sections
            section_name += ukSection->get_version_name();
            symbol_name += ukSection->get_version_name();
            if (is_in_section(section_name)){
                spdlog::warn("Section: {} already exists", section_name);
                return false;
            }
            set_modified_sections.insert(section_name);
            ukSection->set_modified();
        }
        map_fct_modified[ukSection->get_symbol()->get_name()] = symbol_name;
        map_local_sections_name[section_name] = ukSection;
        vec_local_sections_name.push_back(section_name);

        ELFIO::section* new_sec = reader.sections.add( ukSection->get_name() );
        new_sec->set_addr_align( 0x0 );
        if (section_name.rfind(TEXT, 0) == 0){
            new_sec->set_type( ELFIO::SHT_PROGBITS );
            new_sec->set_flags( ELFIO::SHF_ALLOC | ELFIO::SHF_EXECINSTR );
        }else if (section_name.rfind(RODATA, 0) == 0){
            new_sec->set_type( ELFIO::SHT_PROGBITS );
            new_sec->set_flags( ELFIO::SHF_ALLOC );
        }else if (section_name.rfind(DATA, 0) == 0){
            new_sec->set_type( ELFIO::SHT_PROGBITS );
            new_sec->set_flags( ELFIO::SHF_ALLOC | ELFIO::SHF_WRITE );
        }else if (section_name.rfind(BSS, 0) == 0){
            new_sec->set_type( ELFIO::SHT_NOBITS );
            new_sec->set_flags( ELFIO::SHF_ALLOC | ELFIO::SHF_WRITE );
        }
        spdlog::info("Section: {} added to {})", section_name, path);

        // Add data to the new section
        new_sec->set_data( ukSection->get_raw_data(), ukSection->get_size() );
        if (new_sec->get_size() != ukSection->get_size()){
            new_sec->set_addr_align( ukSection->get_addr_align() );
            new_sec->set_size( ukSection->get_size() );
        }
        ukSection->set_ndx(new_sec->get_index());

        ELFIO::string_section_accessor stra( reader.sections[".strtab"] );
        ELFIO::section* symtab_sec = reader.sections[".symtab"];
        ELFIO::symbol_section_accessor symtab( reader, symtab_sec );

        // check if section_name is not in map_local_symbols
        if (map_local_symbols.find(section_name) == map_local_symbols.end()){
            auto s_index = symtab.get_symbols_num();
            ukSection->set_new_symtab_index(s_index);
            spdlog::debug("Section: {} index: to {})", ukSection->get_name(), ukSection->get_new_symtab_index());
            map_local_symbols[section_name] = s_index;
            // Add .text.foo section to the string table and symbol table
            if(symtab.add_symbol(stra.add_string(ukSection->get_name()), 0, 0, ELFIO::STT_SECTION|ELFIO::STV_DEFAULT, ELFIO::STB_LOCAL, ukSection->get_ndx()) == 0){
                spdlog::critical("Failed to add symbol: {}", section_name);
                throw std::runtime_error("Failed to add symbol (1): " + section_name);
            }
            symtab_sec->set_info(s_index+1);
            spdlog::warn("Add section {} in map_local_symbols", section_name);
        }else{
            ukSection->set_new_symtab_index(symtab.get_symbols_num());
            spdlog::error("[ANOMALY] Section: {} index: to {})", ukSection->get_name(), ukSection->get_new_symtab_index());
        }

        // check if symbol_name is not in map_local_symbols
        if (map_local_symbols.find(symbol_name) == map_local_symbols.end()){
            // Add foo symbol to the string table and symbol table
            auto s_index = symtab.get_symbols_num();
            map_local_symbols[symbol_name] = s_index;
            // Change visibility to STB_GLOBAL for the symbol
            auto visibility = ELFIO::STB_GLOBAL;

            if(symtab.add_symbol(stra.add_string( ukSection->get_symbol()->get_name()), ukSection->get_symbol()->get_value(), ukSection->get_symbol()->get_size(), visibility/*ukSection->get_symbol()->get_bind()*/, ukSection->get_symbol()->get_type(), ukSection->get_symbol()->get_other(), ukSection->get_ndx()) == 0){
                spdlog::critical("Failed to add symbol: {}", symbol_name);
                throw std::runtime_error("Failed to add symbol (2): " + symbol_name);
            }
            if (is_modified){
                ukcommon->add_weak_symbol(ukSection->get_symbol()->get_name());
            }
            symtab_sec->set_info(s_index+1);
        }

        if (ukSection->get_relocations().size() == 0){
            spdlog::debug("Section: {} has no relocations", section_name);
            return true;
        }

        // Add relocations to handle later
        UkReloSection* ukSectionRelo = new UkReloSection(ukSection->get_name(),  ukSection->get_symbol()->get_name(), ukSection->get_ndx(), is_modified);
        for (const UkRelocation* ukRelocation : ukSection->get_relocations()){
            ukSectionRelo->add_relocation(ukRelocation);
        }
        need_to_relocate.push_back(ukSectionRelo);

        return true;
    }

    inline void add_relocations(){
        std::for_each(need_to_relocate.begin(), need_to_relocate.end(), [&](const UkReloSection* o) { 
            add_relocation(o);
            delete o;
        });
    }

    bool save(){
        return reader.save(path);
    }

    bool have_modified_sections() const{
        return set_modified_sections.size() > 0;
    }

    bool have_weak_symbols() const{
        return ukcommon->get_weak_symbols().size() > 0;
    }

    const std::vector<UkSymbol*> get_local_symbols_external() const {
        return vec_local_symbols_external;
    }

    const std::vector<UkSection*> get_rela_sections() const {

        std::vector<UkSection*> rela_sections;
        for (const UkSection* ukSection : vec_rela_sections){
            std::string rela_name = ukSection->get_name().substr(RELA.size());
            auto s = map_local_sections_name.find(rela_name);
            UkSection* ref_section = vec_local_sections[s->second->get_ndx()];
            rela_sections.push_back(ref_section);
        }
        return rela_sections;
    }

private:
    std::string path;
    UkCommon* ukcommon;

    ELFIO::elfio reader;
    std::unordered_map<std::string, UkSection*> map_local_sections_name;

    std::unordered_map<std::string, ELFIO::Elf_Xword> map_local_symbols;
    std::unordered_map<std::string, std::string> map_fct_modified;

    std::unordered_map<std::string, const UkSymbol*> map_name_symbol;

    // Map the relocation hash to the addend (offset in the section data)
    // map_relo_hash_addend["rodata"]["hash_value"] = addend;
    std::unordered_map<std::string, std::unordered_map<std::string, ELFIO::Elf_Sxword>> map_relo_hash_addend;
    std::set<std::string> set_modified_sections;

    std::vector<UkSection*> vec_local_sections;
    std::vector<UkSymbol*> vec_local_symbols;
    std::vector<UkSymbol*> vec_local_symbols_external;
    std::vector<UkReloSection*> need_to_relocate;

    std::vector<std::string> vec_local_sections_name;
    std::vector<int> vec_index_relo_section;

    std::unordered_map<std::string, std::vector<const UkRelocation*>> map_vec_zero;

    std::unordered_map<std::string, const UkRelocation*> map_inner_relocation;

    std::unordered_map<std::string, ELFIO::Elf64_Addr> map_old_new_offset;
    std::unordered_map<std::string, ELFIO::Elf64_Addr> map_old_new_addend;

    std::vector<UkSection*> vec_rela_sections;

    void parse_section(){
        ELFIO::Elf_Half sec_num = reader.sections.size();
        for (int i = 0; i < sec_num; i++) {
            
            ELFIO::section* psec = reader.sections[i];
            UkSection* uk_section = new UkSection(psec, path);

            vec_local_sections.push_back(uk_section);
            if (psec->get_name().length() == 0){
                spdlog::debug("Skip section: {}", psec->get_name());
                continue;
            }

            if (psec->get_type() == ELFIO::SHT_REL || psec->get_type() == ELFIO::SHT_RELA) {
                spdlog::debug("Rel section: {}", uk_section->get_name());
                if (psec->get_name().find(TEXT) == std::string::npos) {
                    spdlog::warn(".rela.(ro)data section: {}", uk_section->get_name());
                    vec_rela_sections.push_back(uk_section);
                }
                vec_index_relo_section.push_back(i);
            }else{
                map_local_sections_name[uk_section->get_name()] = uk_section;
                vec_local_sections_name.push_back(uk_section->get_name());
            }

            if (ukcommon != nullptr && (psec->get_name().rfind(TEXT, 0) == 0 || psec->get_name().rfind(RODATA + ".", 0) == 0 || psec->get_name().rfind(DATA + ".", 0) == 0 || psec->get_name().rfind(BSS + ".", 0) == 0)){
                spdlog::info("{} added to uk_common: ", uk_section->get_name());
                ukcommon->add_section(uk_section);
            }
            spdlog::debug("Parse section: {} {}", uk_section->get_name(), path);
        }
    }

    void parse_symbols(){
        ELFIO::symbol_section_accessor symbols(reader, reader.sections[".symtab"]);
        for (ELFIO::Elf_Xword i = 0; i < symbols.get_symbols_num(); i++) {
            std::string name;
            ELFIO::Elf64_Addr value = 0;
            ELFIO::Elf_Xword size = 0;
            unsigned char bind = 0;
            unsigned char type = 0;
            ELFIO::Elf_Half ndx = 0;
            unsigned char other = 0;

            symbols.get_symbol(i, name, value, size, bind, type, ndx, other);
            if (name.length() == 0){
                // For SECTION type, the symbol name is empty (override it with the section name)
                name = reader.sections[ndx]->get_name();
            }
            UkSymbol* symbol = new UkSymbol(name, value, size, bind, type, ndx, other, i);

            if (type == ELFIO::STT_FUNC||type == ELFIO::STT_SECTION){
                vec_local_sections[ndx]->add_symbol(symbol);
            }else if (ukcommon != nullptr && type == ELFIO::STT_OBJECT){
                // for aggregated symbols
                vec_local_symbols_external.push_back(symbol);
                symbol->set_related_section(reader.sections[ndx]->get_name());
            }else if (ukcommon != nullptr && type == ELFIO::STT_NOTYPE && bind == ELFIO::STB_GLOBAL){
                vec_local_symbols_external.push_back(symbol);
            }else{
                spdlog::debug("Skip symbol: {} {}", name, path);
            }

            vec_local_symbols.push_back(symbol);
            map_local_symbols[name] = i;
            
        }
    }

    void parse_relocations(ELFIO::section* psec){
        // Iterate through all relocations
        ELFIO::relocation_section_accessor relocations(reader, psec);
        
        for (ELFIO::Elf_Xword j = 0; j < relocations.get_entries_num(); j++) {
            ELFIO::Elf64_Addr offset = 0;
            ELFIO::Elf_Word symbol_index = 0;
            ELFIO::Elf_Word type = 0;
            ELFIO::Elf_Sxword addend = 0;
            relocations.get_entry(j, offset, symbol_index, type, addend);
            
            UkRelocation* relocation = new UkRelocation(offset, symbol_index, type, addend, vec_local_symbols[symbol_index]->get_name(), this->path);

            // Make binding to the associated text section
            vec_local_sections[psec->get_info()]->addRelocation(relocation);
            // Make binding to the relocation symbol
            relocation->setSymbol(vec_local_symbols[symbol_index]);

            // Get ndx of the symbol
            const int ndx = vec_local_symbols[symbol_index]->get_ndx();
            if (ndx <= 0) {
                spdlog::debug("Symbol index: {} is not valid ({})", ndx, vec_local_symbols[symbol_index]->get_name());
                continue;
            }

            // Get associated section from ndx
            ELFIO::section* data_sec = reader.sections[ndx];
            if (data_sec->get_name().find(TEXT) != std::string::npos) {
                continue;
            }
            const char* data_bytes = data_sec->get_data();
            if (data_bytes == nullptr || data_sec->get_size() == 0){
                // .bss section -> no data
                spdlog::debug("Relocation: {} section is null (psec: {})", data_sec->get_name(), psec->get_name());
                continue;
            }

            // Parse data from the section
            if (relocation->get_type() == ELFIO::R_X86_64_PC32||relocation->get_type() == ELFIO::R_X86_64_32 || relocation->get_type() == ELFIO::R_X86_64_32S || relocation->get_type() == ELFIO::R_X86_64_64){
                if (psec->get_name().find(TEXT) != std::string::npos) {
                    // .rela.text
                    map_reloc_to_section_data(data_bytes, data_sec->get_size(), data_sec->get_name(), addend, relocation, psec->get_name());
                }else{
                    // .rela.data/.rela.rodata
                    if (psec->get_name().find(RODATA) != std::string::npos || psec->get_name().find(DATA) != std::string::npos){
                        map_reloc_to_section_data(data_bytes, data_sec->get_size(), data_sec->get_name(), addend, relocation, psec->get_name());
                    }else{
                        std::cout << "TODO CHECK HERE" << std::endl;
                    }
                }
            }else if (relocation->get_type() == ELFIO::R_X86_64_PLT32){
                spdlog::debug("Relocation: {} has type: {}", relocation->get_name(), relocation->get_type());
            }else{
                spdlog::critical("Unknown relocation: {} has type: {}", relocation->get_name(), relocation->get_type());
            }
        }
    }

    ELFIO::Elf_Xword round_up(ELFIO::Elf_Xword value, ELFIO::Elf_Xword alignment){
        return (value + alignment - 1) & ~(alignment - 1);
    } 

    void map_reloc_to_section_data(const char* data_bytes, const ELFIO::Elf_Xword size, const std::string &name,const ELFIO::Elf_Sxword addend, UkRelocation* ukRelocation, std::string psec_name){
        
        int zeroIndex = -1;
        // Find the first zero byte in the data (addend is the offset in the section data where the relocation should be applied to)
        for (ELFIO::Elf_Xword i = addend; i < size; i++) {
            if (data_bytes[i] == 0) {
                zeroIndex = i + 1;
                break;
            }
        }

        if (zeroIndex != -1) {
            // Copy elements from original array to a new array until zero byte is found
            size_t data_size = zeroIndex - addend;

            if (data_size == 1/* && data_bytes[addend] == 0*/){
                spdlog::debug("Relocation: {} (from {}) has size 1 (offset: 0x{:x} - content: 0x{:x})", ukRelocation->get_name(), psec_name, ukRelocation->get_offset(), data_bytes[addend]);
                ukRelocation->set_vec_zero();
                return;
            }

            char* newArray = new char[data_size + 1]; // +1 for the null terminator
            std::memcpy(newArray, data_bytes + addend, data_size);
            newArray[data_size] = '\0'; // Null-terminate the new array
            ukRelocation->setSectionData(newArray, data_size);
#if LIMIT_SIZE_SECTION
            if (name.rfind(RODATA, 0) == 0){
                map_relo_hash_addend[name][ukRelocation->get_hash()] = addend;
            }
#endif
        } else {
            spdlog::debug("No null byte found for relocation: {} ({}) - {}", ukRelocation->get_name(), strlen(data_bytes), name);
        }
    }

    void external_relocation(const std::string &symbol_name, ELFIO::symbol_section_accessor symtab, ELFIO::section* symtab_sec, ELFIO::string_section_accessor stra, const UkRelocation* ukRelocation, ELFIO::relocation_section_accessor relo){

        // declare extern as a const string
        const std::string EXTERN_RELO = "_extern";
        std::string relo_name = ukRelocation->get_name();
        ELFIO::Elf_Half bind = ukRelocation->get_uk_symbol()->get_bind();
        ELFIO::Elf_Half type = ukRelocation->get_type();
        ELFIO::Elf_Half sym_type = ukRelocation->get_uk_symbol()->get_type();
        ELFIO::Elf_Xword sym_size = ukRelocation->get_uk_symbol()->get_size();
        ELFIO::Elf_Half other = ukRelocation->get_uk_symbol()->get_other();
        ELFIO::Elf_Sxword addend = ukRelocation->get_addend();

        // get related section from the symbol
        ELFIO::section* related_sec = reader.sections[ukRelocation->get_uk_symbol()->get_related_section()];
        ELFIO::Elf_Half ndx = related_sec->get_index();

        // if TEXT is in the relocation name, then remove it
        bool found = false;
        if (relo_name.rfind(TEXT + ".", 0) == 0){
            relo_name = relo_name.substr(TEXT.size() + 1); // TEXT + .
            found = true;
        }

        if (found || sym_type == ELFIO::STT_FUNC){    
            bind = ELFIO::STB_GLOBAL;
            //std::cout << "**** Relocation: " << relo_name << " not found in " << path << std::endl;
            type = ELFIO::R_X86_64_PLT32;
            //addend = 0;
            sym_type = ELFIO::STT_NOTYPE;
            sym_size = 0;
            //other = ELFIO::STT_NOTYPE;
        }
        else if (sym_type == ELFIO::STT_OBJECT){
            bind = ELFIO::STB_GLOBAL;
            //type = ELFIO::R_386_32;
            sym_type = ELFIO::STT_NOTYPE;
            sym_size = 0;
            ndx = ELFIO::SHN_UNDEF;
            //other = ELFIO::STT_NOTYPE;
        }
        //TODO CHECK the symbol object

        // Check if already in the map
        if (map_local_symbols.find(relo_name + EXTERN_RELO) != map_local_symbols.end()){
            //relo.add_entry(ukRelocation->get_offset(), map_local_symbols[relo_name + EXTERN_RELO], ELFIO::R_386_PLT32, -4);
            relo.add_entry(ukRelocation->get_offset(), map_local_symbols[relo_name + EXTERN_RELO], type, addend);
            spdlog::error("[FIXED_2] Relocation' Symbol: [{}] not found in {}", relo_name, path);
            return;
        }

        if(symtab.add_symbol(stra.add_string(relo_name), ukRelocation->get_uk_symbol()->get_value(), sym_size, bind, sym_type, other, ndx) == 0){
        //if(symtab.add_symbol(stra.add_string(relo_name), ukRelocation->get_uk_symbol()->get_value(), 0, ELFIO::STB_GLOBAL, ELFIO::STV_DEFAULT, ELFIO::STT_NOTYPE, 0) == 0){
            spdlog::critical("Failed to add symbol: {}", symbol_name);
            throw std::runtime_error("Failed to add symbol (2): " + symbol_name);
        }

        symtab_sec->set_info(symtab.get_symbols_num());
        map_local_symbols[relo_name + EXTERN_RELO] = symtab.get_symbols_num()-1;

        ukcommon->add_global_section(relo_name, path);

        relo.add_entry(ukRelocation->get_offset(), map_local_symbols[relo_name + EXTERN_RELO], type, addend);
        //relo.add_entry(ukRelocation->get_offset(), map_local_symbols[relo_name + EXTERN_RELO], ELFIO::R_386_PLT32, -4);
        spdlog::error("[FIXED_1] Relocation' Symbol: [{}] not found in {}", relo_name, path);
    }

    void add_relocation(const UkReloSection* ukReloSection){

        ELFIO::string_section_accessor stra( reader.sections[".strtab"] );
        ELFIO::section* symtab_sec = reader.sections[".symtab"];
        ELFIO::symbol_section_accessor symtab( reader, symtab_sec );

        if (ukReloSection->get_relocations().size() > 0){
            ELFIO::section* relo_sec = reader.sections.add( ".rela" + ukReloSection->get_name());
            relo_sec->set_type( ELFIO::SHT_RELA );
            relo_sec->set_info( ukReloSection->get_ndx());
            relo_sec->set_addr_align( 0x8 );
            relo_sec->set_entry_size( 0x18 );
            relo_sec->set_flags( ELFIO::SHF_INFO_LINK );
            relo_sec->set_link( symtab_sec->get_index() );
            ELFIO::relocation_section_accessor relo( reader, relo_sec );
            for (const UkRelocation* ukRelocation : ukReloSection->get_relocations()){
                std::string relo_name = ukRelocation->get_name();
                
                if (ukReloSection->is_modified() && map_fct_modified.find(relo_name) != map_fct_modified.end()){
                    // Map relo_name to the new symbol name
                    relo_name = map_fct_modified[relo_name];
                }


                // Map the old symbol index to the new symbol index
                if (map_local_symbols.find(relo_name) != map_local_symbols.end()){
                    ELFIO::Elf_Sxword addend = ukRelocation->get_addend();
                    ELFIO::Elf_Xword index_sym_tab = map_local_symbols[relo_name];


                    if (ukRelocation->get_type() == ELFIO::R_X86_64_32 || ukRelocation->get_type() == ELFIO::R_X86_64_PC32 || ukRelocation->get_type() == ELFIO::R_X86_64_32S || ukRelocation->get_type() == ELFIO::R_X86_64_64){

                        ELFIO::section* related_sec = get_section_in_map(relo_name);
                        if (related_sec == nullptr){
                            external_relocation(ukReloSection->get_symbol_name(), symtab, symtab_sec, stra, ukRelocation, relo);
                            continue;
                        }

                        if (relo_name.rfind(BSS, 0) == 0){
                            // Skip BSS section and relocation that refer to .text section
                            relo.add_entry(ukRelocation->get_offset(), index_sym_tab, ukRelocation->get_type(), addend);
                            spdlog::debug("Relocation: {} added to {}", relo_name, path);
                            continue;
                        }

                        if (ukRelocation->is_vec_zero_relocation() && ukRelocation->get_name().rfind(TEXT, 0) != 0){

                            map_vec_zero[ukReloSection->get_name()].push_back(ukRelocation);

                            map_inner_relocation[ukReloSection->get_name() + "@" + std::to_string(ukRelocation->get_offset())] = ukRelocation;

                            //relo.add_entry(ukRelocation->get_offset(), index_sym_tab, ukRelocation->get_type(), addend);
                            spdlog::critical("--> Relocation: {} (->{}) has zero relocation 0x{:x}", ukReloSection->get_name(), ukRelocation->get_uk_symbol()->get_name(), addend);
                            continue;
                        }

                        spdlog::warn("Relocation: {} - ref: {} get_offset: 0x{:x} -> {} (bool={})", relo_name, related_sec->get_name(), ukRelocation->get_offset(), ukRelocation->get_data_size(), ukRelocation->is_vec_zero_relocation());

                        if (relo_name.rfind(RODATA, 0) == 0){
                            // Check if ukRelocation->get_hash is in map_relo_hash_addend
                            if (map_relo_hash_addend[relo_name].find(ukRelocation->get_hash()) != map_relo_hash_addend[relo_name].end()){
                                // Retrieve old addend to avoid duplicated data
                                //TODO save ukRelocation->get_data() into a file for tracking purpose
                                spdlog::warn("Relocation: {} found in map_relo_hash_addend (size={})", relo_name, ukRelocation->get_data_size());
                                addend = map_relo_hash_addend[relo_name][ukRelocation->get_hash()];
                            }else{
                                spdlog::info("Relocation: {} not found in map_relo_hash_addend [{}] = [{}]", relo_name, ukRelocation->get_hash(), ukRelocation->get_data());
                                // Update the addend to have the correct offset in the new section
                                addend = related_sec->get_size();
                                related_sec->append_data( ukRelocation->get_data(), ukRelocation->get_data_size() );
#if LIMIT_SIZE_SECTION
                                map_relo_hash_addend[relo_name][ukRelocation->get_hash()] = addend;
#endif
                                }
                        }
                        //std::cout << "Relocation: " << relo_name << " - ref: " << related_sec->get_name() << " addend: 0x" << std::hex << addend << std::endl;
                    }else if (ukRelocation->get_type() == ELFIO::R_X86_64_PLT32){
                        //TODO handle other types of relocations
                    }else{
                        //TODO handle other types of relocations
                        spdlog::critical("Unknown relocation: {} has type: {}", relo_name, ukRelocation->get_type());
                    }
                    //TODO update symbol value
                    relo.add_entry(ukRelocation->get_offset(), index_sym_tab, ukRelocation->get_type(), addend);
                    spdlog::debug("Relocation: {} added to {}", relo_name, path);
                }else{
                    external_relocation(ukReloSection->get_symbol_name(), symtab, symtab_sec, stra, ukRelocation, relo);
                }
            }
        }
    }
};