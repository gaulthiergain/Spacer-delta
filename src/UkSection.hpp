#pragma once

#include <string>
#include <vector>
#include <spdlog/spdlog.h>
#include <elfio/elfio.hpp>

#include "xxhash.hpp"
#include "UkSymbol.hpp"
#include "UkRelocation.hpp"

class UkSection {
public:
    // Constructor
    UkSection(const ELFIO::section* elfioSection, const std::string& ukPath)
        : occurence(ukPath), name(elfioSection->get_name()),  addr_align(elfioSection->get_addr_align()), _size(elfioSection->get_size()) {
        raw_data = elfioSection->get_data();
        sect_type = elfioSection->get_type();
        hash = computeHash(elfioSection);
        uksymbol = nullptr;
        new_symtab_index = -1;
        ndx = elfioSection->get_index();
    }

    ~UkSection(){
        for (const UkRelocation* ukRelocation : relocations){
            delete ukRelocation;
        }
    }

    void set_new_symtab_index(int symtab_index) {
        new_symtab_index = symtab_index;
    }

    int get_new_symtab_index() const {
        return new_symtab_index;
    }

    ELFIO::Elf_Word get_type() const {
        return sect_type;
    }

    void set_ndx(int ndx) {
        this->ndx = ndx;
    }

    ELFIO::Elf_Xword get_ndx() const {
        return ndx;
    }

    const std::string get_occurence() const {
        return occurence;
    }

    void add_symbol(UkSymbol* symbol) {
        uksymbol = symbol;
    }

    ELFIO::Elf_Xword get_size() const {
        return _size;
    }

    const std::string get_hash() const {
        return hash;
    }

    void addRelocation(const UkRelocation* ukRelocation) {
        relocations.push_back(ukRelocation);
    }

    UkSymbol* get_symbol() const {
        return uksymbol;
    }

    const std::vector<const UkRelocation*> get_relocations() const {
        return relocations;
    }

    const std::string get_name() const {
        return name;
    }

    void set_modified() {
        modified = true;
    }

    bool is_modified() const {
        return modified;
    }

    const char* get_raw_data() const {
        return raw_data;
    }

    ELFIO::Elf_Xword get_addr_align() const {
        return addr_align;
    }

    const std::string get_version_name() const {
        std::regex versionRegex("v([0-9]+)\\.o");
        std::smatch match;

        std::regex_search(occurence, match, versionRegex);
        int version = std::stoi(match[1]);
        return "__v" + std::to_string(version) + "__";
    }

private:
    const std::string occurence;
    const std::string name;
    const char* raw_data;
    const ELFIO::Elf_Xword addr_align;
    const ELFIO::Elf_Xword _size = 0;
    ELFIO::Elf_Word sect_type;
    ELFIO::Elf_Xword ndx;
    int new_symtab_index;
    
    std::string hash;
    std::vector<const UkRelocation*> relocations;
    UkSymbol* uksymbol;
    bool modified = false;

    // Member function to compute hash
    static std::string computeHash(const ELFIO::section* elfioSection) {
        if (elfioSection == nullptr || elfioSection->get_data() == nullptr || elfioSection->get_size() == 0){
            return "";
        }else{
            XXHash64 xxhash64(0);
            xxhash64.add(elfioSection->get_data(), elfioSection->get_size());
            return std::to_string(xxhash64.hash());
        }
    }
};
