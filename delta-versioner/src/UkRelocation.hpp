#pragma once

#include <string>

#include <elfio/elfio.hpp>

class UkRelocation {
public:
    UkRelocation(ELFIO::Elf64_Addr offset, ELFIO::Elf_Word symbol, ELFIO::Elf_Word type, ELFIO::Elf_Sxword addend, const std::string &symbol_name, const std::string &obj_name)
        : offset(offset), symbol(symbol), type(type), addend(addend), symbol_name(symbol_name), obj_name(obj_name) {
    }

    ~UkRelocation(){
        if (section_data != nullptr){
            delete[] section_data;
        }
    }

    void setSymbol(const UkSymbol* symbol){
        uk_symbol = symbol;
    }

    const std::string get_name() const {
        return symbol_name;
    }

    void setSectionData(const char* data, const size_t data_size){
        section_data = data;
        section_data_size = data_size;
        hash = computeHash(section_data, section_data_size);
    }

    const char* get_data() const {
        return section_data;
    }

    size_t get_data_size() const {
        return section_data_size;
    }

    ELFIO::Elf64_Addr get_offset() const {
        return offset;
    }

    ELFIO::Elf_Word get_symbol() const {
        return symbol;
    }

    ELFIO::Elf_Word get_type() const {
        return type;
    }

    ELFIO::Elf_Sxword get_addend() const {
        return addend;
    }

    const std::string get_hash() const {
        return hash;
    }

    const UkSymbol* get_uk_symbol() const {
        return uk_symbol;
    }

    void set_vec_zero(){
        is_vec_zero = true;
    }

    bool is_vec_zero_relocation() const {
        return is_vec_zero;
    }

    const std::string &get_obj_name() const {
        return obj_name;
    }

private:

    ELFIO::Elf64_Addr offset;
    ELFIO::Elf_Word symbol;
    ELFIO::Elf_Word type;
    ELFIO::Elf_Sxword addend;
    const std::string symbol_name;
    const std::string &obj_name;

    std::string hash = "";
    size_t section_data_size = 0;
    bool is_vec_zero = false;
    const UkSymbol* uk_symbol = nullptr;
    const char *section_data = nullptr;

    // Member function to compute hash
    static std::string computeHash(const char* data, const size_t data_size) {
        if (data == nullptr || data_size == 0){
            return "";
        }else{
            XXHash64 xxhash64(0);
            xxhash64.add(data, data_size);
            return std::to_string(xxhash64.hash());
        }
    }
};