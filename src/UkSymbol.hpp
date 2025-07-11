#pragma once

#include <string>
#include <elfio/elfio.hpp>

class UkSymbol {
public:
    UkSymbol(std::string name, ELFIO::Elf64_Addr value, ELFIO::Elf_Xword size, unsigned char bind, unsigned char type, ELFIO::Elf_Half ndx, unsigned char other, unsigned int index_entry = 0)
        : name(name), value(value), size(size), bind(bind), type(type), ndx(ndx), other(other), index_entry(index_entry) {
    }

    ~UkSymbol() {
    }

    const std::string get_name() const {
        return name;
    }

    ELFIO::Elf_Half get_ndx() const {
        return ndx;
    }

    ELFIO::Elf64_Addr get_value() const {
        return value;
    }

    ELFIO::Elf_Xword get_size() const {
        return size;
    }

    unsigned char get_bind() const {
        return bind;
    }

    unsigned char get_type() const {
        return type;
    }

    unsigned char get_other() const {
        return other;
    }

    void set_related_section(const std::string &section) {
        related_section = section;
    }

    const std::string get_related_section() const {
        return related_section;
    }

    // set value
    void set_value(ELFIO::Elf64_Addr value) {
        this->value = value;
    }

    // get index entry
    unsigned int get_index_entry() const {
        return index_entry;
    }

private:
    std::string name;
    ELFIO::Elf64_Addr value;
    ELFIO::Elf_Xword size;
    unsigned char bind; //info
    unsigned char type; //info
    ELFIO::Elf_Half ndx;
    unsigned char other; /* Symbol visibility */
    std::string related_section;
    unsigned int index_entry; // Index in the symbol table
};