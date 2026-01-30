#include <vector>
#include <elfio/elfio.hpp>
#include "UkRelocation.hpp"

class UkReloSection {
public:
    UkReloSection(const std::string& name, const std::string& symbol_name, ELFIO::Elf_Xword ndx, bool modified)
        : name(name), symbol_name(symbol_name), ndx(ndx), modified(modified) {
    }

    const std::string get_name() const {
        return name;
    }

    const std::string get_symbol_name() const {
        return symbol_name;
    }

    ELFIO::Elf_Xword get_ndx() const {
        return ndx;
    }

    bool is_modified() const {
        return modified;
    }

    // setter relocations vector
    void add_relocation(const UkRelocation* ukRelocation) {
        relocations.push_back(ukRelocation);
    }

    // getter relocations vector
    const std::vector<const UkRelocation*> get_relocations() const {
        return relocations;
    }

private:
    const std::string name;
    const std::string symbol_name;
    const ELFIO::Elf_Xword ndx;
    std::vector<const UkRelocation*> relocations;
    const bool modified;
};