
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cstdint>

class UkModifier
{
    
public:
    UkModifier(const std::string& filepath) : filepath(filepath) {
        elf_data = read_elf_file(filepath);
    }

    // Main function to modify the symbol
    bool modify_symbol_binding(const std::vector<std::string> &symbol_names) {

        // Get ELF header
        auto *ehdr = reinterpret_cast<Elf64_Ehdr *>(elf_data.data());

        // Locate the section headers
        auto *shdrs = reinterpret_cast<Elf64_Shdr *>(elf_data.data() + ehdr->e_shoff);

        // Locate the symbol table and associated string table
        Elf64_Shdr *symtab = nullptr;
        Elf64_Shdr *strtab = nullptr;
        Elf64_Shdr *shstrtab = nullptr;
        for (int i = 0; i < ehdr->e_shnum; ++i) {
            if (shdrs[i].sh_type == 2) { // SHT_SYMTAB
                symtab = &shdrs[i];
            } else if (symtab && !strtab && shdrs[i].sh_type == 3) { // SHT_STRTAB (assume linked to symtab)
                strtab = &shdrs[i];
            } else if (symtab && strtab && shdrs[i].sh_type == 3) { // SHT_STRTAB (assume linked to symtab)
                shstrtab = &shdrs[i];
            }
        }

        if (!symtab || !strtab || !shstrtab) {
            std::cerr << "Failed to locate symbol or string table" << std::endl;
            return false;
        }

        // Parse the symbol table
        auto *symbols = reinterpret_cast<Elf64_Sym *>(elf_data.data() + symtab->sh_offset);
        size_t symbol_count = symtab->sh_size / sizeof(Elf64_Sym);
        const char *string_table = reinterpret_cast<const char *>(elf_data.data() + strtab->sh_offset);

        // Find and modify the target symbol
        for(const auto& symbol_name : symbol_names) {
            if (!modify_symbol_binding(symbols, symbol_count, string_table, symbol_name)) {
                std::cerr << "Symbol not found: " << symbol_name << std::endl;
            }else{
                std::cout << "Symbol modified: " << symbol_name << std::endl;
            }
        }
        
        return true;
    }

    // Function to write the modified ELF file
    void write_elf_file() {
        std::ofstream file(filepath, std::ios::binary | std::ios::trunc);
        if (!file) {
            throw std::runtime_error("Failed to open ELF file for writing");
        }

        if (!file.write(reinterpret_cast<const char *>(elf_data.data()), elf_data.size())) {
            throw std::runtime_error("Failed to write ELF file");
        }
    }

private:
    std::vector<uint8_t> elf_data;
    std::string filepath;

    typedef uint16_t Elf64_Half;
    typedef int16_t Elf64_SHalf;
    typedef uint32_t Elf64_Word;
    typedef int32_t Elf64_Sword;
    typedef uint64_t Elf64_Xword;
    typedef int64_t Elf64_Sxword;

    typedef uint64_t Elf64_Off;
    typedef uint64_t Elf64_Addr;
    typedef uint16_t Elf64_Section;

    // ELF header structure
    typedef struct {
        unsigned char   e_ident[16]; 
        Elf64_Half      e_type;
        Elf64_Half      e_machine;
        Elf64_Word      e_version;
        Elf64_Addr      e_entry;
        Elf64_Off       e_phoff;
        Elf64_Off       e_shoff;
        Elf64_Word      e_flags;
        Elf64_Half      e_ehsize;
        Elf64_Half      e_phentsize;
        Elf64_Half      e_phnum;
        Elf64_Half      e_shentsize;
        Elf64_Half      e_shnum;
        Elf64_Half      e_shstrndx;
    } Elf64_Ehdr;

    // Section header structure
    typedef struct {
            Elf64_Word      sh_name;
            Elf64_Word      sh_type;
            Elf64_Xword     sh_flags;
            Elf64_Addr      sh_addr;
            Elf64_Off       sh_offset;
            Elf64_Xword     sh_size;
            Elf64_Word      sh_link;
            Elf64_Word      sh_info;
            Elf64_Xword     sh_addralign;
            Elf64_Xword     sh_entsize;
    } Elf64_Shdr;

    // Symbol table entry structure
    typedef struct {
            Elf64_Word      st_name;
            unsigned char   st_info;
            unsigned char   st_other;
            Elf64_Half      st_shndx;
            Elf64_Addr      st_value;
            Elf64_Xword     st_size;
    } Elf64_Sym;

    // Function to read the ELF file
    std::vector<uint8_t> read_elf_file(const std::string &filename) {
        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        if (!file) {
            throw std::runtime_error("Failed to open ELF file");
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<uint8_t> buffer(size);
        if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
            throw std::runtime_error("Failed to read ELF file");
        }

        return buffer;
    }

    bool modify_symbol_binding(Elf64_Sym *symbols, size_t symbol_count, const char *string_table, const std::string &symbol_name) {
        for (size_t i = 0; i < symbol_count; ++i) {
            const char *name = string_table + symbols[i].st_name;
            //std::cout << "Checking symbol: " << name << std::endl;
            if (std::strcmp(name, symbol_name.c_str()) == 0) {

                // Change binding from GLOBAL to WEAK
                unsigned char binding = (symbols[i].st_info >> 4);
                unsigned char type = (symbols[i].st_info & 0xf);
                if (binding == 1) { // STB_GLOBAL
                    symbols[i].st_info = (0x2 << 4) | type; // STB_WEAK
                    std::cout << "Modified symbol binding to WEAK" << std::endl;

                    return true;
                } else {
                    std::cerr << "Symbol is not GLOBAL, no modification needed" << std::endl;
                    return false;
                }
            }
        }

        return false;
    }
};