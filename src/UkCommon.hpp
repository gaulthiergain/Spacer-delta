#pragma once

#include <set>
#include <list>
#include <string>
#include <elfio/elfio.hpp>
#include <spdlog/spdlog.h>

#include "UkSection.hpp"
#include "UkSymbol.hpp"

class UkCommon
{
public:
    UkCommon() = default;

    void add_section(const UkSection* section){
        all_sections_name[section->get_name()].push_back(section->get_occurence());
        all_sections_hash[section->get_name()].push_back(section->get_hash());
    }

    const std::unordered_map<std::string, std::list<std::string>>& get_all_sections_name() const {
        return all_sections_name;
    }

    const std::unordered_map<std::string, std::list<std::string>>& get_all_sections_hash() const {
        return all_sections_hash;
    }

    void add_global_section(const std::string& name, const std::string& chosen_uk){
        global_sections[name] = chosen_uk;
    }

    const std::unordered_map<std::string, std::string>& get_global_sections() const {
        return global_sections;
    }

    void add_weak_symbol(const std::string& name){
        weak_symbols.push_back(name);
    }

    const std::vector<std::string>& get_weak_symbols() const {
        return weak_symbols;
    }

    static const char* slice_array(const char* original, int max_size, int start, int length) {
        // Ensure start and length are within bounds
        if (start < 0 || length > max_size) {
            return nullptr;  // Return nullptr if indices are out of bounds
        }

        char* sliced = new char[length];

        // Copy characters from original string to sliced string
        std::memcpy(sliced, original + start, length);

        return sliced;
    }

private:

    std::unordered_map<std::string, std::list<std::string>> all_sections_name;
    std::unordered_map<std::string, std::list<std::string>> all_sections_hash;
    std::unordered_map<std::string, std::string> global_sections;

    std::vector<std::string> weak_symbols;

};