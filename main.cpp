#include <string>
#include <iostream>
#include <filesystem>
#include <spdlog/spdlog.h>
#include <argparse/argparse.hpp>

#include "src/UkObjectManager.hpp"

const static std::string UK_SECT = "lambda";
const static std::string WORKSPACE = "test/v1/";
const static std::string LINK_FILE = "link64.lds";
const static std::string UK_NAME = "lib-lambda-v";
const static std::string SEC_TO_PATCH = "sec_to_patch.txt";
const static std::string SEC_TO_GLOBALIZE = "sec_to_globalize.txt";

void init_logger(const std::string &mode){
    if (mode == "debug")
        spdlog::set_level(spdlog::level::debug); // Set global log level to debug
    else if (mode == "info")
        spdlog::set_level(spdlog::level::info); // Set global log level to info
    else if (mode == "warn" || mode == "warning")
        spdlog::set_level(spdlog::level::warn); // Set global log level to warn
    else if (mode == "error")
        spdlog::set_level(spdlog::level::err); // Set global log level to error
    else if (mode == "critical")
        spdlog::set_level(spdlog::level::critical); // Set global log level to critical
    else
        spdlog::set_level(spdlog::level::off); // Disable all
   //spdlog::set_pattern("[%H:%M:%S %z] [%n] [%^---%L---%$] [thread %t] %v");
}

int main( int argc, char** argv )
{
    argparse::ArgumentParser program("spacer_delta");

    program.add_argument("-w", "--workspace")
        .default_value(WORKSPACE)
        .help("specify the workspace folder.");
    program.add_argument("-u", "--uksection")
        .default_value(UK_SECT)
        .help("specify the workspace folder.");
    program.add_argument("-l", "--log")
        .default_value(std::string("info"))
        .help("specify the log level.");
    program.add_argument("--link")
        .default_value(LINK_FILE)
        .help("specify the link file to use.");
    program.add_argument("--uk_name")
        .help("The unikernel name to version (default: lib-lambda-v).")
        .default_value(UK_NAME);
    program.add_argument("--sec_to_patch")
        .default_value(SEC_TO_PATCH)
        .help("Write in a file the modified sections to patch.");
    program.add_argument("--sec_to_globalize")
        .default_value(SEC_TO_GLOBALIZE)
        .help("Write in a file the sections to globalize.");
    program.add_argument("--uk_version")
        .help("The unikernel version to versionize (default: 2).")
        .default_value(2)
        .scan<'i', int>();

    try {
        program.parse_args(argc, argv);
    }catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        return 1;
    }

    init_logger(program.get<std::string>("--log"));
    
    const int uk_version = program.get<const int>("--uk_version");
    const std::string workspace = program.get<std::string>("--workspace");

    if (uk_version == 1){
        spdlog::info("Copy only the object file to diff-v1.o");
        try{
            fs::copy_file(workspace + "lib-lambda-v1.o", workspace + "diff-v1.o", fs::copy_options::overwrite_existing);
        }catch(const fs::filesystem_error& e){
            spdlog::critical("Failed to copy file: {}", e.what());
            exit(EXIT_FAILURE);
        }
        return 0;
    }

    UkObjectManager manager(workspace,
                            program.get<std::string>("--uk_name"),
                            program.get<std::string>("--uksection"),
                            program.get<std::string>("--link"),
                            program.get<std::string>("--sec_to_patch"),
                            program.get<std::string>("--sec_to_globalize"),
                            uk_version);

    try {
        manager.process_folder();
    }catch (const std::exception& err) {
        spdlog::error(err.what());
        return 1;
    }

    manager.process_symbols();
    manager.process_section();

    manager.update_size_section();
    manager.adjust_symtab();
    manager.get_updated_symbols();

    manager.update_relocations();

    manager.add_custom_relocations();

    if (manager.save_merged() == false){
        spdlog::error("Failed to save the merged object file");
        return 1;
    }

    if (manager.have_global_sections()){
        manager.write_global_sections();
    }

    manager.modify_symbol_binding();

    /*if (manager.have_modified_sections()){
        manager.write_modified_sections();
    }*/

    return 0;
}
