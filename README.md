# Spacer-Δ: Delta-Based Versioning for Unikernels

**Spacer-Δ** is a prototype tool for generating lightweight, delta-based versions of static libraries to enable efficient memory deduplication across multiple unikernel instances. It supports version-aware memory layouts that preserve alignment and sharing opportunities, while maintaining backward compatibility.

This tool is particularly useful in unikernel-based cloud environments where fine-grained memory sharing and performance isolation are critical.

Spacer-Δ relies on Spacer-SLT for some of the experiments (load time deduplication), please refer to the following repository to install and setup Spacer-SLT: https://github.com/gaulthiergain/Spacer-SLT

This repository contains the implementation, tooling, benchmarks, and experimental setup used to evaluate Spacer-SLT.

---

## 🧱 Project Structure

- `aligner/`: Toolchain for producing aligned unikernel binaries. These components enforce deterministic placement of code and data sections to maximize page sharing across unikernel instances.  
  - `aslr/` contains support for generating ASLR-enabled unikernels and the associated binary rewriter.  
  - `helpers/` provides scripts to minimize ELF binaries, extract shared libraries into `/dev/shm`, and generate description files used by Spacer-Δ.

- `apps/`: Applications used with Spacer-Δ. Each application is maintained in a separate repository and should be cloned using Git.

- `benchmark/`: Benchmarking scripts and experimental configurations. This directory contains the artifacts required to reproduce the experimental evaluation presented in the paper.

- `libs/`: Libraries used with Spacer-Δ. Each library is maintained in a separate repository and should be cloned using Git. The libraries are categorized into versioned and non-versioned libraries. For each versioned library, specific commit hashes are provided to ensure reproducibility.

- `tests/`: The test suite for Spacer-Δ, including tests and integration tests to validate functionality and performance. Only basic tests are provided in the folder. For further tests, please read the file `libs/libs.md` and `apps/apps.md` to clone the libraries and applications used for testing.

- `unikraft/`: The Unikraft codebase used for Spacer-Δ. This directory contains the script to dowload the specific Unikraft version used for the experimental evaluation.

## 🛠️ Dependencies

Spacer-Δ depends on the several dependencies for building and running the tools and experiments.

C++ dependencies:

- [`ELFIO`](https://github.com/serge1/ELFIO) (C++ ELF manipulation library)
- [`argparse`](https://github.com/p-ranav/argparse) (C++ argument parsing)
- [`spdlog`](https://github.com/gabime/spdlog) (Fast logging library)

Python dependencies:

- [`Lief`](https://pypi.org/project/lief/): Library to instrument executable formats - used in the aligner tool for ASLR-enabled unikernels.
- [`pyelftools`](https://pypi.org/project/pyelftools/): Library for analyzing ELF files and DWARF debugging information - used in helper scripts for ELF manipulation.

You can install them with your system package manager or manually clone and build them.

## 🚀 Building and Running Spacer-Δ

Spacer-Δ relies on the aligner toolchain to produce aligned unikernel binaries and to the delta-versioner tool to generate delta-based versions. First, ensure to build the delta-versioner tool as described below.

### Delta-versioner Tool

The `delta-versioner/` directory contains the source code for the Spacer-Δ tool, which generates delta-based versions of unikernel binaries. It is written in C++ and uses several libraries for ELF manipulation and logging. The main components of the tool are as follows:

- `src/UkCommon.hpp`: Common utility functions and constants used across the Spacer-Δ tool, including ELF section/type and helper macros.
- `src/UkModifier.hpp`: Contains logic for modify symbol binding.
- `src/UkObjectFile.hpp`: Abstraction for reading, analyzing, and manipulating individual ELF object files using ELFIO++.
- `src/UkObjectManager.hpp`: Manages multiple UkObjectFile instances and coordinates version comparisons, delta generation, and symbol tracking.
- `src/UkReloSection.hpp`: Maps relocation to section.
- `src/UkRelocation.hpp`: Models an ELF relocation, including its content, alignment, and position. Provides logic to hash section.
- `src/UkSection.hpp`: Models an ELF section, including its content, alignment, and position. Provides logic to hash section.
- `src/UkSymbol.hpp`: Handles symbol entries and properties.
- `src/xxhash.hpp`: Header-only implementation of the xxHash algorithm for fast hashing. Used to detect identical function bodies or sections.

Use the provided `Makefile` to build delta-versioner. Simply navigate to the `delta-versioner/` directory and run:

```bash
make
```

Then run it with:

```c++
Usage: delta-versioner [--help] [--version] [--workspace VAR] [--uksection VAR] [--log VAR] [--link VAR] [--uk_name VAR] [--sec_to_patch VAR] [--sec_to_globalize VAR] [--uk_version VAR]

Optional arguments:
  -h, --help          shows help message and exits
  -v, --version       prints version information and exits
  -w, --workspace     specify the workspace folder. [nargs=0..1] [default: "test/v1/"]
  -u, --uksection     specify the workspace folder. [nargs=0..1] [default: "lambda"]
  -l, --log           specify the log level. [nargs=0..1] [default: "info"]
  --link              specify the link file to use. [nargs=0..1] [default: "link64.lds"]
  --uk_name           The unikernel name to version (default: lib-lambda-v). [nargs=0..1] [default: "lib-lambda-v"]
  --sec_to_patch      Write in a file the modified sections to patch. [nargs=0..1] [default: "sec_to_patch.txt"]
  --sec_to_globalize  Write in a file the sections to globalize. [nargs=0..1] [default: "sec_to_globalize.txt"]
  --uk_version        The unikernel version to versionize (default: 2). [nargs=0..1] [default: 2]
```

### Testing and using Spacer-Δ

Spacer-Δ requires can be run by executing the `benchmark/benchmark_build` script. This script automates the process of building and running the Spacer-Δ experiments. It sets up the necessary environment, compiles the unikernels, and executes the benchmarks. The scripts accept several parameters to customize the experiments, such as `$TEST`and `$ASLR`, which control the type of test to run and whether to enable ASLR. Tests 1-10 correspond to basic tests to validate the functionality of Spacer-Δ, while other tests must be cloned to the `apps/` and `libs/` directories as listed in the `apps/apps.md` and `libs/libs.md` files.

You can add new tests by following these steps:

1. Create a `testX/` folder in the `tests/` directory, where `X` is the test number.
2. Create each version of the unikernel in subfolders `lib-lambda-v1/`, `lib-lambda-v2/`, etc.
3. Populate each version folder with the unikernel source code and necessary build files (`Makefile.uk` and `Makefile`). You can clone existing unikernels from the `apps/` and `libs/` directories.
4. Each subfolder must contain a `main_lambda.c` that includes the unikernel's main logic.
  4.1. Some tests may require specific configurations or dependencies. Ensure to include any additional files or scripts needed to build and run the unikernel. For doing, you can write a `script.sh` file that will be executed before building the unikernel.
5. Run the `benchmark/benchmark_build` script to build and execute your new test case.

---

## 🔬 Research Context

Spacer-Δ is part of a broader investigation into memory efficiency and consolidation in unikernel-based systems and was published into a paper presented at [IEEE CLOUD](https://www.computer.org/csdl/proceedings-article/cloud/2025/). If you use this code for academic work, or use Spacer-SLT, please cite the corresponding publication:

```bibtex
@inproceedings{gain2025socc,
    author = { Gain, Gaulthier and Knott, Benoit and Mathy, Laurent},
    booktitle = { 2025 IEEE 18th International Conference on Cloud Computing (CLOUD)},
    title = {{ Efficient Versioning for Unikernels }},
    year = {2025},
    volume = {},
    ISSN = {},
    pages = {296-307},
    keywords = {Memory management;Layout;Pipelines;Merging;Serverless computing;Collaboration;Libraries;Virtualization;Kernel;Software development management},
    doi = {10.1109/CLOUD67622.2025.00038},
    url = {https://doi.ieeecomputersociety.org/10.1109/CLOUD67622.2025.00038},
    publisher = {IEEE Computer Society},
    address = {Los Alamitos, CA, USA},
    month =Jul
  }
```

## 🤝 License and Contributions

This project is licensed under the BSD 3-Clause License. See the LICENSE file for details.

Contributions, feedback, and suggestions are welcome. Feel free to open an issue or submit a pull request.
